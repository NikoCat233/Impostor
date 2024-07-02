using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Impostor.Api.Config;
using Impostor.Api.Innersloth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static Impostor.Server.Http.GamesController;

namespace Impostor.Server.Http;

/// <summary>
/// This controller has a method to get an auth token.
/// </summary>
[Route("/api/user")]
[ApiController]
public sealed class TokenController : ControllerBase
{
    private readonly ILogger<TokenController> _logger;
    private readonly AntiCheatConfig _antiCheatConfig;
    private readonly HttpServerConfig _httpServerConfig;
    public readonly EacController.EACFunctions _eacFunctions;

    public static HashSet<UserPayload> AuthClientData = new();
    private readonly Dictionary<string, int> MmRequestFailure = new();

    public TokenController(
        ILogger<TokenController> logger,
        IOptions<AntiCheatConfig> antiCheatOptions,
        IOptions<HttpServerConfig> httpServerOptions,
        EacController.EACFunctions eacFunctions)
    {
        _logger = logger;
        _antiCheatConfig = antiCheatOptions.Value;
        _httpServerConfig = httpServerOptions.Value;
        _eacFunctions = eacFunctions;
    }

    /// <summary>
    /// Get an authentication token.
    /// </summary>
    /// <param name="request">Token parameters that need to be put into the token.</param>
    /// <returns>A bare minimum authentication token that the client will accept.</returns>
    [HttpPost]
    public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequest request)
    {
        var ipAddress = "127.0.0.1";

        if (Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedIps))
        {
            var forwardedIp = forwardedIps.First()!.Split(',').Select(ip => ip.Trim()).FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedIp))
            {
                ipAddress = forwardedIp;
            }
        }

        if (string.IsNullOrEmpty(ipAddress))
        {
            ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        if (string.IsNullOrEmpty(ipAddress))
        {
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
        }

        // InnerSloth Udp network can not handle ipv6. If you need puid auth, do not open your server on ipv6
        if (IPAddress.TryParse(ipAddress, out var parsedIpAddress) && parsedIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (_antiCheatConfig!.ForceAuthOrKick)
            {
                _logger.LogInformation("IPv6 address for {0} {1} is not allowed", request.Username, ipAddress);
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
            }
        }

        var notLocalFc = string.Empty;
        bool shouldAuthorize = false;

        if (_httpServerConfig.UseInnerSlothAuth)
        {
            shouldAuthorize = true;
        }

        if (GetUnUsedUserPayLoad(request.ProductUserId, ipAddress, out var matchingUser))
        {
            if (matchingUser.CreatedAt < DateTime.UtcNow.AddMinutes(-1))
            {
                matchingUser.Used = true;
                AuthClientData.Remove(matchingUser);
                shouldAuthorize = true;
            }
            else
            {
                shouldAuthorize = false;
            }
        }

        if (shouldAuthorize)
        {
            if (Request.Headers.ContainsKey("Authorization"))
            {
                if (MmRequestFailure.TryGetValue(ipAddress.ToString(), out var failtimes))
                {
                    if (failtimes > 5)
                    {
                        _logger.LogWarning("Too many failed mm requests from {0}", ipAddress);
                        return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.TooManyRequests)));
                    }
                }

                try
                {
                    // Get the Authorization header
                    var authHeader = Request.Headers["Authorization"].ToString();

                    // Check if the Authorization header starts with "Bearer "
                    if (authHeader.StartsWith("Bearer "))
                    {
                        // Extract the Bearer token from the Authorization header
                        var bearerToken = authHeader.Substring("Bearer ".Length);
                        var (resultStatus, friendcode) = await SendRequestWithBearerAsync(bearerToken);
                        notLocalFc = friendcode;

                        if (resultStatus == DisconnectReason.Unknown)
                        {
                            var (tokenpuid, platformEat) = ReadPuidFromBearer(bearerToken);
                            _logger.LogInformation(tokenpuid + " " + platformEat);

                            if (tokenpuid != request.ProductUserId)
                            {
                                _logger.LogWarning("Puid mismatch {0}({1}) IS:{2} Client:{3}", request.Username, ipAddress, tokenpuid, request.ProductUserId);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
                            }

                            if (platformEat.ToLower() == "deviceid" || platformEat == string.Empty)
                            {
                                _logger.LogWarning("Kick Guest Account / Bad Account {0}({1}) {2} for {3}", request.Username, ipAddress, request.ProductUserId, platformEat);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.SelfPlatformLock)));
                            }

                            _logger.LogInformation(ipAddress + " " + HashedPuid(tokenpuid) + " " + friendcode + " " + platformEat);
                        }
                        else
                        {
                            if (resultStatus != DisconnectReason.ServerError)
                            {
                                AddMMFailure(ipAddress.ToString());
                            }

                            _logger.LogWarning("Failed to get friendcode for {0} ({1}) ({2})", request.Username, request.ProductUserId, resultStatus);

                            return Unauthorized(new MatchmakerResponse(new MatchmakerError(resultStatus)));
                        }
                    }
                    else
                    {
                        AddMMFailure(ipAddress.ToString());
                        return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error while processing the Authorization header");
                    AddMMFailure(ipAddress.ToString());
                    return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));
                }
            }
            else
            {
                AddMMFailure(ipAddress.ToString());
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
            }
        }

        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var random = new Random();
        var result = new string(
            Enumerable.Repeat(chars, 8)
                      .Select(s => s[random.Next(s.Length)])
                      .ToArray());

        var randomHash = HashedPuid(request.ProductUserId) + result;

        if (string.IsNullOrWhiteSpace(request.ProductUserId))
        {
            _logger.LogInformation("{0} apparently had no account", request.Username);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));
        }

        if (_httpServerConfig.UseInnerSlothAuth && _httpServerConfig.UseEacCheck
            && (_eacFunctions.CheckHashPUIDExists(HashedPuid(request.ProductUserId))
            || _eacFunctions.CheckFriendCodeExists(notLocalFc)))
        {
            _logger.LogWarning("{0} ({1}) ({2}) is banned by EAC", request.Username, HashedPuid(request.ProductUserId), ipAddress);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(SanctionReasons.CheatingHacking, DateTimeOffset.Parse("2114-5-14"))));
        }

        if (!GetUnUsedUserPayLoad(request.ProductUserId, ipAddress, out var matchingUser1))
        {
            matchingUser1 = new UserPayload(request.ProductUserId, notLocalFc, randomHash, request.Username, DateTime.UtcNow, ipAddress);
            AuthClientData.Add(matchingUser1);
            _logger.LogInformation("{0} ({1}) ({2}) has been added to puids", request.Username, HashedPuid(request.ProductUserId), ipAddress);
        }
        else
        {
            matchingUser1.Hash = randomHash;
        }

        var token = new Token
        {
            Content = new TokenPayload
            {
                ProductUserId = request.ProductUserId,
                ClientVersion = request.ClientVersion,
            },
            Hash = randomHash,
        };

        // Wrap into a Base64 sandwich
        var serialized = JsonSerializer.SerializeToUtf8Bytes(token);
        return Ok(Convert.ToBase64String(serialized));
    }

    public void AddMMFailure(string ip)
    {
        if (MmRequestFailure.ContainsKey(ip))
        {
            MmRequestFailure[ip]++;
        }
        else
        {
            MmRequestFailure.Add(ip, 1);
        }
    }

    private bool GetUnUsedUserPayLoad(string puid, string preIp, out UserPayload matchingUser)
    {
        matchingUser = AuthClientData.FirstOrDefault(user => user.Puid == puid && user.PreIp == preIp && !user.Used);
        return matchingUser != null;
    }

    public async Task<(DisconnectReason DisconnectReason, string Friendcode)> SendRequestWithBearerAsync(string bearerToken)
    {
        try
        {
            // Create a new HttpClient
            using (var client = new HttpClient())
            {
                // Create a new HttpRequestMessage
                var request = new HttpRequestMessage();

                // Set the method to GET
                request.Method = HttpMethod.Get;

                // Set the URL
                var url = "https://backend.innersloth.com/api/user/username";
                request.RequestUri = new Uri(url);

                // Set the headers
                request.Headers.Add("Accept", "application/vnd.api+json");
                request.Headers.Add("Accept-Encoding", "deflate, gzip");
                request.Headers.Add("User-Agent", "UnityPlayer/2020.3.45f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)");
                request.Headers.Add("X-Unity-Version", "2020.3.45f1");
                request.Headers.Add("Authorization", "Bearer " + bearerToken);

                // Send the request
                var response = await client.SendAsync(request);

                // Check the response status code
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    return (DisconnectReason.NotAuthorized, string.Empty);
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return (DisconnectReason.Unknown, string.Empty);
                }
                else if (response.IsSuccessStatusCode)
                {
                    var contentStream = await response.Content.ReadAsStreamAsync();
                    Stream decompressedStream;

                    if (response.Content.Headers.ContentEncoding.Contains("gzip"))
                    {
                        decompressedStream = new GZipStream(contentStream, CompressionMode.Decompress);
                    }
                    else if (response.Content.Headers.ContentEncoding.Contains("deflate"))
                    {
                        decompressedStream = new DeflateStream(contentStream, CompressionMode.Decompress);
                    }
                    else
                    {
                        decompressedStream = contentStream;
                    }

                    using (var reader = new StreamReader(decompressedStream))
                    {
                        var content = await reader.ReadToEndAsync();
                        var jsonDocument = JsonDocument.Parse(content);
                        var root = jsonDocument.RootElement;

                        if (root.TryGetProperty("data", out var dataProperty) &&
                            dataProperty.TryGetProperty("attributes", out var attributesProperty))
                        {
                            var username = attributesProperty.GetProperty("username").GetString();
                            var discriminator = attributesProperty.GetProperty("discriminator").GetString();
                            var friendcode = $"{username}#{discriminator}";

                            return (DisconnectReason.Unknown, friendcode);
                        }

                        throw new Exception("Could not extract friendcode from response content.");
                    }
                }
                else
                {
                    return (DisconnectReason.ServerError, string.Empty);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.ToString());

            // Catch any other exceptions
            return (DisconnectReason.ServerError, string.Empty);
        }
    }

    public (string Puid, string Eat) ReadPuidFromBearer(string jwt)
    {
        try
        {
            // JWT is in the format Header.Payload.Signature
            // Split the JWT to get the Payload
            var parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Invalid JWT");
            }

            // The Payload is Base64Url encoded, decode it
            var payload = parts[1];
            var payloadBytes = Convert.FromBase64String(payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '='));
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            // Parse the JSON
            var jsonDocument = JsonDocument.Parse(payloadJson);
            var root = jsonDocument.RootElement;

            // Extract the `eat` value and `sub` value
            string eat = string.Empty;
            string puid = string.Empty;

            if (root.TryGetProperty("act", out var actProperty) && actProperty.TryGetProperty("eat", out var eatProperty))
            {
                eat = eatProperty.GetString();
            }

            if (root.TryGetProperty("sub", out var subProperty))
            {
                puid = subProperty.GetString();
            }

            if (string.IsNullOrEmpty(eat) || string.IsNullOrEmpty(puid))
            {
                throw new Exception("Could not extract `eat` or `sub` from JWT");
            }

            return (puid, eat);
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    public static string HashedPuid(string puid2)
    {
        if (puid2 == null || puid2 == string.Empty)
        {
            return string.Empty;
        }

        var sha256Bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(puid2));
        var sha256Hash = BitConverter.ToString(sha256Bytes).Replace("-", string.Empty).ToLower();

        return string.Concat(sha256Hash.AsSpan(0, 5), sha256Hash.AsSpan(sha256Hash.Length - 4));
    }

    public DisconnectReason CheckMMToken(string bearerToken)
    {
        try
        {
            // Check if the token starts with "Bearer "
            if (!bearerToken.StartsWith("Bearer "))
            {
                throw new ArgumentException("Invalid bearer token");
            }

            // Remove the "Bearer " prefix
            var jwt = bearerToken.Substring("Bearer ".Length);

            // Decode the base64 encoded JSON
            var bytes = Convert.FromBase64String(jwt);
            var json = Encoding.UTF8.GetString(bytes);

            // Parse the JSON
            var jsonDocument = JsonDocument.Parse(json);
            var root = jsonDocument.RootElement;

            // Extract the `Content` object
            if (root.TryGetProperty("Content", out var contentProperty))
            {
                // Extract the `Puid` and `Hash` values
                if (contentProperty.TryGetProperty("Puid", out var puidProperty) && root.TryGetProperty("Hash", out var hashProperty))
                {
                    var matchingUser = AuthClientData.FirstOrDefault(user => user.Hash == hashProperty.ToString());

                    if (matchingUser == null)
                    {
                        return DisconnectReason.NotAuthorized;
                    }
                    else
                    {
                        if (matchingUser.Puid != puidProperty.ToString())
                        {
                            return DisconnectReason.NotAuthorized;
                        }
                        else
                        {
                            return DisconnectReason.Unknown;
                        }
                    }
                }
                else
                {
                    throw new ArgumentException("Can not get puid and hash");
                }
            }
            else
            {
                throw new ArgumentException("No Content found");
            }
        }
        catch (Exception e)
        {
            _logger.LogWarning($"Failed to extract and print Puid and Hash from JWT: {e.Message}");
            return DisconnectReason.ServerError;
        }
    }

    // Check if the ip is similar, if its similar we compare username and assign auth data.
    public bool CustomCompareIps(string ip1, string ip2)
    {
        try
        {
            var ip1Parts = ip1.Trim().Split('.');
            var ip2Parts = ip2.Trim().Split('.');

            if (ip1Parts[0] != ip2Parts[0] || ip1Parts[1] != ip2Parts[1])
            {
                return false;
            }

            var part3Ip1 = int.Parse(ip1Parts[2]);
            var part3Ip2 = int.Parse(ip2Parts[2]);
            if (Math.Abs(part3Ip1 - part3Ip2) <= 1)
            {
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Body of the token request endpoint.
    /// </summary>
    public class TokenRequest
    {
        [JsonPropertyName("Puid")]
        public required string ProductUserId { get; init; }

        [JsonPropertyName("Username")]
        public required string Username { get; init; }

        [JsonPropertyName("ClientVersion")]
        public required int ClientVersion { get; init; }

        [JsonPropertyName("Language")]
        public required Language Language { get; init; }
    }

    public class UserPayload
    {
        public UserPayload(string puid, string friendCode, string hash, string name, DateTime createdAt, string preIp)
        {
            Puid = puid;
            FriendCode = friendCode;
            Hash = hash;
            Name = name;
            CreatedAt = createdAt;
            PreIp = preIp;
        }

        public string Puid { get; set; }

        public string FriendCode { get; set; }

        public string Hash { get; set; }

        public string Name { get; set; }

        public DateTime CreatedAt { get; init; }

        public string PreIp { get; set; }

        public string RealIp { get; set; } = string.Empty;

        public bool Used { get; set; } = false;
    }

    /// <summary>
    /// Token that is returned to the user with a "signature".
    /// </summary>
    public sealed class Token
    {
        [JsonPropertyName("Content")]
        public required TokenPayload Content { get; init; }

        [JsonPropertyName("Hash")]
        public required string Hash { get; init; }
    }

    /// <summary>
    /// Actual token contents.
    /// </summary>
    public sealed class TokenPayload
    {
        private static readonly DateTime DefaultExpiryDate = new(2012, 12, 21);

        [JsonPropertyName("Puid")]
        public required string ProductUserId { get; init; }

        [JsonPropertyName("ClientVersion")]
        public required int ClientVersion { get; init; }

        [JsonPropertyName("ExpiresAt")]
        public DateTime ExpiresAt { get; init; } = DefaultExpiryDate;
    }
}
