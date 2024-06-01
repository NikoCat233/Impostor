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
using Impostor.Api.Innersloth;
using Impostor.Server.Net;
using Impostor.Server.Net.Manager;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using static Impostor.Server.Http.GamesController;

namespace Impostor.Server.Http;

/// <summary>
/// This controller has a method to get an auth token.
/// </summary>
[Route("/api/user")]
[ApiController]
public sealed class TokenController : ControllerBase
{
    private readonly ILogger _logger = Log.Logger;
    public static readonly Dictionary<string, int> MmRequestFailure = new();

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
            if (Client._antiCheatConfig!.ForceAuthenticationOrKick)
            {
                _logger.Information("IPv6 address for {0} {1} is not allowed", request.Username, ipAddress);
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
            }
        }

        var notLocalFc = string.Empty;
        bool shouldAuthorize = false;

        if (MatchmakerService._httpServerConfig.UseInnerSlothAuth)
        {
            shouldAuthorize = true;
        }

        if (ClientManager._puids.TryGetValue(request.ProductUserId, out var existingToken))
        {
            if (existingToken.Ips.Contains(ipAddress.ToString()))
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
                        _logger.Warning("Too many failed mm requests from {0}", ipAddress);
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
                            var (tokenpuid, platformEat) = ExtractEatAndPuidFromJwt(bearerToken);
                            _logger.Information(tokenpuid + " " + platformEat);

                            if (tokenpuid != request.ProductUserId)
                            {
                                _logger.Warning("Puid mismatch {0}({1}) IS:{2} Client:{3}", request.Username, ipAddress, tokenpuid, request.ProductUserId);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
                            }

                            if (platformEat.ToLower() == "deviceid" || platformEat == string.Empty)
                            {
                                _logger.Warning("Kick Guest Account / Bad Account {0}({1}) {2} for {3}", request.Username, ipAddress, request.ProductUserId, platformEat);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.SelfPlatformLock)));
                            }

                            _logger.Information(ipAddress + " " + HashedPuid(tokenpuid) + " " + friendcode + " " + platformEat);
                        }
                        else
                        {
                            if (resultStatus != DisconnectReason.ServerError)
                            {
                                AddMMFailure(ipAddress.ToString());
                            }

                            _logger.Warning("Failed to get friendcode for {0} ({1}) ({2})", request.Username, request.ProductUserId, resultStatus);

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
                    _logger.Error(ex, "Error while processing the Authorization header");
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
            _logger.Information("{0} apparently had no account", request.Username);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));
        }

        if (MatchmakerService._httpServerConfig.UseEacCheck && MatchmakerService._eacFunctions.CheckHashPUIDExists(HashedPuid(request.ProductUserId)))
        {
            _logger.Warning("{0} ({1}) ({2}) is banned by EAC", request.Username);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(SanctionReasons.CheatingHacking, DateTimeOffset.Parse("2114-5-14"))));
        }

        // We can not handle the case where a user connect to server with 2 different account from a same ip.
        // If it happens, we should reject it while doing token response. Code related is in Game.Incoming.cs
        if (ClientManager._puids.Any(p => p.Key != request.ProductUserId && p.Value.Ips.Contains(ipAddress.ToString())))
        {
            _logger.Warning("{0} ({1}) ({2}) IpAddress already present in other puid tokens", request.Username, HashedPuid(request.ProductUserId), ipAddress);

            if (Client._antiCheatConfig!.ForceAuthenticationOrKick)
            {
                _logger.Warning("Decided to kick the new client. ForceAuthenticationOrKick");
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.DuplicateConnectionDetected)));
            }
            else
            {
                _logger.Warning("Still try to create a puid-token, but it probably conflicts with the previous one!");
            }
        }

        if (!ClientManager._puids.TryGetValue(request.ProductUserId, out var existingToken2))
        {
            _logger.Information("{0} ({1}) ({2}) has been added to puids", request.Username, HashedPuid(request.ProductUserId), ipAddress);
            ClientManager._puids.TryAdd(request.ProductUserId, new UserPayload(notLocalFc, new List<string> { ipAddress.ToString() }, new()));
            existingToken2 = ClientManager._puids[request.ProductUserId];
        }
        else if (!existingToken2.Ips.Contains(ipAddress.ToString()))
        {
            _logger.Information("{0} ({1}) ({2}) IP has been added.", request.Username, HashedPuid(request.ProductUserId), ipAddress);
            existingToken2.Ips.Add(ipAddress.ToString());
            ClientManager._puids[request.ProductUserId] = existingToken2;
        }

        if (!existingToken2.Hashes.Contains(randomHash))
        {
            existingToken2.Hashes.Add(randomHash);
            ClientManager._puids[request.ProductUserId] = existingToken2;
        }
        else // Impossible to reach this point
        {
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));
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
            _logger.Error(ex.ToString());

            // Catch any other exceptions
            return (DisconnectReason.ServerError, string.Empty);
        }
    }

    public (string Puid, string Eat) ExtractEatAndPuidFromJwt(string jwt)
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

    public class UserPayload
    {
        public UserPayload(string friendCode, List<string> ips, List<string> hashes)
        {
            FriendCode = friendCode;
            Ips = ips;
            Hashes = hashes;
            Clients = new();
        }

        public string FriendCode { get; set; }

        public List<string> Ips { get; set; }

        public List<string> Hashes { get; set; }

        public List<int> Clients { get; set; }
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

    public string InnerSlothServer(string region)
    {
        switch (region)
        {
            case "na":
                return "https://matchmaker.among.us";
            case "eu":
                return "https://matchmaker-eu.among.us";
            case "asia":
                return "https://matchmaker-as.among.us";

            default:
                return "https://matchmaker.among.us";
        }
    }
}
