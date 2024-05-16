using System;
using System.Collections.Generic;
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
                        var (resultStatus, puid, friendcode) = await SendRequestWithBearerAsync(bearerToken, request.ProductUserId);
                        notLocalFc = friendcode;

                        if (resultStatus == DisconnectReason.Unknown)
                        {
                            if (puid != request.ProductUserId)
                            {
                                _logger.Warning("Puid mismatch {0}({1}) IS:{2} Client:{3}", request.Username, ipAddress, puid, request.ProductUserId);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ErrorAuthNonceFailure)));
                            }

                            var platformEat = ExtractEatFromJwt(bearerToken);

                            if (platformEat.ToLower() == "deviceid" || platformEat == string.Empty)
                            {
                                _logger.Warning("Kick Guest Account / Bad Account {0}({1}) {2} for {3}", request.Username, ipAddress, puid, platformEat);
                                AddMMFailure(ipAddress.ToString());
                                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.SelfPlatformLock)));
                            }
                        }
                        else
                        {
                            if (resultStatus != DisconnectReason.ServerError)
                            {
                                AddMMFailure(ipAddress.ToString());
                            }

                            return Unauthorized(new MatchmakerResponse(new MatchmakerError(resultStatus)));
                        }

                        _logger.Information(ipAddress + " " + HashedPuid(puid) + " " + friendcode + " " + ExtractEatFromJwt(bearerToken));
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

    public async Task<(DisconnectReason DisconnectReason, string Puid, string Friendcode)> SendRequestWithBearerAsync(string bearerToken, string productUserId)
    {
        try
        {
            // Create a new HttpClient
            using (var client = new HttpClient())
            {
                // Create a new HttpRequestMessage
                var request = new HttpRequestMessage();

                // Set the method to POST
                request.Method = HttpMethod.Post;

                // Set the URL
                string url = InnerSlothServer(MatchmakerService._httpServerConfig.InnerSlothServerRegion) + "/api/user";
                request.RequestUri = new Uri(url);

                // Set the headers
                request.Headers.Add("Accept", "text/plain");
                request.Headers.Add("Authorization", "Bearer " + bearerToken);

                // Set the body
                var body = new
                {
                    Puid = productUserId, // Replace with your Puid
                    Username = "Impostor", // Replace with your Username
                    ClientVersion = "50603650", // Replace with your ClientVersion
                    Language = 13, // Replace with your Language
                };
                var bodyJson = JsonSerializer.Serialize(body);
                var httpContent = new StringContent(bodyJson, Encoding.UTF8, "application/json");

                // Add the content to the request
                request.Content = httpContent;

                // Send the request
                var response = await client.SendAsync(request);

                // Check if the response was successful
                if (response.IsSuccessStatusCode)
                {
                    // Get the response content
                    var content = await response.Content.ReadAsStringAsync();

                    // Decode the base64 content
                    var decodedContent = Encoding.UTF8.GetString(Convert.FromBase64String(content));

                    // Parse the JSON content
                    var jsonDocument = JsonDocument.Parse(decodedContent);
                    var root = jsonDocument.RootElement;

                    if (root.TryGetProperty("Content", out var contentProperty))
                    {
                        if (contentProperty.TryGetProperty("Puid", out var puidProperty))
                        {
                            var puidAndFriendcode = puidProperty.GetString().Split(' ');
                            if (puidAndFriendcode.Length == 2)
                            {
                                return (DisconnectReason.Unknown, puidAndFriendcode[0], puidAndFriendcode[1]);
                            }
                        }
                    }

                    throw new Exception("Could not extract Puid from response content.");
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // Handle the Unauthorized error
                    return (DisconnectReason.NotAuthorized, string.Empty, string.Empty);
                }
                else
                {
                    // Handle other errors
                    return (DisconnectReason.ServerError, string.Empty, string.Empty);
                }
            }
        }
        catch
        {
            // Catch any other exceptions
            return (DisconnectReason.ServerError, string.Empty, string.Empty);
        }
    }

    public string ExtractEatFromJwt(string jwt)
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
            var payloadBytes = Convert.FromBase64String(payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '='));
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            // Parse the JSON
            var jsonDocument = JsonDocument.Parse(payloadJson);
            var root = jsonDocument.RootElement;

            // Extract the `eat` value
            if (root.TryGetProperty("act", out var actProperty))
            {
                if (actProperty.TryGetProperty("eat", out var eatProperty))
                {
                    return eatProperty.GetString();
                }
            }

            throw new Exception("Could not extract `eat` from JWT");
        }
        catch
        {
            return string.Empty;
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
