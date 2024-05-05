using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    /// <summary>
    /// Get an authentication token.
    /// </summary>
    /// <param name="request">Token parameters that need to be put into the token.</param>
    /// <returns>A bare minimum authentication token that the client will accept.</returns>
    [HttpPost]
    public IActionResult GetToken([FromBody] TokenRequest request)
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

        var token = new Token
        {
            Content = new TokenPayload
            {
                ProductUserId = request.ProductUserId,
                ClientVersion = request.ClientVersion,
            },
            Hash = "MalumMenu_was_not_here",
        };

        if (string.IsNullOrWhiteSpace(token.Content.ProductUserId))
        {
            _logger.Information("{0} apparently had no account", request.Username);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));
        }

        if (MatchmakerService._httpServerConfig.UseEacCheck && MatchmakerService._eacFunctions.CheckHashPUIDExists(HashedPuid(request.ProductUserId)))
        {
            _logger.Warning("{0} ({1}) ({2}) is banned by EAC", request.Username);
            return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.Hacking)));
        }

        if (!ClientManager._puids.ContainsKey(ipAddress.ToString()))
        {
            _logger.Information("{0} ({1}) ({2}) has been added to puids", request.Username, HashedPuid(request.ProductUserId), ipAddress);
            ClientManager._puids.TryAdd(ipAddress.ToString(), request.ProductUserId);
        }
        else if (ClientManager._puids[ipAddress.ToString()] != request.ProductUserId)
        {
            _logger.Information("{0} ({1}) ({2}) has been updated to ({3})", request.Username, HashedPuid(ClientManager._puids[ipAddress.ToString()]), ipAddress, HashedPuid(request.ProductUserId));
            ClientManager._puids[ipAddress.ToString()] = request.ProductUserId;
        }

        // Wrap into a Base64 sandwich
        var serialized = JsonSerializer.SerializeToUtf8Bytes(token);
        return Ok(Convert.ToBase64String(serialized));
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
