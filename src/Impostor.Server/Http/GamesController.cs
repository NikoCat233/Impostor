using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Impostor.Api.Config;
using Impostor.Api.Games;
using Impostor.Api.Games.Managers;
using Impostor.Api.Innersloth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Serilog;

namespace Impostor.Server.Http;

/// <summary>
/// This controller has method to get a list of public games, join by game and create new games.
/// </summary>
[Route("/api/games")]
[ApiController]
public sealed class GamesController : ControllerBase
{
    private readonly IGameManager _gameManager;
    private readonly ListingManager _listingManager;
    private readonly HostServer _hostServer;
    private readonly ILogger _logger = Log.Logger;

    public static Dictionary<string, List<string>> MmTokens = new Dictionary<string, List<string>>();


    /// <summary>
    /// Initializes a new instance of the <see cref="GamesController"/> class.
    /// </summary>
    /// <param name="gameManager">GameManager containing a list of games.</param>
    /// <param name="listingManager">ListingManager responsible for filtering.</param>
    /// <param name="serverConfig">Impostor configuration section containing the public ip address of this server.</param>
    public GamesController(IGameManager gameManager, ListingManager listingManager, IOptions<ServerConfig> serverConfig)
    {
        _gameManager = gameManager;
        _listingManager = listingManager;
        var config = serverConfig.Value;
        _hostServer = HostServer.From(IPAddress.Parse(config.ResolvePublicIp()), config.PublicPort);
    }

    /// <summary>
    /// Get a list of active games.
    /// </summary>
    /// <param name="mapId">Maps that are requested.</param>
    /// <param name="lang">Preferred chat language.</param>
    /// <param name="numImpostors">Amount of impostors. 0 is any.</param>
    /// <param name="authorization">Authorization header containing the matchmaking token.</param>
    /// <returns>An array of game listings.</returns>
    [HttpGet]
    public IActionResult Index(int mapId, GameKeywords lang, int numImpostors, [FromHeader] AuthenticationHeaderValue authorization)
    {
        switch (CheckMmToken(authorization.ToString()))
        {
            case DisconnectReason.Unknown:
                var token = JsonSerializer.Deserialize<TokenController.Token>(Convert.FromBase64String(authorization.Parameter));
                if (token == null)
                {
                    return BadRequest();
                }

                var clientVersion = new GameVersion(token.Content.ClientVersion);

                var listings = _listingManager.FindListings(HttpContext, mapId, numImpostors, lang, clientVersion);
                return Ok(listings.Select(GameListing.From));

            case DisconnectReason.NotAuthorized:
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));

            case DisconnectReason.ServerError:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));

            default:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));
        }
    }

    /// <summary>
    /// Get the address a certain game is hosted at.
    /// </summary>
    /// <param name="gameId">The id of the game that should be retrieved.</param>
    /// <param name="authorization">Authorization.</param>
    /// <returns>The server this game is hosted on.</returns>
    [HttpPost]
    public IActionResult Post(int gameId, [FromHeader] AuthenticationHeaderValue authorization)
    {
        switch (CheckMmToken(authorization.ToString()))
        {
            case DisconnectReason.Unknown:
                var code = new GameCode(gameId);
                var game = _gameManager.Find(code);

                if (game == null)
                {
                    return NotFound(new MatchmakerResponse(new MatchmakerError(DisconnectReason.GameNotFound)));
                }

                return Ok(HostServer.From(game.PublicIp));

            case DisconnectReason.NotAuthorized:
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));

            case DisconnectReason.ServerError:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));

            default:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));
        }
    }

    /// <summary>
    /// Get the address to host a new game on.
    /// </summary>
    /// <summary>
    /// <param name="authorization">Authorization.</param>
    /// </summary>
    /// <returns>The address of this server.</returns>
    [HttpPut]
    public IActionResult Put([FromHeader] AuthenticationHeaderValue authorization)
    {
        switch (CheckMmToken(authorization.ToString()))
        {
            case DisconnectReason.Unknown:
                return Ok(_hostServer);

            case DisconnectReason.NotAuthorized:
                return Unauthorized(new MatchmakerResponse(new MatchmakerError(DisconnectReason.NotAuthorized)));

            case DisconnectReason.ServerError:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));

            default:
                return BadRequest(new MatchmakerResponse(new MatchmakerError(DisconnectReason.ServerError)));
        }
    }

    private static uint ConvertAddressToNumber(IPAddress address)
    {
#pragma warning disable CS0618 // Among Us only supports IPv4
        return (uint)address.Address;
#pragma warning restore CS0618
    }

    public DisconnectReason CheckMmToken(string bearerToken)
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
                    if (MmTokens.TryGetValue(puidProperty.ToString(), out var hashes))
                    {
                        if (hashes.Contains(hashProperty.ToString()))
                        {
                            return DisconnectReason.Unknown;
                        }
                        else
                        {
                            return DisconnectReason.NotAuthorized;
                        }
                    }
                    else
                    {
                        return DisconnectReason.NotAuthorized;
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
            _logger.Warning($"Failed to extract and print Puid and Hash from JWT: {e.Message}");
            return DisconnectReason.ServerError;
        }
    }

    public class HostServer
    {
        [JsonPropertyName("Ip")]
        public required long Ip { get; init; }

        [JsonPropertyName("Port")]
        public required ushort Port { get; init; }

        public static HostServer From(IPAddress ipAddress, ushort port)
        {
            return new HostServer
            {
                Ip = ConvertAddressToNumber(ipAddress),
                Port = port,
            };
        }

        public static HostServer From(IPEndPoint endPoint)
        {
            return From(endPoint.Address, (ushort)endPoint.Port);
        }
    }

    public class MatchmakerResponse
    {
        [SetsRequiredMembers]
        public MatchmakerResponse(MatchmakerError error)
        {
            Errors = new[] { error };
        }

        [JsonPropertyName("Errors")]
        public required MatchmakerError[] Errors { get; init; }
    }

    public class MatchmakerError
    {
        [SetsRequiredMembers]
        public MatchmakerError(DisconnectReason reason)
        {
            Reason = reason;
        }

        [SetsRequiredMembers]
        public MatchmakerError(SanctionReasons sanctionReason, DateTimeOffset endsAt)
        {
            Reason = DisconnectReason.Sanctions;
            SanctionReason = sanctionReason;
            EndsAt = endsAt;
        }

        [JsonPropertyName("Reason")]
        public required DisconnectReason Reason { get; init; }

        [JsonPropertyName("SanctionReason")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public SanctionReasons SanctionReason { get; init; }

        /// <remarks>A value equal to <see cref="DateTimeOffset.MaxValue"/> means the sanction is permanent.</remarks>
        [JsonPropertyName("EndsAt")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public DateTimeOffset EndsAt { get; init; }
    }

    private class GameListing
    {
        [JsonPropertyName("IP")]
        public required uint Ip { get; init; }

        [JsonPropertyName("Port")]
        public required ushort Port { get; init; }

        [JsonPropertyName("GameId")]
        public required int GameId { get; init; }

        [JsonPropertyName("PlayerCount")]
        public required int PlayerCount { get; init; }

        [JsonPropertyName("HostName")]
        public required string HostName { get; init; }

        [JsonPropertyName("HostPlatformName")]
        public required string HostPlatformName { get; init; }

        [JsonPropertyName("Platform")]
        public required Platforms Platform { get; init; }

        [JsonPropertyName("Age")]
        public required int Age { get; init; }

        [JsonPropertyName("MaxPlayers")]
        public required int MaxPlayers { get; init; }

        [JsonPropertyName("NumImpostors")]
        public required int NumImpostors { get; init; }

        [JsonPropertyName("MapId")]
        public required MapTypes MapId { get; init; }

        [JsonPropertyName("Language")]
        public required GameKeywords Language { get; init; }

        public static GameListing From(IGame game)
        {
            var platform = game.Host?.Client.PlatformSpecificData;

            return new GameListing
            {
                Ip = ConvertAddressToNumber(game.PublicIp.Address),
                Port = (ushort)game.PublicIp.Port,
                GameId = game.Code,
                PlayerCount = game.PlayerCount,
                HostName = game.DisplayName ?? game.Host?.Client.Name ?? "Unknown host",
                HostPlatformName = platform?.PlatformName ?? string.Empty,
                Platform = platform?.Platform ?? Platforms.Unknown,
                Age = 0,
                MaxPlayers = game.Options.MaxPlayers,
                NumImpostors = game.Options.NumImpostors,
                MapId = game.Options.Map,
                Language = game.Options.Keywords,
            };
        }
    }
}
