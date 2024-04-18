using System.Text.Json.Serialization;

namespace Impostor.Http
{
    public class FriendsListRequest
    {
        [JsonPropertyName("username")]
        public string? Username { get; set; }

        [JsonPropertyName("recipient_puid")]
        public string? RecipientId { get; set; }

        [JsonPropertyName("recipient_friendcode")]
        public string? RecipientUsername { get; set; }

        [JsonPropertyName("data")]
        public RequestData? Data { get; set; }

        public static FriendsListRequest ChangeUsername(string username)
        {
            return new FriendsListRequest
            {
                Data = new RequestData
                {
                    Attributes = new FriendsListRequest { Username = username },
                    Type = "change_username",
                },
            };
        }

        public static FriendsListRequest SendRequest(string recipientId, string type)
        {
            return new FriendsListRequest
            {
                Data = new RequestData
                {
                    Attributes = new FriendsListRequest { RecipientId = recipientId },
                    Type = type,
                },
            };
        }

        public class RequestData
        {
            [JsonPropertyName("type")]
            public string? Type { get; set; }

            [JsonPropertyName("attributes")]
            public FriendsListRequest? Attributes { get; set; }
        }
    }
}
