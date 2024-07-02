using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;

namespace Impostor.Server.Http
{
    public class EacController
    {
        public class EacData
        {
            public string FriendCode { get; set; }

            public string HashPUID { get; set; }

            public string Name { get; set; }

            public string Reason { get; set; }
        }

        public class EACList
        {
            public List<EacData> EACDataList { get; set; }
        }

        public class EACFunctions
        {
            private readonly ILogger _logger = Log.Logger;
            private string EndPointURL = "https://tohre.niko233.me/eac?token=";
            public EACList _eacList;

            public async Task UpdateEACListFromURLAsync(string token)
            {
                try
                {
                    using var client = new HttpClient();
                    string url = EndPointURL + token;
                    string json = await client.GetStringAsync(url);
                    List<EacData> eacDataList = JsonSerializer.Deserialize<List<EacData>>(json);
                    _eacList = new EACList { EACDataList = eacDataList };

                    _logger.Information("EACList updated successfully.");
                }
                catch (Exception ex)
                {
                    _logger.Error("Error occurred while retrieving EAC data: " + ex.Message);
                }
            }

            public bool CheckHashPUIDExists(string hashPUID)
            {
                if (_eacList == null)
                {
                    _logger.Warning("EACList is null.");
                    return false;
                }

                foreach (var eacData in _eacList.EACDataList)
                {
                    if (eacData.HashPUID == hashPUID)
                    {
                        _logger.Information("HashPUID {0} exists in EACList. Reason {1}", hashPUID, eacData.Reason);
                        return true;
                    }
                }

                return false;
            }
        }
    }
}
