using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;

namespace Impostor.Server.Http;

[Route("/api/filtertags")]
[ApiController]
public sealed class FilterGamesController : ControllerBase
{
    [HttpGet]
    public IActionResult Index([FromHeader] AuthenticationHeaderValue authorization)
    {
        if (authorization.Scheme != "Bearer" || authorization.Parameter == null)
        {
            return BadRequest();
        }

        return Ok();
    }
}
