using Auth_using_jwt.Models;
using Auth_using_jwt.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Auth_using_jwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthsController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthsController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("RegisterAsync")]
        public async Task<IActionResult> RegisterAsync(RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result=await _authService.RegisterAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("LoginAsync")]
        public async Task<IActionResult> LoginAsync(LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.LoginAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [Authorize(Roles ="Admin")]
        [HttpPost("AddUserRoleAsync")]
        public async Task<IActionResult> AddUserRoleAsync(UserRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddUserRoleAsync(model);

            if(!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok();
        }
    }
}
