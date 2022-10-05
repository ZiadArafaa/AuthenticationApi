using Auth_using_jwt.Helpers;
using Auth_using_jwt.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth_using_jwt.Services
{
    public class AuthService: IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager,RoleManager<IdentityRole> roleManager,IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt=jwt.Value;
        }


        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) != null)
                return new AuthModel { Message = "Email Already Exist !" };

            if(await _userManager.FindByNameAsync(model.UserName) !=null)
                return new AuthModel { Message = "UserName Already Exist !" };

            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName=model.FirstName,
                LastName=model.LastName
            };

            var result = await _userManager.CreateAsync(user, model.PassWord);
            if(!result.Succeeded)
            {
                var Error = string.Empty;

                foreach (var error in result.Errors)
                    Error += $"{error.Description} , ";

                return new AuthModel { Message = Error };
            }


            var resultRole= await _userManager.AddToRoleAsync(user, "User");
            if (!resultRole.Succeeded)
            {
                var Error = string.Empty;

                foreach (var error in resultRole.Errors)
                    Error += $"{error.Description} , ";

                return new AuthModel { Message = Error };
            }

            var token = await CreateTokenAsync(user);

            return new AuthModel
            {
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpairsOn = token.ValidTo,
            };

        }
        public async Task<AuthModel> LoginAsync(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, model.PassWord))
                return new AuthModel { Message = "Email Or PassWord Incorrect" };

            var roles = await _userManager.GetRolesAsync(user);
            var token =await CreateTokenAsync(user);

            return new AuthModel
            {
                Email = user.Email,
                UserName = user.UserName,
                FirstName = user.FirstName,
                LastName = user.LastName,
                IsAuthenticated = true,
                Roles = roles.ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpairsOn = token.ValidTo,
            };

        }

        public async Task<string> AddUserRoleAsync(UserRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user == null|| !await _roleManager.RoleExistsAsync(model.RoleName))
                return "User Not Exist Or Role Not Valid";

            if (await _userManager.IsInRoleAsync(user, model.RoleName))
                return $"User Already In role {model.RoleName} ";

            var resultRole = await _userManager.AddToRoleAsync(user, model.RoleName);
            if (!resultRole.Succeeded)
            {
                var Error = string.Empty;

                foreach (var error in resultRole.Errors)
                    Error += $"{error.Description} , ";

                return Error;
            }

            return string.Empty;
        }

        private async Task<JwtSecurityToken> CreateTokenAsync(ApplicationUser user)
        {
            var UserClaims= await _userManager.GetClaimsAsync(user);
            var Roles =await _userManager.GetRolesAsync(user);
            var RoleClaims = new List<Claim>();

            foreach (var role in Roles)
                RoleClaims.Add(new Claim("roles", role));

            var Claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim("uid",user.Id)
            }.Union(UserClaims).Union(RoleClaims);

            var SymmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var SigningCredentials = new SigningCredentials(SymmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer:_jwt.Issuer,
                audience:_jwt.Audience,
                claims:Claims,
                expires:DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials:SigningCredentials
                );
        }

    }
}
