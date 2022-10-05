using Auth_using_jwt.Models;

namespace Auth_using_jwt.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(LoginModel model);
        Task<string> AddUserRoleAsync(UserRoleModel model);
    }
}
