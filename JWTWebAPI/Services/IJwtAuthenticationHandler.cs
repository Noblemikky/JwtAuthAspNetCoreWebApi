using JWTWebAPI.Models;

namespace JWTWebAPI.Services
{
    public interface IJwtAuthenticationHandler
    {
        UserModel AuthenticateUser(UserModel userinfo);
        string GenerateJwtTokens(UserModel userinfo);
    }
}
