using JWTWebAPI.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTWebAPI.Services
{
    public class JwtAuthenticationHandler : IJwtAuthenticationHandler
    {
        IConfiguration _config;
        public JwtAuthenticationHandler(IConfiguration config)
        {
            _config = config;
        }
        public UserModel AuthenticateUser(UserModel userinfo)
        {
            UserModel login = null;
            if(userinfo.UserName == _config["UserAuthenticationDetails:UserName"] && userinfo.Password == _config["UserAuthenticationDetails:Password"])
            {
                login = new UserModel
                {
                    UserName = _config["UserAuthenticationDetails:UserName"],
                    EmailAddress = _config["UserAuthenticationDetails:EmailAddress"],
                    Password = _config["UserAuthenticationDetails:Password"]
                };
                

            }
            return login;
        }

        public string GenerateJwtTokens(UserModel userinfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //define claims
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userinfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email, userinfo.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            //define token and write
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(300),
                signingCredentials: credentials
                );
            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodedToken;
        }
       
    }
}
