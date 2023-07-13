# .Net Core web 
### Restful Api with authentication Login, Register and JWT


## Create project.
```cs
dotnet new webapi -o JwtWebApi
```

Install packages
For create token.
```cs
dotnet add package Microsoft.IdentityModel.Tokens

For create JWT
```cs
System.IdentityModel.Tokens.Jwt
```

Create Dtos Directory and create file name : UserDto.cs.
```cs
namespace JwtWebApi.Dtos
{
    public class UserDto
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;  
    }
    
}
```

Create Models directory and create file name : User.cs model file
```cs
namespace JwtWebApi.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set;}
    }
    
}
```

Then after finish above step create controller file and copy below code push it in you AuthController.cs file.
```cs
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using JwtWebApi.Dtos;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace JwtWebApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration _configuration;
        public static User user = new User();

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            // Create password hash.
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = userDto.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDto userDto)
        {
            if (user.Username != userDto.Username)
            {
                return BadRequest("User not found!");
            }

            if (!VerifyPasswordHash(userDto.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Invalid password!");
            }


            string token = CreateToken(user);

            return Ok("user login");
        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

    }
}
```


## Reference.
[.NET 6 Web API 🔒 Create JSON Web Tokens (JWT) - User Registration / Login / Authentication](https://www.youtube.com/watch?v=v7q3pEK1EA0&t=1124s)