using System;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("{id}")]
        public ActionResult<User> GetUser(string id)
        {
            var user = _userService.FindById(id);
            return Ok(user);
        }

        [HttpPost]
        public ActionResult<User> CreateUser(UserDto dto)
        {
            var result = _userService.Create(dto.Name, dto.Email);
            return Created("", result);
        }

        [HttpDelete("{id}")]
        public ActionResult DeleteUser(string id)
        {
            _userService.Delete(id);
            return NoContent();
        }
    }
}
