﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
{
    //Controller yerine controllerbase kullanırsa bir api olduğu ortaya çıkar.
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;

        }
        [HttpPost, Route("request")]
        public IActionResult RequestToken([FromBody] TokenRequest tokenRequest)
        {
            //Aşağıdaki kod amelasyonu engeller. Tek tek username boş mu password boş mu diye bakmayız.
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);

            }
            string token;
            if (_authenticationService.IsAuthenticated(tokenRequest, out token))
            {
                return Ok(token);
            }
            return BadRequest("Invalid Request");
        }

    }
}