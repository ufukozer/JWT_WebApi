using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApi
{
    public interface IAuthenticationService
    {
        bool IsAuthenticated(TokenRequest tokenRequest, out string token);
    }
}
