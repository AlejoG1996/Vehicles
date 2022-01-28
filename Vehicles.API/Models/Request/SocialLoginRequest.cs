using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Vehicles.Common.Enums;

namespace Vehicles.API.Models.Request
{
    public class SocialLoginRequest
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }

        [Required]
        public string Id { get; set; }

        [Required]
        public LoginType LoginType { get; set; }

        [Required]
        public string FullName { get; set; }

        public string PhotoURL { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }
    }
}
