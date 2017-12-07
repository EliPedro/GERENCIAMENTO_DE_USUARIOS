using System;
using System.ComponentModel.DataAnnotations;

namespace Infra.CrossCutting.Identity.Model
{
    public class ExternalLoginConfirmationViewModel
    {

        [Required]
        [Display(Name = "E-mail")]
        public string Email { get; set; }

        [Required]
        [Display(Name = "Nome")]
        public string Name { get; set; }

        [Required]
        [Display(Name = "Sobrenome")]
        public string LastName { get; set; }

        [ScaffoldColumn(false)]
        public string ImageUrl { get; set; }
    }
}
