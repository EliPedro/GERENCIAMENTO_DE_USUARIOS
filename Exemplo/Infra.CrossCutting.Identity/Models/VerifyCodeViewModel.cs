using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace Infra.CrossCutting.Identity.Model
{
    public class VerifyCodeViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        [Display(Name = "Código")]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }

        [Display(Name = "Lembrar este browser?")]
        public bool RememberBrowser { get; set; }

        public bool RememberMe { get; set; }

        [HiddenInput]
        public string UserId { get; set; }
    }
}
