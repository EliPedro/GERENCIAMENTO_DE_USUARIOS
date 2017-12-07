using System.ComponentModel.DataAnnotations;

namespace Infra.CrossCutting.Identity.Model
{
    public class AddPhoneNumberViewModel
    {
        [Required]
        [Phone]
        [Display(Name = "Celular")]
        public string Number { get; set; }
    }
}
