using System;
using System.ComponentModel.DataAnnotations;

namespace Mvc.ViewsModels
{
    public class ClaimsViewModel
    {
        public ClaimsViewModel()
        {
            Id = Guid.NewGuid();
        }
       
        public Guid Id { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Fornceça um nome para a Claim")]
        [MaxLength(128, ErrorMessage = "Tamanho máximo {0} excedido")]
        [Display(Name = "Nome da Claim")]
        public string Name { get; set; }
    }

}
