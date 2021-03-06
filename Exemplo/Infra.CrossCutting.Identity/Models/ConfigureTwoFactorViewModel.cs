﻿using System.Collections.Generic;
using System.Web.Mvc;

namespace Infra.CrossCutting.Identity.Model
{
    public class ConfigureTwoFactorViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<SelectListItem> Providers { get; set; }
    }
}
