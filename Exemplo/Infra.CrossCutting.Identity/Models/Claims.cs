using System;

namespace Infra.CrossCutting.Identity.Model
{
    public class Claims
    {
        public Claims()
        {
            Id = Guid.NewGuid();
        }

        public Guid Id { get; set; }
        public string Name { get; set; }


    }
}
