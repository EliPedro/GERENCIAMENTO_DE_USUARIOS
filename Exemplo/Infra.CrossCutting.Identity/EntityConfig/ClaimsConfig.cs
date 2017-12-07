
using Infra.CrossCutting.Identity.Model;
using System.Data.Entity.ModelConfiguration;

namespace Infra.CrossCutting.Identity.EntityConfig
{
    public class ClaimsConfig : EntityTypeConfiguration<Claims>
    {
        public ClaimsConfig()
        {
            HasKey(c => c.Id);

            ToTable("Claims");
        }
    }
}
