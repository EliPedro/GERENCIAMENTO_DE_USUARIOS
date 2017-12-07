
using Infra.CrossCutting.Identity.Model;
using System.Data.Entity.ModelConfiguration;

namespace Infra.CrossCutting.Identity.EntityConfig
{
    public class ClientConfig : EntityTypeConfiguration<Client>
    {
        public ClientConfig()
        {
            HasKey(c => c.Id);
            ToTable("Clients");
        }
    }
}
