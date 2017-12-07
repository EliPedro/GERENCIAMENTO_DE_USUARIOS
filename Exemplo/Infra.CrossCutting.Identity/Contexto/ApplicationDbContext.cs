using Infra.CrossCutting.Identity.EntityConfig;
using Infra.CrossCutting.Identity.Model;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;

namespace Infra.CrossCutting.Identity.Contexto
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext() : base("DbConnection", throwIfV1Schema: false) { } 
        
        public DbSet<Client> Clients { get; set; }
        public DbSet<Claims> Claims { get; set; }

        public static ApplicationDbContext Create() => new ApplicationDbContext();

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();

            modelBuilder.Configurations.Add(new ClientConfig());
            modelBuilder.Configurations.Add(new ClaimsConfig());

            modelBuilder.Entity<ApplicationUser>().ToTable("Usuarios");
            modelBuilder.Entity<IdentityRole>().ToTable("Papeis");
            modelBuilder.Entity<IdentityUserRole>().ToTable("UsersPapeis");
            modelBuilder.Entity<IdentityUserLogin>().ToTable("Logins");
            modelBuilder.Entity<IdentityUserClaim>().ToTable("UsersClaims");

        }
    }
}
