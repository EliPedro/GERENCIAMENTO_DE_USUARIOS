namespace Infra.CrossCutting.Identity.Migrations
{
    using Infra.CrossCutting.Identity.Contexto;
    using System.Data.Entity.Migrations;
    
    internal sealed class Configuration : DbMigrationsConfiguration<ApplicationDbContext>
    {
        public Configuration() => AutomaticMigrationsEnabled = true;

        protected override void Seed(Infra.CrossCutting.Identity.Contexto.ApplicationDbContext context)
        {
            
        }
    }
}
