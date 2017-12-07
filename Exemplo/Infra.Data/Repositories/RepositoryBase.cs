using System.Linq;
using System.Collections.Generic;
using Exemplo.Dominio.Usuario.Interfaces.Repository;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;
using Dapper;

namespace Infra.Data.Repositories
{
    public class RepositoryBase<T> : IRepositoryBase<T> where T : class
    {
        protected readonly IDbConnection _db;
        public RepositoryBase()
        {
             
            _db = new SqlConnection(ConfigurationManager.ConnectionStrings["DbConnection"].ConnectionString);
        }
        
        public IEnumerable<T> ObterTodosUsuario()
        {
            return _db.Query<T>("SELECT * FROM Usuarios").ToList();
        }
    }
}
