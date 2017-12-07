using Exemplo.Dominio.Usuario;
using Exemplo.Dominio.Usuario.Interfaces.Repository;

namespace Infra.Data.Repositories
{
    public class UsuarioRepository : RepositoryBase<Usuario>, IUsuarioRepository
    {
    }
}
