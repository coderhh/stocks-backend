using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using stocks_backend.Entities;

namespace stocks_backend.Helpers
{
    public class DataContext: DbContext
    {
        public DbSet<Account> Accounts { get; set;}
        private readonly IConfiguration Configuration;
        public DataContext(IConfiguration configuration){
            Configuration = configuration;
        }
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to SQLite database
            options.UseSqlite(Configuration.GetConnectionString("stocksDatabase"));
        }
    }
}