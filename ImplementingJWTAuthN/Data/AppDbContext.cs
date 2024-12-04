using Microsoft.EntityFrameworkCore;
using ImplementingJWTAuthN.Models;

namespace ImplementingJWTAuthN.Data
{
    public class AppDbContext : DbContext
    {
        public required DbSet<User> Users { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().HasIndex(u => u.Email).IsUnique(); // Ensure unique emails
        }
    }
}