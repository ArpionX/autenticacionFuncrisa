using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using System.Text;
using Turnos.data.entidades;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Turnos.core.interfaces;
using Turnos.core.servicios;
using Microsoft.Extensions.DependencyInjection;
using Turnos.data;
using Turnos.data.repositorios.interfaces;
using Turnos.data.repositorios.repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

//-------------INJECTION DEPENDENCY DE AUTHSERVICE----------------//
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();


//------------DB CONTEXT CONFIGURATION o CONEXION A BD----------------//
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);
//------------IDENTITY CONFIGURATION----------------//
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // == reglas de contraseña 
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;

    //== reglas de Usuario
    options.User.RequireUniqueEmail = true;
    //options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    //valor por defecto

    // == reglas de bloqueo por si intentan hacer un ataque de fuerza bruta
    /*options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // por defecto es 5 minutos
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;*/ //estos valores estan por defecto

    // == reglas de correo
    //options.SignIn.RequireConfirmedEmail = false; valor por defecto es false
    
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
//------------CONFIGURACION JWT---------------------//
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "Mi API .NET 9";
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
