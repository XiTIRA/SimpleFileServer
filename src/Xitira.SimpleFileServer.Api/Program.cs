using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Models;
using Scalar.AspNetCore;

Dictionary<string, string> shares = new Dictionary<string, string>();
shares.Add("sh1", @"/home/rlaffey/Desktop/testShare/");

var builder = WebApplication.CreateSlimBuilder(args);

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "SimpleFileServer";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "SimpleFileServerUsers";
var jwtKey =
    builder.Configuration["Jwt:Key"] ??
    "YourSecretKeyForAuthenticationOfSimpleFileServer12345"; // In production, use a proper secret management system
var jwtExpiration = builder.Configuration["Jwt:Expiration"] ?? "4";

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ShareRead", policy =>
        policy.RequireRole("User").RequireClaim("scope", "read")
            .AddRequirements(new ShareAccessRequirement()));
    
    options.AddPolicy("ShareWrite", policy =>
        policy.RequireRole("User").RequireClaim("scope", "write")
            .AddRequirements(new ShareAccessRequirement()));
    
    options.AddPolicy("ShareDelete", policy =>
        policy.RequireRole("User").RequireClaim("scope", "delete")
            .AddRequirements(new ShareAccessRequirement()));
});

// Register the authorization handler
builder.Services.AddSingleton<IAuthorizationHandler, ShareAccessAuthorizationHandler>();


builder.Services.AddOpenApi(options =>
{
    options.AddScalarTransformers();
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        var tagGroups = new OpenApiArray
        {
            new OpenApiObject
            {
                ["name"] = new OpenApiString("Admin"),
                ["tags"] = new OpenApiArray
                {
                    new OpenApiString("Auth"),
                    new OpenApiString("Users"),
                    new OpenApiString("Shares")
                }
            },
            new OpenApiObject
            {
                ["name"] = new OpenApiString("Share Operations"),
                ["tags"] = new OpenApiArray
                {
                    new OpenApiString("File"),
                    new OpenApiString("Directory")
                }
            },
        };

        document.Extensions.Add("x-tagGroups", tagGroups);
        return Task.CompletedTask;
    });
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var app = builder.Build();
app.MapOpenApi();
app.MapScalarApiReference();

var authGroup = app.MapGroup("/auth");
var apiGroup = app.MapGroup("/v1");


authGroup.MapPost("/login",
        ([FromBody] LoginModel login) =>
        {
            // In a real app, validate credentials against a database
            if (login.Username == "admin" && login.Password == "password")
            {
                var claims = new List<Claim>
                {
                    new("sub", login.Username),
                    new("name", login.Username),
                    new("role", "Admin"),
                    new("role", "User"),
                    new("scope", "read"),
                    new("scope", "write"),
                    new("scope", "delete"),
                    new("share", "sh1")
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: jwtIssuer,
                    audience: jwtAudience,
                    claims: claims,
                    expires: DateTime.Now.AddHours(int.Parse(jwtExpiration)),
                    signingCredentials: creds);

                return Results.Ok(new JwtSecurityTokenHandler().WriteToken(token));
            }

            return Results.Unauthorized();
        })
    .WithDescription("Generate a token for further access")
    .WithSummary("Login")
    .WithBadge("new")
    .WithTags("Auth")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);


apiGroup.MapPost("/file/mv/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path,
            [FromBody] [Description("Destination to move the file to")]
            FileDestination fileDestination
        ) =>
        {
            return Results.Ok($"moving {path} to {fileDestination.Path}");
        })
    .WithDescription("Move a file, returns the new path")
    .WithSummary("Move File")
    .WithBadge("new")
    .WithTags("File")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);

apiGroup.MapPost("/file/cp/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path,
            [FromBody] [Description("Destination to copy the file to")]
            FileDestination fileDestination
        ) =>
        {
            return Results.Ok($"moving {path} to {fileDestination.Path}");
        })
    .WithDescription("Copy a file, returns the new path")
    .WithSummary("Copy File")
    .WithBadge("new")
    .WithTags("File")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);


apiGroup.MapGet("/file/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path
        ) =>
        {
            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (!File.Exists(fullPath))
            {
                return Results.NotFound("Directory does not exist.");
            }

            byte[] fileBytes = System.IO.File.ReadAllBytes(fullPath);

            return Results.File(fileBytes, null, Path.GetFileName(fullPath));
        })
    .WithDescription("Downloads a file")
    .WithSummary("Get File")
    .WithBadge("new")
    .WithTags("File")
    .RequireAuthorization("ShareRead")
    .Experimental()
    .Produces<string>(StatusCodes.Status404NotFound);

apiGroup.MapPut("/file/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path,
            [FromForm] IFormFile file
        ) =>
        {
            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (File.Exists(fullPath))
            {
                return Results.Conflict("File already exists.");
            }

            try
            {
                using var stream = new FileStream(fullPath, FileMode.Create);
                file.CopyTo(stream);
            }
            catch (DirectoryNotFoundException ex)
            {
                return Results.BadRequest("Part of the path does not exist.");
            }
            catch
            {
                return Results.BadRequest("An error occurred while saving the file.");
            }

            return Results.Ok($"File saved to {fullPath[shares[share].Length ..]}");
        })
    .WithDescription("Uploads a file")
    .WithSummary("Upload File")
    .WithBadge("new")
    .WithTags("File")
    .RequireAuthorization("ShareWrite")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound)
    .DisableAntiforgery();

apiGroup.MapDelete("/file/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path
        ) =>
        {
            if (!shares.ContainsKey(share))
            {
                return Results.NotFound("The share does not exist.");
            }


            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (!File.Exists(fullPath))
            {
                return Results.Conflict("File does not exist.");
            }

            try
            {
                File.Delete(fullPath);
            }
            catch
            {
                return Results.BadRequest("An error occurred while deleting the file.");
            }

            return Results.Ok($"File deleted from {fullPath[shares[share].Length ..]}");
        })
    .WithDescription("Deletes a file")
    .WithSummary("Delete File")
    .WithBadge("new")
    .WithTags("File")
    .RequireAuthorization("ShareDelete")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);


apiGroup.MapGet("/dir/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path,
            [FromQuery] bool recursive = false
        ) =>
        {
            if (!shares.ContainsKey(share))
            {
                return Results.NotFound("The share does not exist.");
            }

            if (path == "{path}" || path == "/" || path == @"\")
            {
                return Results.BadRequest(
                    "You must specify a path to a directory. Use ~ (tilde) to refer to the home directory.");
            }

            if (path == "~")
            {
                path = string.Empty;
            }

            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (!Directory.Exists(fullPath))
            {
                return Results.NotFound("Directory does not exist.");
            }

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(fullPath, "*", searchOption);
            var directories = Directory.GetDirectories(fullPath, "*", searchOption);
            var model = new DirectoryListModel
            {
                Files = files.Select(f => NormalizePath(f[shares[share].Length ..].Replace(fullPath, ""))).ToList(),
                Directories = directories.Select(d => NormalizePath(d.Replace(fullPath, ""))).ToList()
            };
            return Results.Ok(model);
        })
    .WithDescription("Returns a directory listing of files and directories. Use ~ for the base of the share")
    .WithSummary("List Directory")
    .WithBadge("new")
    .WithTags("Directory")
    .RequireAuthorization("ShareRead")
    .WithMetadata("UseBearer")
    .Experimental()
    .Produces<DirectoryListModel>()
    .Produces<string>(StatusCodes.Status404NotFound)
    .Produces<string>(StatusCodes.Status400BadRequest);

apiGroup.MapPut("/dir/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path
        ) =>
        {
            if (!shares.ContainsKey(share))
            {
                return Results.NotFound("The share does not exist.");
            }

            if (path == "{path}" || path == "/" || path == @"\")
            {
                return Results.BadRequest(
                    "You must specify a path to a directory. Use ~ (tilde) to refer to the home directory.");
            }

            if (path == "~")
            {
                path = string.Empty;
            }

            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (Directory.Exists(fullPath))
            {
                return Results.NotFound("Directory already exist.");
            }

            try
            {
                Directory.CreateDirectory(fullPath);
            } catch {return Results.BadRequest("An error occurred while creating the directory.");}
            
            return Results.Ok(fullPath[shares[share].Length ..]);
        })
    .WithDescription("Creates a directory")
    .WithSummary("Create Directory")
    .WithBadge("new")
    .WithTags("Directory")
    .RequireAuthorization("ShareWrite")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);

apiGroup.MapDelete("/dir/{share}/{*path}",
        (
            [FromRoute] [Description("The name of the share")]
            string share,
            [FromRoute] [Description("The path of the file or directory")]
            string path
        ) =>
        {
            if (!shares.ContainsKey(share))
            {
                return Results.NotFound("The share does not exist.");
            }

            if (path == "{path}" || path == "/" || path == @"\")
            {
                return Results.BadRequest(
                    "You must specify a path to a directory. Use ~ (tilde) to refer to the home directory.");
            }

            if (path == "~")
            {
                path = string.Empty;
            }

            var fullPath = Path.Combine(shares[share], NormalizePath(path));

            if (!fullPath.StartsWith(shares[share]))
            {
                return Results.BadRequest("You cannot access files outside of the share.");
            }

            if (!Directory.Exists(fullPath))
            {
                return Results.NotFound("Directory does not exist.");
            }

            try
            {
                Directory.Delete(fullPath);
            }
            catch
            {
                return Results.BadRequest("An error occurred while creating the directory.");
            }

            return Results.Ok($"Directory Deleted");
        })
    .WithDescription("Delets a directory")
    .WithSummary("Delete Directory")
    .WithBadge("new")
    .WithTags("Directory")
    .RequireAuthorization("ShareDelete")
    .Experimental()
    .Produces<string>()
    .Produces<string>(StatusCodes.Status404NotFound);

app.Run();

static string NormalizePath(string path)
{
    path = path.Replace('\\', '/');

    if (path.StartsWith('/'))
        path = path[1..];

    return path;
}

public record FileDestination(
    [Description("Target destination for the file operation")]
    string Path);

public record struct LoginModel(
    [Description("Username for authenticating user")]
    string Username,
    [Description("Password for authenticating user")]
    string Password);


public class DirectoryListModel
{
    [Description("List of filenames")] public List<string> Files { get; set; } = new List<string>();
    [Description("List of directories")] public List<string> Directories { get; set; } = new List<string>();
}

public class ShareAccessRequirement : IAuthorizationRequirement
{
}

public class ShareAccessAuthorizationHandler : AuthorizationHandler<ShareAccessRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ShareAccessRequirement requirement)
    {
        var endpoint = context.Resource as HttpContext;
        if (endpoint == null)
        {
            return Task.CompletedTask;
        }

        var routeValues = endpoint.Request.RouteValues;
        if (!routeValues.TryGetValue("share", out var shareValue) || shareValue == null)
        {
            // If there's no share parameter, we can't validate the requirement
            return Task.CompletedTask;
        }

        string requestedShare = shareValue.ToString()!;

        // Check if the user has a claim for this share
        if (context.User.HasClaim(c => c.Type == "share" && c.Value == requestedShare))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

[JsonSerializable(typeof(FormFile))]
[JsonSerializable(typeof(FormFileCollection))]
[JsonSerializable(typeof(IFormFileCollection))]
[JsonSerializable(typeof(IFormFile))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(FileDestination))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(LoginModel))]
[JsonSerializable(typeof(DirectoryListModel))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}