using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Scalar.AspNetCore;

Dictionary<string, string> shares = new Dictionary<string, string>();
shares.Add("sh1",@"/mnt/source/Xitira.SimpleFileServer/test/share1");

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.AddOpenApi();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddAntiforgery();

var app = builder.Build();


app.MapOpenApi();
app.MapScalarApiReference();

var apiGroup = app.MapGroup("/api").WithTags("api").WithDescription("File Serve API").DisableAntiforgery();

var fileApiGroup = apiGroup.MapGroup("/file").WithTags("file").WithDescription("File Operations").DisableAntiforgery();

fileApiGroup.MapPost("/mv/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path, [FromBody] FileDestination fileDestination) =>
    {
        return Results.Ok($"moving {path} to {fileDestination.Path}");
    });

fileApiGroup.MapPost("/cp/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path, [FromBody] FileDestination fileDestination) =>
    {
        return Results.Ok($"copying {path} to {fileDestination.Path}");
    });

fileApiGroup.MapGet("/{share}/{path}", ([FromRoute] string share, [FromRoute] string path) => "Hello World!");
fileApiGroup.MapPut("/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path, [FromForm] IFormFile file,
        [FromQuery] bool? overwrite = false) =>
    {
        return Results.Ok($"{share}:{path}:{file.FileName}");
    });

fileApiGroup.MapDelete("/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path) => $"deleting file {path}");

var directoryApiGroup = apiGroup.MapGroup("/directory").WithTags("directory").WithDescription("Directory Operations").DisableAntiforgery();

directoryApiGroup.MapGet("/{share}/{path?}",
    ([FromRoute] string share, [FromRoute] string? path , bool recursive = false) =>
    {
        var fullPath = Path.Combine(shares[share] , path);
        var files = Directory.GetFiles(fullPath);
        return Results.Ok(files);   
    });

directoryApiGroup.MapPut("/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path) => { return Results.Ok($"{share}:{path}"); });

directoryApiGroup.MapDelete("/{share}/{path}",
    ([FromRoute] string share, [FromRoute] string path) => { return Results.Ok(); });

app.Run();

public record FileDestination(string Path);


[JsonSerializable(typeof(FormFile))]
[JsonSerializable(typeof(FormFileCollection))]
[JsonSerializable(typeof(IFormFileCollection))]
[JsonSerializable(typeof(IFormFile))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(FileDestination))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(string[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}