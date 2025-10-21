# Simple File Server Client

A simple client to the Simple File Server Api.

# Quickstart

```csharp
using Xitira.SimpleFileServer.Client;
// ...
var client = new SimpleFileServerClient();
var success = client.LoginAsync("user","pass");
if (success) {
    Console.WriteLine("Login successful");
    var listing = await client.ListDirectoryAsync("share","path",recursive:true);
    foreach(var file in listing.Files)
        Console.WriteLine(file.Name)
}

```

Note: This is a work in progress.