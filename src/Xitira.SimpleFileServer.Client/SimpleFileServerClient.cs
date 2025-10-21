using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Xitira.SimpleFileServer.Client;

/// <summary>
/// Client class for interacting with the SimpleFileServer API
/// </summary>
public class SimpleFileServerClient
{
    private readonly HttpClient _httpClient;
    private TokenModel? _token;

    /// <summary>
    /// Creates a new client instance
    /// </summary>
    /// <param name="baseUrl">The base url of the service (ie, http://localhost:5050)</param>
    public SimpleFileServerClient(string baseUrl)
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/'))
        };
    }
    
    /// <summary>
    /// Authenticates with the server and retrieves a JWT token
    /// </summary>
    public async Task<bool> LoginAsync(string username, string password)
    {
        var response = await _httpClient.PostAsJsonAsync("/auth/login", new LoginModel(username, password));
        
        if (!response.IsSuccessStatusCode) return false;

        _token = await response.Content.ReadFromJsonAsync<TokenModel>();
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token.Value.Token);
        
        return true;
    }

    /// <summary>
    /// Lists the contents of a directory
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share (use "~" for root)</param>
    /// <param name="recursive">Whether to list contents recursively</param>
    /// <returns>A model containing file and directory listings</returns>
    public async Task<DirectoryListModel?> ListDirectoryAsync(string share, string path, bool recursive = false)
    {
        var response = await _httpClient.GetAsync($"/v1/dir/{share}/{path}?recursive={recursive}");
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadFromJsonAsync<DirectoryListModel>();
    }

    /// <summary>
    /// Creates a new directory
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share</param>
    /// <returns>Path of the created directory or null if failed</returns>
    public async Task<string?> CreateDirectoryAsync(string share, string path)
    {
        var response = await _httpClient.PutAsync($"/v1/dir/{share}/{path}", null);
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Deletes a directory
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share</param>
    /// <returns>True if successful, false otherwise</returns>
    public async Task<bool> DeleteDirectoryAsync(string share, string path)
    {
        var response = await _httpClient.DeleteAsync($"/v1/dir/{share}/{path}");
        
        return response.IsSuccessStatusCode;
    }

    /// <summary>
    /// Downloads a file
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share</param>
    /// <returns>The file stream or null if not found</returns>
    public async Task<Stream?> DownloadFileAsync(string share, string path)
    {
        var response = await _httpClient.GetAsync($"/v1/file/{share}/{path}");
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStreamAsync();
    }

    /// <summary>
    /// Uploads a file
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share (including filename)</param>
    /// <param name="fileStream">The stream containing the file content</param>
    /// <param name="fileName">The name of the file</param>
    /// <returns>Result message or null if failed</returns>
    public async Task<string?> UploadFileAsync(string share, string path, Stream fileStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var streamContent = new StreamContent(fileStream);
        content.Add(streamContent, "file", fileName);
        
        var response = await _httpClient.PutAsync($"/v1/file/{share}/{path}", content);
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Deletes a file
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path within the share</param>
    /// <returns>Result message or null if failed</returns>
    public async Task<string?> DeleteFileAsync(string share, string path)
    {
        var response = await _httpClient.DeleteAsync($"/v1/file/{share}/{path}");
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Moves a file
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path of the file to move</param>
    /// <param name="destinationPath">The destination path</param>
    /// <returns>Result message or null if failed</returns>
    public async Task<string?> MoveFileAsync(string share, string path, string destinationPath)
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new FileDestination(destinationPath)), 
            Encoding.UTF8, 
            "application/json");
        
        var response = await _httpClient.PostAsync($"/v1/file/mv/{share}/{path}", content);
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Copies a file
    /// </summary>
    /// <param name="share">The share name (e.g., "sh1")</param>
    /// <param name="path">The path of the file to copy</param>
    /// <param name="destinationPath">The destination path</param>
    /// <returns>Result message or null if failed</returns>
    public async Task<string?> CopyFileAsync(string share, string path, string destinationPath)
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new FileDestination(destinationPath)), 
            Encoding.UTF8, 
            "application/json");
        
        var response = await _httpClient.PostAsync($"/v1/file/cp/{share}/{path}", content);
        
        if (!response.IsSuccessStatusCode) return null;
        
        return await response.Content.ReadAsStringAsync();
    }
}

/// <summary>
/// Login model for authenticating with the server
/// </summary>
/// <param name="Username">Username</param>
/// <param name="Password">Password</param>
public record struct LoginModel(string Username, string Password);
/// <summary>
/// Model to store file and directory listings
/// </summary>
/// <remarks>All files and directories contain the full path relative to the share</remarks>
public class DirectoryListModel
{
    /// <summary>
    /// List of files
    /// </summary>
    public List<string> Files { get; set; } = new List<string>();
    
    /// <summary>
    /// List of directories
    /// </summary>
    public List<string> Directories { get; set; } = new List<string>();
}
/// <summary>
/// Payload for moving or copying a file
/// </summary>
/// <param name="Path">The target file location</param>
public record FileDestination(
    string Path);


/// <summary>
/// Model for storing JWT token data
/// </summary>
public record struct TokenModel
{
    /// <summary>
    /// The JWT token body
    /// </summary>
    public string Token { get; set; }
    /// <summary>
    /// Number of hours this token is valid for
    /// </summary>
    public int ExpiresIn { get; set; }
    /// <summary>
    /// THe time (in UTC) this token was issued
    /// </summary>
    public DateTime Issued { get; set; }
}