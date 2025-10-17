using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Xitira.SimpleFileServer.Client;

public class SimpleFileServerClient
{
    private readonly HttpClient _httpClient;
    private string? _token;

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
        
        _token = await response.Content.ReadAsStringAsync();
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        
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

public record struct LoginModel(string Username, string Password);
public class DirectoryListModel
{
    public List<string> Files { get; set; } = new List<string>();
    
    public List<string> Directories { get; set; } = new List<string>();
}
public record FileDestination(
    string Path);