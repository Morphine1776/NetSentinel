namespace NetSentinel;

public sealed class DashboardOptions
{
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = "changeme";
}

public sealed class SnmpOptions
{
    public int TrapPort { get; set; } = 1162;
    public bool TrapEnabled { get; set; } = true;
    public int TimeoutMs { get; set; } = 2000;
    public int Retries { get; set; } = 1;
    public int MaxConcurrentPolls { get; set; } = 8;
    public int FailureThreshold { get; set; } = 2;
}

public static class DashboardAuth
{
    public static bool Verify(string? username, string? password, string expectedUser, string expectedPassword)
    {
        var userOk = FixedEquals(username ?? "", expectedUser ?? "");
        var passOk = FixedEquals(password ?? "", expectedPassword ?? "");
        return userOk && passOk;
    }

    private static bool FixedEquals(string left, string right)
    {
        var a = System.Text.Encoding.UTF8.GetBytes(left);
        var b = System.Text.Encoding.UTF8.GetBytes(right);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
    }
}
