using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using MimeKit;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class EmailNotifier
{
    private readonly AppDbContext _db;
    private readonly ILogger<EmailNotifier> _logger;

    public EmailNotifier(AppDbContext db, ILogger<EmailNotifier> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task NotifyAsync(string deviceName, IReadOnlyList<AlertTransition> transitions, CancellationToken cancellationToken)
    {
        if (transitions.Count == 0)
        {
            return;
        }

        var settings = await _db.Settings.AsNoTracking().OrderBy(s => s.Id).FirstOrDefaultAsync(cancellationToken);
        if (settings is null || !settings.SmtpEnabled)
        {
            return;
        }

        var lines = transitions.Select(transition =>
            $"{transition.Type.ToString().ToUpperInvariant()} [{transition.Severity}] {transition.Message}");
        var body = $"NetSentinel alert update for {deviceName}\n\n" + string.Join("\n", lines);
        var subject = $"NetSentinel: {deviceName}";
        try
        {
            await SendAsync(settings, subject, body, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SMTP notification failed for {Device}", deviceName);
        }
    }

    public async Task SendTestAsync(CancellationToken cancellationToken)
    {
        var settings = await _db.Settings.AsNoTracking().OrderBy(s => s.Id).FirstAsync(cancellationToken);
        if (!settings.SmtpEnabled)
        {
            throw new InvalidOperationException("Enable SMTP and save settings before sending a test.");
        }

        await SendAsync(settings, "NetSentinel test", "This is a test message from NetSentinel.", cancellationToken);
    }

    private async Task SendAsync(AppSetting settings, string subject, string body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.SmtpHost) || string.IsNullOrWhiteSpace(settings.SmtpFrom) || string.IsNullOrWhiteSpace(settings.SmtpTo))
        {
            throw new InvalidOperationException("SMTP host, from address, and to address are required.");
        }

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(settings.SmtpFrom.Trim()));
        foreach (var recipient in settings.SmtpTo.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            message.To.Add(MailboxAddress.Parse(recipient));
        }

        message.Subject = subject;
        message.Body = new TextPart("plain") { Text = body };

        using var client = new SmtpClient();
        var mode = settings.SmtpSecurity switch
        {
            "None" => SecureSocketOptions.None,
            "SslOnConnect" => SecureSocketOptions.SslOnConnect,
            _ => SecureSocketOptions.StartTls
        };
        await client.ConnectAsync(settings.SmtpHost.Trim(), settings.SmtpPort, mode, cancellationToken);
        if (!string.IsNullOrWhiteSpace(settings.SmtpUser))
        {
            await client.AuthenticateAsync(settings.SmtpUser, settings.SmtpPassword ?? "", cancellationToken);
        }

        await client.SendAsync(message, cancellationToken);
        await client.DisconnectAsync(true, cancellationToken);
    }
}
