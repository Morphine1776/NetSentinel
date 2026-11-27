namespace NetSentinel.Core;

public enum HaBadge
{
    Unavailable,
    Active,
    Passive,
    Other
}

public sealed record HaReading(HaBadge Badge, string Label, string? Token, string? Peer, string? Vendor)
{
    public static HaReading Unavailable { get; } = new(HaBadge.Unavailable, "N/A", null, null, null);

    public string CssClass => Badge switch
    {
        HaBadge.Active => "ha-active",
        HaBadge.Passive => "ha-passive",
        HaBadge.Other => "ha-other",
        _ => "ha-na"
    };
}

public sealed record HaProbeAnswer(bool Answered, string? Raw);

public interface IHaVendor
{
    string Id { get; }
    IReadOnlyList<string> StateOids { get; }
    IReadOnlyList<string> PeerOids { get; }
    HaProbeAnswer Interpret(string? raw, bool missing);
    HaReading ToReading(string? token, string? peerRaw);
}

public static class HaStatus
{
    public static IReadOnlyList<IHaVendor> Vendors { get; } = new IHaVendor[]
    {
        new PaloAltoHaVendor(),
        new CiscoRfHaVendor()
    };

    public static HaReading Resolve(Func<IReadOnlyList<string>, HaProbeAnswer> query)
    {
        ArgumentNullException.ThrowIfNull(query);
        foreach (var vendor in Vendors)
        {
            var state = query(vendor.StateOids);
            var interpreted = vendor.Interpret(state.Raw, !state.Answered);
            if (!interpreted.Answered)
            {
                continue;
            }

            var peer = query(vendor.PeerOids);
            var peerText = peer.Answered ? NormalizePeer(peer.Raw) : null;
            return vendor.ToReading(interpreted.Raw, peerText);
        }

        return HaReading.Unavailable;
    }

    public static HaReading FromStored(string? token, string? peer, string? vendor, bool snmpOk)
    {
        if (!snmpOk)
        {
            return HaReading.Unavailable with { Peer = string.IsNullOrWhiteSpace(peer) ? null : peer };
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            return HaReading.Unavailable with { Peer = BlankToNull(peer), Vendor = BlankToNull(vendor) };
        }

        var vendorImpl = Vendors.FirstOrDefault(item => item.Id.Equals(vendor ?? "", StringComparison.OrdinalIgnoreCase))
            ?? Vendors[0];
        return vendorImpl.ToReading(token, BlankToNull(peer));
    }

    public static string? NormalizePeer(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var text = raw.Trim();
        if (IsMissingToken(text))
        {
            return null;
        }

        return text.Length > 80 ? text[..80] : text;
    }

    public static bool IsMissingToken(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var text = raw.Trim();
        return text.Equals("noSuchObject", StringComparison.OrdinalIgnoreCase)
            || text.Equals("noSuchInstance", StringComparison.OrdinalIgnoreCase)
            || text.Equals("endOfMibView", StringComparison.OrdinalIgnoreCase)
            || text.Equals("null", StringComparison.OrdinalIgnoreCase);
    }

    private static string? BlankToNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed class PaloAltoHaVendor : IHaVendor
{
    public string Id => "paloalto";

    public IReadOnlyList<string> StateOids { get; } = new[]
    {
        "1.3.6.1.4.1.25461.2.1.2.1.11.0",
        "1.3.6.1.4.1.25461.2.1.2.1.11"
    };

    public IReadOnlyList<string> PeerOids { get; } = new[]
    {
        "1.3.6.1.4.1.25461.2.1.2.1.12.0",
        "1.3.6.1.4.1.25461.2.1.2.1.12"
    };

    public HaProbeAnswer Interpret(string? raw, bool missing)
    {
        if (missing || HaStatus.IsMissingToken(raw))
        {
            return new HaProbeAnswer(false, null);
        }

        var token = Canonical(raw!);
        if (token is null)
        {
            return new HaProbeAnswer(true, null);
        }

        return new HaProbeAnswer(true, token);
    }

    public HaReading ToReading(string? token, string? peerRaw)
    {
        var canonical = string.IsNullOrWhiteSpace(token) ? null : Canonical(token);
        if (canonical is null)
        {
            return new HaReading(HaBadge.Unavailable, "N/A", null, peerRaw, Id);
        }

        var badge = canonical switch
        {
            "active" => HaBadge.Active,
            "passive" => HaBadge.Passive,
            _ => HaBadge.Other
        };
        var label = canonical switch
        {
            "active" => "Active",
            "passive" => "Passive",
            "non-functional" => "Non-functional",
            _ => char.ToUpperInvariant(canonical[0]) + canonical[1..]
        };
        return new HaReading(badge, label, canonical, peerRaw, Id);
    }

    public static string? Canonical(string raw)
    {
        var text = raw.Trim().Trim('"').ToLowerInvariant().Replace('_', '-').Replace(' ', '-');
        while (text.Contains("--", StringComparison.Ordinal))
        {
            text = text.Replace("--", "-", StringComparison.Ordinal);
        }

        return text switch
        {
            "" or "disabled" or "none" or "not-configured" or "n/a" or "na" => null,
            "active" or "passive" or "suspended" or "initial" or "tentative" or "non-functional" or "nonfunctional" => text == "nonfunctional" ? "non-functional" : text,
            _ => text.Length > 40 ? text[..40] : text
        };
    }
}

public sealed class CiscoRfHaVendor : IHaVendor
{
    public string Id => "cisco-rf";

    public IReadOnlyList<string> StateOids { get; } = new[]
    {
        "1.3.6.1.4.1.9.9.176.1.1.2.0",
        "1.3.6.1.4.1.9.9.176.1.1.2"
    };

    public IReadOnlyList<string> PeerOids { get; } = Array.Empty<string>();

    public HaProbeAnswer Interpret(string? raw, bool missing)
    {
        if (missing || HaStatus.IsMissingToken(raw))
        {
            return new HaProbeAnswer(false, null);
        }

        var token = Canonical(raw!);
        return token is null
            ? new HaProbeAnswer(true, null)
            : new HaProbeAnswer(true, token);
    }

    public HaReading ToReading(string? token, string? peerRaw)
    {
        var canonical = string.IsNullOrWhiteSpace(token) ? null : Canonical(token);
        if (canonical is null)
        {
            return new HaReading(HaBadge.Unavailable, "N/A", null, peerRaw, Id);
        }

        if (canonical is "active")
        {
            return new HaReading(HaBadge.Active, "Active", canonical, peerRaw, Id);
        }

        if (canonical is "passive")
        {
            return new HaReading(HaBadge.Passive, "Passive", canonical, peerRaw, Id);
        }

        var label = canonical.Replace('-', ' ');
        label = char.ToUpperInvariant(label[0]) + label[1..];
        return new HaReading(HaBadge.Other, label, canonical, peerRaw, Id);
    }

    public static string? Canonical(string raw)
    {
        var text = raw.Trim().ToLowerInvariant().Replace('_', '-').Replace(' ', '-');
        if (int.TryParse(text, out var code))
        {
            return code switch
            {
                1 or 2 => null,
                3 => "initialization",
                4 => "negotiation",
                5 => "standby-cold",
                6 => "standby-cold-config",
                7 => "standby-cold-filesys",
                8 => "standby-cold-bulk",
                9 => "passive",
                10 or 11 or 12 or 13 or 14 or 15 or 16 => "active",
                _ => null
            };
        }

        return text switch
        {
            "" or "disabled" or "notknown" or "not-known" or "unknown" => null,
            "active" or "activefast" or "active-fast" or "activedrain" or "active-drain" => "active",
            "standbyhot" or "standby-hot" or "passive" or "standby" => "passive",
            "standbycold" or "standby-cold" => "standby-cold",
            "initialization" or "initialisation" or "init" => "initialization",
            "negotiation" => "negotiation",
            _ => null
        };
    }
}

public static class HaAlerts
{
    public static AlertTransition? Change(string scope, string deviceName, bool hadReading, string? previousToken, string? nextToken, bool enabled)
    {
        if (!enabled || !hadReading)
        {
            return null;
        }

        var previous = Norm(previousToken);
        var next = Norm(nextToken);
        if (string.Equals(previous, next, StringComparison.Ordinal))
        {
            return null;
        }

        var from = Display(previous);
        var to = Display(next);
        return new AlertTransition(
            AlertTransitionType.Open,
            $"{scope}:ha:{previous}->{next}:{DateTime.UtcNow.Ticks}",
            AlertKind.HaChange,
            AlertSeverity.Info,
            $"Device {deviceName} HA state changed from {from} to {to}.",
            null,
            null);
    }

    private static string Norm(string? token) => string.IsNullOrWhiteSpace(token) ? "" : token.Trim().ToLowerInvariant();

    private static string Display(string token)
        => token.Length == 0 ? "N/A" : token;
}
