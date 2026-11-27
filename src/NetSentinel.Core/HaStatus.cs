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
    /// <summary>
    /// True when no vendor answered. An answered value that canonicalizes to N/A is a real reading and stays false.
    /// </summary>
    public bool ProbeFailed { get; init; }

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

    public static bool LooksLikePaloAlto(string? sysObjectId, string? sysDescr)
    {
        var oid = NormalizeOid(sysObjectId);
        if (oid.StartsWith("1.3.6.1.4.1.25461", StringComparison.Ordinal))
        {
            return true;
        }

        var text = sysDescr ?? "";
        return text.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase)
            || text.Contains("PAN-OS", StringComparison.OrdinalIgnoreCase)
            || text.Contains("PA-3440", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeCisco(string? sysObjectId, string? sysDescr)
    {
        var oid = NormalizeOid(sysObjectId);
        if (oid.StartsWith("1.3.6.1.4.1.9.", StringComparison.Ordinal) || oid == "1.3.6.1.4.1.9")
        {
            return true;
        }

        return (sysDescr ?? "").Contains("Cisco", StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyList<IHaVendor> ForDevice(string? sysObjectId, string? sysDescr)
    {
        var palo = Vendors.First(vendor => vendor.Id == "paloalto");
        var cisco = Vendors.First(vendor => vendor.Id == "cisco-rf");
        var paloAlto = LooksLikePaloAlto(sysObjectId, sysDescr);
        var ciscoDevice = LooksLikeCisco(sysObjectId, sysDescr);
        if (paloAlto && !ciscoDevice)
        {
            return new IHaVendor[] { palo };
        }

        if (ciscoDevice && !paloAlto)
        {
            return new IHaVendor[] { cisco };
        }

        return Vendors;
    }

    public static HaReading Resolve(Func<IReadOnlyList<string>, HaProbeAnswer> query, IReadOnlyList<IHaVendor>? vendors = null)
    {
        ArgumentNullException.ThrowIfNull(query);
        foreach (var vendor in vendors ?? Vendors)
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

        return HaReading.Unavailable with { ProbeFailed = true };
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

    private static string NormalizeOid(string? oid)
        => (oid ?? "").Trim().TrimStart('.');
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
        var text = raw.Trim().Trim('\0').Trim('"').ToLowerInvariant().Replace('_', '-').Replace(' ', '-');
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

public sealed record HaTrack(
    bool HadReading,
    string? State,
    string? Peer,
    string? Vendor,
    string? PendingState,
    int PendingCount);

public sealed record HaDecision(
    string? State,
    string? Peer,
    string? Vendor,
    string? PendingState,
    int PendingCount,
    AlertTransition? Alert);

public static class HaAlerts
{
    public static HaDecision Observe(
        string scope,
        string deviceName,
        HaTrack current,
        string? nextState,
        string? nextPeer,
        string? nextVendor,
        bool alertsEnabled,
        bool probeFailed)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (probeFailed)
        {
            return new HaDecision(
                current.State,
                current.Peer,
                current.Vendor,
                current.PendingCount > 0 ? current.PendingState : null,
                current.PendingCount > 0 ? current.PendingCount : 0,
                null);
        }

        var next = Norm(nextState);
        if (!current.HadReading)
        {
            return Store(next, nextPeer, nextVendor, null);
        }

        var previous = Norm(current.State);
        if (previous == next)
        {
            return new HaDecision(
                StoreToken(previous),
                HaStatus.NormalizePeer(nextPeer),
                PickVendor(nextVendor, current.Vendor),
                null,
                0,
                null);
        }

        // A pending token of "" is a pending N/A. Count stays 1 until the same token is read again.
        if (previous.Length == 0 || next.Length == 0)
        {
            var pending = current.PendingCount > 0 ? Norm(current.PendingState) : null;
            if (pending is not null && pending == next)
            {
                return Store(next, nextPeer, nextVendor, alertsEnabled ? Build(scope, deviceName, previous, next) : null);
            }

            return new HaDecision(StoreToken(previous), Blank(current.Peer), Blank(current.Vendor), next, 1, null);
        }

        return Store(next, nextPeer, nextVendor, alertsEnabled ? Build(scope, deviceName, previous, next) : null);
    }

    private static HaDecision Store(string next, string? peer, string? vendor, AlertTransition? alert)
        => new(StoreToken(next), HaStatus.NormalizePeer(peer), Blank(vendor), null, 0, alert);

    private static string? StoreToken(string norm)
        => norm.Length == 0 ? null : norm;

    private static string? PickVendor(string? next, string? current)
        => string.IsNullOrWhiteSpace(next) ? Blank(current) : next.Trim();

    private static string? Blank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static AlertTransition Build(string scope, string deviceName, string previous, string next)
        => new(
            AlertTransitionType.Open,
            $"{scope}:ha:{previous}->{next}:{DateTime.UtcNow.Ticks}",
            AlertKind.HaChange,
            AlertSeverity.Info,
            $"Device {deviceName} HA state changed from {Display(previous)} to {Display(next)}.",
            null,
            null);

    private static string Norm(string? token)
        => string.IsNullOrWhiteSpace(token) ? "" : token.Trim().ToLowerInvariant();

    private static string Display(string token)
        => token.Length == 0 ? "N/A" : token;
}
