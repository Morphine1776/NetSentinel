using System.Text.RegularExpressions;

namespace NetSentinel.Core;

public enum InterfacePatternSyntax
{
    Glob,
    Regex
}

public sealed record InterfaceIdentity(string Name, string Descr, string Alias, int AdminStatus);

public sealed record InterfaceMonitorRules(
    string IncludePattern,
    string ExcludePattern,
    InterfacePatternSyntax Syntax,
    bool MatchName,
    bool MatchDescr,
    bool MatchAlias,
    bool ExcludeAdminDown,
    bool RequireAlias)
{
    public static InterfaceMonitorRules MonitorAll { get; } = new("", "", InterfacePatternSyntax.Glob, true, true, true, false, false);
}

public enum InterfaceTrapEffect
{
    None,
    Suppress,
    OpenDown,
    ResolveDown
}

public static class InterfaceMonitor
{
    public const int AdminDown = 2;
    public const int MaxPatternLength = 500;

    public static bool Evaluate(InterfaceIdentity iface, InterfaceMonitorRules rules, bool? manualOverride)
    {
        ArgumentNullException.ThrowIfNull(iface);
        ArgumentNullException.ThrowIfNull(rules);
        if (manualOverride is bool forced)
        {
            return forced;
        }

        return FollowsRules(iface, rules);
    }

    public static bool FollowsRules(InterfaceIdentity iface, InterfaceMonitorRules rules)
    {
        ArgumentNullException.ThrowIfNull(iface);
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.RequireAlias && string.IsNullOrWhiteSpace(iface.Alias))
        {
            return false;
        }

        if (rules.ExcludeAdminDown && iface.AdminStatus == AdminDown)
        {
            return false;
        }

        var fields = Fields(iface, rules);
        if (Split(rules.IncludePattern).Count > 0 && !fields.Any(value => MatchesAny(rules.IncludePattern, value, rules.Syntax)))
        {
            return false;
        }

        if (fields.Any(value => MatchesAny(rules.ExcludePattern, value, rules.Syntax)))
        {
            return false;
        }

        return true;
    }

    public static string? Validate(InterfaceMonitorRules rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.IncludePattern.Length > MaxPatternLength || rules.ExcludePattern.Length > MaxPatternLength)
        {
            return $"Patterns must be {MaxPatternLength} characters or fewer.";
        }

        if (!rules.MatchName && !rules.MatchDescr && !rules.MatchAlias)
        {
            return "Choose at least one of ifName, ifDescr, or ifAlias.";
        }

        if (rules.Syntax == InterfacePatternSyntax.Regex)
        {
            foreach (var pattern in Split(rules.IncludePattern).Concat(Split(rules.ExcludePattern)))
            {
                try
                {
                    _ = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
                }
                catch (ArgumentException)
                {
                    return $"Invalid regular expression '{pattern}'.";
                }
            }
        }

        return null;
    }

    public static IReadOnlyList<string> Split(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return Array.Empty<string>();
        }

        return pattern
            .Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => item.Length > 0)
            .ToArray();
    }

    public static bool TrySyntax(string? text, out InterfacePatternSyntax syntax)
    {
        var value = (text ?? "").Trim();
        if (value.Length == 0 || value.Equals("glob", StringComparison.OrdinalIgnoreCase))
        {
            syntax = InterfacePatternSyntax.Glob;
            return true;
        }

        if (value.Equals("regex", StringComparison.OrdinalIgnoreCase) || value.Equals("regexp", StringComparison.OrdinalIgnoreCase))
        {
            syntax = InterfacePatternSyntax.Regex;
            return true;
        }

        syntax = InterfacePatternSyntax.Glob;
        return false;
    }

    public static string FormatSyntax(InterfacePatternSyntax syntax)
        => syntax == InterfacePatternSyntax.Regex ? "regex" : "glob";

    public static bool TryParseFields(string? text, out bool name, out bool descr, out bool alias)
    {
        name = false;
        descr = false;
        alias = false;
        if (string.IsNullOrWhiteSpace(text))
        {
            name = true;
            descr = true;
            alias = true;
            return true;
        }

        foreach (var part in text.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var token = part.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal);
            if (token.Equals("name", StringComparison.OrdinalIgnoreCase) || token.Equals("ifname", StringComparison.OrdinalIgnoreCase))
            {
                name = true;
            }
            else if (token.Equals("descr", StringComparison.OrdinalIgnoreCase)
                || token.Equals("ifdescr", StringComparison.OrdinalIgnoreCase)
                || token.Equals("description", StringComparison.OrdinalIgnoreCase))
            {
                descr = true;
            }
            else if (token.Equals("alias", StringComparison.OrdinalIgnoreCase) || token.Equals("ifalias", StringComparison.OrdinalIgnoreCase))
            {
                alias = true;
            }
            else
            {
                return false;
            }
        }

        return name || descr || alias;
    }

    public static string FormatFields(bool name, bool descr, bool alias)
    {
        var parts = new List<string>();
        if (name)
        {
            parts.Add("name");
        }

        if (descr)
        {
            parts.Add("descr");
        }

        if (alias)
        {
            parts.Add("alias");
        }

        return parts.Count == 0 ? "name,descr,alias" : string.Join(",", parts);
    }

    private static List<string> Fields(InterfaceIdentity iface, InterfaceMonitorRules rules)
    {
        var fields = new List<string>();
        if (rules.MatchName)
        {
            fields.Add(iface.Name ?? "");
        }

        if (rules.MatchDescr)
        {
            fields.Add(iface.Descr ?? "");
        }

        if (rules.MatchAlias)
        {
            fields.Add(iface.Alias ?? "");
        }

        return fields;
    }

    private static bool MatchesAny(string? pattern, string value, InterfacePatternSyntax syntax)
    {
        foreach (var alternative in Split(pattern))
        {
            var matched = syntax == InterfacePatternSyntax.Regex
                ? RegexIsMatch(alternative, value)
                : GlobIsMatch(alternative, value);
            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    private static bool RegexIsMatch(string pattern, string value)
    {
        try
        {
            return Regex.IsMatch(value, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool GlobIsMatch(string pattern, string value)
    {
        var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*", StringComparison.Ordinal).Replace("\\?", ".", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(value, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
    }
}

public static class InterfaceTrapPolicy
{
    public static InterfaceTrapEffect Decide(string? linkEvent, bool? monitored)
    {
        if (linkEvent is not ("down" or "up"))
        {
            return InterfaceTrapEffect.None;
        }

        if (monitored is not true)
        {
            return monitored == false ? InterfaceTrapEffect.Suppress : InterfaceTrapEffect.None;
        }

        return linkEvent == "down" ? InterfaceTrapEffect.OpenDown : InterfaceTrapEffect.ResolveDown;
    }
}
