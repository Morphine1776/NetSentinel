using NetSentinel.Core;
using NetSentinel.Services;

namespace NetSentinel.Pages.Shared;

public sealed class PolicyEditorModel
{
    public PolicyForm Form { get; init; } = new();
    public ResolvedPolicy Effective { get; init; } = null!;
    public ResolvedPolicy? Inherited { get; init; }
    public bool AllowInherit { get; init; } = true;
    public string Prefix { get; init; } = "Policy";
}
