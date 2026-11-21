using System.Net;
using System.Text;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace NetSentinel.Snmp;

public sealed record ParsedTrap(
    string Version,
    string SecurityName,
    string TrapOid,
    string Summary,
    string Varbinds,
    bool IsInform);

public static class SnmpTrapParser
{
    public static IReadOnlyList<ParsedTrap> Parse(byte[] buffer, UserRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentNullException.ThrowIfNull(registry);

        var messages = MessageFactory.ParseMessages(buffer, 0, buffer.Length, registry);
        var parsed = new List<ParsedTrap>();
        foreach (var message in messages)
        {
            var trap = Describe(message);
            if (trap is not null)
            {
                parsed.Add(trap);
            }
        }

        return parsed;
    }

    public static ParsedTrap? Describe(ISnmpMessage message)
    {
        var type = message.TypeCode();
        if (type is not (SnmpType.TrapV1Pdu or SnmpType.TrapV2Pdu or SnmpType.InformRequestPdu))
        {
            return null;
        }

        var security = SafeCommunity(message);
        var varbinds = FormatVarbinds(message);
        if (message is TrapV1Message v1)
        {
            var oid = v1.Enterprise.ToString();
            var summary = $"SNMPv1 {v1.Generic} from {v1.AgentAddress} ({oid})";
            if (v1.Generic == GenericCode.EnterpriseSpecific)
            {
                summary += $" specific {v1.Specific}";
            }

            return new ParsedTrap("v1", security, oid, summary, varbinds, false);
        }

        var version = message.Version == VersionCode.V3 ? "v3" : "v2c";
        var trapOid = message is TrapV2Message v2
            ? v2.Enterprise.ToString()
            : FindTrapOid(message) ?? "";
        var kind = type == SnmpType.InformRequestPdu ? "inform" : "trap";
        var text = $"SNMP{version} {kind} {trapOid}";
        return new ParsedTrap(version, security, trapOid, text, varbinds, type == SnmpType.InformRequestPdu);
    }

    public static byte[]? InformResponse(ISnmpMessage message)
    {
        if (message.TypeCode() != SnmpType.InformRequestPdu || message.Version == VersionCode.V3)
        {
            return null;
        }

        var response = new ResponseMessage(
            message.RequestId(),
            message.Version,
            message.Community(),
            ErrorCode.NoError,
            0,
            message.Variables());
        return response.ToBytes();
    }

    private static string FindTrapOid(ISnmpMessage message)
    {
        try
        {
            foreach (var variable in message.Variables())
            {
                if (variable.Id.ToString() == "1.3.6.1.6.3.1.1.4.1.0" && variable.Data is ObjectIdentifier oid)
                {
                    return oid.ToString();
                }
            }
        }
        catch (Exception)
        {
            return "";
        }

        return "";
    }

    private static string FormatVarbinds(ISnmpMessage message)
    {
        try
        {
            var builder = new StringBuilder();
            foreach (var variable in message.Variables())
            {
                if (builder.Length > 0)
                {
                    builder.Append('\n');
                }

                builder.Append(variable.Id);
                builder.Append(" = ");
                builder.Append(SnmpValues.Format(variable.Data));
                builder.Append(" (");
                builder.Append(variable.Data.TypeCode);
                builder.Append(')');
                if (builder.Length > 7900)
                {
                    builder.Append("\n…");
                    break;
                }
            }

            return builder.ToString();
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private static string SafeCommunity(ISnmpMessage message)
    {
        try
        {
            return message.Community().ToString();
        }
        catch (Exception)
        {
            return "";
        }
    }
}
