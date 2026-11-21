using System.Globalization;
using Lextm.SharpSnmpLib;

namespace NetSentinel.Snmp;

public static class SnmpValues
{
    public static string Format(ISnmpData data)
    {
        try
        {
            return data switch
            {
                OctetString text => text.ToString(),
                ObjectIdentifier oid => oid.ToString(),
                Integer32 integer => integer.ToInt32().ToString(CultureInfo.InvariantCulture),
                Counter32 counter => counter.ToUInt32().ToString(CultureInfo.InvariantCulture),
                Counter64 counter => counter.ToUInt64().ToString(CultureInfo.InvariantCulture),
                Gauge32 gauge => gauge.ToUInt32().ToString(CultureInfo.InvariantCulture),
                TimeTicks ticks => ticks.ToUInt32().ToString(CultureInfo.InvariantCulture),
                Null => "null",
                NoSuchObject => "noSuchObject",
                NoSuchInstance => "noSuchInstance",
                EndOfMibView => "endOfMibView",
                _ => data.ToString() ?? ""
            };
        }
        catch (Exception)
        {
            return data.ToString() ?? "";
        }
    }

    public static ulong? AsUnsigned(ISnmpData data) => data switch
    {
        Counter32 counter => counter.ToUInt32(),
        Counter64 counter => counter.ToUInt64(),
        Gauge32 gauge => gauge.ToUInt32(),
        TimeTicks ticks => ticks.ToUInt32(),
        Integer32 integer when integer.ToInt32() >= 0 => (ulong)integer.ToInt32(),
        _ => null
    };

    public static double? AsDouble(ISnmpData data)
    {
        var unsigned = AsUnsigned(data);
        if (unsigned is not null)
        {
            return unsigned.Value;
        }

        if (data is Integer32 integer)
        {
            return integer.ToInt32();
        }

        if (data is OctetString text
            && double.TryParse(text.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    public static int? CounterWidth(ISnmpData data) => data switch
    {
        Counter32 => 32,
        Counter64 => 64,
        _ => null
    };

    public static bool IsException(ISnmpData data) => data is NoSuchObject or NoSuchInstance or EndOfMibView or Null;
}
