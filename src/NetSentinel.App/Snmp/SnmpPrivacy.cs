using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Security;

namespace NetSentinel.Snmp;

public static class SnmpPrivacy
{
    public static IPrivacyProvider Create(string? authProtocol, string? authPassword, string? privProtocol, string? privPassword)
    {
        var authName = (authProtocol ?? "None").Trim().ToUpperInvariant();
        IAuthenticationProvider authentication = authName switch
        {
            "MD5" => new MD5AuthenticationProvider(new OctetString(authPassword ?? "")),
            "SHA" or "SHA1" => new SHA1AuthenticationProvider(new OctetString(authPassword ?? "")),
            "SHA256" => new SHA256AuthenticationProvider(new OctetString(authPassword ?? "")),
            "SHA384" => new SHA384AuthenticationProvider(new OctetString(authPassword ?? "")),
            "SHA512" => new SHA512AuthenticationProvider(new OctetString(authPassword ?? "")),
            _ => DefaultAuthenticationProvider.Instance
        };

        var privacyName = (privProtocol ?? "None").Trim().ToUpperInvariant();
        return privacyName switch
        {
            "DES" => new DESPrivacyProvider(new OctetString(privPassword ?? ""), authentication),
            "AES" or "AES128" => new AESPrivacyProvider(new OctetString(privPassword ?? ""), authentication),
            "AES192" => new AES192PrivacyProvider(new OctetString(privPassword ?? ""), authentication),
            "AES256" => new AES256PrivacyProvider(new OctetString(privPassword ?? ""), authentication),
            _ => new DefaultPrivacyProvider(authentication)
        };
    }
}
