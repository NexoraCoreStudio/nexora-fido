using System;
using System.Formats.Cbor;
using System.Linq;

namespace Nexora.Fido.Ctap2;

/// <summary>
/// Only notifies RP IDs (domains, not URLs) for successful authenticatorMakeCredential
/// and authenticatorGetAssertion commands. Never exposes users, PINs, tokens or credentials.
/// </summary>
public static class RelyingPartyActivity
{
    /// <summary>Args: operation ("inscription"/"connexion"), rpId (host).</summary>
    public static event Action<string, string>? Succeeded;

    internal static void NotifySuccessfulRequest(byte command, byte[] body)
    {
        if (command != 0x01 && command != 0x02) return;
        try
        {
            if (body.Length > 16384) return;
            var reader = new CborReader(body, CborConformanceMode.Lax);
            reader.ReadStartMap();
            string? rpId = null;
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadInt32();
                if (command == 0x02 && key == 1)
                {
                    rpId = reader.ReadTextString();
                }
                else if (command == 0x01 && key == 2)
                {
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        var field = reader.ReadTextString();
                        if (field == "id") rpId = reader.ReadTextString();
                        else reader.SkipValue();
                    }
                    reader.ReadEndMap();
                }
                else reader.SkipValue();
            }
            reader.ReadEndMap();
            if (!IsValidRpId(rpId)) return;

            var action = command == 0x01 ? "inscription" : "connexion";
            var listeners = Succeeded;
            if (listeners is null) return;
            foreach (Action<string, string> listener in listeners.GetInvocationList())
            {
                try { listener(action, rpId!.ToLowerInvariant()); }
                catch (Exception)
                {
                    NLog.LogManager.GetCurrentClassLogger().Warn("Relying party audit observer failed; CTAP result preserved.");
                }
            }
        }
        catch (Exception)
        {
            NLog.LogManager.GetCurrentClassLogger().Warn("Unable to read RP ID for history; CTAP result preserved.");
        }
    }

    private static bool IsValidRpId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253 || value.StartsWith('.') || value.EndsWith('.'))
            return false;
        if (value.Any(c => !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z'
                             or >= '0' and <= '9' or '.' or '-')))
            return false;
        return value.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-');
    }
}
