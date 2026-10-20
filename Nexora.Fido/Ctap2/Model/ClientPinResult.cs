using System.Security.Cryptography;

namespace Nexora.Fido.Ctap2.Model
{
    /// <summary>Only the fields relevant to the subCommand that produced this result are set.</summary>
    internal record ClientPinResult(
        ECParameters? KeyAgreementPublicKey = null,
        byte[]? PinUvAuthTokenEnc = null,
        int? PinRetries = null);
}
