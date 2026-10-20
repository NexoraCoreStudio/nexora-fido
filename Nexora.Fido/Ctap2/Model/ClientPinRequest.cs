using System.Security.Cryptography;

namespace Nexora.Fido.Ctap2.Model
{
    internal record ClientPinRequest(
        byte PinProtocol,
        byte SubCommand,
        ECParameters? KeyAgreement,
        byte[]? PinUvAuthParam,
        byte[]? NewPinEnc,
        byte[]? PinHashEnc);
}
