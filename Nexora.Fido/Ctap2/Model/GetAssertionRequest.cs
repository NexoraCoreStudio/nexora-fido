using System.Collections.Generic;

namespace Nexora.Fido.Ctap2.Model
{
    internal record GetAssertionRequest(
        string RpId,
        byte[] ClientDataHash,
        IReadOnlyList<byte[]> AllowList,
        byte[]? PinUvAuthParam = null,
        byte? PinUvAuthProtocol = null,
        bool RequireUserVerification = false,
        bool RequireUserPresence = true);
}
