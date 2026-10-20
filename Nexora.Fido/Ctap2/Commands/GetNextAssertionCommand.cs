using IAuthenticator = Nexora.Fido.Ctap2.Authenticator.IAuthenticator;

namespace Nexora.Fido.Ctap2.Commands
{
    /// <summary>authenticatorGetNextAssertion (0x08), CTAP2 section 6.3. Takes no request body.</summary>
    internal static class GetNextAssertionCommand
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        internal static async Task<byte[]> Handle(IAuthenticator authenticator)
        {
            Logger.Debug("authenticatorGetNextAssertion");
            return GetAssertionCommand.Encode(await authenticator.GetNextAssertionAsync());
        }
    }
}
