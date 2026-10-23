using System.Formats.Cbor;
using Nexora.Fido.Ctap2;
using Xunit;

namespace Nexora.Fido.Tests;

public class RelyingPartyActivityTests
{
    [Fact]
    public void GetAssertion_ExtractsRelyingPartyDomain()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteTextString("webAuthn.Example.com");
        writer.WriteInt32(2);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        string? site = null;
        string? action = null;
        void OnSucceeded(string operation, string rpId)
        {
            if (rpId != "webauthn.example.com") return;
            site = rpId;
            action = operation;
        }
        RelyingPartyActivity.Succeeded += OnSucceeded;
        try
        {
            RelyingPartyActivity.NotifySuccessfulRequest(0x02, writer.Encode());
            Assert.Equal("webauthn.example.com", site);
            Assert.Equal("connexion", action);
        }
        finally { RelyingPartyActivity.Succeeded -= OnSucceeded; }
    }

    [Fact]
    public void MakeCredential_ExtractsNestedRelyingPartyDomain()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        writer.WriteStartMap(2);
        writer.WriteTextString("id");
        writer.WriteTextString("example.org");
        writer.WriteTextString("name");
        writer.WriteTextString("Example");
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool seen = false;
        void OnSucceeded(string operation, string rpId) { if (rpId == "example.org" && operation == "inscription") seen = true; }
        RelyingPartyActivity.Succeeded += OnSucceeded;
        try
        {
            RelyingPartyActivity.NotifySuccessfulRequest(0x01, writer.Encode());
            Assert.True(seen);
        }
        finally { RelyingPartyActivity.Succeeded -= OnSucceeded; }
    }

    [Theory]
    [InlineData("https://example.com/login")]
    [InlineData("example.com/path")]
    [InlineData("example.com@evil.com")]
    public void NonDomainsAreNotRecorded(string invalidRpId)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteTextString(invalidRpId);
        writer.WriteEndMap();

        bool received = false;
        void OnSucceeded(string operation, string rpId) { if (rpId == invalidRpId) received = true; }
        RelyingPartyActivity.Succeeded += OnSucceeded;
        try
        {
            RelyingPartyActivity.NotifySuccessfulRequest(0x02, writer.Encode());
            Assert.False(received);
        }
        finally { RelyingPartyActivity.Succeeded -= OnSucceeded; }
    }
}
