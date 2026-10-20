using System.Security.Cryptography;
using Nexora.Crypt;
using Nexora.SecretManager;
using Nexora.SecretManager.VaultSecretStore;

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("Windows est requis pour les tests DPAPI de Nexora 1.2.");
    return 1;
}

string directory = Path.Combine(Path.GetTempPath(), "NexoraVaultFido-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    string path = Path.Combine(directory, "Nexora.vault");
    VaultCreationResult created = VaultStore.Create(path, "1234");
    byte[] challenge = RandomNumberGenerator.GetBytes(32);
    byte[] handle;
    byte[] credentialId = RandomNumberGenerator.GetBytes(32);
    byte[] signature;
    byte[] publicKey;
    byte[] leaf;
    using (var session = VaultStore.OpenOnAuthorizedComputer(path, "1234"))
    {
        var sync = new object();
        var keys = new VaultKeyStore(session, sync, "clef1");
        var credentials = new VaultCredentialStore(session, sync, "clef1");
        var signingKey = keys.CreateEs256Key();
        handle = signingKey.ExportHandle();
        signature = signingKey.Sign(challenge);
        publicKey = signingKey.ExportCosePublicKey();
        credentials.Save(new StoredCredential
        {
            CredentialId = credentialId,
            RpId = "example.invalid",
            UserId = new byte[] { 1, 2 },
            KeyHandle = handle,
            UserName = "test",
        });
        keys.Save(new PinState(new byte[] { 9, 8, 7 }, 5));
        leaf = keys.GetOrCreateAttestationCertificate().CertificateChainDer[0];
    }
    using (var session = VaultStore.OpenOnAuthorizedComputer(path, "1234"))
    {
        var sync = new object();
        var keys = new VaultKeyStore(session, sync, "clef1");
        var credentials = new VaultCredentialStore(session, sync, "clef1");
        var found = credentials.Find(credentialId) ?? throw new Exception("Credential manquante apres redemarrage.");
        if (found.RpId != "example.invalid" || !found.KeyHandle.SequenceEqual(handle))
            throw new Exception("Credential modifiee.");
        if (!keys.LoadKey(handle).ExportCosePublicKey().SequenceEqual(publicKey))
            throw new Exception("Cle publique non persistante.");
        if (keys.LoadKey(handle).Sign(challenge).Length == 0 || signature.Length == 0)
            throw new Exception("Signature ECDSA indisponible.");
        if (!keys.GetOrCreateAttestationCertificate().CertificateChainDer[0].SequenceEqual(leaf))
            throw new Exception("Attestation non persistante.");
        if (keys.Load()?.Retries != 5) throw new Exception("Etat PIN CTAP2 perdu.");
        credentials.Delete(credentialId);
        keys.DeleteKey(handle);
        if (credentials.Find(credentialId) is not null) throw new Exception("Suppression credential echouee.");
    }
    string ciphertext = File.ReadAllText(path);
    if (ciphertext.Contains("example.invalid", StringComparison.Ordinal) || ciphertext.Contains("clef1", StringComparison.Ordinal))
        throw new Exception("Donnees FIDO2 visibles en clair.");
    if (created.RecoveryCode.Replace("-", "").Length != 64) throw new Exception("Code de recuperation incomplet.");
    Console.WriteLine("OK Nexora Crypt + FIDO Vault 1.2 : persistance, signature, attestation, PIN et chiffrement.");
    return 0;
}
finally
{
    try { Directory.Delete(directory, recursive: true); }
    catch (IOException) { }
    catch (UnauthorizedAccessException) { }
}
