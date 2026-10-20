using System.Security.Cryptography;
using System.Text.Json;
using Nexora.Crypt;
using Nexora.SecretManager.Crypto;

namespace Nexora.SecretManager.VaultSecretStore;

/// <summary>FIDO2 credentials kept exclusively inside the authenticated Nexora.vault payload.</summary>
public sealed class VaultCredentialStore : ICredentialStore
{
    private readonly VaultSession _vault;
    private readonly object _sync;
    private readonly string _prefix;

    public VaultCredentialStore(VaultSession vault, object syncRoot, string stickName)
    {
        _vault = vault;
        _sync = syncRoot;
        _prefix = $"sticks/{stickName}/credentials/";
    }

    private string PathFor(byte[] credentialId) => _prefix + Convert.ToHexString(credentialId) + ".cred";

    public void Save(StoredCredential credential)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(credential);
        lock (_sync) _vault.WriteFile(PathFor(credential.CredentialId), bytes);
        CryptographicOperations.ZeroMemory(bytes);
    }

    public StoredCredential? Find(byte[] credentialId)
    {
        lock (_sync)
        {
            byte[]? bytes = _vault.ReadFile(PathFor(credentialId));
            if (bytes is null) return null;
            try { return JsonSerializer.Deserialize<StoredCredential>(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    public IReadOnlyList<StoredCredential> FindAll()
    {
        lock (_sync)
        {
            return _vault.ListPaths()
                .Where(p => p.StartsWith(_prefix, StringComparison.Ordinal) && p.EndsWith(".cred", StringComparison.Ordinal))
                .Select(p =>
                {
                    byte[]? bytes = _vault.ReadFile(p);
                    if (bytes is null) return null;
                    try { return JsonSerializer.Deserialize<StoredCredential>(bytes); }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                })
                .Where(c => c is not null).Select(c => c!).ToArray();
        }
    }

    public IReadOnlyList<StoredCredential> FindByRp(string rpId) =>
        FindAll().Where(c => c.RpId == rpId).ToArray();

    public void Delete(byte[] credentialId)
    {
        lock (_sync) _vault.DeleteFile(PathFor(credentialId));
    }
}

/// <summary>Private ECDSA keys never written as ordinary files; handles are opaque 16-byte GUIDs.</summary>
public sealed class VaultKeyStore : IKeyStore, IPinStateStore
{
    private static readonly Guid FileStoreAaguid = new("f11e0a10-0ea1-4b1f-8b0a-1b0a1e0a1b0a");
    private static readonly Guid AttestationId = new("00000000-0000-0000-0000-000000000001");
    private readonly VaultSession _vault;
    private readonly object _sync;
    private readonly string _prefix;
    public byte[] Aaguid => FileStoreAaguid.ToByteArray(bigEndian: true);

    public VaultKeyStore(VaultSession vault, object syncRoot, string stickName)
    {
        _vault = vault;
        _sync = syncRoot;
        _prefix = $"sticks/{stickName}/";
    }

    private string KeyPath(Guid id) => _prefix + "keys/" + id.ToString("N") + ".key";
    private string CertPath(string name) => _prefix + "attestation/" + name;
    private byte[]? Read(string path) { lock (_sync) return _vault.ReadFile(path); }
    private void Write(string path, byte[] bytes) { lock (_sync) _vault.WriteFile(path, bytes); }

    public ISigningKey CreateEs256Key()
    {
        using var ecdsa = EcdsaProvider.GenerateP256();
        Guid id = Guid.NewGuid();
        byte[] pkcs8 = ecdsa.ExportPkcs8PrivateKey();
        try { Write(KeyPath(id), pkcs8); }
        finally { CryptographicOperations.ZeroMemory(pkcs8); }
        return LoadKey(id.ToByteArray());
    }

    public ISigningKey LoadKey(byte[] handle)
    {
        if (handle.Length != 16) throw new ArgumentException("Invalid vault key handle.", nameof(handle));
        byte[] bytes = Read(KeyPath(new Guid(handle))) ?? throw new KeyNotFoundException("Signing key missing in vault.");
        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(bytes, out _);
            return new VaultSigningKey(key, (byte[])handle.Clone());
        }
        catch { key.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void DeleteKey(byte[] handle)
    {
        if (handle.Length != 16) throw new ArgumentException("Invalid vault key handle.", nameof(handle));
        lock (_sync) _vault.DeleteFile(KeyPath(new Guid(handle)));
    }

    public AttestationCertificate GetOrCreateAttestationCertificate()
    {
        lock (_sync)
        {
            byte[]? leafCert = _vault.ReadFile(CertPath("leaf.der"));
            byte[]? intermediateCert = _vault.ReadFile(CertPath("intermediate.der"));
            byte[]? storedLeafKey = _vault.ReadFile(KeyPath(AttestationId));
            bool hasKey = storedLeafKey is not null;
            if (storedLeafKey is not null) CryptographicOperations.ZeroMemory(storedLeafKey);
            if (leafCert is not null && intermediateCert is not null && hasKey)
                return new AttestationCertificate(AttestationId.ToByteArray(), new[] { leafCert, intermediateCert });

            // Generate chain once and store every private key and certificate in the vault.
            // Certificate issuance uses the same implementation as the existing file backend.
            using var rootKey = EcdsaProvider.GenerateP256();
            byte[] rootDer = AttestationCertificateFactory.CreateSelfSignedRoot(rootKey);
            using var intermediateKey = EcdsaProvider.GenerateP256();
            byte[] intermediaryDer = AttestationCertificateFactory.CreateIntermediate(intermediateKey, rootKey, rootDer);
            using var leafKey = EcdsaProvider.GenerateP256();
            byte[] leafDer = AttestationCertificateFactory.CreateAttestationLeaf(leafKey, intermediateKey, intermediaryDer, Aaguid);
            byte[] leafPrivate = leafKey.ExportPkcs8PrivateKey();
            try
            {
                _vault.WriteFile(KeyPath(AttestationId), leafPrivate);
                _vault.WriteFile(CertPath("leaf.der"), leafDer);
                _vault.WriteFile(CertPath("intermediate.der"), intermediaryDer);
            }
            finally { CryptographicOperations.ZeroMemory(leafPrivate); }
            return new AttestationCertificate(AttestationId.ToByteArray(), new[] { leafDer, intermediaryDer });
        }
    }

    public PinState? Load()
    {
        byte[]? bytes = Read(_prefix + "auth/pin-state.json");
        if (bytes is null) return null;
        try { return JsonSerializer.Deserialize<PinState>(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void Save(PinState state)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        try { Write(_prefix + "auth/pin-state.json", bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed class VaultSigningKey : ISigningKey
    {
        private readonly ECDsa _ecdsa;
        private readonly byte[] _handle;
        public VaultSigningKey(ECDsa ecdsa, byte[] handle) { _ecdsa = ecdsa; _handle = handle; }
        public int CoseAlgorithm => -7;
        public byte[] Sign(byte[] data) => EcdsaProvider.SignDerSha256(_ecdsa, data);
        public byte[] ExportCosePublicKey() => CoseKeyEncoder.Encode(_ecdsa.ExportParameters(false));
        public byte[] ExportHandle() => (byte[])_handle.Clone();
    }
}
