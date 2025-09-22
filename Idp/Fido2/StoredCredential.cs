using Fido2NetLib.Objects;

public class StoredCredential
{
    /// <summary>Credential ID of the public key credential source.</summary>
    public required byte[] Id { get; set; }

    /// <summary>Credential public key of the public key credential source.</summary>
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();

    /// <summary>Latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.</summary>
    public uint SignCount { get; set; }

    /// <summary>Value returned from getTransports() when the public key credential source was registered.</summary>
    public AuthenticatorTransport[] Transports { get; set; } = Array.Empty<AuthenticatorTransport>();

    /// <summary>Value of the BE flag when the public key credential source was created.</summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>Latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.</summary>
    public bool IsBackedUp { get; set; }

    /// <summary>Value of the attestationObject attribute when the public key credential source was registered. Storing this enables the Relying Party to reference the credential's attestation statement at a later time.</summary>
    public byte[] AttestationObject { get; set; } = Array.Empty<byte>();

    /// <summary>Value of the clientDataJSON attribute when the public key credential source was registered. Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.</summary>
    public byte[] AttestationClientDataJson { get; set; } = Array.Empty<byte>();

    public byte[] UserId { get; set; } = Array.Empty<byte>();

    /// <summary>Returns a Descriptor Object for this credential, used as input to the library for certain operations.</summary>
    public PublicKeyCredentialDescriptor Descriptor => new(PublicKeyCredentialType.PublicKey, Id, Transports);

    public byte[] UserHandle { get; set; } = Array.Empty<byte>();

    public string AttestationFormat { get; set; } = string.Empty;

    public DateTimeOffset RegDate { get; set; } = DateTimeOffset.MinValue;

    public Guid AaGuid { get; set; } = Guid.Empty;
}