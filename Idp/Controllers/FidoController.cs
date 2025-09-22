using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Idp.Pages.Login;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Idp.Fido2.Controllers;
[Route("api/fido")]
public class FidoController(IFido2 fido2, TestUserStore? users = null) : Controller
{
    private static readonly FidoStorage _storage = new();
    private static readonly Dictionary<string, CredentialCreateOptions> _pendingCredentials = new();
    private static readonly Dictionary<string, AssertionOptions> _pendingAssertions = new();
    private static string FormatException(Exception e) => $"{e.Message}{e.InnerException?.Message ?? string.Empty}";

    [HttpPost("credential-options")]
    public CredentialCreateOptions GetCredentialOptions(
      [FromForm] string? username,
      [FromForm] string? displayName,
      [FromForm] AttestationConveyancePreference? attestationType,
      [FromForm] AuthenticatorAttachment? authenticator,
      [FromForm] UserVerificationRequirement? userVerification,
      [FromForm] ResidentKeyRequirement? residentKey)
    {
        try
        {
            var key = username;
            if(string.IsNullOrEmpty(username))
            {
                var created = DateTime.UtcNow;
                if(string.IsNullOrEmpty(displayName))
                {
                    username = $"(Usernameless user created {created})";
                }
                else
                {
                    username = $"{displayName} (Usernameless user created {created.ToShortDateString()})";
                }
                key = Convert.ToBase64String(Encoding.UTF8.GetBytes(username));
            }
            Debug.Assert(key != null);
            var user = _storage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username)
            });
            var existingKeys = _storage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            var authenticatorSelection = AuthenticatorSelection.Default;
            if(authenticator != null)
            {
                authenticatorSelection.AuthenticatorAttachment = authenticator;
            }
            if(userVerification != null)
            {
                authenticatorSelection.UserVerification = userVerification.Value;
            }
            if(residentKey != null)
            {
                authenticatorSelection.ResidentKey = residentKey.Value;
            }
            var options = fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = user,
                ExcludeCredentials = existingKeys,
                AuthenticatorSelection = authenticatorSelection,
                AttestationPreference = attestationType ?? AttestationConveyancePreference.None,
                Extensions = new AuthenticationExtensionsClientInputs
                {
                    Extensions = true,
                    UserVerificationMethod = true,
                    CredProps = true
                }
            });
            _pendingCredentials[key] = options;
            return options;
        }
        catch(Exception)
        {
            throw;
        }
    }

    [HttpPut("{username}/credential")]
    public async Task<string> CreateCredentialAsync([FromRoute] string username, [FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            var options = _pendingCredentials[username];
            var credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = CredentialIdUniqueToUserAsync
            }, cancellationToken: cancellationToken);
            _storage.AddCredentialToUser(options.User, new StoredCredential
            {
                AttestationFormat = credential.AttestationFormat,
                Id = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignCount = credential.SignCount,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = credential.Transports,
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson,
            });
            _pendingCredentials.Remove(Request.Host.ToString());
            return "OK";
        }
        catch(Exception e)
        {
            return FormatException(e);
        }
    }

    [HttpPost("assertion-options")]
    public IActionResult MakeAssertionOptions([FromForm] string username, [FromForm] UserVerificationRequirement? userVerification)
    {
        try
        {
            var existingKeys = new List<PublicKeyCredentialDescriptor>();
            var user = _storage.GetUser(username);
            if(user != null)
            {
                existingKeys = _storage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }
            var exts = new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true,
                Extensions = true
            };
            var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = existingKeys,
                UserVerification = userVerification ?? UserVerificationRequirement.Discouraged,
                Extensions = exts
            });
            _pendingAssertions[new string(options.Challenge.Select(b => (char)b).ToArray())] = options;
            return Json(options);
        }
        catch(Exception)
        {
            throw;
        }
    }

    [HttpPost("assertion")]
    public async Task<string> MakeAssertionAsync([FromBody] AuthenticatorAssertionRawResponse clientResponse,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = JsonSerializer.Deserialize<AuthenticatorResponse>(clientResponse.Response.ClientDataJson);
            if(response is null)
            {
                return "Error: Could not deserialize client data";
            }
            var key = new string(response.Challenge.Select(b => (char)b).ToArray());
            if(!_pendingAssertions.TryGetValue(key, out var options))
            {
                return "Error: Challenge not found, please get a new one via GET tion-options";
            }
            _pendingAssertions.Remove(key);
            var creds = _storage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");
            var res = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = creds.PublicKey,
                StoredSignatureCounter = creds.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = UserHandleOwnerOfCredentialIdAsync
            }, cancellationToken: cancellationToken);
            _storage.UpdateCounter(res.CredentialId, res.SignCount);
            var user = users!.FindByUsername(Encoding.UTF8.GetString(creds.UserHandle));
            if(user == null)
            {
                throw new Exception("User not found");
            }
            var props = new AuthenticationProperties();
            props.IsPersistent = true;
            props.ExpiresUtc = DateTimeOffset.UtcNow.Add(LoginOptions.RememberMeLoginDuration);
            var isuser = new IdentityServerUser(user.SubjectId)
            {
                DisplayName = user.Username
            };
            await HttpContext.SignInAsync(isuser, props);
            return "https://localhost:44300/login";
        }
        catch(Exception e)
        {
            return $"Error: {FormatException(e)}";
        }
    }

    [HttpGet("ping")]
    public string Ping()
    {
        return "Pong!";
    }

    private static async Task<bool> CredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
    {
        var users = await _storage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
        return users.Count <= 0;
    }

    private static async Task<bool> UserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationToken)
    {
        var storedCreds = await _storage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
        return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
    }
}