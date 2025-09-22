# Passkeys IdentityServer Solution

A comprehensive demonstration of modern authentication using **FIDO2/WebAuthn passkeys** with **Duende IdentityServer** and a Blazor Server client application. This solution showcases passwordless authentication, secure credential management, and OpenID Connect integration.

## 🏗️ Solution Architecture

This solution consists of two main projects that work together to provide a complete authentication ecosystem:

```
passkeys-identityserver/
├── Idp/                    # Identity Provider (Duende IdentityServer + FIDO2)
├── Client/                 # Blazor Server Client Application
└── global.json            # .NET SDK configuration
```

## 🔐 Key Features

- **Passwordless Authentication**: Complete FIDO2/WebAuthn implementation
- **Passkey Support**: Biometric authentication, security keys, and platform authenticators
- **OpenID Connect Integration**: Standards-based authentication flow
- **Modern .NET 9**: Latest framework features and performance improvements
- **Secure Credential Storage**: In-memory credential management for development
- **Interactive UI**: Blazor Server components for seamless user experience

## 📋 Prerequisites

- **.NET 9.0 SDK** (as specified in global.json)
- **Visual Studio 2022** or **Visual Studio Code**
- **HTTPS development certificates** configured
- **Compatible browser** with FIDO2/WebAuthn support (Chrome, Firefox, Safari, Edge)
- **Authenticator device** (Windows Hello, Touch ID, security key, or mobile device)

## 🚀 Getting Started

### 1. Clone and Setup
```bash
git clone https://github.com/bjorndaniel/passkeys-identityserver.git
cd passkeys-identityserver
dotnet restore
```

### 2. Run the Identity Provider
```bash
cd Idp
dotnet run
```
The Identity Provider will start at `https://localhost:5001`

### 3. Run the Client Application
```bash
cd Client
dotnet run
```
The Client application will start at `https://localhost:44300`

### 4. Test the Authentication Flow
1. Navigate to `https://localhost:44300`
2. Click on login or access a protected resource
3. You'll be redirected to the Identity Provider
4. Register a new passkey or use an existing one
5. Complete the authentication and return to the client

---

## 🔧 Project Details

## Identity Provider (Idp)

The **Identity Provider** is the core authentication server built on Duende IdentityServer with FIDO2/WebAuthn capabilities.

### 🎯 Purpose
- Provides OpenID Connect and OAuth 2.0 authentication services
- Handles FIDO2/WebAuthn passkey registration and authentication
- Manages user credentials and authentication sessions
- Issues JWT tokens for authenticated users

### 🏛️ Architecture

#### Core Components

**Program.cs**
- Application bootstrapping with Serilog logging
- FIDO2 service configuration with origin validation
- Duende IdentityServer pipeline setup

**Config.cs**
- Identity resources (OpenID, Profile)
- API scopes configuration
- Client definitions with PKCE support
- Redirect URI management

**FidoController.cs**
- RESTful API for FIDO2 operations
- Credential registration endpoint (`/api/fido/credential-options`)
- Authentication assertion endpoint (`/api/fido/assertion-options`)
- Secure credential storage and validation

#### FIDO2 Implementation

**FidoStorage.cs**
- In-memory credential storage (development use)
- User and credential relationship management
- Thread-safe operations for concurrent access

**StoredCredential.cs**
- Credential data model with all FIDO2 properties
- Attestation format and public key storage
- Signature counter and backup status tracking

### 🔌 Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `Duende.IdentityServer` | 7.3.2 | OpenID Connect server implementation |
| `Fido2.AspNet` | 4.0.0-beta.16 | ASP.NET Core FIDO2 integration |
| `Fido2` | 4.0.0-beta.16 | Core FIDO2/WebAuthn library |
| `Serilog.AspNetCore` | 9.0.0 | Structured logging |
| `Microsoft.AspNetCore.Authentication.Google` | 9.0.9 | External authentication provider |

### 🌐 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid_configuration` | GET | OpenID Connect discovery |
| `/connect/authorize` | GET | Authorization endpoint |
| `/connect/token` | POST | Token endpoint |
| `/api/fido/credential-options` | POST | Get credential creation options |
| `/api/fido/{username}/credential` | PUT | Register new credential |
| `/api/fido/assertion-options` | POST | Get authentication options |
| `/api/fido/assertion` | POST | Perform authentication |

### ⚙️ Configuration

The Identity Provider supports various FIDO2 configuration options:

- **Server Domain**: Configurable origin validation
- **Attestation Preferences**: None, Direct, or Indirect
- **Authenticator Selection**: Platform, Cross-platform, or Both
- **User Verification**: Required, Preferred, or Discouraged
- **Resident Keys**: Required, Preferred, or Discouraged

---

## Client Application (Client)

The **Client Application** is a Blazor Server application that demonstrates authentication against the Identity Provider.

### 🎯 Purpose
- Demonstrates OpenID Connect client implementation
- Provides user interface for authentication flows
- Shows protected resource access patterns
- Illustrates token management and claims handling

### 🏛️ Architecture

#### Core Components

**Program.cs**
- Blazor Server configuration with interactive components
- OpenID Connect authentication setup
- Cookie-based session management
- Authorization middleware pipeline

**AccountController.cs**
- Authentication challenge initiation
- Sign-out functionality
- Callback handling for OIDC flows

#### Blazor Components

**Login.razor**
- User-friendly login interface
- Automatic redirection to Identity Provider
- JavaScript integration for seamless UX

**Logout.razor**
- Secure logout functionality
- Session cleanup and token revocation

**Protected.razor**
- Demonstrates authorization requirements
- Claims display and user information
- Protected content rendering

### 🔌 Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `Microsoft.AspNetCore.Authentication.OpenIdConnect` | 9.0.9 | OpenID Connect client |

### ⚙️ Authentication Configuration

```json
{
  "Authentication": {
    "Authority": "https://localhost:5001",
    "ClientId": "interactive",
    "ClientSecret": "49C1A7E1-0C79-4A89-A3D6-A37998FB86B0",
    "ResponseType": "code",
    "SaveTokens": true,
    "GetClaimsFromUserInfoEndpoint": true,
    "RequireHttpsMetadata": false,
    "Scope": "openid profile"
  }
}
```

### 🔄 Authentication Flow

1. **Unauthenticated Request**: User accesses protected resource
2. **Challenge Initiation**: Redirect to Identity Provider
3. **FIDO2 Authentication**: User completes passkey authentication
4. **Authorization Code**: Identity Provider returns authorization code
5. **Token Exchange**: Client exchanges code for tokens
6. **Session Creation**: Authenticated session established
7. **Resource Access**: User can access protected resources

---

## 🔒 Security Features

### FIDO2/WebAuthn Security
- **Strong Cryptography**: Public-key cryptography with hardware security
- **Phishing Resistance**: Origin-bound credentials prevent replay attacks
- **Biometric Integration**: Touch ID, Face ID, Windows Hello support
- **Hardware Security Keys**: YubiKey, FIDO Alliance certified devices

### OpenID Connect Security
- **PKCE**: Proof Key for Code Exchange for public clients
- **State Parameter**: CSRF protection during authentication
- **Nonce Validation**: Replay attack prevention
- **HTTPS Enforcement**: Encrypted communication channels

### Additional Security Measures
- **Token Validation**: JWT signature and claims verification
- **Secure Cookies**: HttpOnly and Secure flags enabled
- **CORS Configuration**: Proper origin validation
- **Rate Limiting**: Built-in protection against brute force attacks

---

## 🛠️ Development and Deployment

### Development Environment
- **Hot Reload**: Blazor Server hot reload for rapid development
- **Debugging**: Full Visual Studio debugging support
- **Logging**: Structured logging with Serilog
- **Development Certificates**: HTTPS development certificate required

### Production Considerations
- **Database Storage**: Replace in-memory storage with persistent database
- **Key Management**: Secure storage for signing keys and secrets
- **Load Balancing**: Session affinity for Blazor Server applications
- **Monitoring**: Application insights and health checks
- **Backup Strategy**: Credential backup and recovery procedures

### Scaling Recommendations
- **Database**: Entity Framework Core with SQL Server/PostgreSQL
- **Caching**: Redis for distributed sessions and caching
- **Message Queuing**: SignalR backplane for multi-instance deployments
- **Container Support**: Docker containerization for cloud deployment

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow .NET coding conventions
- Add unit tests for new functionality
- Update documentation for API changes
- Ensure FIDO2 compliance with specifications

---

## 📚 Additional Resources

### Documentation
- [Duende IdentityServer Documentation](https://docs.duendesoftware.com/identityserver/v7)
- [FIDO2/WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [Blazor Server Documentation](https://docs.microsoft.com/en-us/aspnet/core/blazor/)

### Related Projects
- [Fido2NetLib](https://github.com/passwordless-lib/fido2-net-lib) - .NET FIDO2 library
- [IdentityServer Samples](https://github.com/DuendeSoftware/Samples) - Official samples
- [WebAuthn Awesome](https://github.com/herrjemand/awesome-webauthn) - Comprehensive WebAuthn resources

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support and Issues

For questions, issues, or contributions:
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share experiences
- **Documentation**: Check the official documentation links above

**Note**: This is a demonstration project for educational purposes. For production use, ensure proper security reviews, persistent storage implementation, and compliance with your organization's security policies.