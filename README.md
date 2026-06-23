# PwshBearerAuth

A PowerShell 7 module that authenticates against any OIDC-compliant authorization server using the **Authorization Code + PKCE** flow and exposes the resulting access token as a Bearer header for use with `Invoke-WebRequest` and `Invoke-RestMethod`.

Tokens are held in module-scope memory only — nothing is written to disk.

---

## Requirements

- PowerShell 7.0+
- A registered **public** OIDC client (no client secret) with:
  - Redirect URI: `http://localhost:58080/callback`
  - Grant types: Authorization Code, Refresh Token
  - PKCE: Required (`code_challenge_method=S256`)

---

## Quick start

```powershell
Import-Module ./scripts/PwshBearerAuth.psm1

# Authenticate (opens browser)
Connect-PwshBearerAuth -ClientId "my-cli-client" -Issuer "https://sso.example.com"

# Use the token
Invoke-RestMethod https://api.example.com/data -Headers (Get-PwshBearerAuthHeader)
```

---

## Commands

### `Connect-PwshBearerAuth`

Opens the system browser to the OIDC authorization endpoint, waits for the local redirect callback, then exchanges the code for tokens.

```powershell
Connect-PwshBearerAuth
    -ClientId  <string>                         # Required. OIDC client_id.
    [-Issuer   <string>]                        # Default: https://sso.identitystudio.io
    [-Scopes   <string>]                        # Default: "openid profile email roles offline_access"
    [-Port     <int>]                           # Default: 58080
```

The local listener binds to `http://localhost:<Port>/` and shuts down as soon as the callback is received (or the 120-second timeout expires).

---

### `Get-PwshBearerAuthHeader`

Returns a `@{ Authorization = "Bearer <token>" }` hashtable. Automatically refreshes the access token using the stored refresh token when it is within 30 seconds of expiry.

```powershell
$headers = Get-PwshBearerAuthHeader

Invoke-RestMethod  https://api.example.com/resource -Headers $headers
Invoke-WebRequest  https://api.example.com/resource -Headers $headers
```

Throws if no session is active or if the token has expired and no refresh token is available.

---

### `Get-PwshBearerAuthSession`

Displays the current session state without exposing raw token values.

```powershell
Get-PwshBearerAuthSession

# ClientId     : my-cli-client
# Issuer       : https://sso.identitystudio.io
# Scopes       : openid profile email roles offline_access
# TokenExpired : False
# HasRefresh   : True
```

---

### `Disconnect-PwshBearerAuth`

Clears all tokens from memory.

```powershell
Disconnect-PwshBearerAuth
```

---

## Auth server client registration

Register a **public** client (no secret) in your OIDC provider's admin UI:

| Setting | Value |
|---|---|
| Client type | Public |
| Redirect URI | `http://localhost:58080/callback` |
| Grant types | Authorization Code, Refresh Token |
| Scopes | openid, profile, email, roles, offline_access |
| PKCE | Required (S256) |

For the identitystudio.io AuthServer, create the client at `/admin/apps/create`.

---

## How the PKCE flow works

```
Connect-PwshBearerAuth
  │
  ├─ Generates random code_verifier + SHA-256 code_challenge
  ├─ Opens browser → GET /authorize?code_challenge=...&state=...
  ├─ Listens on http://localhost:58080/
  ├─ Auth server redirects browser → http://localhost:58080/callback?code=...&state=...
  ├─ Validates state (CSRF guard)
  └─ POST /token with code + code_verifier → stores access_token + refresh_token

Get-PwshBearerAuthHeader
  ├─ Checks token expiry from JWT exp claim (with 30s buffer)
  ├─ If expired: POST /token with refresh_token → updates stored tokens
  └─ Returns @{ Authorization = "Bearer <access_token>" }
```

---

## Persistent sessions across terminals

Tokens are scoped to the PowerShell session (module-level `$script:` variables). To persist across terminals, serialize and restore the token manually:

```powershell
# Save (sensitive — treat like a password)
$session = Get-PwshBearerAuthSession
# ... export as needed

# Or simply re-run Connect-PwshBearerAuth in each new terminal.
# If the auth server session cookie is still valid, the browser login
# will complete silently with no password prompt.
```
