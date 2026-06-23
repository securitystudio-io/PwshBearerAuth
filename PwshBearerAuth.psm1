#Requires -Version 7.0
<#
.SYNOPSIS
    OIDC authentication module for identitystudio.io services.

.DESCRIPTION
    Implements Authorization Code + PKCE flow against the identitystudio.io auth server.
    Tokens are held in module-scope memory for the session.

    Register a public client in the admin UI with:
      Redirect URI: http://localhost:58080/callback
      Grant types:  Authorization Code, Refresh Token
      PKCE:         Required

.EXAMPLE
    Import-Module ./scripts/PwshBearerAuth.psm1
    Connect-PwshBearerAuth -ClientId "my-cli-client"
    Invoke-WebRequest https://api.identitystudio.io/endpoint -Headers (Get-PwshBearerAuthHeader)
#>

Set-StrictMode -Version Latest

# ── Module state ──────────────────────────────────────────────────────────────

$script:Session = $null

# ── Private helpers ───────────────────────────────────────────────────────────

function New-PkceChallenge {
    $verifier = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) `
        -replace '\+', '-' -replace '/', '_' -replace '='

    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))
    $sha.Dispose()

    $challenge = [Convert]::ToBase64String($hash) `
        -replace '\+', '-' -replace '/', '_' -replace '='

    return @{ Verifier = $verifier; Challenge = $challenge }
}

function New-State {
    return [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)) `
        -replace '\+', '-' -replace '/', '_' -replace '='
}

function Wait-LocalCallback {
    param([int]$Port, [string]$ExpectedState, [int]$TimeoutSeconds = 120)

    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Start()

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    try {
        while ([DateTime]::UtcNow -lt $deadline) {
            $task = $listener.GetContextAsync()
            $completed = $task.Wait([TimeSpan]::FromSeconds(1))
            if (-not $completed) { continue }

            $ctx = $task.Result

            # Ignore stray requests (browser favicon, etc.)
            if ($ctx.Request.Url.AbsolutePath -notmatch '^/callback') {
                $ctx.Response.StatusCode = 204
                $ctx.Response.Close()
                continue
            }

            $query = $ctx.Request.Url.Query.TrimStart('?')
            $params = @{}
            foreach ($pair in $query -split '&') {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2) { $params[[Uri]::UnescapeDataString($kv[0])] = [Uri]::UnescapeDataString($kv[1]) }
            }

            $html = if ($params.ContainsKey('error')) {
                "<html><body><h2>Authentication failed: $($params['error'])</h2><p>You may close this tab.</p></body></html>"
            } else {
                "<html><body><h2>Authentication successful.</h2><p>You may close this tab.</p></body></html>"
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes($html)
            $ctx.Response.ContentType = 'text/html; charset=utf-8'
            $ctx.Response.ContentLength64 = $bytes.Length
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()

            if ($params.ContainsKey('error')) {
                throw "Auth server returned error: $($params['error']) — $($params['error_description'])"
            }
            if ($params['state'] -ne $ExpectedState) {
                throw "State mismatch — possible CSRF. Aborting."
            }

            return $params['code']
        }
        throw "Timed out waiting for browser callback after $TimeoutSeconds seconds."
    }
    finally {
        $listener.Stop()
        $listener.Close()
    }
}

function Invoke-TokenRequest {
    param([hashtable]$Body, [string]$TokenEndpoint)

    $form = ($Body.GetEnumerator() | ForEach-Object { "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString($_.Value))" }) -join '&'
    $response = Invoke-RestMethod -Method Post -Uri $TokenEndpoint `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body $form
    return $response
}

function Get-DiscoveryDocument {
    param([string]$Issuer)
    $url = $Issuer.TrimEnd('/') + '/.well-known/openid-configuration'
    return Invoke-RestMethod -Uri $url
}

function Test-TokenExpired {
    param([string]$AccessToken)
    $parts = $AccessToken -split '\.'
    if ($parts.Count -lt 2) { return $true }
    $payload = $parts[1]
    $padded = $payload + ('=' * ((4 - $payload.Length % 4) % 4))
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
    $claims = $json | ConvertFrom-Json
    if ($null -eq $claims.exp) { return $false }
    $exp = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp)
    return [DateTimeOffset]::UtcNow -ge $exp.AddSeconds(-30)
}

# ── Public functions ──────────────────────────────────────────────────────────

function Connect-PwshBearerAuth {
    <#
    .SYNOPSIS
        Opens a browser to authenticate against the identitystudio.io auth server via OIDC.
    .PARAMETER ClientId
        The OIDC client_id registered in the auth server admin UI.
    .PARAMETER Issuer
        Base URL of the auth server. Defaults to https://sso.identitystudio.io.
    .PARAMETER Scopes
        Space-separated list of scopes to request.
    .PARAMETER Port
        Local port to listen on for the redirect. Must match the redirect URI
        registered in the auth server (default: 58080).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientId,

        [string]$Issuer = 'https://sso.identitystudio.io',

        [string]$Scopes = 'openid profile email roles offline_access',

        [int]$Port = 58080
    )

    $redirectUri = "http://localhost:$Port/callback"
    Write-Host "Fetching OIDC discovery document from $Issuer ..."
    $discovery = Get-DiscoveryDocument -Issuer $Issuer

    $pkce  = New-PkceChallenge
    $state = New-State

    $authUrl = $discovery.authorization_endpoint +
        "?response_type=code" +
        "&client_id=$([Uri]::EscapeDataString($ClientId))" +
        "&redirect_uri=$([Uri]::EscapeDataString($redirectUri))" +
        "&scope=$([Uri]::EscapeDataString($Scopes))" +
        "&state=$([Uri]::EscapeDataString($state))" +
        "&code_challenge=$([Uri]::EscapeDataString($pkce.Challenge))" +
        "&code_challenge_method=S256"

    Write-Host "Opening browser for authentication..."
    Start-Process $authUrl

    Write-Host "Waiting for callback on $redirectUri (timeout: 120s)..."
    $code = Wait-LocalCallback -Port $Port -ExpectedState $state

    Write-Host "Exchanging code for tokens..."
    $tokens = Invoke-TokenRequest -TokenEndpoint $discovery.token_endpoint -Body @{
        grant_type            = 'authorization_code'
        code                  = $code
        redirect_uri          = $redirectUri
        client_id             = $ClientId
        code_verifier         = $pkce.Verifier
    }

    $script:Session = @{
        ClientId      = $ClientId
        Issuer        = $Issuer
        Port          = $Port
        Scopes        = $Scopes
        AccessToken   = $tokens.access_token
        RefreshToken  = $tokens.refresh_token
        TokenEndpoint = $discovery.token_endpoint
    }

    $sub = try {
        $parts = $tokens.id_token -split '\.'
        $payload = $parts[1]
        $padded = $payload + ('=' * ((4 - $payload.Length % 4) % 4))
        ($padded | ForEach-Object { [Convert]::FromBase64String($_) } | ForEach-Object { [Text.Encoding]::UTF8.GetString($_) } | ConvertFrom-Json).name
    } catch { '(unknown)' }

    Write-Host "Authenticated as: $sub" -ForegroundColor Green
}

function Disconnect-PwshBearerAuth {
    <#
    .SYNOPSIS
        Clears the stored OIDC session from memory.
    #>
    $script:Session = $null
    Write-Host "Session cleared." -ForegroundColor Yellow
}

function Get-PwshBearerAuthHeader {
    <#
    .SYNOPSIS
        Returns a hashtable with a Bearer Authorization header for use with Invoke-WebRequest / Invoke-RestMethod.

    .EXAMPLE
        Invoke-RestMethod https://api.identitystudio.io/data -Headers (Get-PwshBearerAuthHeader)
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    if ($null -eq $script:Session) {
        throw "No active session. Run Connect-PwshBearerAuth first."
    }

    if (Test-TokenExpired -AccessToken $script:Session.AccessToken) {
        if ([string]::IsNullOrEmpty($script:Session.RefreshToken)) {
            throw "Access token expired and no refresh token available. Run Connect-PwshBearerAuth again."
        }

        Write-Verbose "Access token expired — refreshing..."
        $tokens = Invoke-TokenRequest -TokenEndpoint $script:Session.TokenEndpoint -Body @{
            grant_type    = 'refresh_token'
            refresh_token = $script:Session.RefreshToken
            client_id     = $script:Session.ClientId
        }

        $script:Session.AccessToken  = $tokens.access_token
        if (-not [string]::IsNullOrEmpty($tokens.refresh_token)) {
            $script:Session.RefreshToken = $tokens.refresh_token
        }
    }

    return @{ Authorization = "Bearer $($script:Session.AccessToken)" }
}

function Get-PwshBearerAuthSession {
    <#
    .SYNOPSIS
        Shows the current session state (without exposing raw token values).
    #>
    if ($null -eq $script:Session) {
        Write-Host "No active session." -ForegroundColor Yellow
        return
    }

    $expired = Test-TokenExpired -AccessToken $script:Session.AccessToken
    [PSCustomObject]@{
        ClientId     = $script:Session.ClientId
        Issuer       = $script:Session.Issuer
        Scopes       = $script:Session.Scopes
        TokenExpired = $expired
        HasRefresh   = (-not [string]::IsNullOrEmpty($script:Session.RefreshToken))
    }
}

function Get-PwshBearerAuthREADME {
    <#
    .SYNOPSIS
        Displays the PwshBearerAuth module documentation.
    .PARAMETER UseBrowser
        Open the README in the default browser instead of rendering in the terminal.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseBrowser
    )

    $content = @'
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

### `Get-PwshBearerAuthREADME`

Displays this documentation. Pass `-UseBrowser` to open it in the default browser instead of rendering in the terminal.

```powershell
Get-PwshBearerAuthREADME
Get-PwshBearerAuthREADME -UseBrowser
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
'@

    if ($UseBrowser) {
        Show-Markdown -InputObject $content -UseBrowser
    } else {
        Show-Markdown -InputObject $content
    }
}

function Get-PwshBearerAuthSBOM {
    <#
    .SYNOPSIS
        Displays the PwshBearerAuth software bill of materials.
    .PARAMETER UseBrowser
        Open the SBOM in the default browser instead of rendering in the terminal.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseBrowser
    )

    $content = @'
# PwshBearerAuth — Software Bill of Materials

**Format:** CycloneDX 1.6
**Serial:** urn:uuid:3f8a2c1d-9b47-4e06-a5f2-d1c8e0b73924
**Generated:** 2026-06-15

---

## Top-level component

| Field | Value |
|---|---|
| Name | PwshBearerAuth |
| Version | 1.0.0 |
| Type | library |
| Description | PowerShell 7 module implementing OIDC Authorization Code + PKCE flow. Stores access and refresh tokens in module-scope memory and exposes them as a Bearer header for use with Invoke-WebRequest and Invoke-RestMethod. |

---

## Dependencies

### PowerShell 7.0.0

| Field | Value |
|---|---|
| Type | framework |
| Publisher | Microsoft Corporation |
| License | MIT |
| purl | pkg:github/PowerShell/PowerShell@v7.0.0 |
| Min version required | 7.0.0 |

This is the sole dependency. No PSGallery modules are required. All functionality is provided by .NET BCL types and built-in cmdlets that ship with PowerShell 7+:

| Capability | .NET / Cmdlet |
|---|---|
| PKCE code verifier | `System.Security.Cryptography.RandomNumberGenerator` |
| SHA-256 challenge hash | `System.Security.Cryptography.SHA256` |
| Local redirect listener | `System.Net.HttpListener` |
| Token endpoint requests | `Invoke-RestMethod` |
| Browser launch | `Start-Process` |
| Markdown rendering | `Show-Markdown` |
| JWT claim parsing | `ConvertFrom-Json` |

---

## Dependency tree

```
PwshBearerAuth@1.0.0
└── PowerShell@7.0.0  (framework, MIT)
    └── (no further dependencies)
```

---

## Machine-readable SBOM

The full CycloneDX 1.6 JSON SBOM is at `scripts/PwshBearerAuth-sbom.json`.
'@

    if ($UseBrowser) {
        Show-Markdown -InputObject $content -UseBrowser
    } else {
        Show-Markdown -InputObject $content
    }
}

Export-ModuleMember -Function Connect-PwshBearerAuth, Disconnect-PwshBearerAuth, Get-PwshBearerAuthHeader, Get-PwshBearerAuthSession, Get-PwshBearerAuthREADME, Get-PwshBearerAuthSBOM
