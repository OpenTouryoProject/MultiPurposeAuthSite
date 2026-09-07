# Security Policy

Click [here](Security.ja.md) for the Japanese version of this file.

## What This Repository Is

**MultiPurposeAuthSite is a reference implementation of an IdP / STS, and a template.**
It is meant to be read, run and customized — see
[`license/LicenseForTemplates.txt`](license/LicenseForTemplates.txt).

**The default configuration is for evaluation, not for production.** Out of the box it uses
an in-memory user store, creates test users, enables the Implicit and ROPC grant types, and
registers test clients whose redirect URIs are reserved constants. Hardening a deployment
derived from this repository is the deployer's responsibility.

Reports that amount to "the shipped defaults are not production-hardened" are already known
(see [Already known](#already-known)). Reports that show a **concrete attack against the
code itself** are welcome.

## Supported Versions

Security fixes are applied to `develop` and to the latest release line only.

| Version | Supported |
|---|---|
| `develop` | :white_check_mark: |
| `02-00` | :white_check_mark: |
| `01-99` and earlier | :x: |

## Reporting a Vulnerability

**Please do not open a public issue for a security problem.**

Use **[Private vulnerability reporting](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/security/advisories/new)**.
The report stays private until a fix is published, and the discussion happens in the same place.

Please include:

- **Which component**, from the table in [Scope](#scope)
- **Which target framework** (`net48` or `net10.0`) — the two are separate applications built
  from a shared library, and **a problem may exist in only one of them**
- **Which configuration**, if it matters (`UserStoreType`, which grant types are enabled,
  `subject_types` of the client, and so on)
- Steps to reproduce, or the code path you believe is affected
- What an attacker gains — which token, whose account, and under what precondition

We are a small team. We will acknowledge the report and tell you what we intend to do,
but we cannot promise a fixed turnaround time.

## Scope

| Path | Scope |
|---|---|
| `root/programs/CommonLibrary/` | **In scope.** Most of the implementation lives here — the ASP.NET Identity stores, and the OAuth 2.0 / OIDC / SAML2 protocol code. **Shared by both applications** |
| `root/programs/MultiPurposeAuthSiteCore/` | **In scope.** The current version (ASP.NET Core MVC / net10.0) |
| `root/programs/MultiPurposeAuthSite/` | **In scope.** The downlevel version (ASP.NET MVC5 + OWIN / net48) |
| `root/programs/CommandLineTools/` | **In scope.** They generate client credentials and JWK Sets |
| `root/programs/authentication_device/` | Sample (Flutter). **Reports are welcome**, but it is a test peer for CIBA and push-based 2FA, not a shipped product |
| `root/files/resource/X509/` | **Out of scope.** Self-signed certificates and private keys **for tests only**. The passphrase is `test`, on purpose |
| `_appsettings.json` / `_app.config` | **Out of scope.** These are the templates. The `client_id` / `client_secret` / JWK values in them are **sample values**, and the real files (`appsettings.json` / `app.config`) are in `.gitignore` |
| `store/` | **Out of scope.** A `docker-compose` setup for a local development database, with fixed passwords |

The framework this site is built on is a separate repository. Problems in
`OpenTouryo.*` belong there:
**https://github.com/OpenTouryoProject/OpenTouryo/security/advisories/new**

## Already known

**A protocol-conformance review of the IdP implementation has been carried out, and the
findings are written down.** Before reporting, please check:

- **[`root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md`](root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md)**
  — the full list, with file and line references
- Issues **[#182](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/182)** –
  **[#189](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/189)**
  — the items already filed

The following are known and deliberate:

- **The test clients in `_appsettings.json` use the reserved redirect URIs
  `test_self_code` / `test_self_token`.** They exist so that the site can act as a client
  against itself. `IsLockedDownRedirectEndpoint` closes them
- **`IsDebug: true` creates test user accounts** on the first request to `/Account/Login`.
  It is a development setting
- **Implicit and ROPC are enabled by default** (`EnableImplicitGrantType`,
  `EnableResourceOwnerPasswordCredentialsGrantType`). Aligning the defaults with OAuth 2.1
  is tracked separately
- **FIDO / WebAuthn is currently not built.** `CommonLibrary/Extensions/FIDO/**` is excluded
  from both projects and the calling code is commented out, even though configuration keys
  and views remain

Reports that show a **concrete exploit** for any of the above are still welcome.

## Security Practices in This Repository

| | |
|---|---|
| Private vulnerability reporting | Enabled |
| Dependabot alerts / security updates | Enabled |
| Secret scanning ＋ Push protection | Enabled |
| Code scanning (CodeQL) | Not enabled |
| Branch protection (`master`) | 1 approving review required |
| Branch protection (`develop`) | Force pushes and deletion blocked |

The settings themselves live on GitHub and are not visible from the files in this repository,
so they are written down here.

Test-only material — the self-signed certificates under `root/files/resource/X509/` and the
third-party minified assets — is excluded from secret scanning **alerts** by
[`.github/secret_scanning.yml`](.github/secret_scanning.yml), so that the Security tab shows
real findings. **That exclusion does not apply to push protection**, which still blocks a
push when it detects a secret.
