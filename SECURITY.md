# Security Policy

Enigma.DataEncryption is a cryptographic library: it encrypts data and streams into an authenticated binary
container that applications rely on to keep that data confidential and to detect tampering. A defect here
does not merely misbehave — it can silently weaken or void the protection of every file an application has
written, and such a file cannot be retroactively re-protected once it has left the application's control.
Vulnerability reports are taken seriously and handled with priority.

## Supported versions

Security fixes are provided for the latest released version. Enigma.DataEncryption follows
[Semantic Versioning](https://semver.org/), and users are encouraged to stay current with the newest
release.

| Version | Supported          |
|---------|--------------------|
| 1.1.x   | :white_check_mark: |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull
requests.** Public disclosure before a fix is available puts every user at risk.

Instead, use **GitHub's private vulnerability reporting**:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** to open a private advisory.
3. Include as much detail as you can — the affected version, the component involved, a description of the
   issue, and, where possible, a minimal reproduction and its impact.

This keeps the report private between you and the maintainers while it is triaged and fixed.

## What to expect

- Your report will be acknowledged and triaged as promptly as possible.
- The issue will be investigated and, once confirmed, a fix prepared and released.
- Coordinated disclosure is preferred: please allow a reasonable period for a fix to ship before any public
  discussion of the vulnerability.
- Your contribution will be credited in the resulting advisory unless you ask to remain anonymous.

## Scope

In scope are the container format and its implementation, the public API surface, and the handling of key
material and plaintext within this library — for example, a header field that escapes validation, a way to
make decryption accept a container it should reject, key or password material that is not cleared, or a
divergence between the implementation and the normative specification in `docs/format.md`.

Because Enigma.DataEncryption performs no cryptography of its own — every primitive comes from
[Enigma.Core](https://github.com/enigmalibs/Enigma.Core), which in turn builds on
[BouncyCastle](https://github.com/bcgit/bc-csharp) — issues rooted in a primitive's implementation should
also be reported upstream to the Enigma.Core project, and where appropriate to BouncyCastle. A report is
still welcome here if you are unsure which layer is at fault.
