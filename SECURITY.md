# Security Policy

## Supported release

Only the latest v0.5.x developer-preview release receives security fixes.

## Report a vulnerability

Do not include evidence, credentials, case exports, or victim data in a public issue. Use GitHub's private vulnerability-reporting feature for the repository. Include the Aries version, affected component, reproduction steps using synthetic data, and expected impact.

## Deployment boundary

Aries v0.5 is a localhost-only Windows application. It has no user authentication, authorization, TLS termination, multi-user isolation, or hardened remote deployment mode. Do not bind it to a non-loopback interface, publish port 8787, or place it directly on the internet.

Treat every forensic artifact and extracted member as untrusted. Aries does not intentionally execute recovered content, but parser defects are possible. Run it on a dedicated forensic workstation or disposable analysis VM with least privilege and network controls appropriate to the case.
