# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ (toy/research only) |

## Important Notice

**Absence v0.1.0 is a research/toy implementation and is NOT intended for production use.**

It has NOT been:
- Professionally audited
- Fuzz tested
- Reviewed for timing side-channels
- Optimized for adversarial inputs

## Reporting a Vulnerability

If you discover a security issue:

1. **Do NOT open a public issue**
2. Email: singhalkritarth@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

I will acknowledge receipt within 48 hours and provide a more detailed response within 7 days.

## Scope

Security-relevant issues include:
- Hash collision vulnerabilities
- Proof forgery attacks
- Root hash manipulation
- Denial of service via malformed input

## Known Limitations

These are NOT security bugs (they are documented design choices):

- Proofs are not zero-knowledge
- Proof size is O(256) hashes (not succinct)
- No protection against timing attacks
- Simple file-based storage
- No encryption of stored fact IDs

See [THREAT_MODEL.md](THREAT_MODEL.md) for details.
