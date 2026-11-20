# Security Policy

## Supported versions

Security fixes are applied to the default branch (`main`). No stable release series is currently declared.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue.

Use GitHub's private vulnerability reporting feature for this repository if it is enabled. If private reporting is unavailable, contact the repository maintainer privately through the contact method listed on the GitHub profile.

Include:
- A clear description and affected component.
- Reproduction steps or a proof of concept that does not expose real users or systems.
- The impact you believe is possible.
- Any suggested mitigation.

Please allow reasonable time for investigation and a fix before public disclosure.

## Scope and safety

Do not test against systems or devices that you do not own or have explicit permission to assess. Do not include real credentials, private keys, tokens, or personal data in reports.

## Security status

A passing build or QEMU test suite is not a security certification. Cryptographic implementations, boot flows, privilege boundaries, network services, and physical-device behavior require independent review and testing.
