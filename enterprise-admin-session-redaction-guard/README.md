# Enterprise Admin Session Redaction Guard

Issue: [#19 Enterprise Tooling](https://github.com/SCIBASE-AI/SCIBASE.AI/issues/19)

This module adds an enterprise governance slice for recorded admin sessions. It checks whether privileged session replays are safe to export or share with institutional auditors by validating redaction, retention, access scope, and evidence completeness.

## Why this fits enterprise tooling

Universities and R&D organizations need auditability without exposing credentials, patient identifiers, billing records, embargoed project data, or identity-provider secrets. Session replay is useful for incident review, but only if the replay package proves that sensitive frames were masked and that reviewer access is bounded.

## Guard coverage

- Detects unredacted secrets, tokens, passwords, patient identifiers, billing accounts, private emails, and embargo markers in admin-session events.
- Requires ticket, reason, and reviewer approval for critical privileged actions.
- Blocks raw playback retention above 30 days unless an explicit legal hold is attached.
- Requires export bundles to include an audit digest, redaction manifest, and viewer access policy.
- Limits shared replay links to approved groups and short-lived expiry windows.

## Local verification

```bash
node test.js
node demo.js
```

Demo artifacts:

- `demo.svg` shows the guard scope and expected verification result.
- `demo.mp4` is a short video rendering of the same verification summary for bounty review.

No external services, private data, credentials, package installs, or live payment integrations are required.
