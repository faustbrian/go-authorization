# Security policy

Please report suspected authorization bypasses, tenant-isolation failures,
unsafe default behavior, policy rollback, or resource-exhaustion issues through
GitHub private vulnerability reporting. Do not open a public issue containing
an exploit or sensitive policy data.

Security fixes are made on the latest published stable major. Publication of
v4 supersedes v3; until v4 is published, v3 remains the latest published line.
The v4 candidate adopts `go-cache/v4`; follow
[compatibility and migration](docs/compatibility.md) and
[cache ownership and lifecycle](docs/cache.md) when upgrading.

A useful report includes the affected version, policy model and combining
algorithm, a minimal request and policy definition, the observed decision, and
the expected fail-closed behavior. Remove credentials, personal data, and
production policy contents before submitting evidence.
