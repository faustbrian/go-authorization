# Security policy

Please report suspected authorization bypasses, tenant-isolation failures,
unsafe default behavior, policy rollback, or resource-exhaustion issues through
GitHub private vulnerability reporting. Do not open a public issue containing
an exploit or sensitive policy data.

Security fixes are made on the latest published stable major. Publication of
v3 supersedes v2; breaking cache security contracts are not silently backported
to the v2 public API. Until v3 is published, v2 remains the latest published
line. The v3 candidate adopts `go-cache/v2`; follow
[compatibility and migration](docs/compatibility.md) and
[cache ownership and lifecycle](docs/cache.md) when upgrading.

A useful report includes the affected version, policy model and combining
algorithm, a minimal request and policy definition, the observed decision, and
the expected fail-closed behavior. Remove credentials, personal data, and
production policy contents before submitting evidence.
