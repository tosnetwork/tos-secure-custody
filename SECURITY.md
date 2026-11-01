# Security policy

## Supported use

All versions in this bootstrap are experimental and inspection-only. No production-custody version
is supported. Do not supply production keys, HSM credentials, seed phrases or funded account access.
The low-level adapter must use disposable test keys only. There is no hosted service.

## Reporting

Do not publish secrets, active exploit details against real deployments, or private institutional
configuration in an issue. After repository creation, maintainers must configure private vulnerability
reporting and a verified contact path. Until that exists, use an already-established private channel
with the TOS maintainers; this bootstrap does not invent a security email address.

Include the exact source revision, minimal synthetic reproducer, affected boundary, expected/actual
behavior and impact assumptions. The project must preserve independent review and evidence rather
than treating a reassuring statement or green CI as a security result.

## Release rule

The no-signing gate remains until all production gates pass on the exact reviewed candidate. Do not
remove a check merely to support more payloads, devices or algorithms. Unknown capabilities fail
closed. Physical hardware, native execution and expert review are mandatory separate workstreams.
