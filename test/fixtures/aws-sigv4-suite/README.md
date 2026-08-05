# aws-sig-v4-test-suite fixtures

A subset of the official AWS Signature Version 4 test suite
(`aws-sig-v4-test-suite`), vendored from the copy shipped in
[boto/botocore](https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite)
(Apache License 2.0 — see NOTICE). Used by
`test/sandbox/aws-sigv4.test.ts` to pin the proxy's SigV4 re-signer.

Each vector directory holds:

- `<name>.req` — the raw HTTP request to sign
- `<name>.creq` — the expected canonical request
- `<name>.sts` — the expected string to sign
- `<name>.authz` — the expected Authorization header
- `<name>.sreq` — the expected signed request (not consumed by the tests)

All vectors sign with the suite's fixed credentials
(`AKIDEXAMPLE` / `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`),
region `us-east-1`, service `service`, date `20150830T123600Z`.
