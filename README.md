# test-resource-lifecycle

`trl` wraps canonical test commands with invocation-owned resource creation, ownership-proof cleanup, audit records, and crash recovery. It supports Python 3.10+ on macOS and Linux with Docker Engine/Desktop and Compose v2.

```console
trl run --config=.test-resource-lifecycle.json --profile=e2e -- npm run test:e2e
trl audit --repo=my-repo --json
trl sweep --repo=my-repo
trl doctor
trl sweeper install
```

Resources are removable only when the global ledger and the complete policy-v1 label/marker identity agree. Missing proof, a live owner, a foreign host or Docker context, and pre-existing unlabeled resources are preserved. The implementation never invokes a global Docker prune or guesses ownership from names or age.

Process identities use a versioned, locale- and timezone-stable birth token. Ledgers written by older releases are treated as unverifiable while their owner PID is live and are preserved fail-closed.

See [`docs/configuration.md`](docs/configuration.md) for the configuration contract and bootstrap lock format.

## Interactive acceptance sessions

`trl run` retains its bounded command timeout. For interactive acceptance the existing
agent supervisor calls `trl session open --config <config> --profile e2e --attempt <unique-id>
--owner-pid <supervisor-pid> --deadline-at <UTC-RFC3339>`. The CLI requires its caller to
be the bound live parent, with exact host, PID and process birth identity. It returns
a context path and a mode-0600 environment file; never print that file or put its values in argv.
Services use the same profile adapters and protected attempt logs. No sleep keeper is needed.

`trl session status --context <path>` is read-only. A command profile timeout is not a
session TTL; the existing supervisor enforces its authorized deadline. Normal completion
or cancellation calls `trl session close --context <path> --owner-pid <supervisor-pid>`.
After supervisor loss, the existing `trl sweep` reclaims only provably dead owners, using
the same adapters and protected recovery environment. Unknown identities or missing recovery
files are preserved. Successful close removes credentials and retains audit evidence.
