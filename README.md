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

See [`docs/configuration.md`](docs/configuration.md) for the configuration contract and bootstrap lock format.
