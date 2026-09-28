# Interactive session validation, v1.1.0

Source: feat/acceptance-sessions, based on 71bb03e. Uses the same policy-v1 ownership ledger and adapters.

`TRL_DOCKER_INTEGRATION=1 python3 -m unittest discover -s tests -v`: 38 tests passed, zero skipped.
This includes real concurrent PostgreSQL instances, distinct URLs/ports and independent actor tables; closing one
leaves the peer queryable. Real CLI service creation returns without waiting for service stdout EOF.
A killed owner is reclaimed by the existing sweeper. Service code cannot execute before durable ownership.
Close serializes against in-progress prepare, can repeat safely, and preserves closed status.
Preparation failures preserve recovery configuration; cleanup loads inherited credentials from private files.

The old one-hour boundary was exercised with an advanced test clock (two hours), not a two-hour wall-clock run.
Status did not mutate context or shorten resource lifetime. The supervisor remains responsible for total deadline.

Native `trl run` tests, locale-safe identity, failure exit preservation, signal handling and zipapp exit semantics
remain in the full suite. This is infrastructure validation, not a POL-146 business acceptance result.

Independent diff Review found and prompted repairs for ledger/context identity, inherited stdout pipes,
missing cleanup credentials, failed-prepare recovery, closed status, service claim ordering, concurrent close,
and SQL URI compatibility. Release consumers must pin the source commit and exact zipapp SHA-256.
