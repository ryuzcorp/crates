# ryuz_workflow

GitHub-Actions-style CI workflows executed in containers: a strict YAML
parser, a parallel container runner and structured events/outcomes.

```yaml
name: ci
on: [push]                     # accepted, ignored
env: { NODE_ENV: production }
jobs:
  build:
    runs-on: boat              # routing hint for the caller; unused locally
    image: oven/bun:1.4.4      # or `container:`; defaults to Settings
    timeout-minutes: 30        # 1..=360; kills the container on expiry
    defaults: { run: { shell: bash, working-directory: app } }
    strategy:
      matrix: { os: [linux, macos], node: [20, 22] }
      max-parallel: 2
      fail-fast: true          # default
    steps:
      - uses: checkout         # no-op: the worktree is already there
      - uses: cache            # no-op: the cache volume is always mounted
        with: { path: ~/.bun/install/cache, key: bun }
      - name: Install
        run: bun install --frozen-lockfile
        env: { CI: "1" }
        timeout-minutes: 10
      - uses: upload-artifact
        with: { path: reports/junit.xml, name: junit }
```

```rust
let workflow = ryuz_workflow::parse(&contents)?;
let outcome = ryuz_workflow::run_with_events(&settings, work_dir, &workflow, |event| {
    // render, stream or persist the structured event
})
.await?;
if !outcome.success() {
    for job in &outcome.jobs {
        eprintln!("{}: {:?}", job.name, job.status);
    }
}
```

## Parsing is strict

Unknown keys, oversize values, `${{ … }}` expressions, absolute or escaping
paths and unsupported actions are config errors with their path
(`jobs.build.steps[2].uses`), not silent no-ops. Accepted surface:

| Level | Keys |
| --- | --- |
| workflow | `name`, `on`, `env`, `jobs` |
| job | `name`, `runs-on`, `image`, `container`, `env`, `defaults`, `timeout-minutes`, `strategy`, `steps` |
| step | `name`, `run`, `env`, `working-directory`, `timeout-minutes`, `shell`, `uses`, `with` |

`matrix` values reach steps as env vars (`build (linux, 20)` sets
`RYUZ_MATRIX_OS=linux`, `RYUZ_MATRIX_NODE=20`): `RYUZ_MATRIX_` + the key
uppercased, every character outside `[A-Z0-9_]` replaced by `_`. An explicit
`env` value of the same name wins. Two matrix keys that map to the same env
name are a config error. `${{ matrix.x }}` stays rejected: the env var is the
contract.

`env` keys that configure the host container CLI or the dynamic loader
(`PATH`, `HOME`, `TMPDIR`, `LD_*`, `DOCKER_*`, `CONTAINER_*`, `PODMAN_*`,
`XDG_*`, proxy/TLS variables) are reserved and rejected: workflow values travel
through the CLI child's environment, so those names would leave the container.
Scripts export what they need inside `run`.

`uses` supports `checkout` / `actions/checkout@…` (no-op), `cache` /
`actions/cache@…` (no-op; `path`/`key` accepted), and `upload-artifact` /
`actions/upload-artifact@…` (`path` required, `name` optional). `env`,
`working-directory`, `timeout-minutes` and `shell` apply to `run` steps; a
`uses` step takes only `name`, `uses` and `with`. `matrix` is
expanded at parse time in GitHub's order (last key varies fastest), with the
display name carrying the values: `build (linux, 20)`. `needs` is rejected:
jobs run in file order, bounded by concurrency. Caps: 64 KiB config, 32
declared jobs, 256 expanded jobs, 32 steps/job, 32 KiB `run`, 512-byte names,
256 env vars, 64 KiB env values, 120-minute step and 360-minute job timeouts.

## Execution contract

One container per job; steps share `/work` in file order and fail fast. Up to
`Settings::max_parallel` jobs run at once; `strategy.max-parallel` caps one
job's matrix members. The caller owns the worktree, image allowlist and
budgets.

- `create --init --cap-drop ALL --cap-add CHOWN --security-opt
  no-new-privileges --pids-limit 2048 --memory ... --cpus ... --pull ...` —
  `CHOWN` exists only for the ownership prep; steps exec as the configured
  uid/gid with no capabilities.
- Env values never reach argv: they are set on the CLI child and referenced as
  `-e KEY`, so `ps` and audit logs show names only. Every configured value of
  at least 4 bytes is masked as `***` in step output; a multi-line value also
  contributes each of its lines as a mask.
- Steps run as `sh -lc <script>` (or `bash -e -o pipefail -l -c` with
  `shell: bash`) inside the container. No host shell ever interprets config
  text; any Docker-compatible CLI works via `Settings::docker_bin`.
- Per-step, per-job and whole-run timeouts kill the container. Exit 137 is
  reported as `Failure::OutOfMemory`; a removed artifact is a note.
- Containers carry a `ryuz_workflow.pid` label and are swept at start, so a
  killed process cannot leak them. Removal is armed from creation: dropping a
  run (cancellation, workflow timeout) spawns `rm -f` instead of leaking.
- Artifacts are copied to a fresh staging directory next to the worktree, then
  installed with `openat`/`O_DIRECTORY|O_NOFOLLOW` + `renameat`: a symlinked
  path component fails the install and the final entry is replaced, never
  followed, so a checkout (or a parallel job's artifact) cannot redirect a
  host write. Per-job copies and `uses: upload-artifact` share one install lock.
  After a successful job, `<container>:/work/<artifact_dir>` is copied back to
  `<work>/<artifact_dir>` best-effort and `lchown`ed without following
  symlinks; `Outcome::artifact_path` is set only for an install that ran.
- The container is removed with `rm -f` whatever happened inside.

## Results

`run_with_events` returns `Ok(Outcome)` whenever the workflow was attempted;
per-job success lives in the outcome:

- `JobStatus::{Success, Failed(Failure), Skipped, Cancelled}`
- `Failure::{StepFailed, OutOfMemory, Timeout, Container}`
- `JobOutcome { name, base_name, matrix, image, status, steps, artifacts, duration }`
- `Outcome { jobs, artifacts, artifact_path }`, `Outcome::success`

`Err` is reserved for a bad config/settings, a bad work dir, a disallowed image
and a scheduler failure. Output lines are decoded lossily (invalid UTF-8 becomes `�` and the stream is
still drained, so a step never blocks on a full pipe) and truncated at a
character boundary.

`run` is `run_with_events` formatted into plain lines
(`workflow: N jobs`, `job: <name> (<image>)`, `step: <name>`, raw output,
`job: <name> done`).

## Features

`runner` (default) pulls in tokio for execution. Build with
`--no-default-features` to use only `parse`, the model, events and outcomes —
for a UI or build script that validates configs without a runtime.

## Tests

```bash
cargo test -p ryuz_workflow
```

Engine tests drive a fake container CLI (argv, labels, env-by-name, exit codes,
OOM, timeouts, redaction, guard cleanup, parallel vs sequential, fail-fast,
upload-artifact, workflow timeout). The real-container test is opt-in:

```bash
RYUZ_WORKFLOW_REAL_DOCKER=1 cargo test -p ryuz_workflow real_docker
```

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE) (derived from Noite's
runner).
