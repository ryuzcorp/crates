# Security model

## Trust boundaries

- The object store is trusted for durability, not for authorization. The
  manifest is the only authority for refs and the live pack set; retired
  objects remain downloadable but never become live again without a CAS.
- Git clients are untrusted. Smart HTTP authorizes before git runs, bounds the
  body, times out, and never hands an unparseable receive head to git.
- The local mirror and worktrees are caches; a hostile local file must never
  become a ref or an object key without validation.
- Hooks are the application boundary: `authorize` returns a role or a refusal;
  policy is evaluated before git mutates refs.

## Defaults

- `validate_refname` rejects empty, control, space, backslash, `..`, `//`,
  leading/trailing `/`, `.lock`, and names outside `refs/` (or `HEAD`).
- `RepoId` rejects `..`, leading `.`, empty segments, and path separators
  beyond one `owner/` segment; local paths are rebuilt from validated parts.
- Bundle/pack/log/checkpoint/lease keys come from `Layout`, never raw input.
- `delete_prefix` refuses empty prefixes and prefixes without a trailing `/`.
- Store credentials are the operator's: never log access keys, session
  tokens, or signed URLs.
- Webhooks: HMAC-SHA256 over the exact body; constant-time compare; delivery
  id for dedup; cursor advances only after 2xx.
- Limits are fail-closed: body/push/bundle/repo/ref counts are checked before
  reading or publishing. A zero where a bound is required is a config error.
- Anonymous read is opt-in. Every write requires a role with write access;
  policy cannot be bypassed by having a write bit. Groups resolve at eval; an
  unresolvable group denies.

## Non-goals for the library

TLS termination, OIDC, browser sessions, CSRF, and multi-tenant billing belong
to the host application. The library supplies hooks and token/Basic helpers so
the host can implement them without reimplementing git.
