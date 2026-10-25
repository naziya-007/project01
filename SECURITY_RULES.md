# Context pasted at the start of every AI session on TrustVault

You are helping build TrustVault, a document-sharing system whose whole point is
that the wrong person can never read a file and that every access is provable.
Security beats convenience in every trade-off. Follow these rules; if a request
conflicts with one, say so instead of quietly working around it.

## Authorization
- `app/authz.py:authorize()` is the only place the application decides access.
  Every service function that takes a document id calls it on its FIRST line,
  before parsing or validating anything else.
- Refuse with 404, never 403, for documents. Never reveal whether a document exists.
- The admin role grants nothing on documents. Do not add admin shortcuts.
- Editors cannot manage access (grants, share links, suggestions). Only owners can.
- Never cache permissions. Never issue a token or URL that outlives a revocation
  (no JWTs, no pre-signed storage URLs).

## Database
- Every protected table has row-level security ENABLED and FORCED. New tables that
  hold document data need policies in a migration, not just app checks.
- Policies must not reference each other in a cycle; denormalise `owner_id` with a
  trigger instead.
- An UPDATE or DELETE that RLS filters matches zero rows silently. Check row counts.
- Never use the system context (`app.system = on`) in a request path except the
  admin ownership transfer.
- Parameterise every query. Never build identifiers from input.

## Audit
- Every state change and every download writes an audit row in the SAME transaction.
- Every refusal calls `audit.deny()` (written after the rollback).
- Never UPDATE or DELETE audit rows. Never weaken the triggers or the hash chain.
- Treat anything from the request (ids, names, user agents) as hostile text.

## Uploads and responses
- Decide file type from bytes; the extension must agree. No HTML, SVG, XML.
- Downloads are always `application/octet-stream`, `attachment`, `POST` + CSRF.

## Tests
- Every new check needs a test that fails when the check is removed, and a
  mutation in `scripts/mutation_check.py`.
- The integration tests must run against a database user that is NOT a superuser.
- When you write a test, say what would make it pass vacuously.

## How to answer
- Show the full changed function, not fragments.
- List any assumption about PostgreSQL or Flask behaviour you are not sure of,
  so I can check it.
