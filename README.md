# TrustVault

Secure document sharing where the wrong person cannot reach a file, and you can
prove who did.

- **Live demo:** `https://<your-service>.onrender.com` ← replace after deploying
  (free instance: the first request after 15 idle minutes takes up to a minute)
- **Demo video:** `<link>` ← replace
- **Write-up:** [WRITEUP.md](WRITEUP.md) · **Threat model:** [THREATS.md](THREATS.md) ·
  **AI log:** [PROMPTS.md](PROMPTS.md) · **API:** [docs/API.md](docs/API.md) ·
  **Permission model:** [docs/PERMISSIONS.md](docs/PERMISSIONS.md)

## Demo accounts

| Role | E-mail | Password | What to try |
|---|---|---|---|
| Admin | `admin@trustvault.demo` | `Admin#Vault2026` | Dashboard, alerts, audit trail, "Verify audit chain". Try to download a document: you can't. |
| Owner | `alice@trustvault.demo` | `Alice#Vault2026` | Owns 3 HR/Audit documents; Victor can read the salary letter. Has edit access to Bob's contract. |
| Owner | `bob@trustvault.demo` | `Bob#Vault2026!` | Owns the Acme contract and an NDA template. |
| Viewer | `victor@trustvault.demo` | `Victor#Vault2026` | Can read exactly one document. |
| Viewer | `eve@trustvault.demo` | `Eve#Vault2026!` | Has been granted nothing. Attack with this one. |

These are public demo credentials. Override them at first boot with
`SEED_PASSWORD_ADMIN`, `SEED_PASSWORD_ALICE`, and so on.

## What it is, in four sentences

Flask + PostgreSQL. Every request is authorised twice, independently: by one
function in the application (`app/authz.py`) and by PostgreSQL row-level
security (`migrations/002_rls.sql`), and the tests prove each lock holds on its
own. Files are encrypted with a per-file key and only ever leave through the
server after authorization, so revoking access works on the very next request.
The audit trail records successes and refusals, cannot be changed through the
database, and is hash-chained so any edit or deletion is detectable.

## Run it locally (from a clean clone)

You need **Python 3.11+** and **PostgreSQL 14+**. The database user must own the
database and must **not** be a superuser (superusers bypass row-level security).

### 1. Start PostgreSQL

Easiest, with Docker:

```bash
docker compose up -d        # creates user "trustvault" and databases trustvault + trustvault_test
```

Or with a local PostgreSQL install:

```bash
psql -U postgres -c "CREATE ROLE trustvault LOGIN PASSWORD 'trustvault' NOSUPERUSER"
psql -U postgres -c "CREATE DATABASE trustvault OWNER trustvault"
psql -U postgres -c "CREATE DATABASE trustvault_test OWNER trustvault"
```

### 2. Install and configure

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # edit if your database differs
set -a; . ./.env; set +a           # Windows PowerShell: see below
```

Windows PowerShell equivalent of the last line:

```powershell
Get-Content .env | Where-Object { $_ -match '^[A-Z]' } | ForEach-Object { $k,$v = $_ -split '=',2; Set-Item "env:$k" $v }
```

### 3. Create the schema, seed demo data, run

```bash
python -m app.migrate        # applies migrations/*.sql (idempotent)
python -m app.seed           # demo users and documents, only if the database is empty
flask --app wsgi run         # http://127.0.0.1:5000
```

### 4. Run the tests

```bash
python -m unittest discover -s tests -t . -v       # 144 tests, ~30 s; needs TEST_DATABASE_URL
python scripts/mutation_check.py                    # deletes 29 checks one by one; all must be caught
```

Every integration test starts from an empty, freshly migrated `trustvault_test`
database. GitHub Actions runs both commands on every push
(`.github/workflows/tests.yml`).

## Deploy to Render (step by step)

1. **Push this repository to GitHub** (public, as the brief requires).
2. Sign in at [render.com](https://render.com) with GitHub.
3. **Dashboard → New → Blueprint** → choose the repository. Render reads
   `render.yaml` and shows two resources: the `trustvault` web service and the
   `trustvault-db` PostgreSQL database. Click **Apply**.
4. Leave `AI_API_KEY` empty (a local heuristic is used) or paste an Anthropic API
   key to rank suggestions with an LLM.
5. Wait for the first deploy. The start command runs migrations, seeds the demo
   data and starts gunicorn. Open the service URL and sign in as each demo user.
6. **Save the generated `MASTER_KEY`** (web service → Environment). It encrypts
   every stored file; if it is lost or changed, files cannot be decrypted.
7. **Before judging: upgrade the database.** Render's free PostgreSQL expires 30
   days after creation and has no backups. Web service → database → upgrade to
   *Basic 256 MB*, or point `DATABASE_URL` at another PostgreSQL that does not expire.
8. Put the URL in this README and smoke-test it as an attacker:

   ```bash
   ./scripts/attack_smoke.sh https://<your-service>.onrender.com <id-of-an-alice-document>
   ```

   Every line should print 401, 403 or 404. (Find an id by signing in as Alice;
   it is in the document page's URL.)

Why the files live in PostgreSQL by default: Render's free web services have an
ephemeral disk that is wiped on every restart. For larger volumes set
`STORAGE_BACKEND=s3` with `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`,
`S3_SECRET_ACCESS_KEY` (Cloudflare R2's free tier works) and uncomment `boto3` in
`requirements.txt`. Files stay encrypted and are still never served by URL.

### Operating it

| Task | How |
|---|---|
| Verify the audit trail | Admin → Dashboard → **Verify audit chain**, or `GET /api/admin/audit/verify` |
| Anchor the chain outside the database | `python scripts/anchor_head.py >> anchors.jsonl` on a schedule (see the script) |
| Purge trash older than 30 days | Runs at every boot; or `python -m app.purge` |
| Offboard a leaver | Admin → Users → deactivate (sessions end at once); Admin → Documents → transfer ownership |
| Investigate a document | Admin → Documents → the document: who can reach it now and every event |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | local | PostgreSQL connection string (non-superuser owner) |
| `MASTER_KEY` | required in production | Wraps per-file encryption keys |
| `SECRET_KEY` | required in production | Signs the flash-message cookie |
| `APP_ENV` | `development` | `production` enables secure cookies, HSTS, key checks |
| `TRUST_PROXY_HOPS` | `1` in production | Proxies in front of the app, for the real client IP |
| `STORAGE_BACKEND` | `db` | `db` or `s3` |
| `MAX_UPLOAD_MB` | `10` | Upload size limit |
| `SESSION_HOURS` / `IDLE_MINUTES` | `8` / `30` | Session lifetime |
| `SHARE_MAX_HOURS` | `168` | Longest allowed share-link expiry |
| `TRASH_RETENTION_DAYS` | `30` | Restore window before purge |
| `AI_API_KEY` / `AI_MODEL` | empty / `claude-haiku-5-5` | Optional LLM suggestions |

## Project layout

```
app/
  authz.py          THE authorization decision (decide + authorize)
  audit.py          hash-chained audit trail, deferred logging of refusals
  db.py             DB wrapper: publishes the user to RLS on every transaction
  crypto.py         per-file AES-256-GCM envelope encryption
  validation.py     upload checks (content sniffing, zip bombs, macros, names)
  security.py       passwords (scrypt), tokens, client IP, rate limiting
  services/         documents, grants, shares, ai, users, admin
  web/api.py        JSON API (each route's docstring says who may call it)
  web/ui.py         server-rendered pages calling the same services
migrations/         schema, row-level security, audit protection (plain SQL)
tests/              unit, RLS, isolation (3 modes), route coverage, audit, features
scripts/            mutation check, chain anchoring, black-box attack smoke test
docs/               API reference, permission model, demo script
```

## Known limits

See "What is unfinished" in [WRITEUP.md](WRITEUP.md) and the *Partial* and
*Accepted* entries in [THREATS.md](THREATS.md).
