# Bait Al Gahwa — Application Form + Admin Dashboard

A small, self-contained web app: applicants fill out the 20-step Gahwa Journey
form, their answers and files (photo, CV, video) are saved to a real
database, and you review them privately at `/admin` — nobody else can see
that page or the data behind it.

- `public/index.html` — the applicant-facing form (no changes needed here)
- `app.py` — the server: receives submissions, serves the admin dashboard
- `data/` — created automatically; holds the database and uploaded files
  (never committed to git — see `.gitignore`)

## Running it on your own computer (optional, to try it first)

You need Python 3.9+ installed.

```
pip install -r requirements.txt
cp .env.example .env
# open .env and set ADMIN_PASSWORD to something real
python3 app.py
```

Then open http://localhost:3000 for the form, and http://localhost:3000/admin
to sign in and see submissions.

## Deploying it for real — Render (recommended, free tier, no credit card)

1. Put this folder in a GitHub repository (create a new repo, upload these
   files — GitHub's "upload files" button in the browser works fine, no git
   command line needed).
2. Go to [render.com](https://render.com) and sign up (free — GitHub login
   works).
3. Click **New +** → **Web Service**, connect the GitHub repo you just made.
4. Render should auto-detect Python. Confirm these settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Under **Environment**, add these variables:
   - `ADMIN_PASSWORD` → pick a strong password — this is what protects your
     applicants' data, so don't reuse a password from elsewhere
   - `SECRET_KEY` → generate one by running
     `python3 -c "import secrets; print(secrets.token_hex(32))"` and pasting
     the output
   - (optional) `ADMIN_USERNAME` → defaults to `admin` if you skip this
6. Click **Create Web Service**. After a minute or two you'll get a URL like
   `https://bait-al-gahwa.onrender.com` — that's your live form. Share that
   link with applicants. Go to `/admin` on that same domain to sign in.

**One thing to know about the free tier:** Render's free plan spins your
service down after 15 minutes of no traffic (the first visitor after a quiet
spell waits ~30 seconds while it wakes up) and its disk is not guaranteed to
survive a redeploy. For a small pilot this is usually fine — just avoid
redeploying once you have real applicants unless you've exported a CSV backup
first (`/admin/export.csv`). When you outgrow this, the fix is either
Render's paid tier with a persistent disk, or moving uploaded files to
object storage (e.g. Cloudflare R2 or AWS S3) and the database to a managed
Postgres — happy to help with that step when you get there.

## Deploying elsewhere

Any host that runs a Python web app works the same way (Railway, Fly.io,
PythonAnywhere, a plain VPS with `gunicorn` behind nginx). The only things
every environment needs are the `ADMIN_PASSWORD` and `SECRET_KEY` environment
variables and `pip install -r requirements.txt` at build time.

## What's actually stored, and where

Every submission goes into `data/gahwa.db` (a SQLite database file) and any
uploaded photo/CV/video goes into `data/uploads/`. Nothing is ever sent to
Anthropic, to Claude, or to any third party — it lives only on whichever
server you deploy this to, under your account, accessible only through your
`/admin` login.

## Security notes

- Change `ADMIN_PASSWORD` before sharing the form link with anyone.
- Set `SECRET_KEY` in production — without it, a new random one is generated
  every time the server restarts, which logs out any signed-in admin.
- The `/admin/*` routes require login; applicant-uploaded files are only
  reachable through an authenticated route, not as plain static files.
- Submissions are rate-limited (8 per hour per IP) to make spam harder.
