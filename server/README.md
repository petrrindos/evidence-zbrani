# Evidence zbrani backend

## Start

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Env vars

- `EVIDENCE_DB_URL` (default: `sqlite:///./evidence_zbrani.db`)
- `EVIDENCE_JWT_SECRET` (change in production)
- `EVIDENCE_ACCESS_TTL_MIN` (default: `120`)

## Main API

- `POST /api/auth/register-owner` - create org + owner account
- `POST /api/auth/login` - login
- `GET /api/auth/me` - current user and role
- `GET /api/state` - load shared state (viewer+)
- `PUT /api/state` - save shared state (editor+)
- `GET /api/org/members` - list members (admin+)
- `POST /api/org/members` - add member (admin+/owner)
- `GET /api/audit` - audit log (admin+)
