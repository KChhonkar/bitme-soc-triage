# BitMe

AI alert-triage console for a live hackathon demo. The feed is a **synthetic replay** of `backend/raw_alerts.csv`. Correlation, asset-aware scoring, Gemini briefs (with template fallback), prevention drafts, and the audit log are real code. Prevention commands are **never** executed against a live system.

## 1. Backend (macOS, Python 3.9+)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# paste GEMINI_API_KEY into .env (optional; the UI falls back to templates)
uvicorn main:app --port 8000
```

Checks: `python verify.py`

## 2. Frontend (second terminal)

Needs Node 20.19+ or 22.12+ (Vite 8).

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** (Vite proxies `/api` to port 8000).

## Demo path

Start the feed (or Skip to end). Three incidents appear, ranked FIN-DB-01 > CEO-Laptop > Guest-WiFi-04 by the risk formula. Select one for the CSV timeline, generate a brief and a prevention draft, then Approve / Modify / Reject. Execute is simulated and writes the audit log (`backend/audit_log.jsonl`), which survives a refresh.
