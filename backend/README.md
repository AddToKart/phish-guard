# PhishGuard AI Backend

FastAPI service that powers the phishing site detector. It extracts heuristic signals from URLs and optional HTML bodies, then returns an AI-inspired score with explanations.

## Getting started

1. **Create & activate a virtual environment** (recommended)
   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
2. **Install dependencies**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```
3. **Run the API locally**
   ```powershell
   python run_server.py
   ```

The API exposes two endpoints:

- `GET /health` – readiness probe
- `POST /analyze` – accepts `{ url: string, html?: string }` and returns a score, verdict, confidence, explanations, and recommendations

## Testing

```powershell
python -m pytest
```

## Environment variables

- Copy `.env.example` to `.env` in this folder and set `GEMINI_API_KEY` to your Gemini API key. The key is **not required** for the heuristic detector to run, but once you integrate Gemini-powered enrichment you'll already have it in place.
- Any variables defined in `.env` are loaded automatically thanks to Pydantic's settings support.

Example:

```dotenv
GEMINI_API_KEY=sk-your-secret-key
```

For production deployments you can set the variable in your hosting platform instead of using a file. You can also tune CORS behaviour by editing `app/main.py`.
