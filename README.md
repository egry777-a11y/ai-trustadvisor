    # AI TrustAdvisor — Fullstack Starter

    This project contains a demo fullstack application that scans a website for reputation signals and provides an AI-generated explanation about whether the site and its payment system look trusted.

    ## What is included
    - `server/index.js` — Express backend with `/api/scan` and `/api/ai-assess` endpoints.
    - `frontend/index.html` — Simple React + Tailwind frontend (dev/demo) that calls the backend.
    - `Dockerfile` + `docker-compose.yml` for quick local deployment.
    - Optional integrations: Google Safe Browsing, VirusTotal, WHOISXMLAPI, OpenAI. Provide API keys via environment variables.

    ## Quickstart (local, without Docker)
    1. Install Node.js (v18+ recommended).
2. In project root run:

```bash
npm install
node server/index.js
```

3. Open http://localhost:4000 in your browser.

## Quickstart (Docker)
1. Build and run with docker-compose:

```bash
docker compose up --build
```

2. Visit http://localhost:4000

## Environment variables
- `GOOGLE_SAFEBROWSING_KEY` — (optional) Google Safe Browsing API key.
- `VIRUSTOTAL_KEY` — (optional) VirusTotal API key (v3).
- `WHOISXMLAPI_KEY` — (optional) WHOISXMLAPI API key.
- `OPENAI_API_KEY` — (optional) OpenAI API key for richer AI explanations.

If not provided, the server will still run and use internal heuristics.

## Notes
- The frontend uses in-browser Babel for JSX — this is suitable for demo/development only. For production build, integrate a proper React build pipeline.
- The Dockerfile installs production dependencies and serves the Express app.

## Next steps I can help with
- Create a production React app (Vite) with Tailwind and build artifacts served by Express.
- Integrate caching (Redis) and persistent storage for scan history.
- Add CI tests and GitHub Actions to run linters and tests.

