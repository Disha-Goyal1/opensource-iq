# OpenSource IQ

A working app that analyses an npm package: it collects data from npm, OSV, EPSS, CISA KEV and GitHub, cleans it, builds a risk score (with risk passed up from dependencies) and shows a dashboard.

No dependencies to install. Needs Node.js 18 or newer.

## Run locally
    node server.js
    # open http://localhost:3000

Optional: `GITHUB_TOKEN=<token> node server.js` raises the GitHub rate limit (60 requests/hour without it).

## Deploy on Render (free)
1. Push this folder to a GitHub repo.
2. On https://render.com choose New > Web Service, pick the repo.
3. Runtime: Node. Build command: leave empty. Start command: `node server.js`.
4. Optional: add the environment variable `GITHUB_TOKEN`.

Railway, Fly.io or any Node host work the same way (`npm start`). It needs a server, so it cannot be hosted on Netlify drop or GitHub Pages.

## How it works (server.js)
1. Collect: dependency tree to depth 2 (max 25 packages), advisories (OSV), exploit likelihood (EPSS), known-exploited list (CISA KEV), repository activity (GitHub).
2. Clean: merge duplicate advisories across GHSA/CVE ids, standardise severity labels, flag missing fields. The dashboard shows before and after counts.
3. Engineer and score: vulnerabilities (max 40), maintenance (max 35), propagated risk from the riskiest dependency (max 25).
4. Explain: every point in the score is listed with its reason.
5. Predict: a prototype logistic formula with hand-set weights. It is a placeholder for a model trained on collected data (XGBoost); it is not trained yet.
