# Phishing Detector (Single-Page Demo)

A front-end phishing analysis demo that implements:

- URL processing (validation + decomposition)
- URL risk indicators (length, suspicious chars, hyphens, dots, subdomains, IP usage, lookalike domains)
- HTML structure analysis (form/password detection, script checks, suspicious text)
- Risk score weighting and classification (Safe / Suspicious / Phishing)
- Local scan-history database model (stored in `localStorage`)
- Authentication (simple username/password check using local stored users)
- Interface for scanning URLs and reviewing history

## Run

Open `logi.html` directly in a browser.

Default login:

- username: `admin`
- password: `admin123`

## Notes

- HTML fetch uses browser `fetch`; some sites may block cross-origin requests, which is handled and scored as a retrieval issue.
- This is a prototype and should be extended with a secure backend for production use.