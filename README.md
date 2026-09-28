# security-watch

A small Python 3.10+ project that tracks three security signals:

- `check_cves(keyword)` queries the NVD CVE API and reports CVEs not seen in the previous run.
- `check_headers(url)` fetches a URL and reports changes to five important HTTP security headers.
- `check_dns_ssl(domain)` checks A, MX, and TXT records, reads the HTTPS certificate expiry date, and warns when expiry is within 30 days.

Each check stores its latest successful result in `data/`. The GitHub Actions workflow runs daily and can also be started manually. It commits changed JSON files back to the repository, giving you a history of scan results.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Edit `KEYWORD`, `URL`, and `DOMAIN` near the top of `main.py` before running scans.

## Push to GitHub

Create an empty repository on GitHub, then run these commands from this directory:

```bash
git init
git add .
git commit -m "Initial security watch project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/security-watch.git
git push -u origin main
```

Replace `YOUR_USERNAME` and the repository URL with your own GitHub details. GitHub Actions must have permission to write repository contents for the workflow to commit scan data.

## Authorization

Only run scans against sites and domains that you own or have explicit permission to test. The default URL and domain are `example.com`; replace them with an authorized target before using this project operationally.
# Cyber-watch
