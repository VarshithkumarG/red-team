# SecureShop application security lab

SecureShop is a small local e-commerce application for the assignment's build → scan → investigate → fix → retest workflow. It has a catalogue, search, registration and login, product details, a session cart, profile and order history, plus an admin area for product management and user listing.

## Lab boundary

Run only on `http://127.0.0.1:5000` on your own computer. The app binds to loopback and rejects requests from non-loopback addresses. Use synthetic demo data only. Do not expose it through a tunnel, LAN bind, cloud host, or public URL. Do not scan anything except this local app. The intentionally vulnerable profile is for the isolated classroom lab; it is not suitable for deployment.

## Run the vulnerable profile

From this directory in PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:LAB_MODE = "vulnerable"
python app.py
```

Open `http://127.0.0.1:5000`. The database is created and seeded on first launch. Demo accounts:

| Role | Email | Password |
| --- | --- | --- |
| Customer | `alice@secureshop.test` | `alice123` |
| Customer | `jordan@secureshop.test` | `jordan123` |
| Admin | `admin@secureshop.test` | `admin123` |

### Admin account and controls

Use the local demo administrator account above to sign in through the normal **Log in** page. After signing in, open `http://127.0.0.1:5000/admin` (or use the Admin link in the navigation, when shown). The admin page lists the seeded users and products and provides a form to add a product with its name, category, description, price, and stock quantity. Admin routes require the `admin` role; a customer account should receive an access-denied response.

These credentials are fixed classroom demo credentials, not a private or production admin account. They work in both lab profiles. The vulnerable profile stores seeded passwords as plaintext to demonstrate the assignment weakness; secure mode rehashes the demo passwords at startup. Keep this service bound to localhost and never reuse these credentials elsewhere.

## Controlled weaknesses and expected evidence

| Category | Vulnerable behavior | Safe local demonstration |
| --- | --- | --- |
| A03 Injection | Search and login interpolate submitted text into SQLite queries. | Search with a quote to observe an error; compare ordinary versus crafted local search behavior. Do not use destructive statements. |
| A01 Broken access control | A signed-in customer can request another customer's profile/order identifiers. | Sign in as Alice and compare `/orders/1` and `/orders/2`; repeat in secure mode. |
| A05 Security misconfiguration | Vulnerable profile omits defensive response headers and marks the session cookie non-HttpOnly. | Inspect response headers and the `Set-Cookie` attributes in browser dev tools or ZAP. |
| A06 Outdated component | Vulnerable requirements pin Flask 2.2.2, released in 2022. | Capture installed version and compare against the current release/advisory references below. |

Injection payloads, if used for coursework, must stay non-destructive and on this seeded local database. No real exploit chain or production target is needed.

## Scan and record

Start the app first, then configure OWASP ZAP to use `http://127.0.0.1:5000` as the sole target. Record the scan date, ZAP version, scan type, alert counts/severity, affected paths, request/response evidence, and whether each alert is confirmed, false positive, or informational. ZAP findings should be manually reviewed. The app's own response includes `X-Lab-Mode` to help identify the active profile.

For a repeatable local scan, use ZAP 2.17.0's official portable Core package and Java 17 or newer. The downloaded package used for this assessment was SHA-256 verified against the official ZAP release page and is kept under the ignored `.labtools/` directory. Start ZAP in its own PowerShell window, bound to loopback:

```powershell
$env:ZAP_API_KEY = "choose-a-random-local-key"
$zap = (Join-Path (Get-Location).Path ".labtools\ZAP_2.17.0")
$java = "C:\Program Files\Eclipse Adoptium\jre-17.0.20.101-hotspot\bin\java.exe"
& $java -Xmx2g -jar "$zap\zap-2.17.0.jar" -daemon -host 127.0.0.1 -port 8090 `
  -config "api.key=$env:ZAP_API_KEY" `
  -config "api.addrs.addr.name=127.0.0.1" `
  -config "api.addrs.addr.regex=false"
```

In a second PowerShell window, set the same `ZAP_API_KEY` and run `python scripts\zap_scan.py vulnerable` while the app is in vulnerable mode. Run `python scripts\manual_validation.py vulnerable` for safe manual checks. After switching dependencies and application mode, repeat with `secure`. The scan helper refuses a scan if the app profile does not match the requested profile; it resets the ZAP session for each report and limits its active scan to the single product-search URL.

## Switch to the remediated profile

Stop the server. In the same virtual environment, install the remediated framework profile, then restart:

```powershell
python -m pip install -r requirements-secure.txt
$env:LAB_MODE = "secure"
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

Secure mode uses parameterized SQL, password hashing for new accounts, ownership checks, CSRF tokens on state-changing forms, hardened cookie attributes and response headers, and generic error output. The demo account passwords are safely rehashed on startup. Repeat the same ZAP crawl and manual checks against the same local URL, then compare evidence. Reset the lab database between experiments by stopping the server and deleting `secureshop.db`.

## Outdated dependency note

- Component: Flask
- Vulnerable lab pin: `2.2.2` (released 2022-08-08)
- Latest release checked on 2026-10-27: `3.1.3`
- Security reference: Flask advisory GHSA-m2qf-hxjv-5gpq / CVE-2023-30861. The vendor advisory describes session-cookie disclosure conditions and fixed releases; the old lab pin predates the fix. Dependency age itself also means missing later fixes and support.
- Fix used here: `requirements-secure.txt` pins Flask 3.1.3. Re-check the vendor advisory and package index when preparing the final submission, because releases can change.

The advisory requires a particular combination of permanent sessions, an eligible caching proxy, and other conditions. This local app does not enable permanent sessions or sit behind that kind of proxy, so document this as an affected dependency/version finding, not as proof that the CVE is exploitable in this specific lab configuration.

References: [Flask security advisories](https://github.com/pallets/flask/security/advisories), [Flask release history](https://pypi.org/project/Flask/), [Flask changes](https://flask.palletsprojects.com/en/stable/changes/).

## Important limitations

This is a teaching prototype, not a production store. The vulnerable profile deliberately has plaintext demo passwords and SQL injection. Even secure mode needs deployment-grade secret management, HTTPS, rate limiting, inventory/order workflows, payment handling, audit logging, and a reviewed production configuration before use outside the localhost lab.

## Assessment results

The completed before/after assessment is in `reports/assessment-report.md`. Raw ZAP findings and sanitized manual evidence are stored in `reports/`. The report records the scan scope, tool version, date, alert counts, affected paths, evidence, findings analysis, fixes, and retest results.

`reports/functional-secure.json` records a separate secure-profile walkthrough of registration, customer login/profile/orders/cart, admin authorization, user listing, and product management. The temporary QA account and product used for that walkthrough were removed afterward.
