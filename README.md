# Compass 1.0

Threat intelligence for investigators. Enter an IP, domain, URL or hash. Compass maps the infrastructure around it, checks what is live today, and asks every threat-intelligence provider you have configured for a verdict. It also analyses email headers and shows how a website looked over time.

## Starting Compass

**Unblock the zip before extracting.** Right-click the downloaded zip → **Properties** → tick **Unblock** → **OK**, then extract. This removes the "downloaded from the internet" mark that makes Smart App Control and SmartScreen treat files as untrusted, and it is the main reason one build runs while another is blocked. Do this first.

Then double-click **Compass.exe**. It starts in the background (no console window), opens in your browser, and puts a compass icon in the notification area (tray) with **Open Compass**, **Open log folder** and **Stop Compass**. Opening it again while it is already running just reopens the browser.

**If Smart App Control still blocks Compass.exe** on a machine, double-click **Install Compass.bat** instead. It creates a **Compass** icon on the Desktop and Start menu that starts Compass through Windows' own signed `pythonw.exe`, which Smart App Control never blocks. (There is no tray icon on this path; stop Compass by ending **pythonw.exe** in Task Manager.)

- Needs Windows 10/11 and Python 3.10 or newer from python.org (tick **Add python.exe to PATH** during install). Compass.exe finds Python on its own.
- The first run asks Windows Firewall about **Python**: allow it on **private** networks so other lab PCs can reach Compass.
- Messages and errors go to `data\compass.log`. For troubleshooting, `tools\Start Compass with console.bat` runs Compass with a visible console window.

### Code-signing Compass.exe (permanent fix, for IT)

Compass.exe is not code-signed, so Smart App Control can still block it on a fresh download even after unblocking. Signing it once with your organisation's trusted code-signing certificate makes it run everywhere with no block:

```
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a Compass.exe
```

The launcher's source and build command are in the `launcher` folder.

## Look and theme

The interface now follows the HeroUI design (heroui.com): soft layered cards, fully rounded buttons and chips, segmented pill tabs, bordered fields with a blue focus ring, and a blue accent. There is a **Light / Dark** switch in the sidebar. Until someone chooses, Compass follows the computer's own light or dark setting; the choice is remembered per browser. Status colours keep the same meaning in both themes (red failed or malicious, amber partial, blue checked and nothing found, green live or done, grey not checked). The sign-in page follows the same theme and has its own Light / Dark switch. Downloaded reports keep their light styling so they print cleanly.

## Upgrading from an earlier version

Stop Compass, replace the program files with this version, and keep your existing `data` folder (users, history and API keys carry over). Start it with **Compass.exe** (unblock the zip first), or **Install Compass.bat** if Smart App Control blocks the exe. No new Python packages are needed.

## Status colours

The same scheme is used on every page, and every colour comes with a word so it still reads on a projector, in print and in CSV exports:

| Colour | Meaning |
|---|---|
| Red | Failed, error or malicious |
| Amber | Partial: rate limited, no API key, wildcard DNS, or needs a second look |
| Blue | Checked, nothing found (for example an inactive subdomain or "no record") |
| Green | Live, done or consistent |
| Grey | Not checked |

## Email header analysis

Paste the headers (Gmail: Show original; Outlook: File › Properties › Internet headers) or upload an `.eml` file. Outlook `.msg` files must be saved as `.eml` first. The page shows only what an investigator needs:

- **Verdict:** Consistent, Inconsistent or Suspicious, with a one-line reason. Compass reports consistency, never "Genuine".
- **Findings:** only the problems (red) and things to check (amber), for example a Message-ID written by Gmail on mail claiming to be from a bank, a Reply-To that sends replies to another webmail account, a lookalike sender domain, or a leaked PC name.
- **Key details:** From, Reply-To and Return-Path (only when they differ), subject, sent time in IST and UTC, SPF / DKIM / DMARC, the originating IP (or why it is not available), and the Message-ID.
- **For your data request:** provider, account and exact time, with a copy button that includes the Message-ID.
- **Route the email took:** the Received chain, collapsed until you open it.

How Compass decides:
- SPF, DKIM and DMARC are trusted only when your own mail server recorded them. Results added by anyone else are marked *unverified*, because a sender can write them.
- A Message-ID from Gmail, Microsoft 365 or another provider is consistent when the From domain has authorised that provider (an aligned DKIM signature Compass verified, or an SPF or DMARC pass).
- With a full `.eml`, Compass verifies DKIM signatures itself. If the DNS lookup for the key fails, it says so instead of calling the signature invalid.
- Lookalike sender domains: names using look-alike characters, non-Latin letters or one wrong character are red. Names that only share the brand name (another ending, added words) are amber, because brands use such names too. Domains in `bank.in`, `gov.in`, `nic.in` and `mil.in` (registration restricted to verified organisations) and known sending services such as Amazon SES are never flagged.

Every analysis is saved to My history and can be downloaded as a report.

## Website history

The **Website history** tab on a domain or URL investigation lists dated Wayback Machine versions of the site: first and latest capture, days captured per year (click a year to filter), every capture where the content changed, page errors, and archived redirects with where they pointed (redirects to other sites are flagged). Snapshots open on web.archive.org, so the site itself is never contacted.

Compass was previously called Veyron (versions 4.x).

## Network use

- **First run:** the sign-in page asks you to create the administrator account.
- Other PCs on the LAN open `http://<server-ip>:8765` (the server's own IP, port 8765). Allow TCP 8765 through Windows Firewall on the server. Keep it on a trusted LAN/VLAN and never port-forward it to the Internet.

Environment variables (optional): `COMPASS_PORT` (default 8765), `COMPASS_HOST` (default 0.0.0.0; use 127.0.0.1 for single-PC use), `COMPASS_VT_PER_MIN` (VirusTotal requests per minute, default 4 for the free API; raise it if you have a premium key), `COMPASS_NO_BROWSER=1` (don't open a browser on start).

## Users and history

- Everyone signs in. There are two roles: **Administrator** (manages API keys and users) and **Analyst**.
- Every investigation and CVE search is saved to the signed-in user's **My history**. Users can see, open, report on and delete only their own records. Administrators cannot see other users' history either.
- Administrators add users one at a time or in bulk (paste a list of usernames, e.g. for a class of trainees). Compass generates a temporary password for each, shown once, with a CSV download. New users must choose their own password at first sign-in.
- Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions last 12 hours and use HttpOnly, SameSite=Strict cookies plus a CSRF token. Five failed sign-ins lock that username for five minutes.
- Deleting a user also deletes their history. Disabling a user signs them out immediately.

## Discovery (new in 5.0)

**Domain or URL.** Compass works out the registered domain using the bundled Public Suffix List, so `www.portal.example.co.in` is searched as `example.co.in`. It then queries these sources in parallel:

| Source | Needs a key | What it adds |
|---|---|---|
| crt.sh, CertSpotter | No | Subdomains from Certificate Transparency logs, and names that share a certificate |
| Wayback Machine | No | Hostnames from archived URLs |
| AlienVault OTX | Optional | Passive DNS: past subdomains and the IPs they used |
| HackerTarget | Optional | Subdomains with IPs (small free daily quota) |
| VirusTotal | Yes | Subdomains and passive-DNS history (counts against the free 4/min limit) |
| urlscan.io | Yes | Subdomains and IPs seen in scans |
| SecurityTrails | Yes (optional) | Large subdomain dataset |

Every name found is then checked against live DNS (DNS-over-HTTPS via Cloudflare/Google). Compass detects wildcard DNS and groups the linked IPs. Each IP is enriched with ASN, prefix and country (RIPEstat), open ports and known CVEs (Shodan InternetDB), VPN/proxy/datacenter flags (ipapi.is) and the Tor exit-node list. The results include:

- **Subdomains:** Live / Inactive (checked, no DNS record today) / Wildcard / Not checked, IPs, CNAME, which sources found them, first and last seen. Use the **Live only** or **Inactive only** checkbox to filter.
- **Linked IPs:** how each is linked (current A record, live subdomain, historical A record, mail server, name server, SPF sender), network, flags, open ports and CVEs.
- **Possible origin servers:** when a site sits behind a CDN such as Cloudflare, these are the non-CDN IPs linked to it.
- **Related domains:** names that share a TLS certificate or a dedicated IP, plus MX, SPF, DMARC and name servers.
- **Domain age:** from RDAP. Domains registered in the last 30 days are flagged.

**IP.** Compass lists the domains seen on the IP (VirusTotal, OTX, urlscan, HackerTarget, Shodan, reverse DNS) and re-checks which still resolve to it. It also shows the network, open ports, CVEs and anonymity flags, and warns when the IP is a CDN or shared host, where co-hosted domains are not evidence of a link.

Every table can be filtered and downloaded as CSV. Selecting any domain or IP starts an investigation of it, and selecting a CVE opens it on the CVE page.

### Passive and active mode

**Passive (default):** Compass never contacts the investigated host. It only queries third-party services. The certificate shown comes from CT logs.

**Active checks (toggle under the search box):** Compass also connects to the target to read its live TLS certificate and tries about 170 common subdomain names. The target can see the server's IP address, so use this only when that is acceptable.

## Data and API keys

- Data lives in the `data` folder: `compass.db` (users, sessions, history), `providers.json` (API keys) and `investigation_cache.json`.
- API keys are encrypted with Windows DPAPI under the Windows account that runs Compass, and are never sent to the browser. Keys saved on one PC or account cannot be decrypted on another, so re-enter them after moving Compass.
- Results are cached for 24 hours, shared between users to save API quota. Cached results say so and offer **Run again with live data**. The cache is not part of anyone's history.
- Free tiers have limits: VirusTotal allows 4 requests a minute and 500 a day, and HackerTarget and ipapi.is have small daily quotas. When a source is rate-limited, the Sources tab says so and the rest of the investigation continues.

## Security notes

- Reports and CSV exports are built in the browser. Raw provider payloads are never included.
- URLhaus malware URLs are shown defanged (`hxxp://evil[.]com`) and are not clickable.
- Pasted indicators may be defanged; Compass refangs `hxxp`, `[.]`, `(.)` and `[:]` automatically.
- CSV cells are protected against spreadsheet formula injection.
- Uploaded files are hashed (MD5) in the browser and never leave the PC.

## Change log

**1.0** - first release.
- IOC investigation (IP, domain, URL, hash) with subdomain discovery, linked IPs, website history and threat-intelligence verdicts.
- Email header analysis with Message-ID checks and built-in DKIM verification.
- CVE search with CISA KEV enrichment.
- Sign-in, user accounts and per-user history.
- HeroUI-style interface with Light / Dark theme.
