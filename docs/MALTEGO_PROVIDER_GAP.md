# Maltego Data Providers vs. Ghost Identity Hunter (gih) — Provider Gap Report

**Author:** Dhayanidhi Rajasekaran
**Date:** 2026-08-02
**Scope:** Which data providers Maltego integrates, which of those gih can reach today, and which are absent.

## Sources

| Source | URL |
| --- | --- |
| Maltego Transform Hub (provider catalogue) | https://www.maltego.com/transform-hub/ |
| Maltego Data Hub solutions folder | https://support.maltego.com/en/support/solutions/folders/15000009687 |
| Data Pass and connectors | https://docs.maltego.com/en/support/solutions/articles/15000058711-data-pass-and-connectors-for-maltego |
| Maltego products / editions | https://www.maltego.com/products/ |
| gih repo | `README.md`, `src/plugins/builtins/`, `src/modules/`, `src/utils/tool_checker.py`, `docs/TOOL_COVERAGE.md`, `docs/EXTERNAL_TOOLS.md` |

**Completeness note:** the 99 provider integrations listed below are the full set rendered by the public Transform Hub catalogue at the time of writing. Maltego separately markets "120+ Data Providers" and "100+ pre-built connectors" (Data Pass), so the real catalogue is larger than 99 — enterprise/on-request providers and connectors are not all published on that page. Treat the named list as authoritative-but-not-exhaustive.

---

## 1. Headline gap

| | Maltego | gih |
| --- | --- | --- |
| Named commercial/OSINT provider integrations | 99 published (120+ claimed) | 4 keyed API providers |
| Local CLI OSINT tools orchestrated | none (everything is a Transform) | 22 plugins over ~36 known tools |
| Provider model | paid marketplace + bring-your-own-key | bring-your-own-key + local tooling only |
| Provider categories covered | 16 | 6 fully, 3 partially, 7 absent |

gih's four keyed providers: **Shodan**, **Have I Been Pwned**, **LeakOSINT**, **Etherscan** (declared in `tool_checker.py`, no plugin yet). Everything else gih does comes from local binaries (Sherlock, Maigret, Holehe, theHarvester, Subfinder, Amass, whois, dig, WhatWeb, Nmap, ExifTool) or built-in modules (phone, email, username, image, dorks, Wayback).

---

## 2. Category-by-category coverage

Legend: **Covered** = gih reaches equivalent data · **Partial** = weaker/free-tier substitute · **Absent** = no path today.

### 2.1 Breaches & Leaks — **Covered (narrow)**
Maltego: SpyCloud Cybercrime Investigations, Constella Intelligence, Have I Been Pwned?, Darkside, Hades, Vysion, Flashpoint, Digital Shadows, Silobreaker, Cybersixgill, ZeroFOX, Cofense Intelligence, Recorded Future.
gih: HIBP (`email_breach_plugin`) + LeakOSINT (`leakosint_plugin`).
Gap: gih gets breach *records* (LeakOSINT) and breach *names* (HIBP). It has no cracked-credential enrichment (SpyCloud), no identity-exposure graph (Constella), no takedown/brand monitoring (ZeroFOX).

### 2.2 Personal Identifiers / People Search — **Partial**
Maltego: Pipl, FullContact, PeopleMon, PhoneSearch, Epieos, OSINT Industries, hunter, Google Social Network Transforms, Google Maps Geocoding, LoginsoftOSINT, Clearbit, LittleSis, FlightAware.
gih: `phone_validation_plugin` (libphonenumber-class validation), email modules, full-name seeds, Google Dorks.
Gap: no paid identity-resolution dataset. Maltego resolves a name to addresses/relatives/phones; gih can only pivot on what free tools return. Highest-value cheap additions: **Hunter.io** (email discovery/verification, free tier), **Epieos** (reverse email → accounts), **OSINT Industries**.

### 2.3 Social Media — **Covered (different mechanism)**
Maltego: Social Links Professional/CE, Espy, Web-IQ, OSINT Industries, Pipl, Tisane Labs, ZeroFOX, PeopleMon, Corvus Intelligence (Telegram).
gih: Sherlock, Maigret, OSRFramework/usufy, built-in username search — 400+ site enumeration.
Gap: gih finds *account existence*; Maltego's partners return *account content* (posts, connections, messengers, Telegram groups). No Telegram/messenger capability in gih at all.

### 2.4 Infrastructure & Network — **Partial**
Maltego: Censys, Shodan, DomainTools Iris/Enterprise, Farsight DNSDB, WhoisXML API, IPInfo, MaxMind, Host.io, PeeringDB, alphaMountain, HYAS Insight, ZETAlytics, GreyNoise, SSL Certificate Transparency, DNSTwist, CrowdSec, urlscan.io, Spamhaus, Criminal IP, Team Cymru.
gih: Shodan plugin, whois, dig, Subfinder, Sublist3r, Amass, WhatWeb, Nmap.
Gap: no passive DNS history (DNSDB/ZETAlytics), no WHOIS history or registrant pivoting (DomainTools), no IP geolocation/ASN enrichment (IPInfo/MaxMind), no certificate-transparency search, no IP reputation (GreyNoise/AbuseIPDB/Spamhaus). **crt.sh, IPInfo, GreyNoise Community, AbuseIPDB and urlscan.io are all free-tier and would close most of this cheaply.**

### 2.5 Web & Image Content — **Partial**
Maltego: TinEye, Image Analyzer, Wayback Machine, GeoSpy, DeepL, Regex Library, Social Links, Tisane Labs.
gih: ExifTool, image hashing, reverse-search *link generation*, Wayback plugin.
Gap: gih generates a TinEye/Google Images URL for the analyst to click; it does not query a reverse-image API, do face/object detection, or geolocate imagery.

### 2.6 Malware / Sandbox — **Absent**
Maltego: VirusTotal (Public + Premium), Hybrid Analysis, Intezer Analyze, PolySwarm, Cisco Threat Grid, CrowdStrike ThreatGraph/Intel, Mandiant, Abuse.ch URLhaus, ThreatCrowd, ThreatMiner, ThreatConnect, OpenCTI, Anomali, Intel 471, Recorded Future.
gih: nothing. No file-hash entity, no sample submission, no IOC enrichment.
Note: **VirusTotal Public API** and **URLhaus** are free and would be the single most recognisable addition — but they only pay off if gih adds a `file_hash` artifact type first.

### 2.7 Vulnerabilities / CVE — **Absent**
Maltego: NIST NVD, Vulners, Censys, GreyNoise Enterprise, Elemendar, ThreatMiner, Team Cymru.
gih: Nmap service/version output only; no CVE mapping.
**NIST NVD is free and unauthenticated** — mapping Nmap banners to CVEs is a self-contained addition.

### 2.8 Deep & Dark Web — **Absent**
Maltego: DarkOwl, Flashpoint, Cybersixgill, Vysion, Silobreaker, Digital Shadows, Intel 471, Darkside, Hades, Social Links, DeepL.
gih: nothing (LeakOSINT is leaked-DB data, not darknet crawl). All of these are paid, contract-gated datasets — realistically not closable.

### 2.9 Company / Corporate Data — **Absent**
Maltego: OpenCorporates, Orbis – Bureau Van Dijk, OCCRP Aleph, OpenSanctions, EntitiesUA, Clearbit, LittleSis, Tisane Labs, Social Links CE.
gih: nothing — no company/organisation entity exists in the model.
**OpenSanctions, OpenCorporates and OCCRP Aleph all have free/open APIs**; the blocker is gih's entity model, not access.

### 2.10 Cryptocurrency — **Absent (declared, unimplemented)**
Maltego: Etherscan, Tatum Blockchain Explorer, Crystal Intelligence, OpenSanctions, Cybersixgill, Vysion.
gih: `etherscan` appears in `src/utils/tool_checker.py` but has no plugin and no wallet artifact type.

### 2.11 Phishing — **Absent**
Maltego: Scamadviser, AbuseIPDB, Abuse.ch URLhaus, Cofense Intelligence, Shodan.
gih: nothing.

### 2.12 Endpoint & Security Events — **Absent / out of scope**
Maltego: CrowdStrike ThreatGraph. Requires an EDR tenant; not relevant to gih's OSINT posture.

### 2.13 Case management & interop — **Absent**
Maltego: Polonious (case system), STIX 2 Utilities, OpenCTI, ATT&CK–MISP, Data Pass connectors (bring-your-own SQL/CSV/API), Discogs/The Movie Database (long-tail).
gih: SQLite + optional Neo4j, its own JSON. No STIX/MISP export, no third-party case-system push.

---

## 3. What gih has that Maltego providers do not supply

Not a gap, but the counterweight: local CLI orchestration (Sherlock/Maigret/Holehe/theHarvester/Amass in one BFS run), automatic identity correlation and confidence scoring, risk assessment, redaction, cross-investigation correlation, delta reports, and four report templates. Maltego has no equivalent of "run everything and hand me a scored report" — its providers return data, the analyst does the resolution.

---

## 4. Recommended additions, ordered by cost-to-value

| # | Provider | Category | Cost | Why | Prereq |
| --- | --- | --- | --- | --- | --- |
| 1 | crt.sh / Certificate Transparency | Infrastructure | Free, no key | Subdomains + issuance history; pure HTTP | none |
| 2 | IPInfo (or MaxMind GeoLite2) | Infrastructure | Free tier | Every `ip` artifact gains geo/ASN/VPN context | none |
| 3 | NIST NVD | Vulnerabilities | Free, no key | Turns Nmap banners into CVEs; opens a whole absent category | `cve` artifact |
| 4 | VirusTotal Public API | Malware | Free key | Most recognised gap; domain/IP verdicts immediately | `file_hash` artifact |
| 5 | Hunter.io | Personal identifier | Free tier | Real email discovery/verification per domain | none |
| 6 | AbuseIPDB + Abuse.ch URLhaus | Phishing / reputation | Free key / free | Cheap reputation and malicious-URL signal | none |
| 7 | urlscan.io | Infrastructure / web | Free tier | Live page capture — also feeds the missing evidence-preservation feature | none |
| 8 | OpenSanctions | Company / sanctions | Free | Sanctions hits on names and wallets; high investigative value | `organisation` entity |
| 9 | Epieos or OSINT Industries | Personal identifier | Paid | Closest single substitute for Maltego's people-search partners | none |
| 10 | Etherscan | Cryptocurrency | Free key | Already declared in `tool_checker.py`; finish it | `wallet` artifact |
| 11 | STIX 2 / MISP export | Interop | Free | Makes gih output consumable by CTI platforms | none |

Structurally unreachable without commercial contracts: SpyCloud, Constella, DomainTools, Farsight, Recorded Future, Flashpoint, Cybersixgill, DarkOwl, Intel 471, Mandiant, CrowdStrike, Pipl, Social Links, Orbis, HYAS, Silobreaker, Digital Shadows, ZeroFOX.

Two model changes unlock most of the list above: adding **`file_hash`/`cve`** artifact types and an **`organisation`** entity. Without them, several free providers have nowhere to attach their results.

---

## Appendix — full published Maltego Transform Hub catalogue (99 items)

Abuse.ch URLhaus · AbuseIPDB · AlienVault OTX · alphaMountain · Anomali · ATT&CK–MISP · Censys · Cisco Threat Grid · Clearbit · Cofense Intelligence · Constella Intelligence · Corvus Intelligence · Criminal IP · CrowdSec · CrowdStrike Intel · CrowdStrike ThreatGraph · Crowlingo · Crystal Intelligence · Cybersixgill · Darkside · DarkOwl · DeepL · Digital Shadows · Discogs · DNSTwist · DomainTools Enterprise · DomainTools Iris Investigate · Dorking · Elemendar · EntitiesUA · Epieos · Espy · Etherscan · Farsight DNSDB · Flashpoint · FlightAware · FullContact · GeoSpy · Google Maps Geocoding · Google Social Network Transforms · GreyNoise Community · GreyNoise Enterprise · Hades · Have I Been Pwned? · Host.io · hunter · HYAS Insight · Hybrid Analysis · Image Analyzer · Intel 471 · Intezer Analyze · IPInfo · LittleSis · LoginsoftOSINT · Mandiant · MaxMind · NIST NVD · OCCRP Aleph · OpenCorporates · OpenCTI · OpenSanctions · Orbis – Bureau Van Dijk · OSINT Industries · PeeringDB · PeopleMon · PhoneSearch · Pipl · Polonious · PolySwarm · Recorded Future · Regex Library · Scamadviser · Shodan · Silobreaker · Social Links CE · Social Links Professional · SOCRadar · Spamhaus Intelligence · SpyCloud Cybercrime Investigations · SSL Certificate Transparency Transforms · STIX 2 Utilities · Tatum Blockchain Explorer · Team Cymru · The Movie Database · ThreatConnect · ThreatCrowd · ThreatMiner · TinEye · Tisane Labs · urlscan.io · VirusTotal Premium API · VirusTotal Public API · Vulners · Vysion · Wayback Machine · Web-IQ · WhoisXML API · ZETAlytics Massive Passive · ZeroFOX
