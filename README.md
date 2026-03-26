
# Entra ID Login Monitoring & Attack Visualization

In this project, I implemented and configured **Microsoft Entra ID (Azure AD)** for Pursue SEO Marketing and built a real-time login monitoring solution integrated with **Microsoft Sentinel** to visualize global sign-in activity — including geographic attack sources — via an interactive heat map workbook.

**Inception State:** The organization had no identity governance, no centralized authentication monitoring, and no visibility into failed sign-in attempts or brute-force activity against corporate accounts.

**Completion State:** Entra ID deployed with Conditional Access policies, MFA enforcement, and a Sentinel workbook providing real-time geolocation mapping of all sign-in events across the environment.

---

<img width="2752" height="1536" alt="Brute Force Bear" src="https://github.com/user-attachments/assets/c48416b8-07b3-4f13-8c29-1588dd6dd823" />



---

## Technology Utilized

- **Microsoft Entra ID** (Azure Active Directory) — Identity provider & Conditional Access
- **Microsoft Sentinel** — SIEM / SOAR for sign-in log ingestion and workbook visualization
- **Microsoft Defender for Cloud Apps** — Session policy enforcement
- **Log Analytics Workspace** — Backend data store for KQL queries
- **KQL (Kusto Query Language)** — Custom sign-in log analysis queries

---

## Table of Contents

- [Project Overview & Objectives](#project-overview--objectives)
- [Entra ID Setup & MFA Enforcement](#step-1-entra-id-setup--mfa-enforcement)
- [Connecting Sign-In Logs to Sentinel](#step-2-connecting-sign-in-logs-to-sentinel)
- [KQL Query Development](#step-3-kql-query-development)
- [Sentinel Workbook — Heat Map Configuration](#step-4-sentinel-workbook--heat-map-configuration)
- [Findings — Successful Logins (USA)](#step-5-findings--successful-logins-usa)
- [Findings — Failed & Blocked Attempts (Global)](#step-6-findings--failed--blocked-attempts-global)
- [Conditional Access Policy Response](#step-7-conditional-access-policy-response)
- [Incident Summary & Metrics](#incident-summary--metrics)
- [Ongoing Monitoring](#ongoing-monitoring)

---

## Project Overview & Objectives

After deploying **Microsoft Entra ID** as the organization's identity provider, I identified a need to monitor authentication events for anomalous activity. The primary objectives were:

1. Gain full visibility into sign-in events across all Entra ID–protected resources
2. Detect and visualize failed login attempts by geographic origin
3. Enforce Conditional Access policies to block high-risk sign-ins automatically
4. Build an executive-facing Sentinel workbook to communicate threat activity clearly

The resulting heat map dashboard enabled rapid identification of ongoing credential-spraying and brute-force campaigns originating from multiple countries.

---

## Step 1) Entra ID Setup & MFA Enforcement

Entra ID was configured as the central identity provider for Pursue SEO Marketing. Key configurations included:

- **MFA enforcement** via Conditional Access for all users
- **Named Locations** defined (USA trusted network ranges)
- **Sign-in risk policies** set to block Medium/High risk sign-ins
- **Legacy authentication protocols blocked** (SMTP, IMAP, POP3) to prevent bypass of MFA

> Blocking legacy protocols eliminated a significant attack surface — many credential spray campaigns specifically target these older endpoints because they cannot process MFA challenges.

---

## Step 2) Connecting Sign-In Logs to Sentinel

Entra ID **Diagnostic Settings** were configured to export the following log categories to the Log Analytics Workspace connected to Microsoft Sentinel:

| Log Category | Purpose |
|---|---|
| `SigninLogs` | Interactive user sign-in events |
| `NonInteractiveUserSigninLogs` | Service-to-service and token refresh activity |
| `AuditLogs` | Identity configuration changes |
| `RiskyUsers` | Identity Protection risk detections |

Once connected, logs began populating the workspace within minutes, enabling KQL-based queries and workbook visualizations.

---

## Step 3) KQL Query Development

The following KQL query forms the backbone of the heat map workbook. It extracts geolocation metadata from sign-in logs and projects the data points used to render the global map:

```kql
SigninLogs
| where TimeGenerated >= ago(30d)
| extend lat = toreal(LocationDetails["geoCoordinates"]["latitude"])
| extend lon = toreal(LocationDetails["geoCoordinates"]["longitude"])
| extend City    = tostring(LocationDetails["city"])
| extend Country = tostring(LocationDetails["countryOrRegion"])
| extend ResultLabel = iff(ResultType == 0, "Success", "Failure")
| project Identity, lat, lon, City, Country, ResultType, ResultLabel, IPAddress
| summarize LoginCount = count() by Identity, lat, lon, City, Country, ResultLabel
```

Additional queries were developed for:

- **Top attacking IPs** — `SigninLogs | where ResultType != 0 | summarize count() by IPAddress | top 20 by count_`
- **Failure reason breakdown** — grouping by `ResultDescription` to distinguish invalid passwords vs. MFA blocks vs. Conditional Access blocks
- **Time-series attack spikes** — `bin(TimeGenerated, 1h)` to identify coordinated burst patterns

---

## Step 4) Sentinel Workbook — Heat Map Configuration

A custom **Azure Monitor Workbook** was built in Microsoft Sentinel using the **Map** visualization type. Configuration highlights:

- **Latitude/Longitude** fields mapped from extracted `geoCoordinates`
- **Color by:** `ResultLabel` — green for Success, red for Failure
- **Bubble size:** Proportional to `LoginCount` (attack volume visible at a glance)
- **Time range selector:** 24h / 7d / 30d toggle
- **Metric label:** Country + LoginCount displayed on hover

<img width="3440" height="1440" alt="Sentinel Workbook" src="https://github.com/user-attachments/assets/40146b61-b166-4ab9-8b46-69deb46f1632" />




The workbook was pinned to the Sentinel dashboard and shared with leadership for ongoing visibility.

---

## Step 5) Findings — Successful Logins (USA)

Over the 30-day monitoring window, **40 successful authentication events** were recorded. All originated from verified U.S.-based IP addresses belonging to known employees.

| Metric | Value |
|---|---|
| Total Successful Logins | 40 |
| Countries of Origin | 1 (United States) |
| MFA Passed Rate | 100% |
| Conditional Access — Compliant | 40 / 40 |
| Flagged for Review | 0 |

Sample verified login locations included Phoenix AZ, Los Angeles CA, New York NY, Dallas TX, Chicago IL, Seattle WA, and Miami FL — consistent with employee home and office locations.

---

## Step 6) Findings — Failed & Blocked Attempts (Global)

The monitoring period revealed **1,207 failed sign-in attempts** from 18 flagged countries. The heat map made it immediately clear that the organization was the target of ongoing, distributed credential-spraying campaigns.

### Top Attack Sources

| Country | Attempts | Primary City | Likely Threat Actor Type |
|---|---|---|---|
| 🇷🇺 Russia | 487 | Moscow / St. Petersburg | APT / Criminal ransomware groups |
| 🇨🇳 China | 318 | Beijing / Shanghai | State-sponsored / espionage |
| 🇹🇭 Thailand | 142 | Bangkok | Proxy / botnet infrastructure |
| 🇮🇷 Iran | 98 | Tehran | State-sponsored / hacktivism |
| 🇧🇴 Bolivia | 71 | La Paz | Proxy / VPN exit nodes |
| 🇰🇵 North Korea | 54 | Pyongyang | State-sponsored / financial theft |
| 🇧🇷 Brazil | 37 | São Paulo | Criminal botnet activity |

> **Note on Bolivia and Thailand:** While these countries are listed as attack sources, the actual threat actors are unlikely to be physically located there. Attackers routinely route through proxy infrastructure, compromised residential IPs, and VPN exit nodes in countries with limited cyber law enforcement cooperation to obfuscate their true origin.

### Failure Reason Breakdown

| Failure Type | Count |
|---|---|
| Invalid Password | 634 |
| MFA Challenge Blocked | 312 |
| Conditional Access Block | 198 |
| Unknown / Non-existent User | 63 |

The high MFA block count confirms that **MFA enforcement was actively stopping otherwise valid stolen credentials** from being used — a key indicator that credential lists from data breaches were being tested against the environment.

![Failure Breakdown](images/failure-breakdown.png)

---

## Step 7) Conditional Access Policy Response

Based on the sign-in findings, I implemented additional **Conditional Access policies** to harden the environment:

**Policy 1 — Block Sign-Ins from High-Risk Countries**
- Conditions: Location = Named Locations (Blocked Countries list)
- Grant: Block access
- Applied to: All users, All cloud apps

**Policy 2 — Require MFA for All External Sign-Ins**
- Conditions: Location = Any location excluding trusted named locations
- Grant: Require MFA
- Applied to: All users, All cloud apps

**Policy 3 — Block Legacy Authentication**
- Conditions: Client apps = Exchange ActiveSync + Other clients
- Grant: Block access
- Applied to: All users

These policies reduced the volume of authentication attempts reaching the MFA challenge stage by approximately **40%** in the subsequent monitoring period, as Conditional Access blocks fire before credentials are even evaluated.

---

## Incident Summary & Metrics

| Metric | Value |
|---|---|
| Total Sign-In Events (30 days) | 1,247 |
| Successful Logins | 40 |
| Failed / Blocked Attempts | 1,207 |
| Countries Flagged | 18 |
| MFA Challenges Issued | 892 |
| Conditional Access Blocks | 198 |
| Accounts at Risk (Identity Protection) | 0 confirmed |
| Credential Spray Campaigns Identified | 3 distinct patterns |

No employee accounts were successfully compromised during the monitoring window. The combination of MFA enforcement, Conditional Access geo-blocking, and legacy protocol blocking provided effective layered defense.

---

## Ongoing Monitoring

The Sentinel workbook and underlying KQL queries remain active. Ongoing monitoring activities include:

- **Daily review** of Identity Protection risky sign-ins and flagged users
- **Weekly KQL queries** to identify new attack source countries or IP ranges
- **Watchlist updates** in Sentinel for known malicious IP ranges (MSTIC feeds)
- **Alert rules** triggering on failed login spikes exceeding threshold (>50 attempts/hour from single IP)
- **Quarterly Conditional Access policy review** to assess new named locations and policy effectiveness

---

*Part of an ongoing Microsoft Security Stack implementation at Pursue SEO Marketing. See also: [Vulnerability Management Program](https://github.com/JoshuaBleechington/Vulnerability-management-program)*
