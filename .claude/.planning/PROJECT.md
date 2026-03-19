# CAISP Outreach Dashboard

## What This Is

A solo sales outreach dashboard for selling cybersecurity certifications (CAISP, CDP, CDE) to CISOs in banking and telecom companies across APAC. The tool handles the full outreach workflow: import leads from CSV, generate personalized cold email drafts, review and approve them, send via Gmail, and track each lead through the sales pipeline.

## Core Value

A CISO lead moves from import to reviewed draft email in one click — so outreach happens consistently without manual copy-pasting.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] User can import leads from a CSV file (name, company, title, email, region)
- [ ] User can view all leads in a pipeline board with stages: New → Contacted → Replied → Meeting → Closed
- [ ] User can generate cold email drafts personalized with CSV data (name, company, title)
- [ ] User can review and edit generated email drafts before sending
- [ ] User can send approved emails via Gmail (SMTP / Gmail API)
- [ ] User can manually move leads between pipeline stages
- [ ] User can see which leads have been contacted and track responses

### Out of Scope

- AI API (LLM) for email generation — using template + merge tags with CSV data instead
- Separate outreach tracks per certification — one unified pitch, qualification on the call
- Multi-user / team access — solo tool
- Automated follow-up sequences — manual control preferred
- CRM integrations (Salesforce, HubSpot) — standalone tool

## Context

- **Certifications being sold:** CAISP (Certified AI Security Professional), CDP, CDE
- **Target market:** CISOs in banking and telecom companies, APAC region
- **Outreach model:** One unified pitch covering all three certifications; qualification happens on discovery call
- **Email personalization:** Driven by CSV fields (name, company, title) — no external AI API needed
- **Gmail sending:** Via SMTP or Gmail API integration
- **Solo user:** No auth/multi-tenant requirements

## Constraints

- **Tech Stack**: Python/Flask backend — preference established
- **Email**: Gmail (SMTP or Gmail API) — must support personal and Google Workspace accounts
- **Deployment**: Local or simple single-server deployment — no enterprise infrastructure needed

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|------------|
| Python/Flask over Next.js | User preference and backend-first simplicity | — Pending |
| Template + merge tags over LLM API | Avoids API costs/latency, user controls message | — Pending |
| One cert pitch (not per-cert tracks) | Qualification happens on the call, reduces complexity | — Pending |
| Gmail for sending | User's existing email infrastructure | — Pending |

---
*Last updated: 2026-03-19 after initialization*
