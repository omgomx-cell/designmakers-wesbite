# Security changes (03-11-2026)

See the summary in chat. Quick reference:

| Area | What now happens |
|---|---|
| HTTPS | Production redirects all HTTP to HTTPS, rejects non-GET over HTTP, sends HSTS (1 year) + CSP with `upgrade-insecure-requests` |
| Sessions | HttpOnly + Secure + SameSite=Strict cookies (`__Host-` prefix on HTTPS). Admin/seller: 30 min idle, 12 h absolute. Customer: 24 h idle (`CUSTOMER_IDLE_MINUTES`), 30 d absolute |
| Logout / reset | Session deleted server-side; password change/reset/credential change/removal revokes sessions; every login gets a brand-new session ID |
| Secrets | Server refuses to start in production without JWT_SECRET, ADMIN1_PASSWORD (non-default), PII_ENCRYPTION_KEY |
| API | Same-origin check on all write calls, per-route rate limits, small body limits on public routes, sub-admin must still exist and be unlocked |
| Errors | Stack traces / raw error text never reach users; clean 404 for unknown pages |
| Files | Only images/fonts are served from disk (no source, .md, package files, demo pages) |
| Dependencies | `npm audit` = 0 vulnerabilities; admin CDN scripts pinned with SRI hashes |
| Sellers | Initial seller password is random (was shop-name + Aadhaar last 4); unsent passwords encrypted at rest; removed hard-coded demo seller |

## Permission review (sub-admins + sellers)

| Finding | Fix |
|---|---|
| Sub-admin "designation" was only a label - any sub-admin could use every admin API | Designation now enforced on the server (ADMIN_AREAS in server.js). No designation = old behaviour (compat). Emergency off-switch: ADMIN_AREA_ENFORCEMENT=off |
| Any sub-admin could delete customers and reset customer passwords (account takeover) | Boss only |
| Any sub-admin could change the site theme | Boss only |
| Seller list showed full Aadhaar / PAN / bank / DOB / UPI to every sub-admin (bypassing the export OTP) | Sub-admins see masked values; boss sees full |
| Seller order view returned the whole order (customer ID, totals incl. other sellers, status log, takeover history) | Explicit allow-list: delivery details + the seller's own lines only |
| Seller could set hotProduct / buyBadgePercent on own products | Ignored; admin-only |
| Seller could accept/decline an order already shipped or cancelled | Blocked |
| Mark-paid had no audit trail | paymentMarkedBy / paymentMarkedAt recorded |
