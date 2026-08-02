# Burp Session Relay

Current release: **v1.0**

A Burp Suite extension (Montoya API) that lets a penetration testing team share session tokens across multiple Burp instances over the LAN — plus a built-in **Session Manager** that auto-refreshes expired tokens during active scans.

When a team shares a single user account on a target application, keeping everyone authenticated is a pain. This extension solves that with a **Leader / Follower** model — one person maintains the session, everyone else stays in sync automatically.

## How It Works

```
┌─────────────────────┐         LAN          ┌─────────────────────┐
│   Leader's Burp     │◄────────────────────► │  Follower's Burp    │
│                     │    GET /tokens        │                     │
│  - Browses target   │    (every 5s)         │  - Auto-injects     │
│  - Captures tokens  │                       │    tokens into      │
│  - Runs HTTP server │                       │    outgoing requests │
│    on port 8888     │                       │                     │
└─────────────────────┘                       └─────────────────────┘
                                              ┌─────────────────────┐
                                              │  Follower's Burp    │
                                              │  (any number)       │
                                              └─────────────────────┘
```

### Leader (one person)
- Logs into the target application and maintains the active session
- The extension automatically captures cookies, JWTs, and CSRF tokens from proxied traffic
- Runs an embedded HTTP server that followers connect to over the LAN
- Also auto-injects the latest tokens into its own requests

### Followers (everyone else)
- Poll the leader's server at a configurable interval (default: 5 seconds)
- Auto-inject fetched tokens (cookies, JWT, CSRF, custom headers) into every outgoing request matching the target scope
- On 401/403 responses, immediately re-fetch tokens from the leader

## SOCKS5 Traffic Relay (share a VPN route)

Token sharing keeps everyone authenticated, but it doesn't get anyone's packets onto a VPN-only target network — that's a routing problem, not a session problem. If only the leader holds a VPN seat, the leader can also expose a **SOCKS5 relay** so followers' own Burp traffic egresses through the leader's machine (and therefore through its VPN route).

### How it works

- The leader checks **Enable** under **SOCKS5 Relay** in the Leader Configuration panel and sets a port (default: `1080`), then clicks **Start Server** (this starts the token server and the SOCKS relay together).
- The relay is a minimal SOCKS5 server (RFC 1928, `CONNECT` only) gated with username/password auth (RFC 1929) using the same **Password** field as the token server. Domain names are resolved on the leader's machine (remote DNS), which is what makes split-DNS VPNs work correctly.
- For domain-selective routing, the follower starts its local routing service and points Burp's SOCKS setting to `127.0.0.1`. The follower sends matching Target Scope domains through the leader and connects to other destinations directly.

### What it does *not* do

- A phone must use the follower's Burp listener as its HTTP/HTTPS proxy. The extension does not provide transparent OS-level routing or NAT for traffic that bypasses Burp.
- The relay only permits destinations matching the configured Target Scope. It still carries sensitive traffic and credentials, so use it only on a trusted LAN and keep the password private.

## Phone → Follower → Leader Domain Routing

The follower includes a loopback-only selective SOCKS proxy. This supports the following flow while keeping interception on the follower:

```
Phone → follower Burp proxy → 127.0.0.1 selective SOCKS → leader SOCKS/VPN → target
Phone ← follower Burp proxy ← 127.0.0.1 selective SOCKS ← leader SOCKS/VPN ← target
```

Only hosts in **Target Scope** are forwarded through the leader. Other hosts connect directly from the follower. Target Scope accepts comma-separated domains and wildcards, for example:

```
example.com, *.internal.example.com, login.partner.test
```

Use **+ Add Domain** to append targets. Use **Route All (*)** on both leader and follower to route every domain through the leader; this also broadens token injection to every hostname, so enable it only intentionally.

Setup:

1. On the leader, enable **SOCKS5 Relay**, choose its port, enter a non-empty password and Target Scope, then start the server.
2. On the follower, enter Leader IP, the same password and Target Scope. Set **Leader SOCKS port** to the leader's relay port and choose a free **Local port** (default `1081`).
3. Click **Start Domain Routing**.
4. In the follower's Burp network settings, set the SOCKS proxy to `127.0.0.1:1081`, select SOCKS5, leave authentication empty, and enable DNS resolution through SOCKS.
5. Configure the phone to use the follower laptop's Burp listener as its HTTP/HTTPS proxy as usual.

DNS-over-SOCKS is required because domain-selective routing needs the original hostname. If Burp resolves a hostname to an IP before SOCKS, the extension cannot safely determine which configured domain it belongs to and the leader will reject it.

## Session Manager (Auto-Refresh)

The Session Manager keeps your session alive automatically — **no Leader/Follower server required**. It works as a standalone feature for solo pentesters or alongside the team sharing features.

### How it works

You configure a **login macro** (the HTTP request that authenticates you). The extension then:

1. **JWT Expiry Pre-check** — Before every outgoing request, decodes the JWT's `exp` claim. If it expires within the buffer window (default: 30 seconds), the login macro fires automatically *before* the request goes out. This prevents 401s proactively.

2. **401/403 Auto-refresh** — If any in-scope response comes back 401 or 403, the login macro fires on a background thread. All subsequent requests get the fresh tokens.

3. **Token capture from login response** — After the login macro runs, the extension extracts new cookies, JWTs (from headers, Set-Cookie, and response body), and CSRF tokens automatically.

### Why this matters for active scanning

Without the Session Manager, a long active scan can lose its session mid-scan — every request after expiry gets 401, making the scan results useless. With it:

- Active scan request about to go out → pre-check catches expired JWT → login macro runs → fresh token injected → request succeeds
- If a 401 slips through, the response handler refreshes for all following requests
- Rate-limited to one refresh per 5 seconds (prevents flooding the login endpoint)

### Session Manager Setup

1. Set the **Target Scope** in the Leader or Follower config (the Session Manager uses the same scope)
2. Scroll down to the **Session Manager** panel (always visible at the bottom)
3. Enter the **Login URL** (e.g., `https://target.com/api/login`)
4. Set the **Method** (POST/GET/PUT) and **Content-Type**
5. Enter the **Body** (e.g., `username=admin&password=pass123` or `{"user":"admin","pass":"secret"}`)
6. Optionally add **Extra Headers** (one per line, `Name: Value` format)
7. Click **Test Login Macro** to verify it works (shows success/failure dialog)
8. Check **Enable Session Manager**
9. The live status shows JWT expiry countdown, refresh count, and last refresh result

### Tab Layout

The Session Manager panel sits at the **bottom half** of the Burp Session Relay tab, below the Leader/Follower cards. Drag the divider to resize.

```
┌─────────────────────────────────────────────────────────┐
│  Role (Token Sharing)                                   │
│  ○ Leader  ○ Follower                                   │
│  [Leader/Follower config fields + token display]        │
│                                                         │
├═══════════════════ draggable divider ═══════════════════─┤
│                                                         │
│  Session Manager — Auto-Refresh                         │
│  [✓] Enable Session Manager       Refresh [30] sec      │
│                                                         │
│  Login URL:      [https://target.com/api/login        ] │
│  Method: [POST ▼]   Content-Type: [application/json   ] │
│  Body:           [{"user":"admin","pass":"secret"}     ] │
│  Extra Headers:  [X-Custom-Header: value              ] │
│                                                         │
│  [Test Login Macro]  [Refresh Now]                      │
│  JWT: Expires in 285s | Refreshes: 3                    │
└─────────────────────────────────────────────────────────┘
```

### Example: Form-based login (POST with URL-encoded body)

```
Login URL:      https://academy.hackthebox.com/api/v1/login
Method:         POST
Content-Type:   application/x-www-form-urlencoded
Body:           email=user@test.com&password=MyPassword123
Extra Headers:  (leave empty)
```

### Example: JSON API login

```
Login URL:      https://api.target.com/auth/login
Method:         POST
Content-Type:   application/json
Body:           {"username":"admin","password":"P@ssw0rd!"}
Extra Headers:  X-Requested-With: XMLHttpRequest
```

### Example: Login with CSRF token

```
Login URL:      https://target.com/login
Method:         POST
Content-Type:   application/x-www-form-urlencoded
Body:           username=admin&password=secret&_token=abc123
Extra Headers:  X-CSRF-Token: abc123
                Referer: https://target.com/login
```

### UI Features

| Feature | Description |
|---------|-------------|
| **Enable checkbox** | Validates that Login URL and Target Scope are set before enabling |
| **Test Login Macro** | Sends the login request once without enabling auto-refresh — shows result dialog |
| **Refresh Now** | Force an immediate session refresh |
| **JWT countdown** | Live display: "Expires in 285s" with color coding (green > 60s, orange < 60s, red = expired) |
| **Refresh counter** | Tracks total number of auto-refreshes performed |
| **Expiry buffer** | Configurable seconds before expiry to trigger refresh (default: 30) |

## What Gets Shared

| Token Type | How It's Captured | How It's Injected |
|------------|-------------------|-------------------|
| **Cookies** | `Set-Cookie` headers from responses | `Cookie` header on requests |
| **JWT** | `Authorization: Bearer` headers, JWTs in cookie values | `Authorization: Bearer <jwt>` header |
| **CSRF** | Configured header name, meta tags in HTML | Configured header on requests |
| **Custom Headers** | User-defined header names (via `[+]` button) | Matching headers on requests |

Some apps bind two of these together (e.g. a session cookie plus a device/session-binding header, or a nonce tied to a specific cookie) — if the pair ever gets split across two different points in time, requests fail even though each field individually looks valid. Capture and injection both read/write every field as a single atomic snapshot (one lock acquisition), so a request is never built from a mix of a fresh field and a stale one.

## JWT Scanner

The extension includes a passive JWT security check (read-only traffic analysis — it never sends forged requests).

| Finding | What it detects | Severity |
|---------|----------------|----------|
| **Algorithm "none"** | JWT header has `"alg": "none"` — no signature | High |
| **Missing expiry** | JWT payload has no `exp` claim — token never expires | Medium |
| **Expired token accepted** | Expired JWT sent in request AND server responded 2xx (confirmed acceptance) | High |
| **Sensitive data in payload** | JWT payload contains fields like `password`, `ssn`, `credit_card` | High |
| **HS256 usage** | JWT uses HS256 — informational flag to remind tester to attempt offline secret cracking with `hashcat -m 16500` | Info |

### Where do findings appear?

JWT scanner findings show up in Burp's **Dashboard** (Issues tab) and **Target → Issues** — not in the Burp Session Relay extension tab. They appear alongside Burp's own findings with the severity and confidence levels shown above, and fire automatically as traffic flows through Burp's proxy.

## Installation

### Build from source

```bash
git clone https://github.com/worldtreeboy/burp-session-share.git
cd burp-session-share
./gradlew shadowJar
```

The JAR will be at `build/libs/burp-session-relay.jar`.

### Load in Burp Suite

1. Go to **Extensions** → **Add**
2. Extension type: **Java**
3. Select `burp-session-relay.jar`
4. The **Burp Session Relay** tab will appear in Burp

## Usage

### Leader Setup

1. Switch to the **Burp Session Relay** tab
2. Select **Leader** role
3. Set the **Target Scope** to your target domain (e.g., `academy.hackthebox.com`)
4. Set a **Password** (shared secret for LAN authentication)
5. Optionally configure **CSRF Header** name and **Custom Headers** via the `[+]` button
6. Optionally check **Enable** under **SOCKS5 Relay** and set a port (default: `1080`) to also share this machine's network route (e.g. a VPN) with followers
7. Click **Start Server**
8. Browse the target app — tokens are captured automatically

### Follower Setup

1. Switch to the **Burp Session Relay** tab
2. Select **Follower** role
3. Enter the leader's **IP address** and **Port** (default: 8888)
4. Enter the same **Password**
5. Set the **Target Scope** to match the leader's
6. Click **Connect**
7. Tokens are now auto-injected into your requests
8. For selective route sharing, enter the leader SOCKS port and a local port, then click **Start Domain Routing**
9. Set Burp's SOCKS5 proxy to `127.0.0.1` and that local port, with DNS resolution through SOCKS enabled

### Solo Use (Session Manager only)

1. Switch to the **Burp Session Relay** tab
2. Set the **Target Scope** in either Leader or Follower config (no need to start server or connect)
3. Configure the **Login Macro** in the Session Manager panel at the bottom
4. Click **Test Login Macro** to verify it works
5. Check **Enable Session Manager**
6. Run your active scan — the session stays alive automatically

## Project Structure

```
src/main/java/com/sessionshare/
├── SessionShareExtension.java      # BurpExtension entry point
├── model/
│   └── TokenStore.java             # Thread-safe token storage
├── leader/
│   ├── TokenCaptureHandler.java    # Captures tokens from proxy traffic
│   ├── TokenServer.java            # Embedded HTTP server (raw ServerSocket)
│   └── SocksRelayServer.java       # Embedded SOCKS5 relay (shares the leader's route/VPN)
├── follower/
│   ├── TokenPoller.java            # Polls leader for tokens
│   └── TokenInjector.java          # Injects tokens into requests
├── session/
│   ├── SessionManager.java         # Login macro, JWT expiry check, auto-refresh
│   └── SessionHttpHandler.java     # HTTP handler for session management
├── scanner/
│   └── JwtPassiveScanCheck.java    # Passive + active JWT security scanner
└── ui/
    └── ConfigPanel.java            # Swing UI tab
```

## API Endpoints (Leader)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/tokens` | `X-Auth` header | Returns all current tokens as JSON |
| `GET` | `/health` | None | Health check / connectivity test |

## Requirements

- Burp Suite Professional or Community (with Montoya API support)
- Java 17+
- Team members on the same LAN (for Leader/Follower sharing)
- Session Manager works solo — no LAN required

## Security Note

This is a **pentest team coordination tool** for use on trusted networks during engagements. The password is a simple shared secret sent as an HTTP header — it is not designed for internet-facing security.

## v1.0

The first Burp Session Relay release includes session-token synchronization, Leader/Follower roles,
domain-selective routing through the leader's VPN, phone and local-tool proxy support, multiple and
wildcard domains, Route All mode, session auto-refresh, scoped SOCKS5 relaying, and Java 17 support.
