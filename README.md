# Burp Session Share

A Burp Suite extension (Montoya API) that lets a penetration testing team share session tokens across multiple Burp instances over the LAN.

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

## What Gets Shared

| Token Type | How It's Captured | How It's Injected |
|------------|-------------------|-------------------|
| **Cookies** | `Set-Cookie` headers from responses | `Cookie` header on requests |
| **JWT** | `Authorization: Bearer` headers, JWTs in cookie values | `Authorization: Bearer <jwt>` header |
| **CSRF** | Configured header name, meta tags in HTML | Configured header on requests |
| **Custom Headers** | User-defined header names (via `[+]` button) | Matching headers on requests |

## JWT Scanner

The extension includes both passive and active JWT security checks.

### Passive Checks (read-only traffic analysis)

| Finding | What it detects | Severity |
|---------|----------------|----------|
| **Algorithm "none"** | JWT header has `"alg": "none"` — no signature | High |
| **Missing expiry** | JWT payload has no `exp` claim — token never expires | Medium |
| **Expired token accepted** | Expired JWT sent in request AND server responded 2xx (confirmed acceptance) | High |
| **Sensitive data in payload** | JWT payload contains fields like `password`, `ssn`, `credit_card` | High |
| **HS256 usage** | JWT uses HS256 — informational flag to remind tester to attempt offline secret cracking with `hashcat -m 16500` | Info |

### Active Checks (sends requests during active scan)

| Finding | What it does | Severity |
|---------|-------------|----------|
| **alg:none bypass** | Changes algorithm to `"none"`, strips signature, sends request — confirms if server accepts unsigned tokens | High |
| **Empty signature** | Keeps original algorithm but removes the signature — confirms if server validates signatures at all | High |
| **Corrupted signature** | Flips bytes in the signature — confirms if server does real cryptographic verification | High |
| **Expiry removal** | Removes the `exp` claim from the payload — confirms if server enforces token expiry | High |

The active check runs during Burp's **active scan** on insertion points that contain a JWT.

## Installation

### Build from source

```bash
git clone https://github.com/worldtreeboy/burp-session-share.git
cd burp-session-share
./gradlew shadowJar
```

The JAR will be at `build/libs/session-share.jar`.

### Load in Burp Suite

1. Go to **Extensions** → **Add**
2. Extension type: **Java**
3. Select `session-share.jar`
4. The **Session Share** tab will appear in Burp

## Usage

### Leader Setup

1. Switch to the **Session Share** tab
2. Select **Leader** role
3. Set the **Target Scope** to your target domain (e.g., `academy.hackthebox.com`)
4. Set a **Password** (shared secret for LAN authentication)
5. Optionally configure **CSRF Header** name and **Custom Headers** via the `[+]` button
6. Click **Start Server**
7. Browse the target app — tokens are captured automatically

### Follower Setup

1. Switch to the **Session Share** tab
2. Select **Follower** role
3. Enter the leader's **IP address** and **Port** (default: 8888)
4. Enter the same **Password**
5. Set the **Target Scope** to match the leader's
6. Click **Connect**
7. Tokens are now auto-injected into your requests

## Project Structure

```
src/main/java/com/sessionshare/
├── SessionShareExtension.java      # BurpExtension entry point
├── model/
│   └── TokenStore.java             # Thread-safe token storage
├── leader/
│   ├── TokenCaptureHandler.java    # Captures tokens from proxy traffic
│   └── TokenServer.java            # Embedded HTTP server (raw ServerSocket)
├── follower/
│   ├── TokenPoller.java            # Polls leader for tokens
│   └── TokenInjector.java          # Injects tokens into requests
├── scanner/
│   └── JwtPassiveScanCheck.java    # Passive JWT security scanner
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
- Team members on the same LAN

## Security Note

This is a **pentest team coordination tool** for use on trusted networks during engagements. The password is a simple shared secret sent as an HTTP header — it is not designed for internet-facing security.
