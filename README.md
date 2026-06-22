# DevGuard — DEV.to & Forem Anti-Bot Platform

DevGuard is a multi-layered, real-time security system designed for Forem-based platforms like [DEV.to](https://dev.to) to monitor, flag, and automatically suspend spam comments, fake followers, and automated bot accounts.

It replaces retroactive purge scripts with a real-time, proactive background daemon and an intuitive modern web dashboard for community moderators.

---

## Key Features

1. **Multi-Layered Detection Engine**:
   - **Browser Fingerprinting**: Detects automation indicators (Selenium, Playwright, Puppeteer, CDP variables, empty plugins arrays, platform mismatches).
   - **IP & ASN Intelligence**: Checks and flags connections from cloud providers (AWS, GCP, Azure, DigitalOcean, Hetzner, etc.) and VPN/Proxy endpoints.
   - **Behavioral Timing**: Flags burst posting (posting faster than humanly possible) and robotic posting cadence (extremely regular comment intervals with low standard deviation).
   - **Spam Heuristics**: Fuzzy matching for duplicate comments across articles, blocklists for URL shorteners, and template matching.
   
2. **Three Operational Modes**:
   - **`detect` (Default)**: Passively scans activity, flags suspicious accounts, and highlights evidence details on the dashboard without enforcing.
   - **`execute` (Enforcement)**: Automatically suspends confirmed bot profiles and unpublishes their content via API, protected by whitelists and safety throttles.
   - **`learn` (Community Engine)**: Reviews reported bot patterns. Administrators can preview rule matches against historical data to ensure zero false positives, then commit them as live system-wide regex block filters.

3. **Unified Web Control Center**:
   - Translucent glassmorphism SPA dashboard for reviewing flagged accounts, manual audit overrides, whitelisting, rule management, and live statistics.

---

## Quick Start

### 1. Prerequisites
- Python 3.10 or higher
- SQLite3 (default database)
- DEV.to / Forem API Key (Admin API key required for `suspend` and `unpublish` actions)

### 2. Local Installation
Clone the repository and install the dependencies:
```bash
# Install package dependencies
pip install -r requirements.txt

# Alternatively, install DevGuard as an editable package
pip install -e .
```

### 3. Setup Configuration
Copy the configuration template:
```bash
cp config.example.yaml config.yaml
```
Open `config.yaml` and add your Forem API base URL and token:
```yaml
devguard:
  api:
    base_url: "https://dev.to/api" # Or your self-hosted Forem URL
    api_key: "your_forem_api_token"
  mode: "detect" # Set to "execute" for auto-blocking
```

### 4. Initialize Database
Initialize the database tables:
```bash
python -m devguard db-init
```

### 5. Launch Service
Start the DevGuard dashboard and background scheduler daemon:
```bash
python -m devguard run
```
Access the web dashboard at **`http://127.0.0.1:8420`**.

---

## Client-Side Fingerprinting

To leverage browser automation detection (bot.sannysoft.com style checks), you must inject the DevGuard fingerprint collector into your Forem instance. 

Add the following `<script>` tag to your layout template (usually in Rails `application.html.erb` or Forem config):
```html
<script src="http://YOUR_DEVGUARD_HOST:8420/collector.js" defer></script>
```
*Note: The script automatically generates a session identifier, checks navigator variables, and reports fingerprint data back to the DevGuard webhook.*

---

## Real-Time Validation API

In addition to passive scanning, DevGuard provides synchronous APIs designed to be called directly within web framework model validations (e.g., Rails ActiveRecord validators) before transactions are committed.

### 1. Validate Comment
Synchronously scans comment content and matches it with the author's browser fingerprint telemetry.
- **Endpoint**: `POST /api/realtime/validate-comment`
- **Request Body**:
  ```json
  {
    "username": "author_username",
    "body": "Comment markdown text",
    "ip_address": "1.2.3.4",
    "session_id": "dg_sess_unique_token_from_cookie"
  }
  ```
- **Response**:
  ```json
  {
    "verdict": "clean | suspicious | likely_bot | confirmed_bot",
    "risk_score": 0.15,
    "is_bot": false,
    "flags": []
  }
  ```

### 2. Validate User
Synchronously scans user registration fields and matches it with browser fingerprint telemetry before registration completes.
- **Endpoint**: `POST /api/realtime/validate-user`
- **Request Body**:
  ```json
  {
    "username": "new_username",
    "name": "Jane Doe",
    "email": "jane@example.com",
    "ip_address": "1.2.3.4",
    "session_id": "dg_sess_unique_token_from_cookie"
  }
  ```
- **Response**:
  ```json
  {
    "verdict": "clean | suspicious | likely_bot | confirmed_bot",
    "risk_score": 0.55,
    "is_bot": false,
    "flags": []
  }
  ```

---

## CLI Usage

DevGuard includes a convenient command line interface for administration tasks:

```bash
# Show all commands
python -m devguard --help

# Initialize the database
python -m devguard db-init

# Start the dashboard and background scanning service
python -m devguard run --config-path custom-config.yaml

# Perform an immediate audit on a single user
python -m devguard scan username123

# Add a user to the whitelist to protect them from audits
python -m devguard whitelist add username123 --reason "Approved partner"

# List all whitelist entries
python -m devguard whitelist list

# Remove a user from the whitelist
python -m devguard whitelist remove username123
```

---

## Docker Deployment

You can deploy DevGuard as a containerized service using Docker Compose:

```bash
# Build and start DevGuard container
docker-compose up --build -d

# Check service logs
docker-compose logs -f
```
The dashboard will be exposed on port `8420`. The database and configuration are persisted on host directories (`./data` and `./config.yaml`).

---

## Project Structure

```
Anti-bot/
├── devguard/                     # Main Python Package
│   ├── api/                      # Forem v1 Client endpoints (Comments, Users, Followers)
│   ├── detection/                # Scoring orchestrator and detection layers
│   ├── modes/                    # Detect, Execute, and Learn mode controllers
│   ├── service/                  # Daemon Scheduler (APScheduler) and Real-time webhooks
│   └── dashboard/                # FastAPI app and static HTML/CSS/JS frontend
├── fingerprint/                  # Client-side fingerprint payload
├── data/                         # Persistent storage for sqlite DB
└── tests/                        # Automated unit tests
```
