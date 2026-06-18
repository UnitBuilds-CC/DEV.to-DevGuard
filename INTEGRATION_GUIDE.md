# DevGuard — DEV.to / Forem Integration Blueprint

This document is a technical blueprint for the DEV.to/Forem engineering team. It explains how to deploy the DevGuard security service and integrate it directly into your platform.

---

## 1. Deployment Overview

DevGuard operates as a standalone service (FastAPI dashboard + background scheduler daemon) alongside Forem. It utilizes an in-memory or persistent SQLite database to audit accounts, log browser fingerprints, track telemetry data, and execute suspensions.

```
+------------------+                   +------------------+
|                  |  -- Webhooks -->  |                  |
|    Forem App     |                   |  DevGuard Engine |
| (Ruby on Rails)  |  <-- API Auth --  |  (Python/FastAPI)|
|                  |                   |                  |
+------------------+                   +------------------+
         |                                      |
   Injects JS Script                      Saves Audit Logs
         |                                      |
         v                                      v
+------------------+                   +------------------+
|  Client Browser  |  -- Telemetry --> |  SQLite database |
|  (Telemetry JS)  |                   |  (data/devguard) |
+------------------+                   +------------------+
```

### Quick Docker Setup
To run the DevGuard backend service:
1. Configure `config.yaml` using the template `config.example.yaml`.
2. Build and start the container:
   ```bash
   docker-compose up --build -d
   ```
The web dashboard is exposed at `http://localhost:8420`.

---

## 2. Integrating Client-Side Telemetry

To collect browser environment variables and active user telemetry (mouse trajectories, scroll speeds, typing cadence, and paste events), you must load `collector.js` on your platform's pages.

### Step A: Script Injection
Inject the collector script into Forem's layout template (e.g. `app/views/layouts/application.html.erb`):

```erb
<% if current_user.present? %>
  <script>
    // Expose current username to DevGuard collector
    window.currentUser = {
      username: "<%= current_user.username %>"
    };
    // Hostname of your DevGuard container service
    window.DEVGUARD_HOST = "https://devguard.yourdomain.com";
  </script>
  <script src="https://devguard.yourdomain.com/collector.js" defer></script>
<% end %>
```

### Step B: What the Script Tracks
*   **Active Telemetry**: Analyzes mouse trajectory angles (flagging perfectly linear scripted paths), speed variance (flagging constant speed bots), key dwell time distributions, and paste-to-keypress ratios.
*   **Environment Audits**: Flags `navigator.webdriver`, window CDP artifacts (`$cdc_`, `__playwright`, etc.), and inconsistent Permissions API structures.

---

## 3. Wiring Real-Time Upstream Webhooks

To move from passive polling to real-time, proactive blocking:

### Step A: Configure Forem Webhooks
Set up a webhook in your Forem admin console or internal event bus:
*   **Target Endpoint**: `https://devguard.yourdomain.com/api/realtime/event`
*   **Triggers**: `comment_created`, `user_registered`
*   **Headers**: Content-Type: `application/json`

### Step B: Payload Structure
Forem should post JSON events matching the following format:
```json
{
  "type": "comment_created",
  "author": "suspicious_user_username",
  "ip_address": "203.0.113.195"
}
```
Upon receipt, DevGuard immediately triggers an out-of-band background scan for that user, combining their profile data, comment histories, and browser fingerprint cache.

---

## 4. Upstream Rails Middleware Blocking (Optimal Solution)

For absolute protection where bot comments never hit the database, call the DevGuard scan engine synchronously during model validations.

Add this validator hook to Forem's `Comment` model:

```ruby
# app/models/comment.rb
class Comment < ApplicationRecord
  validate :check_anti_bot_reputation, on: :create

  private

  def check_anti_bot_reputation
    # Only audit logged-in, non-admin users
    return if user.has_role?(:admin)

    # Query DevGuard synchronous manual scan endpoint
    response = HTTParty.post(
      "https://devguard.yourdomain.com/api/scan-user",
      headers: { 'Content-Type' => 'application/json' },
      body: { username: user.username }.to_json,
      timeout: 1.5 # Strict timeout to protect Rails request cycle
    )

    if response.code == 200
      data = JSON.parse(response.body)
      if data["verdict"] == "confirmed_bot" || (data["verdict"] == "likely_bot" && data["risk_score"] > 0.85)
        errors.add(:base, "Your comment was flagged by our security system. Please contact site administrators.")
      end
    end
  rescue Timeout::Error, StandardError => e
    Rails.logger.error("DevGuard connection failed: #{e.message}")
    # Fail open to guarantee normal user uptime if service is down
  end
end
```
---

## 5. Security & Safety Controls

1.  **Whitelist**: Add trusted community members, team accounts, and partner bots (e.g. RSS posters) using the command line tool:
    ```bash
    python -m devguard whitelist add trusted_user --reason "Internal RSS Poster"
    ```
2.  **Suspending Accounts**: To enable automated suspension actions, set `devguard.execute.enabled` to `true` and `dry_run` to `false` in `config.yaml`.
3.  **Action Throttles**: Set a conservative limit on suspensions (e.g. `max_actions_per_hour: 10`) to safeguard the system against sudden unexpected edge cases.
