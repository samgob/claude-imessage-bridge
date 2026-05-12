# Running under launchd

For unattended operation, run the daemon as a user-level launchd agent.
This survives logout but NOT reboot until login (which is what you want
— FDA-bearing processes should be tied to interactive login).

## ⚠️ Read before you do this

- The launchd process inherits **Full Disk Access** from whatever you
  granted in `System Settings → Privacy & Security → Full Disk Access`.
  You almost certainly want to grant FDA to `/usr/bin/python3` or the
  specific Python you launch with, **not** to launchd itself. If FDA is
  granted to "Terminal," foreground runs will work but a launchd run
  won't — they're different processes.
- AppleScript send requires **Automation > Messages** for the launching
  process. If Terminal already has this, the launchd python will need
  the same grant. macOS prompts on first send if a Terminal session of
  yours has the grant.
- The launchd-managed daemon writes `~/.claude-imessage-bridge/status.json`
  every heartbeat (5 min by default). Stale `status.json` is the fastest
  way to detect a hung daemon.

## Install the agent

1. Make sure the bridge runs cleanly in foreground first:
   ```bash
   python3 -m src.daemon --once
   ```
   Verify a `[INFO] selftest: bash denied` line and no errors.

2. Create `~/Library/LaunchAgents/dev.samgob.claude-imessage-bridge.plist`
   with the following contents (adjust paths for your install):

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
     "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>dev.samgob.claude-imessage-bridge</string>

       <key>ProgramArguments</key>
       <array>
           <string>/opt/homebrew/bin/python3.11</string>
           <string>-m</string>
           <string>src.daemon</string>
       </array>

       <key>WorkingDirectory</key>
       <string>/Users/YOU/path/to/claude-imessage-bridge</string>

       <!-- Run on login, restart on crash (with a sane backoff). -->
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <dict>
           <key>SuccessfulExit</key>
           <false/>
       </dict>
       <key>ThrottleInterval</key>
       <integer>30</integer>

       <!-- Logs. Rotate manually; macOS won't. -->
       <key>StandardOutPath</key>
       <string>/Users/YOU/.claude-imessage-bridge/logs/stdout.log</string>
       <key>StandardErrorPath</key>
       <string>/Users/YOU/.claude-imessage-bridge/logs/stderr.log</string>

       <!-- Environment scrub the daemon does internally is one layer; -->
       <!-- pass only what's needed at launch. -->
       <key>EnvironmentVariables</key>
       <dict>
           <key>PATH</key>
           <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
       </dict>

       <!-- Do NOT set Crashed mode aggressively; the circuit breaker -->
       <!-- already auto-pauses on N consecutive claude failures, and -->
       <!-- you want the daemon to stop on a PAUSE file, not loop. -->
   </dict>
   </plist>
   ```

3. Validate and load:
   ```bash
   plutil -lint ~/Library/LaunchAgents/dev.samgob.claude-imessage-bridge.plist
   launchctl bootstrap gui/$(id -u) \
     ~/Library/LaunchAgents/dev.samgob.claude-imessage-bridge.plist
   launchctl print gui/$(id -u)/dev.samgob.claude-imessage-bridge | head
   ```

4. Verify with `status.json`:
   ```bash
   sleep 10
   cat ~/.claude-imessage-bridge/status.json | jq .
   ```

## Stop / restart

```bash
# Stop
launchctl bootout gui/$(id -u)/dev.samgob.claude-imessage-bridge

# Restart
launchctl kickstart -k gui/$(id -u)/dev.samgob.claude-imessage-bridge
```

## Quick pause without unloading

```bash
touch ~/.claude-imessage-bridge/PAUSE
# … later …
rm ~/.claude-imessage-bridge/PAUSE
```

The daemon polls the PAUSE file every tick. No launchctl needed for
short pauses.

## Health check from cron

```bash
*/15 * * * * /usr/local/bin/jq -e '
  .paused == false and
  .stop_requested == false and
  ((now - (.ts | fromdate)) < 1800) and
  .consecutive_failures < 3
' ~/.claude-imessage-bridge/status.json > /dev/null || \
  /usr/bin/say "claude imessage bridge unhealthy"
```

`(now - (.ts | fromdate)) < 1800` checks the heartbeat is < 30 min old.
