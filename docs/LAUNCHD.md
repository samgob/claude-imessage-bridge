# Running under launchd

For unattended operation, run the daemon as a user-level launchd agent.
This survives logout but NOT reboot until login (which is what you want
— FDA-bearing processes should be tied to interactive login).

## Quick install (recommended)

Use the bundled `scripts/cimb-install-agent` — it does Python detection,
plist generation, plutil validation, bootstrap, and post-install
verification in one command:

```bash
cd /path/to/claude-imessage-bridge
./scripts/cimb-install-agent
```

The script will prompt for an OAuth token if `$CLAUDE_CODE_OAUTH_TOKEN`
isn't already in your env. After it finishes it prints exact paste-able
paths for the two steps Apple won't let scripts do (granting Full Disk
Access and Automation > Messages to the launched Python binary).

Other modes:

```bash
./scripts/cimb-install-agent --dry-run    # print the plist, don't write
./scripts/cimb-install-agent --status     # check installed/loaded state
./scripts/cimb-install-agent --uninstall  # stop + remove (keeps state.db)
./scripts/cimb-install-agent --python /opt/local/bin/python3.12
```

The rest of this doc walks the same install manually for operators who
prefer the long form or need to customize the plist beyond what the
script exposes.

## ⚠️ Read before you do this

- FDA is **per-binary**. Grant Full Disk Access to the *exact* Python
  binary you launch with — find it with `which python3.11` and pass
  the full resolved path to `System Settings → Privacy & Security →
  Full Disk Access → +`. The plist example below uses
  `/opt/homebrew/bin/python3.11` (Homebrew on Apple Silicon); yours may
  be `/usr/local/bin/python3.11` (Homebrew on Intel) or
  `/opt/local/bin/python3.11` (MacPorts). FDA granted to Terminal does
  NOT extend to a launchd-spawned python — they are different
  processes from the OS's perspective.
- AppleScript send requires **Automation > Messages** for the same
  launching binary. macOS prompts on first send.
- The bridge needs Claude auth (one of `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`) in its environment. launchd does NOT
  inherit your shell env, so the plist must provide it — see
  `EnvironmentVariables` below. Without this, every claude call fails
  and operators see the canned "Couldn't run Claude" message with no
  hint why.
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
       <!-- ⚠ DO NOT commit a plist with the OAuth token inlined. -->
       <!-- Safer pattern: use `launchctl setenv CLAUDE_CODE_OAUTH_TOKEN -->
       <!--   "$(security find-generic-password -s claude-code -w)"` -->
       <!-- in a login hook, then reference it here via $CLAUDE_CODE_OAUTH_TOKEN. -->
       <key>EnvironmentVariables</key>
       <dict>
           <key>PATH</key>
           <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
           <!-- Pick ONE auth path. Prefer the OAuth token over the API key. -->
           <key>CLAUDE_CODE_OAUTH_TOKEN</key>
           <string><!-- token here, OR remove and use launchctl setenv --></string>
           <!--
           <key>ANTHROPIC_API_KEY</key>
           <string><!- alternative auth -></string>
           -->
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
