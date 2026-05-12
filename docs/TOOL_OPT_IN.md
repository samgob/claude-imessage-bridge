# Tool opt-in decision tree

The bridge defaults to `allowed_tools: []` — pure text chat, no tools.
This is the recommended posture. Adding tools to `allowed_tools` widens
the attack surface in well-defined ways. Use this guide before opting in.

## Decision tree

### Step 1 — Do you actually need the tool?

Most "I want claude to do X" use cases over iMessage are NOT improved by
giving claude a tool. Some examples:

| You want… | Better path |
|---|---|
| "What's the weather?" | Don't enable WebFetch — claude can't read your weather anyway. Get it from elsewhere. |
| "Read this file from my project" | Don't enable Read. Paste the relevant content into the message instead. The hermetic sandbox cwd doesn't include your project. |
| "Send this to Slack" | Don't enable any MCP. Bridge is one-way to the sender of the inbound message. |
| "Run my tests" | Don't enable Bash. Use a foreground Claude Code session — the bridge isn't an automation surface. |

If none of those apply and you *really* need the tool, continue.

### Step 2 — Is the tool in `HARD_FORBIDDEN_TOOLS`?

```python
# src/claude_runner.py
HARD_FORBIDDEN_TOOLS: Final = frozenset({
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "WebFetch", "WebSearch",
    "Skill", "Agent", "ToolSearch",
    "CronCreate", "CronDelete", "CronList", "CronToggle",
    "ScheduleWakeup",
    "RemoteTrigger", "PushNotification",
    "EnterWorktree", "ExitWorktree",
})
```

**If yes: STOP.** These are blocked at the config layer; the daemon refuses
to start with any of them in `allowed_tools`. They got there because they
can be coerced via prompt injection into doing things that leak your
filesystem (`Read`/`Write`), exfiltrate via the network (`WebFetch`),
re-enable denied tools (`Skill`, `Agent`, `ToolSearch`), or persist
arbitrary execution (`Cron*`, `ScheduleWakeup`).

To override, you'd need to edit `claude_runner.py` AND update the threat
model. Don't, unless you've understood S3 in [THREAT_MODEL.md](THREAT_MODEL.md).

### Step 3 — Is it an MCP-namespaced tool (`mcp__*`)?

**Reject by default.** The bridge can't vet what an MCP tool actually does
— a single `mcp__personal-gmail__send_message` tool can email arbitrary
addresses on your behalf, and the hermetic sandbox doesn't load MCP
servers anyway. If you enable an MCP tool the call will fail (the
sandbox's `empty-mcp.json` excludes everything).

### Step 4 — Is it a read-only inspection tool?

| Tool | What it does | Realistic abuse |
|---|---|---|
| `Read` | Read a file under cwd | cwd is the hermetic sandbox — empty. But a prompt-injected `Read("/etc/passwd")` would work outside cwd. |
| `Glob` | Pattern-match filenames | Similar — bounded by FDA scope. |
| `Grep` | Search file contents | Same. |
| `LS` | List a directory | Same. |

These are in `HARD_DISALLOWED` but **NOT** in `HARD_FORBIDDEN_TOOLS`. You
*can* opt into them (the config layer allows it). But you shouldn't unless:

1. You've audited the project_directory contents.
2. You accept that prompt injection over iMessage can drive these tools.
3. You understand that the daemon has Full Disk Access — `Read` is not
   actually bounded to `project_directory` at the OS level.

### Step 5 — What if I really really want Bash?

Run a regular foreground Claude Code session. The bridge is not the
right tool for "execute commands on my mac via iMessage."

If you genuinely need this — say, for a personal lab where the attack
surface is acceptable — the safer path is:
1. Use a dedicated Apple ID that's only on your devices.
2. Use a dedicated project_directory with no secrets.
3. Configure `allowed_tools: [Bash]` AND `daily_cost_cap_usd: 1.00` AND
   `reply_rate_limit_per_minute: 2` to limit the blast radius.
4. Add a startup selftest invariant for each new tool you opt into
   (e.g., a Bash selftest that verifies it works in the sandbox cwd
   only).
5. Document the deviation in your own fork's threat model.

This is explicitly outside what the upstream README recommends. Don't
push the change upstream; keep it on a personal branch.

## Tools currently in HARD_DISALLOWED

This list is the **runtime** deny list — what gets passed to
`--disallowed-tools` on every claude invocation. Anything you put in
`allowed_tools` gets removed from this set for that call.

```
# Filesystem write / exec
Bash, Write, Edit, MultiEdit, NotebookEdit
# Filesystem read
Read, Grep, Glob, LS, NotebookRead
# Network egress
WebFetch, WebSearch
# Tool/skill/agent loading
Skill, Agent, ToolSearch
# Scheduling
CronCreate, CronDelete, CronList, CronToggle, ScheduleWakeup
# Communication / out-of-band
AskUserQuestion, RemoteTrigger, PushNotification
# Task / state / plan
TodoWrite, TaskStop, TaskOutput,
EnterWorktree, ExitWorktree, EnterPlanMode, ExitPlanMode
# MCP introspection
ListMcpResourcesTool, ReadMcpResourceTool
```

**HARD_FORBIDDEN_TOOLS** (cannot be opted into) is a subset; see Step 2.
