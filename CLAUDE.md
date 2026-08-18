# embarch-umbrella

## Docs

Design doc: [../embarch-doc/embarch-umbrella/design.md](../embarch-doc/embarch-umbrella/design.md) — source of truth for this project's architecture/design.
Update it proactively per [../embarch-doc/DOC-PROTOCOL.md](../embarch-doc/DOC-PROTOCOL.md) whenever a notable design decision, feature, or status change happens here.

Current execution plan: [../embarch-doc/embarch-umbrella/milestone-6.md](../embarch-doc/embarch-umbrella/milestone-6.md).

## Local dev safety

`setup`/`up`/`down`/`setup --uninstall` write real, shared machine state (canonical install, `PATH` via registry or rc files, a real OS service, a system-wide token file — see [design.md](../embarch-doc/embarch-umbrella/design.md) §3 decision 28). **The repo owner has explicitly authorized running these live against their real daily-use machine directly — no need to ask first there** (2026-08-17). [dev-sandbox/](dev-sandbox/) still exists for anyone who'd rather stay fully isolated (a different machine, a different person, or a change risky enough to want a disposable environment regardless). Full detail: [../embarch-doc/embarch-dev-workflow.md](../embarch-doc/embarch-dev-workflow.md) §5. This authorization doesn't extend to firmware build/flash, which stays a separate, unchanged rule.
