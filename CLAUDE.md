# embarch-umbrella

## Docs

Design doc: [../embarch-doc/embarch-umbrella/design.md](../embarch-doc/embarch-umbrella/design.md) — source of truth for this project's architecture/design.
Update it proactively per [../embarch-doc/DOC-PROTOCOL.md](../embarch-doc/DOC-PROTOCOL.md) whenever a notable design decision, feature, or status change happens here.

Current execution plan: [../embarch-doc/embarch-umbrella/milestone-6.md](../embarch-doc/embarch-umbrella/milestone-6.md).

## Local dev safety

`setup`/`up`/`down`/`setup --uninstall` write real, shared machine state (canonical install, `PATH` via registry or rc files, a real OS service, a system-wide token file — see [design.md](../embarch-doc/embarch-umbrella/design.md) §3 decision 28). Never run one of these live against a real machine unsupervised — ask first, same standing rule as firmware build/flash — unless it's running inside [dev-sandbox/](dev-sandbox/) or an equivalently disposable environment. Full detail: [../embarch-doc/embarch-dev-workflow.md](../embarch-doc/embarch-dev-workflow.md) §5. Unit tests remain the default, fully-autonomous way to verify this logic.
