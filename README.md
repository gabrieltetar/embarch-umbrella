# embarch-umbrella

Part of the [EmbArch](https://github.com/gabrieltetar/embarch-doc) suite — a set of tools for firmware engineers that spans from software to the physical hardware bench.

This is the binary you download first. `embarch` gets a firmware engineer from *nothing installed* to *`embarch-api build_and_flash my-project` works, from a terminal or from an AI coding agent* — on whatever topology their machine happens to be: Core native on Windows with the API in WSL2, both native on a Mac, both native on Linux, or Core on a separate box.

> **Status: bootstrap only.** The command surface below parses and every command reports itself unimplemented. The behavior behind it is [Milestone 6](https://github.com/gabrieltetar/embarch-doc/blob/main/embarch-umbrella/milestone-6.md).

## What it does

| Command | Scope | Behavior |
|---|---|---|
| `embarch setup` | once per machine | Detect the topology, install `embarch-core` as a service that starts at boot, ensure the shared token exists, put both binaries on `PATH` |
| `embarch init` | once per firmware repo | Scaffold `embarch/embarch.toml` and a separate build directory, register the MCP server, exclude it all locally. `--uninstall` reverses it |
| `embarch doctor` | anytime | Verify the whole chain — binaries, service, reachability, token, probe, config, build command, artifact paths, MCP registration — with a fix for every failure. `--json` |
| `embarch status` | anytime, cheap | Is Core up, which topology, how many probes. `--json` |
| `embarch up` / `down` | fallback | Start/stop Core when it isn't already a running service, including across the WSL2⟷Windows boundary |

## What it deliberately isn't

- **Not a process supervisor or daemon.** No restart loop, no health polling, no resident process. `embarch-core`'s own cross-platform service install is what keeps Core running; `up` exists only for when that isn't in place or has died.
- **Not in the runtime path.** Nothing routes through this binary after setup. It is not an MCP server, not a proxy, and specifically not the process an MCP client spawns. Delete it from a working machine and the stack keeps working.
- **Not a hardware or build layer.** It never links `probe-rs` or `serialport` and never runs a build command — every capability it appears to have is a shell-out to `embarch-core`/`embarch-api` or an HTTP call to Core's existing endpoints.
- **Not multi-machine orchestration.** No SSH, no remote install. A Core on a separate box is started by a human on that box; umbrella only detects and verifies it.

The load-bearing design point: **Core is meant to be an installed, autostarting OS service**, so on every same-machine topology there is nothing for a human to start, ever. That's what makes "one button starts everything" a *setup* problem rather than a process-management problem — and it's why this is a setup-and-diagnostics tool rather than a launcher.

```
                    setup / init / doctor / status / up / down
                                    |
                                 embarch
                          /         |          \
        embarch-core CLI  |    embarch-api CLI  |  HTTP+Bearer -> embarch-core
        (install/start)   |    + its config     |

after setup, the runtime path has no umbrella in it:

Claude Code --stdio--> embarch-api --HTTP+Bearer--> embarch-core --> hardware
human ------CLI------> embarch-api ----------------^
```

## Building

```sh
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo test
```

## Design doc

The full design record — why this is its own sub-project, topology auto-detection, the `doctor` check list, per-firmware-repo integration, MCP-registration options and their trade-offs, and distribution — lives in [embarch-doc/embarch-umbrella/design.md](https://github.com/gabrieltetar/embarch-doc/blob/main/embarch-umbrella/design.md), treated as the durable source of truth ahead of any chat history that produced it. The guide it has to satisfy is [embarch-user-guide.md](https://github.com/gabrieltetar/embarch-doc/blob/main/embarch-user-guide.md).

## License

MIT — see [LICENSE](LICENSE).
