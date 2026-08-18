# A disposable environment for exercising the LIVE behavior of commands
# that write to real, shared machine state — `embarch setup`/`up`/`down`/
# `doctor --prune`/`setup --uninstall`, and embarch-core's own
# `install`/`start`/`stop`/`uninstall`. Real filesystem/service writes
# happen here, but entirely inside this container's own `/root`,
# `/var/lib`, and service manager — no WSL2 interop, no `/mnt/c`, no route
# to a real Windows host, unless you explicitly bind-mount one in. Nothing
# this container touches is real, so an agent can run setup/up/down/
# uninstall here without asking first the way it must on a real machine.
#
# See ../../embarch-doc/embarch-dev-workflow.md §5.
#
# NOT YET VERIFIED — written 2026-08-17 with no `docker` binary available
# in the session that wrote it. Standard, low-risk content (a stock Rust
# image plus one apt install), but its first real `docker build`/`run`
# should still be watched, same as any new automation.
FROM rust:1.83-slim-bookworm

# libudev-dev/pkg-config: embarch-core's probe-rs/serialport dependencies
# need these to build at all (embarch-core/README.md's own Linux note).
#
# Deliberately NOT trying to run a real systemd/D-Bus inside this
# container (that needs --privileged plus cgroup mounts run.sh doesn't
# set up) — a plain `docker run` has no init system, so
# `embarch-core install`/`start` will fail cleanly here (systemd
# unreachable) rather than actually persist a service. That is fine for
# this sandbox's actual goal: confirming the *code path* (does it print
# the right elevation message, does it error the way it should) with
# zero risk, not exercising a real persisted service end to end. If you
# need that too, add `--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw`
# to run.sh's `docker run` and give the container a real init (`CMD
# ["/lib/systemd/systemd"]`) — not done here since it widens what the
# container can affect on the host, which cuts against this sandbox's
# whole point.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libudev-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
