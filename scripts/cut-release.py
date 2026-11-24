#!/usr/bin/env python3
"""Cut a signed EmbArch suite release. Dry run by default; --go acts.

Every git and gh call goes through one Runner, which the tests fake.
Docs: embarch-doc/embarch-umbrella/interfaces/cut-release.md
"""
import argparse
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

COMPONENTS = ("core", "api", "umbrella")
OWNER = "gabrieltetar"
INSTALL_VERB = "embarch install-core"


class Stop(Exception):
    """The script halts here; the message says why and what the owner does next."""


class Runner:
    """The only place git or gh runs. `query` is read-only and always runs;
    `act` changes something and, in a dry run, is only printed."""

    def __init__(self, dry_run, out=print):
        self.dry_run = dry_run
        self.out = out

    def query(self, argv):
        p = subprocess.run(argv, capture_output=True, text=True)
        return p.returncode, p.stdout

    def act(self, argv):
        self.out("+ " + " ".join(argv))
        if self.dry_run:
            return 0, ""
        p = subprocess.run(argv, text=True)
        return p.returncode, ""

    def sleep(self, s):
        time.sleep(s)


def repo_slug(name):
    return f"{OWNER}/embarch-{name}"


def cargo_version(path):
    with open(path / "Cargo.toml", "rb") as f:
        return tomllib.load(f)["package"]["version"]


def vkey(tag):
    return [int(x) for x in re.findall(r"\d+", tag)]


def latest_tag(runner, path):
    rc, out = runner.query(["git", "-C", str(path), "tag", "--list", "v*"])
    tags = [t.strip() for t in out.split() if re.fullmatch(r"v\d+\.\d+\.\d+", t.strip())]
    return max(tags, key=vkey) if rc == 0 and tags else None


def read_suite(path):
    with open(path / "suite.toml", "rb") as f:
        return tomllib.load(f)


def rewrite_suite_toml(text, tags):
    for name, tag in tags.items():
        text = re.sub(rf'(?m)^{name}\s*=\s*"[^"]*"', f'{name} = "{tag}"', text)
    return text


def plan(runner, paths):
    """Per component: (name, version, latest tag or None, needs_tag)."""
    rows = []
    for name in COMPONENTS:
        v = cargo_version(paths[name])
        t = latest_tag(runner, paths[name])
        rows.append((name, v, t, t != f"v{v}"))
    return rows


def wait_for_run(runner, slug, ref, workflow, attempts=30, delay=10):
    """Find the run a tag push started and watch it. A failure raises Stop."""
    runner.out(f"+ wait for {workflow} on {ref} in {slug}")
    runner.out("  (a `release` environment run needs the OWNER's approval in GitHub; "
               "this script never approves it)")
    if runner.dry_run:
        return
    run_id = None
    for _ in range(attempts):
        rc, out = runner.query(["gh", "run", "list", "-R", slug, "--workflow", workflow,
                                "--branch", ref, "--limit", "1",
                                "--json", "databaseId", "--jq", ".[0].databaseId"])
        if rc == 0 and out.strip():
            run_id = out.strip()
            break
        runner.sleep(delay)
    if run_id is None:
        raise Stop(f"no {workflow} run appeared for {ref} in {slug}")
    rc, _ = runner.act(["gh", "run", "watch", run_id, "-R", slug, "--exit-status"])
    if rc != 0:
        raise Stop(f"{workflow} failed for {ref} in {slug}; nothing later was tagged")


def tag_and_push(runner, path, tag):
    for argv in (["git", "-C", str(path), "tag", tag],
                 ["git", "-C", str(path), "push", "origin", tag]):
        rc, _ = runner.act(argv)
        if rc != 0:
            raise Stop("failed: " + " ".join(argv))


def cut(runner, paths, umbrella, suite_version, go, dest):
    out = runner.out
    rows = plan(runner, paths)
    for name, v, t, changed in rows:
        if changed:
            out(f"{name}: Cargo.toml {v}, latest tag {t or 'none'} -> would tag v{v}")
        else:
            out(f"{name}: Cargo.toml {v} equals latest tag {t}; skipped")
    wanted = {name: (f"v{v}" if changed else t) for name, v, t, changed in rows}
    current = read_suite(umbrella)
    toml_changes = {k: (current.get(k), v) for k, v in wanted.items() if current.get(k) != v}
    for k, (a, b) in toml_changes.items():
        out(f"suite.toml: {k} {a} -> {b}")
    if not go:
        out("dry run: nothing was run; add --go to act")
    changed_names = [r[0] for r in rows if r[3]]
    if changed_names or toml_changes:
        for name, v, t, changed in rows:
            if changed:
                tag_and_push(runner, paths[name], f"v{v}")
                wait_for_run(runner, repo_slug(name), f"v{v}", "release.yml")
        if toml_changes:
            p = umbrella / "suite.toml"
            if go:
                p.write_text(rewrite_suite_toml(p.read_text(), wanted), newline="\n")
            out("suite.toml " + ("rewritten" if go else "would be rewritten")
                + ". Commit it, then run this script again with the same arguments.")
            if go:
                raise Stop("stopped for the owner to commit suite.toml")
            return
    rc, st = runner.query(["git", "-C", str(umbrella), "status", "--porcelain", "--", "suite.toml"])
    if st.strip():
        raise Stop("suite.toml has uncommitted changes: commit it, then run again")
    stag = f"suite-v{suite_version}"
    tag_and_push(runner, umbrella, stag)
    wait_for_run(runner, repo_slug("umbrella"), stag, "assemble-suite.yml")
    rc, _ = runner.act(["gh", "release", "download", stag, "-R", repo_slug("umbrella"),
                        "-D", str(dest)])
    if rc != 0:
        raise Stop(f"could not download {stag}")
    rc, _ = runner.act(["embarch", "verify-release", str(dest)])
    if rc != 0:
        raise Stop(f"VERIFICATION FAILED for {stag} in {dest}: do not install it")
    out(f"verified {stag}. Install it from an elevated shell:")
    out(f"  {INSTALL_VERB} {dest}")


def main(argv=None):
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("suite_version", help="suite version for the suite-v<version> tag, e.g. 0.2.0")
    ap.add_argument("--go", action="store_true", help="act; the default is a dry run")
    ap.add_argument("--root", type=Path, default=here.parent,
                    help="folder holding embarch-core and embarch-api checkouts")
    ap.add_argument("--umbrella", type=Path, default=here, help="this repo's checkout")
    ap.add_argument("--dest", type=Path, default=None, help="where to download the release")
    a = ap.parse_args(argv)
    paths = {"core": a.root / "embarch-core", "api": a.root / "embarch-api",
             "umbrella": a.umbrella}
    dest = a.dest or (a.umbrella / "dist" / f"suite-v{a.suite_version}")
    try:
        cut(Runner(not a.go), paths, a.umbrella, a.suite_version, a.go, dest)
    except Stop as e:
        print(f"STOP: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
