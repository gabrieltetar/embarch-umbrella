"""Tests for cut-release.py with a fake runner: no network, no real tag.
Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("cr", Path(__file__).with_name("cut-release.py"))
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)


class Fake(cr.Runner):
    def __init__(self, dry_run, tags, fail=(), porcelain=""):
        super().__init__(dry_run, out=lambda s: self.lines.append(s))
        self.lines, self.queries, self.acted = [], [], []
        self.tags, self.fail, self.porcelain = tags, fail, porcelain

    def query(self, argv):
        self.queries.append(argv)
        if argv[:2] == ["git", "-C"] and "tag" in argv:
            name = Path(argv[2]).name.replace("embarch-", "")
            return 0, "\n".join(self.tags[name])
        if argv[0] == "git":
            return 0, self.porcelain
        if argv[:3] == ["gh", "run", "list"]:
            return 0, "42\n"
        return 1, ""

    def act(self, argv):
        self.lines.append("+ " + " ".join(argv))
        if self.dry_run:
            return 0, ""
        self.acted.append(argv)
        return (1 if any(f in argv for f in self.fail) else 0), ""

    def sleep(self, s):
        pass


def setup(versions=None):
    d = Path(tempfile.mkdtemp())
    versions = versions or {"core": "0.2.0", "api": "0.1.0", "umbrella": "0.1.0"}
    paths = {}
    for n, v in versions.items():
        p = d / f"embarch-{n}"
        p.mkdir()
        (p / "Cargo.toml").write_text(f'[package]\nname="x"\nversion = "{v}"\n')
        paths[n] = p
    (paths["umbrella"] / "suite.toml").write_text(
        '# c\ncore = "v0.1.4"\napi = "v0.1.0"\numbrella = "v0.1.0"\n')
    return d, paths


TAGS = {"core": ["v0.1.4", "v0.1.10", "v0.1.9"], "api": ["v0.1.0"], "umbrella": ["v0.1.0"]}

SETTLED = {"core": ["v0.1.4"], "api": ["v0.1.0"], "umbrella": ["v0.1.0"]}


class T(unittest.TestCase):
    def test_dry_run_prints_commands_runs_none(self):
        d, paths = setup()
        r = Fake(True, TAGS)
        cr.cut(r, paths, paths["umbrella"], "0.2.0", False, d / "dl")
        self.assertEqual(r.acted, [])
        text = "\n".join(r.lines)
        self.assertIn("git -C", text)
        self.assertIn("tag v0.2.0", text)
        self.assertIn("suite.toml: core v0.1.4 -> v0.2.0", text)
        self.assertIn("never approves", text)
        self.assertEqual(
            (paths["umbrella"] / "suite.toml").read_text().count("v0.1.4"), 1)

    def test_equal_version_skipped(self):
        d, paths = setup()
        r = Fake(True, TAGS)
        cr.cut(r, paths, paths["umbrella"], "0.2.0", False, d / "dl")
        text = "\n".join(r.lines)
        self.assertIn("api: Cargo.toml 0.1.0 equals latest tag v0.1.0; skipped", text)
        self.assertFalse([l for l in r.lines if l.startswith("+") and "embarch-api" in l])

    def test_latest_tag_is_numeric(self):
        d, paths = setup()
        self.assertEqual(cr.latest_tag(Fake(True, TAGS), paths["core"]), "v0.1.10")

    def test_failed_component_run_stops_before_suite_tag(self):
        d, paths = setup()
        r = Fake(False, TAGS, fail=("watch",))
        with self.assertRaises(cr.Stop):
            cr.cut(r, paths, paths["umbrella"], "0.2.0", True, d / "dl")
        flat = [" ".join(a) for a in r.acted]
        self.assertTrue(any("tag v0.2.0" in f for f in flat))
        self.assertFalse(any("suite-v" in f for f in flat))
        self.assertIn("v0.1.4", (paths["umbrella"] / "suite.toml").read_text())

    def test_go_rewrites_suite_toml_and_stops(self):
        d, paths = setup()
        r = Fake(False, TAGS)
        with self.assertRaises(cr.Stop):
            cr.cut(r, paths, paths["umbrella"], "0.2.0", True, d / "dl")
        t = (paths["umbrella"] / "suite.toml").read_text()
        self.assertIn('core = "v0.2.0"', t)
        self.assertIn("# c", t)
        self.assertFalse(any("suite-v" in " ".join(a) for a in r.acted))

    def test_second_run_tags_suite_verifies_and_prints_install(self):
        d, paths = setup({"core": "0.1.4", "api": "0.1.0", "umbrella": "0.1.0"})
        r = Fake(False, SETTLED)
        cr.cut(r, paths, paths["umbrella"], "0.2.0", True, d / "dl")
        flat = [" ".join(a) for a in r.acted]
        self.assertTrue(any("tag suite-v0.2.0" in f for f in flat))
        self.assertTrue(any("verify-release" in f for f in flat))
        self.assertIn(f"{cr.INSTALL_VERB} {d / 'dl'}", "\n".join(r.lines))

    def test_failed_verification_stops_and_says_so(self):
        d, paths = setup({"core": "0.1.4", "api": "0.1.0", "umbrella": "0.1.0"})
        r = Fake(False, SETTLED, fail=("verify-release",))
        with self.assertRaises(cr.Stop) as c:
            cr.cut(r, paths, paths["umbrella"], "0.2.0", True, d / "dl")
        self.assertIn("VERIFICATION FAILED", str(c.exception))
        self.assertNotIn(cr.INSTALL_VERB, "\n".join(r.lines))

    def test_uncommitted_suite_toml_stops(self):
        d, paths = setup({"core": "0.1.4", "api": "0.1.0", "umbrella": "0.1.0"})
        r = Fake(False, SETTLED, porcelain=" M suite.toml\n")
        with self.assertRaises(cr.Stop):
            cr.cut(r, paths, paths["umbrella"], "0.2.0", True, d / "dl")
        self.assertEqual(r.acted, [])


if __name__ == "__main__":
    unittest.main()
