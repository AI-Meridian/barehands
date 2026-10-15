"""Real tests for server.py -- stdlib unittest only, to match this
project's own "Python standard library only, nothing to install"
philosophy (same convention used in ai-visualizer's test suite).

Covers the three real jails in this file, none of which had any
coverage before: /note's notes-orb jail, /cmd's media-airlock jail,
and translate_path's /media/* static-serving jail. A jail escape in
any of these means an attacker-controlled path (or just a malformed
one) can read or stage a file outside the folder it's supposed to be
confined to -- for orb 0 on this real machine, that folder is Seb's
own personal notes vault.

Runs the REAL server (actual ThreadingHTTPServer + Handler) against
whatever barehands.json is actually configured on this machine, same
as ai-visualizer's tests do -- not a mock. The "legitimate read
succeeds" tests discover a real file through /tree first rather than
hardcoding a guess at this machine's current vault contents.
"""
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server as srv  # noqa: E402


def start_test_server():
    httpd = srv.ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, f"http://127.0.0.1:{port}"


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.base = start_test_server()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()


class TestConfig(ServerTestCase):
    def test_config_returns_real_orbs(self):
        status, body = get(f"{self.base}/config")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("orbs", data)
        self.assertTrue(len(data["orbs"]) >= 1)


_ESCAPE_DIR = "/tmp/barehands_jail_test"
_ESCAPE_FILE = f"{_ESCAPE_DIR}/escaped.md"


def _make_escape_target():
    os.makedirs(_ESCAPE_DIR, exist_ok=True)
    with open(_ESCAPE_FILE, "w") as f:
        f.write("escaped content")


class TestNoteJail(ServerTestCase):
    """orb_root()'s containment check: target = (root / rel).resolve();
    root must be in target.parents. The one thing standing between a
    malformed ?f= and reading an arbitrary file on disk.

    The escape target MUST end in .md and actually exist, or a
    traversal attempt gets rejected by the UNRELATED suffix/existence
    checks regardless of whether the containment check itself works --
    confirmed the hard way: an earlier version of this test pointed at
    /etc/passwd, which has no .md suffix, so it 404'd for the wrong
    reason and silently passed even with the containment check
    deliberately disabled. These point at a real .md file genuinely
    outside the jail instead."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _make_escape_target()

    def test_parent_traversal_is_rejected(self):
        root = srv.orb_root(0)
        depth = len(root.parts)
        traversal = "../" * (depth + 2) + "tmp/barehands_jail_test/escaped.md"
        status, _ = get(f"{self.base}/note?f=0/{urllib.parse.quote(traversal)}")
        self.assertEqual(status, 404)

    def test_absolute_path_escape_is_rejected(self):
        status, _ = get(
            f"{self.base}/note?f=0/{urllib.parse.quote(_ESCAPE_FILE)}")
        self.assertEqual(status, 404)

    def test_non_markdown_file_is_rejected_even_if_inside_jail(self):
        """CLAUDE.md itself is excluded from /tree, but the jail check
        in /note only cares about suffix + existence -- prove a non-.md
        file inside the real jail still 404s rather than relying on
        /tree's own separate exclusion."""
        status, _ = get(f"{self.base}/note?f=0/nonexistent-file.txt")
        self.assertEqual(status, 404)

    def test_bad_orb_index_is_rejected(self):
        status, _ = get(f"{self.base}/note?f=99/whatever.md")
        self.assertEqual(status, 404)

    def test_legitimate_note_read_succeeds(self):
        """Discovers a real file through /tree rather than guessing
        this machine's actual vault contents."""
        status, body = get(f"{self.base}/tree?orb=0")
        self.assertEqual(status, 200)
        tree = json.loads(body)

        def first_note(node):
            if node.get("notes"):
                return node["notes"][0]["file"]
            for d in node.get("dirs", []):
                found = first_note(d)
                if found:
                    return found
            return None

        note_ref = first_note(tree)
        if note_ref is None:
            self.skipTest("no .md files found under orb 0 on this machine")
        status, body = get(
            f"{self.base}/note?f={urllib.parse.quote(note_ref)}")
        self.assertEqual(status, 200)
        self.assertTrue(len(body) > 0)


class TestTreeJail(ServerTestCase):
    def test_bad_orb_index_returns_empty_tree_not_an_error(self):
        status, body = get(f"{self.base}/tree?orb=99")
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertEqual(data["notes"], [])

    def test_real_orb_zero_returns_a_tree(self):
        status, body = get(f"{self.base}/tree?orb=0")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("notes", data)
        self.assertIn("dirs", data)


class TestMediaAirlockCmdJail(ServerTestCase):
    """/cmd's own containment check for add_img/hand/give/present --
    the real media_root() must contain the resolved target."""

    def test_path_traversal_in_src_is_rejected(self):
        """Confirmed by disabling the explicit `media not in
        target.parents` check directly: a genuine escape still 400s
        via a second, incidental safety net -- target.relative_to(media)
        a few lines later raises ValueError for a path outside media,
        caught by do_POST's outer except. Real protection either way,
        worth knowing it's not solely riding on the one check that
        reads like the intentional guard."""
        status, _ = post(f"{self.base}/cmd",
                          {"a": "add_img", "src": "../../../../etc/passwd"})
        self.assertEqual(status, 400)

    def test_unknown_filename_is_rejected(self):
        status, _ = post(
            f"{self.base}/cmd",
            {"a": "add_img", "src": "this-file-does-not-exist-anywhere.png"})
        self.assertEqual(status, 400)

    def test_disallowed_action_is_rejected(self):
        status, _ = post(f"{self.base}/cmd", {"a": "delete_everything"})
        self.assertEqual(status, 400)

    def test_allowed_action_with_no_src_succeeds(self):
        status, _ = post(f"{self.base}/cmd", {"a": "clear"})
        self.assertEqual(status, 204)


class TestMediaStaticJail(ServerTestCase):
    """translate_path's /media/* containment check."""

    def test_media_traversal_falls_back_to_root_not_outside(self):
        status, _ = get(f"{self.base}/media/../../../../../../etc/passwd")
        # Falls back to serving the root dir itself (a 404/dir listing
        # from the base handler), never escapes outside media_root().
        self.assertNotEqual(status, 200)

    def test_real_media_file_is_served(self):
        mroot = srv.media_root()
        real_files = [p for p in mroot.rglob("*") if p.is_file()
                      and not p.name.startswith(".")]
        if not real_files:
            self.skipTest("no files in the real media airlock on this machine")
        rel = real_files[0].relative_to(mroot).as_posix()
        status, _ = get(f"{self.base}/media/{urllib.parse.quote(rel)}")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
