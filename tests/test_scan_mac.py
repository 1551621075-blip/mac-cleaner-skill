"""Only synthetic fixtures; never import the legacy scanner before AST checks."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan_mac.py"


class StaticSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))

    def test_main_function_exists(self):
        self.assertTrue(any(isinstance(n, ast.FunctionDef) and n.name == "main"
                            and n.args.args and n.args.args[0].arg == "argv"
                            for n in self.tree.body), "missing main(argv)")

    def test_main_guard_exists(self):
        self.assertTrue(any(isinstance(n, ast.If) and
                            ast.unparse(n.test) == "__name__ == '__main__'"
                            for n in self.tree.body), "missing main guard")

    def test_argparse_is_used(self):
        self.assertTrue(any(isinstance(n, ast.Import) and
                            any(a.name == "argparse" for a in n.names)
                            for n in self.tree.body), "missing argparse")

    def test_skill_read_only_consent_contract(self):
        text = (SCRIPT.parents[1] / "SKILL.md").read_text(encoding="utf-8")
        for forbidden in ("rm -rf", "~30 seconds", "trash <path>", "你想清理哪些", "MD5"):
            self.assertNotIn(forbidden, text)
        for required in ("--home", "--hash-duplicates", "--output", "not_run", "本次", "许可"):
            self.assertIn(required, text)

    def test_runtime_imports_are_only_approved_standard_library(self):
        approved = {"argparse", "collections", "contextlib", "datetime", "errno",
                    "hashlib", "json", "os", "stat", "sys", "time"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                self.assertTrue({a.name for a in node.names} <= approved)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, approved)

    def test_no_implicit_home_or_fixed_report(self):
        source = ast.unparse(self.tree)
        self.assertNotIn("Path.home()", source, "implicit real-home scan")
        self.assertNotIn("/tmp/mac_scan_result.json", source)


def load_scanner():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    assert any(isinstance(n, ast.If) and
               ast.unparse(n.test) == "__name__ == '__main__'" for n in tree.body), \
        "unsafe legacy module: dynamic import blocked"
    spec = importlib.util.spec_from_file_location("scanner_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(root):
    """Compare contents, identities, sizes and mtimes, deliberately excluding atime."""
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(parent) / name
            st = p.lstat()
            content = (hashlib.sha256(p.read_bytes()).hexdigest()
                       if stat.S_ISREG(st.st_mode) else
                       os.readlink(p) if stat.S_ISLNK(st.st_mode) else None)
            result[str(p.relative_to(root))] = (
                st.st_mode, st.st_ino, st.st_size, st.st_mtime_ns, content)
    return result


class SyntheticTests(unittest.TestCase):
    NOW = 2_000_000_000
    LIMITS = {"large": 100, "duplicate": 8, "cache": 10,
              "download_age": 30 * 86400, "log_age": 7 * 86400}

    def setUp(self):
        self.m = load_scanner()
        self.temp = tempfile.TemporaryDirectory(prefix="mac-cleaner-test-")
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / "synthetic-home"
        self.home.mkdir(mode=0o700)
        self.out = self.base / "reports"
        self.out.mkdir(mode=0o700)
        self.before = None
        self.network = contextlib.ExitStack()
        for method in ("connect", "connect_ex", "sendto"):
            self.network.enter_context(mock.patch.object(socket.socket, method,
                side_effect=AssertionError("network forbidden")))
        self.network.enter_context(mock.patch.object(socket, "create_connection",
            side_effect=AssertionError("network forbidden")))

    def tearDown(self):
        try:
            if self.before is not None:
                self.assertEqual(self.before, snapshot(self.home), "input was changed")
        finally:
            self.network.close()
            self.temp.cleanup()

    def put(self, path, content=b"x", age=0):
        p = self.home / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        os.utime(p, (self.NOW - age, self.NOW - age))
        return p

    def scan(self, **kwargs):
        self.before = snapshot(self.home)
        return self.m.scan(str(self.home), now=self.NOW, thresholds=self.LIMITS, **kwargs)

    def category(self, name, **kwargs):
        return self.scan(**kwargs)["categories"][name]

    def main(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.m.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_missing_roots_and_hash_off(self):
        report = self.scan()
        self.assertEqual(report["categories"]["duplicate_files"]["status"], "not_run")
        self.assertTrue(all(c["status"] == "not_present" for k, c in
                            report["categories"].items() if k != "duplicate_files"))
        missing = self.m.scan(str(self.home / "missing"))
        self.assertEqual(missing["categories"]["large_files"]["status"], "not_present")

    def test_six_rules_and_strict_boundaries(self):
        self.put("Desktop/__MACOSX/.Trashes/.DS_Store", b"123")
        self.put("Desktop/__MACOSX/other", b"1234")
        self.put("Pictures/Thumbs.db", b"12")
        self.put("Music/desktop.ini", b"1")
        self.put("Movies/.Spotlight-V100/f", b"1234")
        self.put("Documents/.fseventsd/f", b"12345")
        self.put("Downloads/big", b"a" * 100)
        self.put("Library/Application Support/big", b"b" * 101)
        self.put("Downloads/small", b"c" * 99)
        self.put("Downloads/old", b"a", age=30 * 86400 + 1)
        self.put("Downloads/exact-age", b"b", age=30 * 86400)
        directory = self.home / "Downloads/old-dir"
        directory.mkdir()
        os.utime(directory, (self.NOW - 30 * 86400 - 1,) * 2)
        self.put("Library/Caches/large/f", b"1" * 11)
        self.put("Library/Caches/equal/f", b"2" * 10)
        self.put("Library/Logs/old.log", b"x", age=7 * 86400 + 1)
        self.put("Library/Logs/exact.log", b"x", age=7 * 86400)
        self.put("Library/Logs/empty.log", b"", age=7 * 86400 + 1)
        self.put("Library/Logs/other.txt", b"x", age=7 * 86400 + 1)
        cats = self.scan()["categories"]
        self.assertEqual(cats["system_junk"]["match_count"], 5)
        self.assertEqual(cats["system_junk"]["known_logical_bytes"], 19)
        self.assertEqual(cats["large_files"]["match_count"], 2)
        self.assertEqual(cats["app_caches"]["match_count"], 1)
        self.assertEqual(cats["old_logs"]["match_count"], 1)
        old = cats["old_downloads"]
        self.assertEqual(old["match_count"], 2)
        self.assertEqual(old["known_logical_bytes"], 1)
        self.assertFalse(old["subtotal_complete"])
        self.assertIsNone(next(i for i in old["items"] if i["kind"] == "directory")["size"])

    def test_top_limits_keep_untruncated_totals(self):
        for i in range(35):
            self.put(f"Downloads/big{i:02}", b"x" * (100 + i))
            self.put(f"Library/Caches/app{i:02}/f", b"x" * (11 + i))
            self.put(f"Library/Logs/{i:02}.log", b"x" * (i + 1), age=8 * 86400)
        cats = self.scan()["categories"]
        for key, limit, total in (("large_files", 20, sum(range(100, 135))),
                                  ("app_caches", 20, sum(range(11, 46))),
                                  ("old_logs", 30, sum(range(1, 36)))):
            c = cats[key]
            self.assertEqual((c["match_count"], c["shown_count"]), (35, limit))
            self.assertEqual(c["known_logical_bytes"], total)
            self.assertTrue(c["truncated"])
            self.assertEqual(c["items"], sorted(c["items"], key=lambda i: (-i["known_logical_bytes"], i["path"])))

    def test_hash_off_never_reads_file_bodies_or_unrelated_roots(self):
        self.put("Downloads/a", b"x" * 20)
        self.put("Documents/b", b"x" * 20)
        self.put("Unrelated/no", b"private")
        self.before = snapshot(self.home)
        real_open = os.open
        def only_directories(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_DIRECTORY, "default scan opened a file")
            self.assertNotEqual(str(path), "Unrelated")
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=only_directories), \
             mock.patch.object(self.m.os, "read", side_effect=AssertionError("body read")), \
             mock.patch("builtins.open", side_effect=AssertionError("body open")):
            report = self.m.scan(str(self.home))
        self.assertEqual(report["categories"]["duplicate_files"]["status"], "not_run")

    def test_hash_same_different_size_boundary_and_hardlinks(self):
        a = self.put("Downloads/a", b"a" * 9)
        self.put("Documents/b", b"a" * 9)
        self.put("Desktop/different", b"b" * 9)
        self.put("Desktop/boundary1", b"c" * 8)
        self.put("Downloads/boundary2", b"c" * 8)
        os.link(a, self.home / "Downloads/hardlink")
        c = self.category("duplicate_files", hash_duplicates=True)
        self.assertEqual(c["match_count"], 1)
        self.assertEqual(c["known_logical_bytes"], 18)
        group = c["items"][0]
        self.assertEqual(len(group["files"]), 2)
        self.assertEqual(group["sha256"], hashlib.sha256(b"a" * 9).hexdigest())
        self.assertEqual(c["skips"]["hardlink_alias"], 1)
        self.assertNotIn("wasted", json.dumps(c))

    def test_duplicate_top20_counts_and_totals(self):
        for i in range(23):
            data = bytes([i]) * (9 + i)
            self.put(f"Downloads/{i}", data)
            self.put(f"Documents/{i}", data)
        c = self.category("duplicate_files", hash_duplicates=True)
        self.assertEqual((c["match_count"], c["shown_count"]), (23, 20))
        self.assertEqual(c["known_logical_bytes"], 2 * sum(range(9, 32)))

    def test_hash_io_failure_is_partial_unknown(self):
        self.put("Downloads/a", b"a" * 9)
        self.put("Downloads/b", b"a" * 9)
        self.before = snapshot(self.home)
        with mock.patch.object(self.m.os, "read", side_effect=PermissionError()):
            c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["uncertain_count"], 2)
        self.assertFalse(c["subtotal_complete"])

    def test_hash_detects_changed_metadata_after_read(self):
        self.put("Downloads/a", b"a" * 9)
        self.put("Downloads/b", b"a" * 9)
        self.before = snapshot(self.home)
        real_fstat, real_read = os.fstat, os.read
        read_fds = set()
        def reading(fd, amount):
            data = real_read(fd, amount)
            read_fds.add(fd)
            return data
        def changed(fd):
            st = real_fstat(fd)
            if fd in read_fds and stat.S_ISREG(st.st_mode):
                attrs = {key: getattr(st, key) for key in dir(st) if key.startswith("st_")}
                attrs["st_mtime_ns"] += 1
                return type("ChangedStat", (), attrs)()
            return st
        with mock.patch.object(self.m.os, "read", side_effect=reading), \
             mock.patch.object(self.m.os, "fstat", side_effect=changed):
            c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["match_count"], 0)

    def test_symlinks_and_special_files_are_not_opened(self):
        self.put("Downloads/plain", b"x" * 9)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"private")
        (self.home / "Downloads/file-link").symlink_to(outside / "secret")
        (self.home / "Downloads/dir-link").symlink_to(outside, target_is_directory=True)
        (self.home / "Downloads/broken").symlink_to(outside / "absent")
        os.mkfifo(self.home / "Downloads/fifo")
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        cwd = os.getcwd()
        try:
            os.chdir(self.home)  # Short relative name avoids macOS AF_UNIX length limit.
            sock.bind("Downloads/sock")
        finally:
            os.chdir(cwd)
        before_outside = snapshot(outside)
        c = self.category("large_files", hash_duplicates=True)
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(c["skips"]["symlink"], 3)
        self.assertEqual(c["skips"]["special"], 2)
        self.assertEqual(before_outside, snapshot(outside))

    def test_root_and_intermediate_symlinks_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.home, target_is_directory=True)
        for path in (alias, alias / "child"):
            code, out, err = self.main(["--home", str(path)])
            self.assertEqual(code, 2)
            self.assertNotIn(str(self.base), out + err)
        outside = self.base / "outside"
        outside.mkdir()
        (self.home / "Library").symlink_to(outside, target_is_directory=True)
        c = self.category("app_caches")
        self.assertEqual(c["status"], "partial")
        self.assertGreater(c["error_count"], 0)

    def test_permission_partial_cache_keeps_known_subtotal(self):
        self.put("Library/Caches/app/known", b"12345")
        self.put("Library/Caches/app/blocked/hidden", b"123456789012345")
        self.before = snapshot(self.home)
        real_open = os.open
        def deny(path, flags, *args, **kwargs):
            if path == "blocked":
                raise PermissionError()
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=deny):
            c = self.m.scan(str(self.home), thresholds=self.LIMITS)["categories"]["app_caches"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(c["uncertain_count"], 1)
        self.assertEqual(c["uncertain_items"][0]["known_logical_bytes"], 5)
        self.assertIsNone(c["uncertain_items"][0]["size"])

    def test_enumeration_failure_is_partial_not_false_zero(self):
        self.put("Downloads/a", b"abc")
        self.before = snapshot(self.home)
        with mock.patch.object(self.m.os, "listdir", side_effect=PermissionError()):
            c = self.m.scan(str(self.home))["categories"]["large_files"]
        self.assertEqual(c["status"], "partial")
        self.assertGreater(c["error_count"], 0)

    def test_device_metadata_is_skipped(self):
        self.put("Downloads/device", b"x" * 200)
        self.before = snapshot(self.home)
        real_stat = os.stat
        def device(path, *args, **kwargs):
            st = real_stat(path, *args, **kwargs)
            if path == "device":
                attrs = {key: getattr(st, key) for key in dir(st) if key.startswith("st_")}
                attrs["st_mode"] = stat.S_IFCHR | 0o600
                return type("DeviceStat", (), attrs)()
            return st
        with mock.patch.object(self.m.os, "stat", side_effect=device):
            c = self.m.scan(str(self.home), thresholds=self.LIMITS)["categories"]["large_files"]
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(c["skips"]["special"], 1)

    def test_relative_paths_and_control_character_escaping(self):
        self.put("Downloads/.DS_Store", b"x")
        self.put("Desktop/line\n\x1b[31m/Thumbs.db", b"xx")
        self.before = snapshot(self.home)
        code, out, err = self.main(["--home", str(self.home)])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertNotIn(str(self.home), out)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\n\\u001b", out)
        self.assertNotIn("可释放", out)

    def test_help_missing_and_invalid_arguments_do_not_scan(self):
        with mock.patch.object(self.m, "scan", side_effect=AssertionError("scanned")):
            self.assertEqual(self.main(["--help"])[0], 0)
            for args in ([], ["--home", "relative"], ["--home", "/"],
                         ["--home", str(self.home), "--invalid"]):
                self.assertEqual(self.main(args)[0], 2)

    def test_explicit_empty_output_is_invalid_without_scanning(self):
        with mock.patch.object(self.m, "scan", wraps=self.m.scan) as scanning:
            code, _, _ = self.main(["--home", str(self.home), "--output", ""])
        self.assertEqual(code, 2)
        scanning.assert_not_called()

    def test_output_exclusive_private_and_outside(self):
        self.put("Downloads/.DS_Store", b"x")
        self.before = snapshot(self.home)
        target = self.out / "report.json"
        code, _, err = self.main(["--home", str(self.home), "--output", str(target)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(json.loads(target.read_text())["schema_version"], 1)
        preserved = target.read_bytes()
        with mock.patch.object(self.m, "scan", side_effect=AssertionError("preflight missed")):
            self.assertEqual(self.main(["--home", str(self.home), "--output", str(target)])[0], 2)
            inside = self.home / "report.json"
            self.assertEqual(self.main(["--home", str(self.home), "--output", str(inside)])[0], 2)
        self.assertEqual(preserved, target.read_bytes())

    def test_output_rejects_links_nonprivate_and_missing_parents(self):
        existing = self.out / "existing"
        existing.write_bytes(b"keep")
        link = self.out / "link"
        link.symlink_to(existing)
        parent_link = self.base / "parent-link"
        parent_link.symlink_to(self.out, target_is_directory=True)
        public = self.base / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        paths = [link, parent_link / "x", public / "x", self.base / "missing/x"]
        with mock.patch.object(self.m, "scan", side_effect=AssertionError("preflight missed")):
            for path in paths:
                self.assertEqual(self.main(["--home", str(self.home), "--output", str(path)])[0], 2)
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_output_write_failure_fatal_and_new_file_not_deleted(self):
        target = self.out / "failed.json"
        self.before = snapshot(self.home)
        with mock.patch.object(self.m.json, "dump", side_effect=OSError("synthetic write failure")):
            code, out, err = self.main(["--home", str(self.home), "--output", str(target)])
        self.assertEqual(code, 2)
        self.assertTrue(target.exists())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertNotIn(str(self.base), out + err)
        self.assertIn("incomplete", err)

    def test_output_parent_exchange_detected_before_creation(self):
        target = self.out / "report.json"
        real_scan = self.m.scan
        def exchange(*args, **kwargs):
            report = real_scan(*args, **kwargs)
            self.out.rename(self.base / "moved-reports")
            self.out.mkdir(mode=0o700)
            return report
        with mock.patch.object(self.m, "scan", side_effect=exchange):
            code, _, _ = self.main(["--home", str(self.home), "--output", str(target)])
        self.assertEqual(code, 2)
        self.assertFalse(target.exists())
        self.assertFalse((self.base / "moved-reports/report.json").exists())

    def test_output_second_exclusive_check_catches_race(self):
        target = self.out / "report.json"
        real_scan = self.m.scan
        def create_target(*args, **kwargs):
            report = real_scan(*args, **kwargs)
            target.write_bytes(b"preserve")
            return report
        with mock.patch.object(self.m, "scan", side_effect=create_target):
            self.assertEqual(self.main(["--home", str(self.home), "--output", str(target)])[0], 2)
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_partial_exit_one(self):
        self.put("Downloads/a", b"x")
        self.before = snapshot(self.home)
        with mock.patch.object(self.m.os, "listdir", side_effect=PermissionError()):
            self.assertEqual(self.main(["--home", str(self.home)])[0], 1)

    def test_unreadable_explicit_root_is_partial(self):
        real_open = os.open
        def deny(path, flags, *args, **kwargs):
            if path == "synthetic-home":
                raise PermissionError()
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=deny):
            report = self.m.scan(str(self.home))
        self.assertEqual(report["categories"]["large_files"]["status"], "partial")
        self.assertEqual(report["categories"]["duplicate_files"]["status"], "not_run")

    def test_duplicate_sort_retains_extra_copy_logical_volume_order(self):
        # 4*9 has 27 extra-copy logical bytes; 2*19 has 19. Not a recovery claim.
        for index in range(4):
            self.put(f"Downloads/small{index}", b"a" * 9)
        for index in range(2):
            self.put(f"Documents/large{index}", b"b" * 19)
        c = self.category("duplicate_files", hash_duplicates=True)
        self.assertEqual(c["items"][0]["size"], 9)
        self.assertNotIn("recoverable", json.dumps(c))

    def test_file_replaced_by_symlink_before_hash_open_is_not_read(self):
        self.put("Downloads/a", b"a" * 9)
        self.put("Downloads/b", b"a" * 9)
        outside = self.base / "outside-secret"
        outside.write_bytes(b"a" * 9)
        real_open = os.open
        changed = False
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "a" and not flags & os.O_DIRECTORY and not changed:
                changed = True
                original = self.home / "Downloads/a"
                original.rename(self.home / "Downloads/saved-a")
                original.symlink_to(outside)
            return real_open(path, flags, *args, **kwargs)
        before_outside = (outside.stat().st_atime_ns, outside.stat().st_mtime_ns)
        # Mutation belongs to the adversarial fixture, not the scanner.
        with mock.patch.object(self.m.os, "open", side_effect=swap):
            c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
        self.assertTrue(changed)
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(before_outside, (outside.stat().st_atime_ns, outside.stat().st_mtime_ns))
        (self.home / "Downloads/a").unlink()
        (self.home / "Downloads/saved-a").rename(self.home / "Downloads/a")

    def test_directory_exchange_before_descend_is_not_followed(self):
        self.put("Downloads/sub/file", b"a" * 200)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"b" * 200)
        outside_before = snapshot(outside)
        real_open = os.open
        changed = False
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "sub" and not changed:
                changed = True
                (self.home / "Downloads/sub").rename(self.home / "Downloads/saved")
                (self.home / "Downloads/sub").symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=swap):
            c = self.m.scan(str(self.home), thresholds=self.LIMITS)["categories"]["large_files"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(outside_before, snapshot(outside))
        (self.home / "Downloads/sub").unlink()
        (self.home / "Downloads/saved").rename(self.home / "Downloads/sub")

    def test_parent_rename_during_output_create_reports_failure(self):
        target = self.out / "report.json"
        real_open = os.open
        changed = False
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "report.json" and flags & os.O_CREAT and not changed:
                changed = True
                self.out.rename(self.base / "moved")
                self.out.mkdir(mode=0o700)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=swap):
            code, _, _ = self.main(["--home", str(self.home), "--output", str(target)])
        self.assertEqual(code, 2)
        self.assertFalse(target.exists())
        # A rename at the syscall boundary can leave the new incomplete file on
        # the pinned old parent. Never claim atomic path containment or unlink it.
        self.assertTrue((self.base / "moved/report.json").exists())

    def test_partial_cache_above_threshold_has_null_size(self):
        self.put("Library/Caches/app/known", b"x" * 11)
        self.put("Library/Caches/app/blocked/x", b"hidden")
        self.before = snapshot(self.home)
        real_open = os.open
        def deny(path, flags, *args, **kwargs):
            if path == "blocked":
                raise PermissionError()
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=deny):
            c = self.m.scan(str(self.home), thresholds=self.LIMITS)["categories"]["app_caches"]
        self.assertEqual(c["match_count"], 1)
        self.assertIsNone(c["items"][0]["size"])
        self.assertEqual(c["known_logical_bytes"], 11)
        self.assertFalse(c["subtotal_complete"])

    def test_metadata_stat_failure_not_zero_complete(self):
        self.put("Downloads/denied", b"x" * 100)
        self.before = snapshot(self.home)
        real_stat = os.stat
        def deny(path, *args, **kwargs):
            if path == "denied":
                raise PermissionError()
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(self.m.os, "stat", side_effect=deny):
            c = self.m.scan(str(self.home))["categories"]["large_files"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["error_count"], 1)
        self.assertFalse(c["subtotal_complete"])

    def test_hardlink_aliases_without_independent_copy_do_not_hash(self):
        a = self.put("Downloads/a", b"x" * 20)
        os.link(a, self.home / "Downloads/b")
        self.before = snapshot(self.home)
        with mock.patch.object(self.m.os, "read", side_effect=AssertionError("no independent copy")):
            c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
        self.assertEqual(c["match_count"], 0)
        self.assertEqual(c["known_logical_bytes"], 0)
        self.assertEqual(c["skips"]["hardlink_alias"], 1)

    def test_opened_fifo_replacement_is_rejected_before_read(self):
        self.put("Downloads/a", b"a" * 9)
        self.put("Downloads/b", b"a" * 9)
        real_open, real_read = os.open, os.read
        changed = False
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "a" and not flags & os.O_DIRECTORY and not changed:
                changed = True
                (self.home / "Downloads/a").rename(self.home / "Downloads/saved-a")
                os.mkfifo(self.home / "Downloads/a")
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)
        def read_regular(fd, amount):
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
            return real_read(fd, amount)
        with mock.patch.object(self.m.os, "open", side_effect=swap), \
             mock.patch.object(self.m.os, "read", side_effect=read_regular):
            c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["match_count"], 0)
        (self.home / "Downloads/a").unlink()
        (self.home / "Downloads/saved-a").rename(self.home / "Downloads/a")

    def test_hash_inode_and_size_change_rejected_before_read(self):
        self.put("Downloads/a", b"a" * 9)
        self.put("Downloads/b", b"a" * 9)
        self.before = snapshot(self.home)
        real_fstat = os.fstat
        for attr in ("st_ino", "st_size"):
            def altered(fd):
                st = real_fstat(fd)
                if stat.S_ISREG(st.st_mode):
                    attrs = {key: getattr(st, key) for key in dir(st) if key.startswith("st_")}
                    attrs[attr] += 1
                    return type("ChangedStat", (), attrs)()
                return st
            with mock.patch.object(self.m.os, "fstat", side_effect=altered), \
                 mock.patch.object(self.m.os, "read", side_effect=AssertionError("changed file read")):
                c = self.m.scan(str(self.home), hash_duplicates=True, thresholds=self.LIMITS)["categories"]["duplicate_files"]
            self.assertEqual(c["status"], "partial")
            self.assertEqual(c["match_count"], 0)

    def test_partial_junk_directory_keeps_known_nested_subtotal(self):
        self.put("Desktop/__MACOSX/.Trashes/.DS_Store", b"123")
        self.put("Desktop/__MACOSX/blocked/f", b"hidden")
        self.before = snapshot(self.home)
        real_open = os.open
        def deny(path, flags, *args, **kwargs):
            if path == "blocked":
                raise PermissionError()
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.m.os, "open", side_effect=deny):
            c = self.m.scan(str(self.home))["categories"]["system_junk"]
        self.assertEqual(c["match_count"], 1)
        self.assertEqual(c["known_logical_bytes"], 3)
        self.assertIsNone(c["items"][0]["size"])
        self.assertEqual(c["status"], "partial")

    def test_old_downloads_are_one_level_not_recursive(self):
        self.put("Downloads/new-dir/nested-old", b"x", age=31 * 86400)
        directory = self.home / "Downloads/new-dir"
        os.utime(directory, (self.NOW,) * 2)
        self.assertEqual(self.category("old_downloads")["match_count"], 0)

    def test_pinned_scan_root_rename_is_partial_not_missing(self):
        self.put("Downloads/a", b"x" * 100)
        original_inventory = self.m.inventory
        moved = self.base / "moved-home"
        def move(chain):
            self.home.rename(moved)
            return original_inventory(chain)
        try:
            with mock.patch.object(self.m, "inventory", side_effect=move):
                c = self.m.scan(str(self.home))["categories"]["large_files"]
            self.assertEqual(c["status"], "partial")
            self.assertGreater(c["error_count"], 0)
        finally:
            moved.rename(self.home)

    def cli(self, args, code=False):
        isolated = self.base / "cli-home"
        cwd = self.base / "cli-cwd"
        isolated.mkdir(exist_ok=True, mode=0o700)
        cwd.mkdir(exist_ok=True, mode=0o700)
        env = {"HOME": str(isolated), "TMPDIR": str(self.base), "PATH": os.environ.get("PATH", "")}
        command = [sys.executable, "-I", "-B"]
        # Direct CLI has no network imports; the import probe blocks socket operations too.
        command += ["-c", args] if code else [str(SCRIPT), *args]
        return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=20)

    def test_import_subprocess_has_no_side_effects(self):
        probe = f'''import contextlib, importlib.util, io, os, pathlib, socket
from unittest import mock
spec = importlib.util.spec_from_file_location("safe_import", {str(SCRIPT)!r})
m = importlib.util.module_from_spec(spec)
buf = io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf), mock.patch.object(pathlib.Path, "home", side_effect=AssertionError("home")), mock.patch.object(os, "listdir", side_effect=AssertionError("scan")), mock.patch.object(os, "scandir", side_effect=AssertionError("scan")), mock.patch.object(os, "open", side_effect=AssertionError("open")), mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
    spec.loader.exec_module(m)
assert not buf.getvalue(), buf.getvalue()
'''
        result = self.cli(probe, code=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_actual_cli_help_missing_sparse_boundary_and_json(self):
        self.assertEqual(self.cli(["--help"]).returncode, 0)
        self.assertEqual(self.cli([]).returncode, 2)
        sparse = self.put("Downloads/exact-100MiB", b"")
        with sparse.open("r+b") as f:
            f.truncate(100 * 1024 * 1024)
        self.before = snapshot(self.home)
        target = self.out / "cli.json"
        result = self.cli(["--home", str(self.home), "--output", str(target)])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(target.read_text())
        self.assertEqual(report["categories"]["large_files"]["match_count"], 1)
        self.assertEqual(report["categories"]["duplicate_files"]["status"], "not_run")
        self.assertNotIn(str(self.home), result.stdout)


if __name__ == "__main__":
    unittest.main()
