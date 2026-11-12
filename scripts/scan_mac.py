#!/usr/bin/env python3
"""Read-only, explicitly scoped metadata inventory. Python 3.12 / macOS.

Names are candidates, not deletion advice. FD-relative operations reduce path
redirection; they are not an OS sandbox or a concurrent-filesystem snapshot.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
import stat
import sys
import time

PERSONAL = ("Desktop", "Downloads", "Documents", "Pictures", "Movies", "Music")
DUP_ROOTS = ("Downloads", "Desktop", "Documents")
ROOTS = PERSONAL + ("Library/Application Support", "Library/Caches", "Library/Logs")
SCOPES = {
    "system_junk": PERSONAL,
    "large_files": PERSONAL + ("Library/Application Support",),
    "duplicate_files": DUP_ROOTS,
    "old_downloads": ("Downloads",),
    "app_caches": ("Library/Caches",),
    "old_logs": ("Library/Logs",),
}
JUNK_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
JUNK_DIRS = {"__MACOSX", ".Spotlight-V100", ".Trashes", ".fseventsd"}
DEFAULT_THRESHOLDS = {"large": 100 * 1024**2, "duplicate": 1024,
                      "cache": 10 * 1024**2, "download_age": 30 * 86400,
                      "log_age": 7 * 86400}
TOP = {"system_junk": 10, "large_files": 20, "duplicate_files": 20,
       "old_downloads": 10, "app_caches": 20, "old_logs": 30}


class BoundaryError(OSError):
    """A path identity or no-follow boundary could not be established."""


def fmt_size(size_bytes):
    if size_bytes is None:
        return "unknown"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TiB"


def absolute_parts(path):
    path = os.fspath(path)
    if not path.startswith("/") or path == "/" or "\x00" in path:
        raise ValueError("an explicit absolute non-root path is required")
    parts = path.split("/")[1:]
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("path components must be explicit (no dot or empty components)")
    return parts


def identity(st):
    return st.st_dev, st.st_ino


def stamp(st):
    return identity(st), st.st_size, st.st_mtime_ns, st.st_ctime_ns


class DirectoryChain:
    """Pin every directory component, and recheck its parent/name association.

    The anchor is /, not resolve(). A renamed/exchanged parent fails verify().
    Checks before/after operations detect many races, not every possible race.
    """
    def __init__(self, path):
        self.fds = []
        self.names = []
        try:
            parts = absolute_parts(path)
            self.fds.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            for name in parts:
                self.push(name)
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def verify(self):
        for index, name in enumerate(self.names):
            try:
                current = os.stat(name, dir_fd=self.fds[index], follow_symlinks=False)
                pinned = os.fstat(self.fds[index + 1])
            except OSError as exc:
                # A previously pinned component disappearing is a change, not
                # evidence that an optional scan root was absent at discovery.
                raise BoundaryError("pinned directory unavailable") from exc
            if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(pinned):
                raise BoundaryError("directory identity changed")

    def push(self, name, expected=None):
        self.verify()
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            current = os.fstat(fd)
            if not stat.S_ISDIR(current.st_mode) or (expected is not None and identity(current) != identity(expected)):
                raise BoundaryError("directory identity changed")
            self.fds.append(fd)
            self.names.append(name)
        except BaseException:
            os.close(fd)
            raise
        try:
            self.verify()
        except BaseException:
            self.pop()
            raise

    def pop(self):
        os.close(self.fds.pop())
        self.names.pop()

    @contextmanager
    def descend(self, names, expected=None):
        depth = len(self.fds)
        try:
            for i, name in enumerate(names):
                self.push(name, expected if i == len(names) - 1 else None)
            yield self
        finally:
            while len(self.fds) > depth:
                self.pop()

    def close(self):
        while self.fds:
            os.close(self.fds.pop())
        self.names.clear()


def issue(events, path, operation, error):
    # Never include str(error): OS error text may disclose an absolute path.
    events.append({"path": path, "operation": operation, "reason": type(error).__name__})


def inventory(chain):
    """One shared metadata walk of the nine explicit roots, never home itself."""
    records, errors, skips, roots = [], [], [], {}
    directories = {"": identity(os.fstat(chain.fd))}

    def walk(rel, node):
        first_error = len(errors)
        before = os.fstat(chain.fd)
        total = 0
        try:
            chain.verify()
            names = sorted(os.listdir(chain.fd))
            chain.verify()
            for name in names:
                path = rel + "/" + name
                try:
                    chain.verify()
                    st = os.stat(name, dir_fd=chain.fd, follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                        skips.append({"path": path, "reason": "symlink" if stat.S_ISLNK(st.st_mode) else "special"})
                        continue
                    entry = {"path": path, "st": st, "directory": stat.S_ISDIR(st.st_mode),
                             "known": 0 if stat.S_ISDIR(st.st_mode) else st.st_size, "complete": True}
                    records.append(entry)
                    if entry["directory"]:
                        entry["complete"] = False
                        with chain.descend([name], expected=st):
                            directories[path] = identity(os.fstat(chain.fd))
                            walk(path, entry)
                    total += entry["known"]
                except (OSError, RecursionError) as exc:
                    issue(errors, path, "metadata", exc)
            chain.verify()
            if stamp(before) != stamp(os.fstat(chain.fd)):
                raise BoundaryError("directory changed during enumeration")
        except (OSError, RecursionError) as exc:
            issue(errors, rel, "enumerate", exc)
        node["known"] = total
        node["complete"] = len(errors) == first_error

    for root in ROOTS:
        try:
            with chain.descend(root.split("/")):
                # Preserve intermediate Library identity for later file opens.
                base = len(chain.fds) - len(root.split("/"))
                for i in range(len(root.split("/"))):
                    directories["/".join(root.split("/")[:i + 1])] = identity(os.fstat(chain.fds[base + i]))
                node = {"known": 0, "complete": True}
                walk(root, node)
                roots[root] = "complete" if node["complete"] else "partial"
        except FileNotFoundError:
            roots[root] = "not_present"
        except OSError as exc:
            roots[root] = "partial"
            issue(errors, root, "open_root", exc)
    return records, errors, skips, roots, directories


def file_hash(chain, entry, directories):
    """Open relative to pinned directories; check identity and metadata around read."""
    parts = entry["path"].split("/")
    depth = len(chain.fds)
    fd = None
    try:
        for i, name in enumerate(parts[:-1]):
            chain.push(name)
            if identity(os.fstat(chain.fd)) != directories.get("/".join(parts[:i + 1])):
                raise BoundaryError("directory changed since inventory")
        chain.verify()
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=chain.fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stamp(before) != stamp(entry["st"]):
            raise BoundaryError("file changed since inventory")
        digest = hashlib.sha256()
        length = 0
        while True:
            chain.verify()
            data = os.read(fd, 65536)
            if not data:
                break
            length += len(data)
            if length > before.st_size:
                raise BoundaryError("file grew during read")
            digest.update(data)
        chain.verify()
        after = os.fstat(fd)
        named = os.stat(parts[-1], dir_fd=chain.fd, follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or stamp(before) != stamp(after)
                or stamp(named) != stamp(after) or length != after.st_size):
            raise BoundaryError("file changed during read")
        return digest.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        while len(chain.fds) > depth:
            chain.pop()


def under(path, roots):
    return any(path == root or path.startswith(root + "/") for root in roots)


def item(entry, unknown_directory=False):
    complete = entry["complete"] and not unknown_directory
    known = 0 if unknown_directory else entry["known"]
    return {"path": entry["path"], "kind": "directory" if entry["directory"] else "file",
            "size": known if complete else None, "known_logical_bytes": known,
            "size_complete": complete, "mtime": entry["st"].st_mtime}


def category(items, uncertain, errors, skips, roots, limit, enabled=True):
    status = ("not_run" if not enabled else "partial" if errors else
              "not_present" if all(s == "not_present" for s in roots.values()) else "complete")
    # Preserve the original Top-N intent, but never call extra-copy logical
    # bytes recoverable capacity (hardlink aliases have already been excluded).
    def ranking(value):
        volume = (value["size"] * (len(value["files"]) - 1)
                  if "files" in value else value["known_logical_bytes"])
        return -volume, value.get("path", value.get("files", [""])[0])
    items.sort(key=ranking)
    uncertain.sort(key=lambda i: (-i["known_logical_bytes"], i["path"]))
    return {"status": status, "roots": roots, "match_count": len(items),
            "shown_count": min(limit, len(items)), "truncated": len(items) > limit,
            "known_logical_bytes": sum(i["known_logical_bytes"] for i in items),
            "subtotal_complete": status == "complete" and not uncertain and all(i["size_complete"] for i in items),
            "items": items[:limit], "uncertain_count": len(uncertain),
            "uncertain_known_logical_bytes": sum(i["known_logical_bytes"] for i in uncertain),
            "uncertain_items": uncertain[:limit], "uncertain_truncated": len(uncertain) > limit,
            "error_count": len(errors), "errors": errors,
            "skip_count": len(skips), "skips": dict(Counter(s["reason"] for s in skips))}


def scan(home, *, hash_duplicates=False, now=None, thresholds=None):
    """Return a JSON-compatible report; no printing/writing. Home must be explicit.

    now (Unix seconds) and thresholds (same keys as DEFAULT_THRESHOLDS) are
    injectable for synthetic tests, not additional CLI options.
    """
    absolute_parts(home)
    now = time.time() if now is None else now
    limits = DEFAULT_THRESHOLDS.copy()
    if thresholds:
        if not thresholds.keys() <= limits.keys() or any(v < 0 for v in thresholds.values()):
            raise ValueError("invalid thresholds")
        limits.update(thresholds)
    chain = None
    try:
        root_error = None
        try:
            chain = DirectoryChain(home)
        except FileNotFoundError:
            pass
        except OSError as exc:
            if isinstance(exc, BoundaryError) or exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise
            root_error = exc
        if chain is None:
            records, errors, skips, directories = [], [], [], {}
            roots = dict.fromkeys(ROOTS, "partial" if root_error else "not_present")
            if root_error:
                for root in ROOTS:
                    issue(errors, root, "open_home", root_error)
        else:
            records, errors, skips, roots, directories = inventory(chain)
        matches = {k: [] for k in SCOPES}
        uncertain = {k: [] for k in SCOPES}
        covered = []
        for entry in sorted(records, key=lambda e: (e["path"].count("/"), e["path"])):
            path, directory = entry["path"], entry["directory"]
            name = path.rsplit("/", 1)[-1]
            if under(path, PERSONAL) and name in (JUNK_DIRS if directory else JUNK_NAMES) and not under(path, covered):
                matches["system_junk"].append(item(entry))
                if directory:
                    covered.append(path)
            if not directory and under(path, SCOPES["large_files"]) and entry["known"] >= limits["large"]:
                matches["large_files"].append(item(entry))
            if path.startswith("Downloads/") and path.count("/") == 1 and entry["st"].st_mtime < now - limits["download_age"]:
                matches["old_downloads"].append(item(entry, unknown_directory=directory))
            if directory and path.startswith("Library/Caches/") and path.count("/") == 2:
                value = item(entry)
                if entry["known"] > limits["cache"]:
                    matches["app_caches"].append(value)
                elif not entry["complete"]:
                    uncertain["app_caches"].append(value)
            if not directory and path.startswith("Library/Logs/") and name.endswith(".log") and entry["known"] > 0 and entry["st"].st_mtime < now - limits["log_age"]:
                matches["old_logs"].append(item(entry))
        hash_errors, hash_skips = [], []
        if hash_duplicates:
            sizes = defaultdict(list)
            seen = set()
            for entry in records:
                if entry["directory"] or not under(entry["path"], DUP_ROOTS) or entry["known"] <= limits["duplicate"]:
                    continue
                inode = identity(entry["st"])
                if inode in seen:
                    hash_skips.append({"path": entry["path"], "reason": "hardlink_alias"})
                else:
                    seen.add(inode)
                    sizes[entry["known"]].append(entry)
            for size, entries in sizes.items():
                if len(entries) < 2:
                    continue
                hashes = defaultdict(list)
                for entry in entries:
                    try:
                        digest = file_hash(chain, entry, directories)
                        hashes[digest].append(entry["path"])
                    except OSError as exc:
                        issue(hash_errors, entry["path"], "hash", exc)
                        value = item(entry)
                        value.update(size=None, known_logical_bytes=0, size_complete=False)
                        uncertain["duplicate_files"].append(value)
                for digest, paths in hashes.items():
                    if len(paths) > 1:
                        matches["duplicate_files"].append({"files": sorted(paths), "sha256": digest,
                            "size": size, "size_complete": True, "known_logical_bytes": size * len(paths),
                            "classification": "suspected_duplicate_digest"})
        categories = {}
        for key, scope in SCOPES.items():
            relevant = lambda e: under(e["path"], scope) and (key != "old_downloads" or e["path"].count("/") <= 1)
            enabled = key != "duplicate_files" or hash_duplicates
            errs = [e for e in errors if relevant(e)] if enabled else []
            skipped = [s for s in skips if relevant(s)] if enabled else []
            if key == "duplicate_files":
                errs += hash_errors
                skipped += hash_skips
            states = {r: roots[r] if enabled else "not_run" for r in scope}
            categories[key] = category(matches[key], uncertain[key], errs, skipped, states, TOP[key], enabled)
        return {"schema_version": 1, "generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "enabled_categories": [k for k in SCOPES if k != "duplicate_files" or hash_duplicates],
                "thresholds": limits, "categories": categories,
                "notes": ["Relative paths; known logical byte subtotals only; categories overlap.",
                          "No physical/APFS recovery estimate or safe-deletion promise.",
                          "Digest matches are suspected duplicates, not a deletion decision.",
                          "No filesystem snapshot or OS sandbox; concurrent changes may escape detection."]}
    finally:
        if chain is not None:
            chain.close()


class OutputTarget:
    """Preflight and exclusive creation through the same pinned private parent."""
    def __init__(self, output, home):
        self.parent = self.home = None
        self.home_path = os.fspath(home)
        try:
            parts, home_parts = absolute_parts(output), absolute_parts(home)
            if parts[:len(home_parts)] == home_parts:
                raise BoundaryError("output must be outside scan root")
            self.name = parts[-1]
            self.parent = DirectoryChain("/" + "/".join(parts[:-1]))
            try:
                self.home = DirectoryChain(home)
            except FileNotFoundError:
                pass
            self.verify()
            try:
                os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise BoundaryError("output already exists")
        except BaseException:
            self.close()
            raise

    def verify(self):
        self.parent.verify()
        st = os.fstat(self.parent.fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise BoundaryError("output parent is not private")
        if self.home is not None:
            self.home.verify()
            if identity(os.fstat(self.home.fd)) in [identity(os.fstat(fd)) for fd in self.parent.fds]:
                raise BoundaryError("output is inside scan root")
        else:
            try:
                appeared = DirectoryChain(self.home_path)
            except FileNotFoundError:
                return
            appeared.close()
            raise BoundaryError("scan root appeared after output preflight")

    def write(self, report):
        self.verify()
        fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.parent.fd)
        try:
            os.fchmod(fd, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BoundaryError("output is not a regular file")
            self.verify()
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
                json.dump(report, stream, ensure_ascii=True, indent=2, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(fd)
            self.verify()
            if identity(os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)) != identity(os.fstat(fd)):
                raise BoundaryError("output name changed")
        finally:
            os.close(fd)

    def close(self):
        for chain in (self.home, self.parent):
            if chain is not None:
                chain.close()


def print_summary(report):
    print("Read-only candidate inventory; logical subtotals, not reclaimable space.")
    for key, value in report["categories"].items():
        # JSON escaping applies to paths and all untrusted names, including controls.
        print(json.dumps({"category": key, **value}, ensure_ascii=True, allow_nan=False))


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid user arguments, possibly absolute paths.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments; use --help.\n")


def main(argv=None):
    parser = SafeParser(prog="scan_mac.py", description="Read-only inventory of an explicitly authorized home-layout directory.")
    parser.add_argument("--home", required=True, help="explicit absolute authorized directory (no symlink components)")
    parser.add_argument("--hash-duplicates", action="store_true", help="allow content reads for same-size duplicate candidates")
    parser.add_argument("--output", help="new JSON file outside scan root; existing private parent required")
    target = None
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code
        absolute_parts(args.home)
        if args.output is not None:
            target = OutputTarget(args.output, args.home)
        report = scan(args.home, hash_duplicates=args.hash_duplicates)
        if target is not None:
            target.write(report)
        print_summary(report)
        return 1 if any(c["status"] == "partial" for c in report["categories"].values()) else 0
    except (OSError, ValueError, RecursionError):
        print("Invalid scope or fatal scan/output failure; any newly created report may be incomplete. No file was deleted.", file=sys.stderr)
        return 2
    finally:
        if target is not None:
            target.close()


if __name__ == "__main__":
    sys.exit(main())
