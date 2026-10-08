#!/usr/bin/env python3
"""Virus-scan the files attached to a "Submit a package" issue.

Run by .github/workflows/scan-submission.yml. Downloads every file attached to
the issue, unpacks archives (including archives inside archives), scans it all
with ClamAV plus a few extra checks, then:
  clean         check it's an Ember package that follows the community rules,
                add it to the community repository and close the issue
  dangerous     remove the file links from the issue, close it and lock it
  not valid     explain what to fix; editing the issue scans it again
  no file       ask the submitter to edit the issue and attach one
The result is one comment on the issue, updated on every re-scan.

  scan-submission.py --local FILE...   scan and check files, change nothing
  scan-submission.py --remove NAME     take a package out of the community repository
"""
import bz2
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
CLAMAV_IMAGE = "clamav/clamav:stable"
MARKER = "<!-- ember-package-scan -->"
SUBMISSION_LABEL = "package-submission"
LABELS = {"published": "published", "rejected": "scan: rejected", "needs-changes": "scan: needs changes",
          "needs-file": "scan: needs file", "error": "scan: error"}
COMMUNITY = "community/x86_64"
OWNERS = "community/owners.tsv"
OFFICIAL_INDEX = "x86_64/index"
COMMUNITY_PUBKEY = ".github/community.pub"
GUIDE = f"https://github.com/{REPO or 'Cherry-Systems/ember-packages'}/blob/main/CONTRIBUTING.md"

MAX_FILES = 10
MAX_DOWNLOAD = 30 << 20           # GitHub's own limit is 25 MB
MAX_UNPACKED = 2 << 30            # more than this from 25 MB is an archive bomb
MAX_MEMBERS = 200_000
MAX_DEPTH = 4                     # archives inside archives

URL_CHARS = r"[^\s)\]<>\"']+"
ATTACHMENT = re.compile(r"https://github\.com/(?:user-attachments/(?:files|assets)/|[\w.-]+/[\w.-]+/files/\d+/)"
                        + URL_CHARS)

# Content that only malware has a reason to contain: reject outright.
DANGEROUS_CONTENT = [
    (re.compile(rb"stratum\d?\+(?:tcp|ssl|tls)://"), "a cryptocurrency miner (mining pool address)"),
]
DANGEROUS_PATHS = [
    (re.compile(r"(^|/)etc/ld\.so\.preload$"),
     "/etc/ld.so.preload, which forces a library into every program (a common rootkit trick)"),
]
# Worth a reviewer's attention in scripts, but normal programs can have these too.
SUSPICIOUS_CONTENT = [
    (re.compile(rb"/dev/(?:tcp|udp)/\S+/\d+"), "opens network connections from a shell script (/dev/tcp)"),
    (re.compile(rb"(?:curl|wget)[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
     "downloads a script and runs it straight away"),
]
SCAN_CONTENT_LIMIT = 64 << 20


class Rejected(Exception):
    """The submission is unsafe; the message says why, in plain words."""


class NeedsChanges(Exception):
    """The submission is safe but can't be published as it is; the message says why."""


def api(method, path, data=None):
    req = urllib.request.Request(
        f"{API}/repos/{REPO}{path}", method=method,
        data=None if data is None else json.dumps(data).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ember-package-scan"})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    return json.loads(body) if body else None


def attachment_pattern():
    extra = os.environ.get("EXTRA_FILE_URL_PREFIX", "").strip()
    if not extra:
        return ATTACHMENT
    return re.compile(f"(?:{ATTACHMENT.pattern})|{re.escape(extra)}{URL_CHARS}")


def find_attachments(body):
    urls = []
    for m in attachment_pattern().finditer(body or ""):
        if m.group(0) not in urls:
            urls.append(m.group(0))
    return urls


def safe_name(name, fallback):
    name = re.sub(r"[^\w.+-]", "_", os.path.basename(urllib.parse.unquote(name)))
    return name.strip("._") or fallback


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "ember-package-scan"})
    total = 0
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        while chunk := r.read(1 << 16):
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise Rejected(f"{os.path.basename(dest)} is bigger than GitHub allows ({MAX_DOWNLOAD >> 20} MB)")
            f.write(chunk)
    return total


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


class Unpacker:
    """Unpacks archives without trusting them: nothing is written outside the
    output folder, links are never followed, and sizes are capped."""

    def __init__(self):
        self.unpacked = 0
        self.members = 0
        self.warnings = []
        self.packages = []
        self.found = []           # (archive, .PKGINFO fields) for each Ember package

    def check_name(self, archive, name, strict):
        """The member's path inside the output folder, or None to skip it."""
        parts = name.replace("\\", "/").split("/")
        if name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name):
            if strict:
                raise Rejected(f"{archive} tries to put files outside its own folder ({name})")
            return None
        return [p for p in parts if p not in ("", ".")]

    def count(self, archive, size):
        self.members += 1
        self.unpacked += size
        if self.members > MAX_MEMBERS or self.unpacked > MAX_UNPACKED:
            raise Rejected(f"{archive} unpacks to an enormous size or number of files (an archive bomb)")

    def write(self, out, parts, src):
        if not parts:
            return
        dest = os.path.join(out, *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            limit = MAX_UNPACKED - self.unpacked + 1
            while chunk := src.read(1 << 20):
                limit -= len(chunk)
                if limit < 0:
                    raise Rejected("an archive unpacks to an enormous size (an archive bomb)")
                f.write(chunk)

    def unpack(self, path, out, label, depth=0):
        """Unpack path into out if it's an archive. Returns True if it was one."""
        if depth >= MAX_DEPTH:
            return False
        # Only the upload and the package inside it get unpacked by ember-pkg, so
        # only those must be well-formed. Deeper files that merely look like
        # archives (e.g. Python's zipimport .pyc) are still scanned as plain files.
        strict = depth <= 1
        if zipfile.is_zipfile(path):
            self.unpack_zip(path, out, label, strict)
        elif self.is_tar(path):
            self.unpack_tar(path, out, label, strict)
        elif self.is_plain_gzip(path):
            os.makedirs(out, exist_ok=True)
            with gzip.open(path) as src:
                self.write(out, [safe_name(os.path.basename(path).removesuffix(".gz"), "file")], src)
        else:
            return False
        for root, _, files in os.walk(out):
            for f in files:
                p = os.path.join(root, f)
                if f == ".PKGINFO":
                    info = self.read_pkginfo(p, label)
                    if root == out:
                        self.found.append((path, info))
                else:
                    self.unpack(p, p + ".unpacked", f"{label}/{os.path.relpath(p, out)}", depth + 1)
        return True

    @staticmethod
    def is_tar(path):
        try:
            return tarfile.is_tarfile(path)
        except (OSError, EOFError, tarfile.TarError):
            return False

    @staticmethod
    def is_plain_gzip(path):
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"

    def unpack_zip(self, path, out, label, strict):
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.flag_bits & 0x1:
                        raise Rejected(f"{label} is password-protected, so it can't be checked")
                    parts = self.check_name(label, info.filename, strict)
                    self.count(label, info.file_size)
                    mode = info.external_attr >> 16
                    if parts is None or info.is_dir() or stat.S_ISLNK(mode):
                        continue
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        self.warnings.append(f"{label}: {info.filename} runs with extra privileges (setuid/setgid)")
                    with z.open(info) as src:
                        self.write(out, parts, src)
        except (zipfile.BadZipFile, NotImplementedError, EOFError, OSError, zlib.error) as e:
            if strict:
                raise Rejected(f"{label} is a damaged zip file, so it can't be checked ({e})")

    def unpack_tar(self, path, out, label, strict):
        try:
            with tarfile.open(path) as t:
                for m in t:
                    parts = self.check_name(label, m.name, strict)
                    if m.islnk():
                        self.check_name(label, m.linkname, strict)
                    self.count(label, m.size)
                    if m.ischr() or m.isblk() or m.isfifo():
                        self.warnings.append(f"{label}: {m.name} is a device file, which packages shouldn't contain")
                    if parts is None or not m.isfile():
                        continue
                    if m.mode & (stat.S_ISUID | stat.S_ISGID):
                        self.warnings.append(f"{label}: {m.name} runs with extra privileges (setuid/setgid)")
                    src = t.extractfile(m)
                    if src:
                        self.write(out, parts, src)
        except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
            if strict:
                raise Rejected(f"{label} is a damaged archive, so it can't be checked ({e})")

    def read_pkginfo(self, path, label):
        info = {}
        with open(path, errors="replace") as f:
            for line in f:
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip()
        if info.get("name"):
            self.packages.append(f"{info['name']} {info.get('version', '')}".strip())
        return info


def check_contents(top, unpacker):
    """Extra checks ClamAV doesn't do: paths and text only malware needs."""
    for root, _, files in os.walk(top):
        for f in files:
            p = os.path.join(root, f)
            rel = os.path.relpath(p, top)
            inside = re.sub(r"\.unpacked(/|$)", "/", rel)
            for pattern, what in DANGEROUS_PATHS:
                if pattern.search(inside):
                    raise Rejected(f"{inside} installs {what}")
            with open(p, "rb") as fh:
                data = fh.read(SCAN_CONTENT_LIMIT)
            for pattern, what in DANGEROUS_CONTENT:
                if pattern.search(data):
                    raise Rejected(f"{inside} contains {what}")
            for pattern, what in SUSPICIOUS_CONTENT if data.startswith(b"#!") else []:
                if pattern.search(data):
                    unpacker.warnings.append(f"{inside} {what}")


def clamscan(top):
    """Scan everything under top with an up-to-date ClamAV. Returns (version, findings)."""
    script = ("freshclam --quiet --no-warnings >/dev/null 2>&1 || echo 'freshclam failed, using bundled database' >&2;"
              " clamscan --version;"
              " exec clamscan --recursive --infected --no-summary --detect-pua=yes --alert-encrypted=yes"
              " --alert-exceeds-max=yes --max-filesize=500M --max-scansize=2000M --max-files=200000 /scan")
    r = subprocess.run(["docker", "run", "--rm", "-v", f"{top}:/scan:ro", "--entrypoint", "sh", CLAMAV_IMAGE,
                        "-c", script], capture_output=True, text=True, timeout=1500)
    lines = r.stdout.splitlines()
    version = lines[0] if lines else "ClamAV"
    if r.returncode not in (0, 1):
        raise RuntimeError(f"ClamAV failed (exit {r.returncode}): {r.stderr.strip()[-500:]}")
    findings = []
    for line in lines[1:]:
        m = re.match(r"/scan/(.*): (\S+) FOUND$", line)
        if m:
            findings.append((re.sub(r"\.unpacked(/|$)", "/", m.group(1)), m.group(2)))
    # ClamAV reports a find in every archive around it too; keep the innermost.
    return version, [(p, s) for p, s in findings
                     if not any(q.startswith(p + "/") and t == s for q, t in findings)]


def explain(signature):
    if signature.startswith("Heuristics.Limits.Exceeded"):
        return " (too big to scan completely)"
    if signature.startswith("Heuristics.Encrypted"):
        return " (password-protected, so it can't be checked)"
    return ""


def scan(paths, names, keep_dir):
    """Scan downloaded files. Returns (report lines, warnings, ClamAV version,
    [(copy of each Ember package found, its .PKGINFO fields)]); raises Rejected
    if anything is dangerous."""
    work = tempfile.mkdtemp(prefix="scan-")
    try:
        top = os.path.join(work, "files")
        os.makedirs(top)
        unpacker = Unpacker()
        report = []
        for path, name in zip(paths, names):
            shutil.copy(path, os.path.join(top, name))
            size = os.path.getsize(path)
            before = len(unpacker.packages)
            is_archive = unpacker.unpack(path, os.path.join(top, name + ".unpacked"), name)
            line = f"`{name}`: {size / 1024:.0f} KB, SHA-256 `{sha256(path)}`"
            found = unpacker.packages[before:]
            if found:
                line += f", Ember package(s): {', '.join(found)}"
            elif not is_archive:
                line += " (not an archive)"
            report.append(line)
        check_contents(top, unpacker)
        version, findings = clamscan(top)
        dangerous = [(p, s) for p, s in findings if not s.startswith("PUA.") or re.search(r"miner", s, re.I)]
        if dangerous:
            raise Rejected("ClamAV found " + "; ".join(f"**{s}**{explain(s)} in {p}" for p, s in dangerous))
        for p, s in findings:
            unpacker.warnings.append(f"{p} looks like a potentially unwanted program to ClamAV ({s})")
        packages = []
        for i, (archive, info) in enumerate(unpacker.found):
            kept = os.path.join(keep_dir, f"package{i}")
            shutil.copy(archive, kept)
            packages.append((kept, info))
        return report, unpacker.warnings, version, packages
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---- community repository ----------------------------------------------------
# The same rules ember-pkg enforces when installing a community package: only new
# files in the usual places for programs, nothing privileged, nothing that could
# write outside the package.

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+~_]*-[0-9]+$")
MUSL_LOADER = "/lib/ld-musl-x86_64.so.1"


def elf_problem(data):
    """Why an ELF program can't run on Ember, or None if it can (or isn't ELF)."""
    if data[:4] != b"\x7fELF":
        return None
    if len(data) < 64 or data[4] != 2 or data[5] != 1 or int.from_bytes(data[18:20], "little") != 62:
        return "isn't built for 64-bit Intel/AMD PCs (x86_64)"
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    for i in range(int.from_bytes(data[56:58], "little")):
        ph = data[phoff + i * phentsize:phoff + (i + 1) * phentsize]
        if len(ph) >= 40 and int.from_bytes(ph[0:4], "little") == 3:  # PT_INTERP
            off, size = int.from_bytes(ph[8:16], "little"), int.from_bytes(ph[32:40], "little")
            loader = data[off:off + size].rstrip(b"\0").decode(errors="replace")
            if loader != MUSL_LOADER:
                return f"is built for glibc, not musl (it needs {loader})"
    return None


def read_index(path):
    """{name: index line fields} from an ember-pkg index file."""
    entries = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if not line.startswith("#") and len(fields) >= 8:
                    entries[fields[0]] = fields
    return entries


def read_owners(path):
    owners = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                name, user_id, login = (line.rstrip("\n").split("\t") + ["", ""])[:3]
                owners[name] = (user_id, login)
    return owners


def check_package(archive, info, official, community, owners, user_id):
    """Raise NeedsChanges unless the package can go in the community repository."""
    name, version = info.get("name", ""), info.get("version", "")
    description, depends = info.get("description", ""), info.get("depends", "").split()
    problems = []
    if not NAME_RE.match(name):
        problems.append(f"the name `{name}` in `.PKGINFO` should be lowercase letters, numbers, `.`, `+` and `-`")
    if not VERSION_RE.match(version):
        problems.append(f"the version `{version}` should be the program's version, a dash and a number, like `1.2-1`")
    if not description or len(description) > 200 or "\t" in description:
        problems.append("`.PKGINFO` needs a one-line description (up to 200 characters)")
    for dep in depends:
        if dep not in official and dep not in community:
            problems.append(f"it depends on `{dep}`, which isn't an Ember package")
    if problems:
        raise NeedsChanges("; ".join(problems))
    if name in official:
        raise NeedsChanges(f"`{name}` is already one of Ember's own packages")
    owner = owners.get(name)
    if owner and owner[0] != str(user_id):
        raise NeedsChanges(f"`{name}` was published by @{owner[1]}; only they can update it, so choose another name")
    if name in community and community[name][1] == version:
        raise NeedsChanges(f"{name} {version} is already published; to update it, raise the number after the dash "
                           f"(e.g. `{version.rsplit('-', 1)[0]}-{int(version.rsplit('-', 1)[1]) + 1}`)")

    allowed = re.compile(rf"^(usr/(bin|lib|libexec|share|include)|opt/{re.escape(name)}|etc/{re.escape(name)})/")
    bad, links = [], []
    try:
        with tarfile.open(archive) as t:
            for m in t:
                path = m.name.removeprefix("./").rstrip("/")
                if path in ("", ".", ".PKGINFO"):
                    continue
                if path.startswith("/") or ".." in path.split("/"):
                    bad.append(f"`{path}` is outside the package")
                elif m.islnk():
                    bad.append(f"`{path}` is a hard link (use a symlink or a copy)")
                elif not (m.isreg() or m.isdir() or m.issym()):
                    bad.append(f"`{path}` is a device or other special file")
                elif m.mode & (stat.S_ISUID | stat.S_ISGID):
                    bad.append(f"`{path}` is setuid/setgid (runs with extra privileges)")
                elif any(path.startswith(link + "/") for link in links):
                    bad.append(f"`{path}` is inside a symlink")
                elif not m.isdir() and not allowed.match(path):
                    bad.append(f"`{path}` isn't in an allowed place")
                elif m.isreg() and m.size:
                    problem = elf_problem(t.extractfile(m).read())
                    if problem:
                        bad.append(f"`{path}` {problem}")
                if m.issym():
                    links.append(path)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
        raise NeedsChanges(f"the package couldn't be read ({e})")
    if bad:
        text = "\n- " + "\n- ".join(bad[:10]) + (f"\n- ...and {len(bad) - 10} more" if len(bad) > 10 else "")
        if any("allowed place" in b for b in bad):
            text += ("\n\nCommunity packages may only put files in `usr/bin`, `usr/lib`, `usr/libexec`, "
                     f"`usr/share`, `usr/include`, `opt/{name}` and `etc/{name}`")
        raise NeedsChanges(text)


def installed_kb(archive):
    with tarfile.open(archive) as t:
        return sum(m.size for m in t if m.isreg() and m.name.removeprefix("./") != ".PKGINFO") // 1024 + 1


def write_index(entries, key_file):
    """Write and sign the community index from {name: fields}."""
    index = os.path.join(COMMUNITY, "index")
    with open(index, "w") as f:
        f.write(f"# ember-pkg index 1 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        for name in sorted(entries):
            f.write("\t".join(entries[name][:8]) + "\n")
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key_file, "-rawin", "-in", index,
                    "-out", index + ".sig"], check=True)
    subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", COMMUNITY_PUBKEY, "-rawin",
                    "-in", index, "-sigfile", index + ".sig"], check=True, capture_output=True)


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def update_community(change, message):
    """Apply change(entries, owners) to the latest community repository, sign
    it and push. Retries if someone else pushed (or `make publish` ran) meanwhile."""
    key = os.environ.get("COMMUNITY_SIGNING_KEY", "")
    if not key:
        raise RuntimeError("the COMMUNITY_SIGNING_KEY secret isn't set")
    key_file = os.path.join(tempfile.mkdtemp(), "community.key")
    with open(os.open(key_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
        f.write(key)
    try:
        for attempt in range(6):
            git("fetch", "--depth", "1", "origin", "main")
            git("reset", "--hard", "FETCH_HEAD")
            os.makedirs(COMMUNITY, exist_ok=True)
            entries = read_index(os.path.join(COMMUNITY, "index"))
            owners = read_owners(OWNERS)
            result = change(entries, owners)
            write_index(entries, key_file)
            with open(OWNERS, "w") as f:
                for name in sorted(owners):
                    f.write("\t".join((name, *owners[name])) + "\n")
            git("add", "-A", "community")
            git("-c", "user.name=Ember package bot", "-c", "user.email=ember-bot@users.noreply.github.com",
                "commit", "-q", "-m", message)
            try:
                git("push", "-q", "origin", "HEAD:main")
                break
            except subprocess.CalledProcessError:
                time.sleep(5 * (attempt + 1))
        else:
            raise RuntimeError("couldn't push to the repository")
    finally:
        os.remove(key_file)
    try:
        api("POST", "/pages/builds")
    except urllib.error.HTTPError:
        pass  # Pages also rebuilds on its own after a push
    return result


def publish(archive, info, user_id, login):
    name, version = info["name"], info["version"]
    file = f"{name}-{version}.tar.xz"

    def change(entries, owners):
        if name in owners and owners[name][0] != str(user_id):
            raise NeedsChanges(f"`{name}` was just published by @{owners[name][1]}; choose another name")
        old = entries.get(name)
        if old and os.path.exists(os.path.join(COMMUNITY, old[2])):
            os.remove(os.path.join(COMMUNITY, old[2]))
        dest = os.path.join(COMMUNITY, file)
        with open(archive, "rb") as src:
            magic = src.read(6)
        if magic == b"\xfd7zXZ\x00":
            shutil.copy(archive, dest)
        else:  # e.g. a gzipped package: same contents, recompressed like every other package
            opener = gzip.open if magic[:2] == b"\x1f\x8b" else bz2.open if magic[:3] == b"BZh" else open
            with opener(archive, "rb") as raw, open(dest, "wb") as out:
                xz = subprocess.Popen(["xz", "-6", "-c"], stdin=subprocess.PIPE, stdout=out)
                shutil.copyfileobj(raw, xz.stdin)
                xz.stdin.close()
                if xz.wait():
                    raise RuntimeError("xz failed")
        description = " ".join(info["description"].split())
        entries[name] = [name, version, file, sha256(dest), str(os.path.getsize(dest)),
                         str(installed_kb(dest)), " ".join(info.get("depends", "").split()), description]
        owners[name] = (str(user_id), login)

    update_community(change, f"Community package {name} {version} (from @{login})")
    return file


def remove_package(name):
    def change(entries, owners):
        if name not in entries:
            raise SystemExit(f"{name} isn't in the community repository")
        path = os.path.join(COMMUNITY, entries.pop(name)[2])
        if os.path.exists(path):
            os.remove(path)
        owners.pop(name, None)

    update_community(change, f"Remove community package {name}")
    print(f"removed {name}")


def scrub(body, urls):
    """Remove every link to the given files from the issue text."""
    note = "*(file removed: it failed the security scan)*"
    for url in urls:
        u = re.escape(url)
        body = re.sub(rf"<img[^>]*{u}[^>]*>", note, body)
        body = re.sub(rf"!?\[[^\]]*\]\(\s*{u}[^)]*\)", note, body)
        body = body.replace(url, note)
    return body


def set_status(number, labels, status, text):
    for name in LABELS.values():
        if name in labels and name != LABELS[status]:
            try:
                api("DELETE", f"/issues/{number}/labels/{urllib.parse.quote(name)}")
            except urllib.error.HTTPError:
                pass
    api("POST", f"/issues/{number}/labels", {"labels": [LABELS[status]]})
    body = f"{MARKER}\n{text}"
    for page in range(1, 20):
        comments = api("GET", f"/issues/{number}/comments?per_page=100&page={page}")
        for c in comments:
            if c["user"]["login"] == "github-actions[bot]" and c["body"].startswith(MARKER):
                api("PATCH", f"/issues/comments/{c['id']}", {"body": body})
                return
        if len(comments) < 100:
            break
    api("POST", f"/issues/{number}/comments", {"body": body})


def handle_issue(event):
    issue = event["issue"]
    number = issue["number"]
    labels = [label["name"] for label in issue["labels"]]
    action = event.get("action")
    if SUBMISSION_LABEL not in labels or issue["state"] != "open" or LABELS["rejected"] in labels:
        return print("nothing to do")
    if action == "edited" and "body" not in event.get("changes", {}):
        return print("title edited only")
    if action == "labeled" and event.get("label", {}).get("name") != SUBMISSION_LABEL:
        return print("another label was added")

    body = issue.get("body") or ""
    urls = find_attachments(body)
    if not urls:
        set_status(number, labels, "needs-file",
                   "### No file attached yet\n"
                   "Please **edit this issue** (the `...` menu at the top, then *Edit*) and drag your package "
                   "into the *Package file* box. GitHub only accepts some file types, so put it in a "
                   "**.zip** or **.tar.gz** first. It will be scanned as soon as you save.")
        return
    if len(urls) > MAX_FILES:
        urls = urls[:MAX_FILES]

    work = tempfile.mkdtemp(prefix="dl-")
    user = issue["user"]
    try:
        try:
            paths, names = download_all(urls, work)
            report, warnings, version, packages = scan(paths, names, work)
            details = scan_details(version, report, warnings)
            archive, info = choose_package(packages)
            check_package(archive, info, read_index(OFFICIAL_INDEX), read_index(os.path.join(COMMUNITY, "index")),
                          read_owners(OWNERS), user["id"])
            publish(archive, info, user["id"], user["login"])
        except Rejected as e:
            reject(number, labels, body, urls, str(e))
            return
        except NeedsChanges as e:
            set_status(number, labels, "needs-changes",
                       "### ✋ Passed the virus scan, but can't be published yet\n"
                       f"{str(e).rstrip('.')}.\n\n"
                       f"See [how to package a program for Ember]({GUIDE}). Then **edit this issue** and attach the "
                       "fixed file; it's checked again as soon as you save.\n\n" + details)
            return
        except Exception as e:
            set_status(number, labels, "error",
                       "### Something went wrong on our side\n"
                       f"The check couldn't finish ({type(e).__name__}). Please try again later by editing this "
                       "issue and saving it.")
            raise
    finally:
        shutil.rmtree(work, ignore_errors=True)

    name = info["name"]
    set_status(number, labels, "published",
               f"### ✅ Published: {name} {info['version']}\n"
               "It passed the virus scan and is now in Ember's community repository. On Ember, install it with:\n"
               f"```sh\nember-pkg update\nember-pkg install {name}\n```\n"
               "(GitHub takes a minute or two to update.) To publish a new version later, submit it the same way "
               "with the same name.\n\n" + details)
    api("PATCH", f"/issues/{number}", {"state": "closed", "state_reason": "completed"})


def download_all(urls, work):
    paths, names = [], []
    for i, url in enumerate(urls):
        name = safe_name(url.rsplit("/", 1)[-1], f"file{i}")
        while name in names:
            name = f"{i}-{name}"
        path = os.path.join(work, name)
        download(url, path)
        paths.append(path)
        names.append(name)
    return paths, names


def scan_details(version, report, warnings):
    text = ["<details><summary>Scan details</summary>", "",
            f"Scanned with {version}, plus checks for miners and rootkit tricks.", ""]
    text += [f"- {line}" for line in report]
    if warnings:
        text += ["", "Worth knowing (not necessarily a problem):"]
        text += [f"- {w}" for w in warnings[:30]]
        if len(warnings) > 30:
            text.append(f"- ...and {len(warnings) - 30} more")
    return "\n".join(text + ["", "</details>"])


def choose_package(packages):
    names = {info.get("name") for _, info in packages}
    if not packages:
        raise NeedsChanges("there's no Ember package in it (a `.tar.xz` with a `.PKGINFO` file inside). "
                           "Only Ember packages can go in the repository, not plain program archives")
    if len(names) > 1:
        raise NeedsChanges(f"it contains more than one package ({', '.join(sorted(map(str, names)))}); "
                           "please submit one package per issue")
    return packages[0]


def reject(number, labels, body, urls, reason):
    api("PATCH", f"/issues/{number}", {"body": scrub(body, urls)})
    set_status(number, labels, "rejected",
               "### ❌ Rejected: failed the security scan\n"
               f"{reason}.\n\n"
               "The file has been removed from this issue and the submission closed. "
               "If you think this is a mistake, open a new issue using *Report an issue*.")
    api("PATCH", f"/issues/{number}", {"state": "closed", "state_reason": "not_planned"})
    api("PUT", f"/issues/{number}/lock")


def main():
    if sys.argv[1:2] == ["--remove"] and len(sys.argv) == 3:
        remove_package(sys.argv[2])
        return 0
    if sys.argv[1:2] == ["--local"]:
        files = sys.argv[2:]
        work = tempfile.mkdtemp(prefix="local-")
        try:
            report, warnings, version, packages = scan(files, [safe_name(os.path.basename(f), "file") for f in files],
                                                       work)
            print(f"PASSED the scan ({version})")
            for line in report + [f"warning: {w}" for w in warnings]:
                print(" ", line)
            archive, info = choose_package(packages)
            check_package(archive, info, read_index(os.environ.get("OFFICIAL_INDEX", OFFICIAL_INDEX)),
                          read_index(os.path.join(COMMUNITY, "index")), read_owners(OWNERS), "local")
            print(f"PUBLISHABLE: {info['name']} {info['version']}")
        except Rejected as e:
            print(f"REJECTED: {e}")
            return 1
        except NeedsChanges as e:
            print(f"NEEDS CHANGES: {e}")
            return 1
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return 0
    with open(os.environ["GITHUB_EVENT_PATH"]) as f:
        handle_issue(json.load(f))
    return 0


if __name__ == "__main__":
    sys.exit(main())
