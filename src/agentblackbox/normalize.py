"""Argument normalisation: turn attacker-controlled strings into canonical facts.

Rules never look at raw strings. They ask a ``NormalizedCall`` for the canonical path,
URL host, decoded text views or shell findings, so every evasion trick is handled here once.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .secrets import decode_tokens

HOME_DIR = "/home/agent"  # virtual home directory for "~"


# =========================== paths ==========================================
@dataclass(frozen=True)
class NormPath:
    raw: str
    abs: str  # canonical absolute path inside the *virtual* filesystem
    root: str
    flags: frozenset[str] = frozenset()

    @property
    def inside_root(self) -> bool:
        return self.abs == self.root or self.abs.startswith(self.root.rstrip("/") + "/")

    def under(self, prefixes: list[str]) -> bool:
        """True if the path is at or below any prefix (relative prefixes are sandbox-relative).

        Comparison is by whole path components, so ``workspace2`` is not under ``workspace``.
        """
        for pre in prefixes:
            base = posixpath.normpath(
                pre if pre.startswith("/") else posixpath.join(self.root, pre)
            )
            if self.abs == base or self.abs.startswith(base.rstrip("/") + "/"):
                return True
        return False


def normalize_path(raw: str, root: str = "/sandbox") -> NormPath:
    """Canonicalise a path relative to the sandbox root, undoing common escapes."""
    flags: set[str] = set()
    p = raw.replace("\x00", "").strip()
    for _ in range(3):  # %2e%2e%2f, and double-encoded %252e
        dec = unquote(p)
        if dec == p:
            break
        flags.add("encoded")
        p = dec
    if "\\" in p:
        flags.add("backslash")
        p = p.replace("\\", "/")
    if p == "~" or p.startswith("~/"):
        flags.add("home")
        p = HOME_DIR + p[1:]
    if p.startswith("/"):
        flags.add("absolute")
    if "//" in p:
        flags.add("doubled_slash")
    if ".." in p.split("/"):
        flags.add("traversal")
    full = p if p.startswith("/") else posixpath.join(root, p)
    return NormPath(raw, posixpath.normpath(full), root, frozenset(flags))


# =========================== URLs ===========================================
@dataclass(frozen=True)
class NormURL:
    raw: str
    scheme: str
    host: str
    port: int | None
    flags: frozenset[str] = frozenset()

    def host_in(self, patterns: list[str]) -> bool:
        return host_matches(self.host, patterns)


def host_matches(host: str, patterns: list[str]) -> bool:
    """Exact match, or ``*.example.com`` for subdomains (never the apex, never a suffix trick)."""
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat.startswith("*."):
            if host.endswith(pat[1:]):
                return True
        elif host == pat:
            return True
    return False


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


def _parse_ipv4_loose(host: str) -> str | None:
    """Parse legacy inet_aton forms: 2130706433, 0x7f000001, 0177.0.0.1, 127.1."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                nums.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0") and part.isdigit():
                nums.append(int(part, 8))
            elif part.isdigit():
                nums.append(int(part))
            else:
                return None
        except ValueError:
            return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(parts)):
        return None
    value = last
    for i, n in enumerate(head):
        value += n << (8 * (3 - i))
    return str(ipaddress.IPv4Address(value))


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def _parse_authority(authority: str, flags: set[str]) -> tuple[str, int | None]:
    if "@" in authority:
        flags.add("userinfo")
        authority = authority.rpartition("@")[2]  # the LAST @ decides the host
    port: int | None = None
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port_s = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port_s = authority.rpartition(":") if ":" in authority else (authority, "", "")
    if port_s:
        if port_s.isdigit() and int(port_s) < 65536:
            port = int(port_s)
        else:
            flags.add("bad_host")
    return host, port


def normalize_url(raw: str) -> NormURL:
    """Parse a URL the way a browser would, recording every oddity as a flag."""
    flags: set[str] = set()
    s = raw.strip()
    cleaned = re.sub(r"[\t\r\n]", "", s)  # browsers silently drop these inside URLs
    if cleaned != s:
        flags.add("stripped_control")
    if "\\" in cleaned:
        flags.add("backslash")
        cleaned = cleaned.replace("\\", "/")  # WHATWG treats \ as / for http(s)

    scheme = ""
    m = _SCHEME_RE.match(cleaned)
    rest = cleaned
    if m and cleaned[m.end() :].startswith("//"):
        scheme, rest = m.group(1).lower(), cleaned[m.end() + 2 :]
    elif m and not re.match(r"^\d+(/|$)", cleaned[m.end() :]):
        # opaque schemes such as javascript:, data:, mailto:
        return NormURL(raw, m.group(1).lower(), "", None, frozenset({"bad_scheme"}))
    elif cleaned.startswith("//"):
        flags.add("no_scheme")
        rest = cleaned[2:]
    else:
        flags.add("no_scheme")  # "evil.com/path" or "evil.com:8080/x"
    if scheme and scheme not in ("http", "https"):
        flags.add("bad_scheme")

    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host, port = _parse_authority(authority, flags)

    for _ in range(2):  # percent-encoded host: api.github.com%2eevil.com
        dec = unquote(host)
        if dec == host:
            break
        flags.add("encoded_host")
        host = dec
    host = unicodedata.normalize("NFKC", host).lower()
    host = host.rstrip(".") if not host.startswith("[") else host

    if not host:
        flags.add("bad_host")
        return NormURL(raw, scheme, "", port, frozenset(flags))

    # --- IP literals ---
    try:
        v6 = ipaddress.IPv6Address(host.split("%")[0]) if ":" in host else None
    except ValueError:
        v6 = None
    v4 = None if v6 else (_parse_ipv4_loose(host) if re.search(r"[0-9]$", host) else None)
    if v6 is not None or v4 is not None:
        ip = ipaddress.ip_address(v4) if v4 else v6
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
            flags.add("ip_obfuscated")
        flags.add("ip_literal")
        canon = str(ip)
        if v4 and canon != host:
            flags.add("ip_obfuscated")
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_reserved
        ):
            flags.add("private_ip")
        return NormURL(raw, scheme, canon, port, frozenset(flags))

    # --- names: IDN / punycode ---
    if not host.isascii():
        flags.add("idn")
        if len(_scripts(host)) > 1:
            flags.add("mixed_script")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            flags.add("bad_host")
    if any(label.startswith("xn--") for label in host.split(".")):
        flags.add("punycode")
        try:
            if len(_scripts(host.encode("ascii").decode("idna"))) > 1:
                flags.add("mixed_script")
        except UnicodeError:
            flags.add("bad_host")
    if not _HOST_OK.match(host):
        flags.add("bad_host")
    return NormURL(raw, scheme, host, port, frozenset(flags))


URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+")


# =========================== text views =====================================
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
MAX_VIEWS = 300
MAX_TEXT = 200_000


def _variants(text: str, depth: int = 0) -> list[tuple[str, str]]:
    """Alternative readings of one string: URL-, base64-, hex-decoded, NFKC, zero-width removed."""
    out: list[tuple[str, str]] = []
    text = text[:MAX_TEXT]
    p = text
    for _ in range(3):
        dec = unquote(p)
        if dec == p:
            break
        p = dec
    if p != text:
        out.append(("url", p))
    if (nfkc := unicodedata.normalize("NFKC", text)) != text:
        out.append(("unicode", nfkc))
    if (nozw := _ZERO_WIDTH.sub("", text)) != text:
        out.append(("zero_width", nozw))
    if depth < 2:
        for source in {text, p}:
            for _tok, enc, decoded in decode_tokens(source):
                out.append((enc, decoded))
                out.extend((f"{enc}>{e2}", t2) for e2, t2 in _variants(decoded, depth + 1))
    return out


# =========================== shell ==========================================
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "eval", "source", "."}
_INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php"}
_WRAPPERS = {
    "sudo",
    "doas",
    "nohup",
    "env",
    "command",
    "exec",
    "time",
    "nice",
    "timeout",
    "xargs",
    "stdbuf",
    "setsid",
}
_DECODERS = {"base64", "xxd", "openssl", "uudecode", "basenc"}
_SEPARATORS = {";", "&&", "||", "&", "(", ")", ";;"}
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_ASSIGN = re.compile(
    r"(?:^|[;&|\n(]\s*)(?:export\s+)?([A-Za-z_]\w*)=('[^']*'|\"[^\"]*\"|[^\s;&|]*)"
)
_DEV_OK = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty"}
_RAW_PATTERNS = [
    ("fork_bomb", re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:")),
    ("reverse_shell", re.compile(r"/dev/(?:tcp|udp)/|\bbash\s+-i\b")),
    (
        "remote_code_exec",
        re.compile(
            r"(?:\b(?:ba|z|da|k)?sh\b|\beval\b|\bsource\b|(?<=\s)\.)[^|;&\n]*(?:<\(|\$\(|`)\s*"
            r"(?:curl|wget)\b"
        ),
    ),
    (
        "persistence",
        re.compile(
            r"authorized_keys|\.bashrc|\.bash_profile|\.zshrc|\.profile\b|/etc/cron|systemctl\s+enable"
        ),
    ),
    (
        "sensitive_file",
        re.compile(r"/etc/shadow|/etc/sudoers|\.ssh/|\.aws/credentials|\.gnupg|/proc/\d+/environ"),
    ),
]


def _decode_ansi_c(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        body = m.group(1)
        body = re.sub(r"\\x([0-9a-fA-F]{2})", lambda h: chr(int(h.group(1), 16)), body)
        body = re.sub(r"\\([0-7]{3})", lambda o: chr(int(o.group(1), 8)), body)
        for esc, ch in (("\\n", "\n"), ("\\t", "\t"), ("\\'", "'"), ("\\\\", "\\")):
            body = body.replace(esc, ch)
        return body

    return _ANSI_C.sub(repl, s)


def _brace_expand(word: str) -> list[str]:
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out.extend(_brace_expand(word[: m.start()] + alt + word[m.end() :]))
    return out


def _expand(cmd: str) -> str:
    """Undo cheap obfuscation: $'..' escapes, ${IFS}, brace expansion, simple variables."""
    s = _decode_ansi_c(cmd)
    s = s.replace("${IFS}", " ").replace("$IFS", " ")
    s = " ".join(w for word in s.replace("\n", " ; ").split(" ") for w in _brace_expand(word))
    env: dict[str, str] = {}
    for m in _ASSIGN.finditer(s):
        val = m.group(2)
        env[m.group(1)] = (
            val[1:-1] if val[:1] in "'\"" and val[-1:] == val[:1] and len(val) > 1 else val
        )
    for name in sorted(env, key=len, reverse=True):
        s = re.sub(rf"\$\{{{name}\}}|\${name}(?![A-Za-z0-9_])", lambda _m, v=env[name]: v, s)
    return s


def _tokenize(s: str) -> list[str]:
    lex = shlex.shlex(s, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: still analyse a best-effort split
        return s.replace("'", " ").replace('"', " ").split()


def _split_pipelines(tokens: list[str]) -> list[list[tuple[list[str], bool]]]:
    """tokens -> pipelines -> commands as (args, has_input_redirect)."""
    pipelines: list[list[tuple[list[str], bool]]] = [[]]
    cur: list[str] = []

    def end_cmd() -> None:
        nonlocal cur
        if cur:
            pipelines[-1].append((cur, "<" in cur))
        cur = []

    for tok in tokens:
        if tok in _SEPARATORS:
            end_cmd()
            if pipelines[-1]:
                pipelines.append([])
        elif tok in ("|", "|&"):
            end_cmd()
        else:
            cur.append(tok)
    end_cmd()
    return [p for p in pipelines if p]


def _outside_workspace(target: str) -> bool:
    if "$" in target or "`" in target:
        return True  # unresolved: assume the worst
    return not normalize_path(target).under(["workspace/"])


def _strip_wrappers(args: list[str]) -> list[str]:
    while args:
        head = posixpath.basename(args[0])
        if "=" in args[0] and re.match(r"^[A-Za-z_]\w*=", args[0]):
            args = args[1:]
        elif head in _WRAPPERS:
            args = args[1:]
            while args and (args[0].startswith("-") or args[0].isdigit()):
                args = args[1:]
        else:
            break
    return args


def _command_findings(args: list[str], depth: int) -> list[str]:
    found: list[str] = []
    # redirects: '> target' writes; keep the rest as plain arguments
    plain: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in (">", ">>", ">|") and i + 1 < len(args):
            tgt = args[i + 1]
            if tgt not in _DEV_OK and _outside_workspace(tgt):
                found.append("redirect_outside_workspace")
            i += 2
        elif args[i] in ("<", ">&", "<&"):
            i += 2 if args[i] == "<" else 1
        else:
            plain.append(args[i])
            i += 1
    plain = _strip_wrappers(plain)
    if not plain:
        return found
    name, rest = posixpath.basename(plain[0]), plain[1:]
    flags = [a for a in rest if a.startswith("-")]
    operands = [a for a in rest if not a.startswith("-")]
    letters = "".join(f[1:] for f in flags if not f.startswith("--"))

    if name == "rm":
        recursive = "r" in letters.lower() or "--recursive" in flags
        if any(_outside_workspace(t) for t in operands) or (recursive and not operands):
            found.append("rm_recursive" if recursive else "rm_outside_workspace")
    elif name == "find" and ("-delete" in rest or ("-exec" in rest and "rm" in rest)):
        if not operands or _outside_workspace(operands[0]):
            found.append("find_delete")
    elif (
        name in ("mkfs", "wipefs", "shred")
        or name.startswith("mkfs.")
        or name == "dd"
        and any(a.startswith("of=/dev/") for a in rest)
    ):
        found.append("disk_wipe")
    elif name in ("shutdown", "reboot", "halt", "poweroff", "killall") or (
        name == "kill" and "-1" in rest
    ):
        found.append("system_control")
    elif name in ("sudo", "su", "doas"):
        found.append("privilege_escalation")
    elif (
        name == "chmod"
        and ("+s" in rest or any(a in ("777", "a+rwx", "0777") for a in rest) or "u+s" in rest)
        and any(_outside_workspace(t) for t in operands[1:])
    ):
        found.append("chmod_dangerous")
    elif name == "chown" and "R" in letters and any(_outside_workspace(t) for t in operands[1:]):
        found.append("chown_dangerous")
    elif name in ("nc", "ncat", "netcat", "socat", "telnet"):
        found.append(
            "reverse_shell" if any(f in ("-e", "-c", "--exec") for f in flags) else "shell_upload"
        )
    elif (
        name in ("scp", "rsync", "sftp", "ftp", "tftp")
        or name == "curl"
        and any(
            f in ("-d", "-F", "-T", "--form", "--upload-file", "--json") or f.startswith("--data")
            for f in flags
        )
        or name == "wget"
        and any(f.startswith("--post") for f in flags)
    ):
        found.append("shell_upload")
    elif name == "crontab" or name == "at":
        found.append("persistence")
    elif name in _SHELLS | _INTERPRETERS and depth < 4:
        for opt in ("-c", "-e"):
            if opt in rest and rest.index(opt) + 1 < len(rest):
                code = rest[rest.index(opt) + 1]
                if name in _INTERPRETERS:
                    if re.search(
                        r"os\.system|subprocess|rmtree|socket|\beval\(|\bexec\(|urlopen|"
                        r"requests\.|system\(",
                        code,
                    ):
                        found.append("inline_code_exec")
                else:
                    found.extend(analyze_shell(code, depth + 1))
        if name == "eval":
            found.extend(analyze_shell(" ".join(rest), depth + 1))
    return found


def analyze_shell(command: str, depth: int = 0) -> list[str]:
    """Names of dangerous patterns in a shell string, after undoing common obfuscation."""
    expanded = _expand(command)
    found: list[str] = []
    for label, rx in _RAW_PATTERNS:
        if rx.search(expanded) or rx.search(command):
            found.append(label)
    for pipeline in _split_pipelines(_tokenize(expanded)):
        names = []
        for args, _ in pipeline:
            stripped = _strip_wrappers([a for a in args if a not in (">", ">>")])
            names.append((posixpath.basename(stripped[0]) if stripped else "", stripped[1:]))
        for idx, (name, _rest) in enumerate(names):
            if idx and (name in _SHELLS or name in _INTERPRETERS):
                before = [(n, r) for n, r in names[:idx]]
                if any(n in ("curl", "wget", "fetch") for n, _ in before):
                    found.append("remote_code_exec")
                if any(
                    n in _DECODERS and any(f in ("-d", "-D", "--decode", "-r", "-dec") for f in r)
                    for n, r in before
                ):
                    found.append("encoded_exec")
        for args, _ in pipeline:
            found.extend(_command_findings(args, depth))
    if depth < 3:  # payloads smuggled as base64/hex tokens
        for _tok, _enc, decoded in decode_tokens(command):
            inner = analyze_shell(decoded, depth + 1)
            found.extend(f"encoded:{f}" for f in inner)
    return list(dict.fromkeys(found))


# =========================== the per-call facade ============================
@dataclass
class NormalizedCall:
    tool: str
    args: dict[str, Any]
    sandbox_root: str = "/sandbox"
    _cache: dict[Any, Any] = field(default_factory=dict, repr=False)

    def _memo(self, key: Any, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def arg_text(self, name: str) -> str | None:
        v = self.args.get(name)
        return v if isinstance(v, str) else None

    def path(self, name: str) -> NormPath | None:
        t = self.arg_text(name)
        return (
            None
            if t is None
            else self._memo(("p", name), lambda: normalize_path(t, self.sandbox_root))
        )

    def url(self, name: str) -> NormURL | None:
        t = self.arg_text(name)
        return None if t is None else self._memo(("u", name), lambda: normalize_url(t))

    def views(self) -> list[tuple[str, str]]:
        """Every string in the arguments as (encoding, text), including decoded readings.

        The concatenation of all strings is also included, so a secret split across two
        arguments is still seen whole.
        """
        return self._memo("views", self._build_views)

    def _build_views(self) -> list[tuple[str, str]]:
        strings = _strings(self.args)
        units = list(strings)
        if len(strings) > 1:
            units.append("".join(strings))
        out: list[tuple[str, str]] = []
        for u in units:
            out.append(("raw", u[:MAX_TEXT]))
            out.extend(_variants(u))
            if len(out) >= MAX_VIEWS:
                break
        return out[:MAX_VIEWS]

    def shell_findings(self, name: str) -> list[str]:
        t = self.arg_text(name)
        return [] if t is None else self._memo(("s", name), lambda: analyze_shell(t))


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return [] if value is None else [str(value)]
