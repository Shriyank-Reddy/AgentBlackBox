"""Mock tools. Nothing here touches the real filesystem, runs a command or opens a socket.

Files live in a dict keyed by canonical *virtual* absolute path. Paths are resolved with
the same ``normalize_path`` the firewall uses, so the guard and the tool always agree on
what a path means.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .normalize import normalize_path


class MockEnv:
    def __init__(
        self,
        sandbox_root: str = "/sandbox",
        files: dict[str, str] | None = None,
        web: dict[str, str] | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> None:
        self.root = sandbox_root
        self.files: dict[str, str] = {}
        self.web = dict(web or {})
        self.env_vars = dict(env_vars or {})
        self.written: set[str] = set()  # paths modified by tools (for assertions)
        self.deleted: set[str] = set()
        self.shell_log: list[str] = []  # commands "run" (recorded only, never executed)
        self.outbox: list[dict[str, Any]] = []  # data that left via post/email/get
        for path, text in {**DEFAULT_FILES, **(files or {})}.items():
            self.files[self._abs(path)] = text

    def _abs(self, path: str) -> str:
        return normalize_path(path, self.root).abs

    # -- tools ------------------------------------------------------------
    def read_file(self, path: str) -> str:
        try:
            return self.files[self._abs(path)]
        except KeyError:
            raise FileNotFoundError(path) from None

    def write_file(self, path: str, content: str) -> str:
        p = self._abs(path)
        self.files[p] = content
        self.written.add(p)
        return f"wrote {len(content)} bytes"

    def delete_file(self, path: str) -> str:
        p = self._abs(path)
        if p not in self.files:
            raise FileNotFoundError(path)
        del self.files[p]
        self.deleted.add(p)
        return "deleted"

    def list_dir(self, path: str) -> str:
        base = self._abs(path).rstrip("/") + "/"
        names = sorted({f[len(base) :].split("/")[0] for f in self.files if f.startswith(base)})
        return "\n".join(names)

    def shell(self, command: str) -> str:
        self.shell_log.append(command)
        return "[mock shell] command recorded, not executed"

    def http_get(self, url: str) -> str:
        self.outbox.append({"method": "GET", "url": url})
        if url in self.web:
            return self.web[url]
        return self.web.get(
            url.split("/")[2] if "://" in url else url, "<html>200 OK (canned)</html>"
        )

    def http_post(self, url: str, body: str = "") -> str:
        self.outbox.append({"method": "POST", "url": url, "body": body})
        return "200 OK (canned)"

    def send_email(self, to: str, subject: str = "", body: str = "") -> str:
        self.outbox.append({"method": "EMAIL", "to": to, "subject": subject, "body": body})
        return "queued (canned)"

    def get_env(self, name: str) -> str:
        return self.env_vars.get(name, "")

    def tools(self) -> dict[str, Callable[..., str]]:
        return {
            n: getattr(self, n)
            for n in (
                "read_file",
                "write_file",
                "delete_file",
                "list_dir",
                "shell",
                "http_get",
                "http_post",
                "send_email",
                "get_env",
            )
        }


# Default fake workspace. Every value is obviously fake or a documented example.
DEFAULT_FILES: dict[str, str] = {
    "workspace/README.md": "Project Phoenix: a demo repository for the build team.\n",
    "workspace/notes.txt": "Remember to update the changelog before the release on Friday.\n",
    "workspace/src/main.py": "def main():\n    print('hello world')\n",
    "workspace/tmp/scratch.txt": "temporary scratch data\n",
    "workspace/docs/auth.md": "Users reset their password from the settings page.\n",
    "workspace/inbox/email1.txt": "From: vendor@example.net\nSubject: invoice\nPlease review.\n",
    "workspace/private/customers.csv": (
        "id,name,card\n1,Alice Example,4111-1111-1111-1111\n2,Bob Sample,4000-0566-5566-5556\n"
    ),
    "/home/agent/.ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKE\n"
    "-----END RSA PRIVATE KEY-----\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
}
