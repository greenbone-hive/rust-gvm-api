#!/usr/bin/env python3
"""Bind Agent Control synchronization to the compose admin using gvmd's typed setting CLI."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import time
import urllib.error
import urllib.request


AGENT_OWNER_SETTING = "1ee1f106-8b2e-461c-b426-7f5d76001b29"


class ConfigurationError(RuntimeError):
    """The enterprise fixture could not be configured deterministically."""


def api_request(
    base_url: str, path: str, username: str, password: str, method: str = "GET"
) -> tuple[int, bytes]:
    authorization = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        method=method,
        headers={"Authorization": f"Basic {authorization}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def admin_id(base_url: str, username: str, password: str) -> str:
    status, body = api_request(base_url, "/api/v1/users?page=1&perPage=100", username, password)
    if status != 200:
        raise ConfigurationError(f"user discovery returned HTTP {status}: {body[:512]!r}")
    document = json.loads(body)
    matches = [
        item["id"]
        for item in document.get("data", [])
        if item.get("name") == username and isinstance(item.get("id"), str)
    ]
    if len(matches) != 1:
        raise ConfigurationError(f"expected one {username!r} user, found {len(matches)}")
    return matches[0]


def run_compose(compose: str, user_id: str) -> None:
    result = subprocess.run(
        [
            compose,
            "exec",
            "-T",
            "gvmd",
            "gvmd",
            f"--modify-setting={AGENT_OWNER_SETTING}",
            f"--value={user_id}",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise ConfigurationError(
            f"gvmd Agent owner setting failed ({result.returncode}): {result.stdout}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--compose", default="scripts/compose-enterprise-agent-control.sh")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    user_id = admin_id(args.base_url, args.username, args.password)
    run_compose(args.compose, user_id)
    status, body = api_request(
        args.base_url, "/api/v1/agents/sync", args.username, args.password, method="POST"
    )
    if status != 204:
        raise ConfigurationError(f"initial Agent Control sync returned HTTP {status}: {body[:512]!r}")

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        status, body = api_request(
            args.base_url, "/api/v1/agents?page=1&perPage=1", args.username, args.password
        )
        if status == 200 and json.loads(body).get("data"):
            print(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "status": "passed",
                        "ownerSetting": AGENT_OWNER_SETTING,
                        "ownerId": user_id,
                        "inventory": "non-empty",
                    },
                    indent=2,
                )
            )
            return 0
        time.sleep(2)
    raise ConfigurationError("Agent Control inventory remained empty after bounded sync")


if __name__ == "__main__":
    raise SystemExit(main())
