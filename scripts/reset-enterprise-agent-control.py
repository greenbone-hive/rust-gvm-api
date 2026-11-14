#!/usr/bin/env python3
"""Reset both stateful emulators and prove unmatched Agent Control routes fail closed."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


class ResetError(RuntimeError):
    """The deterministic enterprise reset contract failed."""


def request(
    url: str,
    token: str | None = None,
    *,
    method: str | None = None,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["X-Emulator-Reset-Token"] = token
    req = urllib.request.Request(
        url,
        method=method or ("POST" if token is not None else "GET"),
        headers=headers,
        data=body,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def reset(base_url: str, token: str, name: str) -> dict[str, object]:
    status, body = request(f"{base_url.rstrip('/')}/_emulator/reset", token)
    if status not in {200, 204}:
        raise ResetError(f"{name} reset returned HTTP {status}: {body[:512]!r}")
    return {"service": name, "status": status}


def reset_proxy(base_url: str, token: str) -> dict[str, object]:
    body = json.dumps({"scenario": "normal"}).encode()
    request_object = urllib.request.Request(
        f"{base_url.rstrip('/')}/__control/scenario",
        method="PUT",
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request_object, timeout=10) as response:
            status = response.status
            document = json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise ResetError(
            f"Agent Control scenario proxy reset returned HTTP {error.code}: {error.read()[:512]!r}"
        ) from error
    if status != 200 or document.get("scenario") != "normal":
        raise ResetError(
            f"Agent Control scenario proxy did not acknowledge normal state: HTTP {status}: {document!r}"
        )
    return {"service": "agent-control-scenario-proxy", "status": status, "scenario": "normal"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-control-url", default="http://127.0.0.1:8090")
    parser.add_argument("--openvasd-url", default="http://127.0.0.1:8086")
    parser.add_argument("--agent-control-proxy-url", default="http://127.0.0.1:8091")
    parser.add_argument("--agent-control-token", default="issue-680-enterprise-reset")
    parser.add_argument("--openvasd-token", default="issue-678-shadow-reset")
    parser.add_argument(
        "--agent-control-proxy-token", default="issue-680-enterprise-proxy-control"
    )
    args = parser.parse_args()

    results = [
        reset_proxy(args.agent_control_proxy_url, args.agent_control_proxy_token),
        reset(args.agent_control_url, args.agent_control_token, "agent-control"),
        reset(args.openvasd_url, args.openvasd_token, "openvasd"),
    ]
    status, _body = request(
        f"{args.agent_control_url.rstrip('/')}/__issue_680_unmatched_route__"
    )
    if status != 404:
        raise ResetError(
            f"Agent Control emulator unmatched route did not fail closed: HTTP {status}"
        )
    print(
        json.dumps(
            {
                "schemaVersion": 1,
                "status": "passed",
                "resets": results,
                "unmatchedRouteStatus": status,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
