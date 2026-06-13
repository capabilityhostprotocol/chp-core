#!/usr/bin/env python3
"""Generate a correctly-signed inbound request for the webhook / slack adapters.

Mirrors the exact HMAC schemes in chp_adapter_webhook / chp_adapter_slack so the
signed payload verifies. Prints the signed headers and a ready-to-run curl that
POSTs to the local host's /invoke.

Examples:
  python sign.py github  --secret dev-webhook-secret --body-file body.json
  python sign.py slack   --secret $SLACK_SIGNING_SECRET --body-file body.txt
  python sign.py stripe  --secret whsec_... --body-file event.json
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
import uuid


def _hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _headers(provider: str, body: str, secret: str, ts: str, header_name: str) -> dict[str, str]:
    if provider == "github":
        return {
            "X-Hub-Signature-256": "sha256=" + _hex(secret, body),
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": str(uuid.uuid4()),
        }
    if provider == "stripe":
        return {"Stripe-Signature": f"t={ts},v1={_hex(secret, f'{ts}.{body}')}"}
    if provider == "slack":
        return {
            "X-Slack-Signature": "v0=" + _hex(secret, f"v0:{ts}:{body}"),
            "X-Slack-Request-Timestamp": ts,
        }
    return {header_name: "sha256=" + _hex(secret, body)}  # generic


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign an inbound webhook/slack payload.")
    parser.add_argument("provider", choices=["github", "stripe", "slack", "generic"])
    parser.add_argument("--secret", required=True)
    parser.add_argument("--body-file", required=True, help="raw request body (signed as-is)")
    parser.add_argument("--ts", default=str(int(time.time())), help="timestamp (stripe/slack)")
    parser.add_argument("--header-name", default="X-Signature-256", help="generic provider header")
    parser.add_argument("--url", default="http://127.0.0.1:8765/invoke")
    parser.add_argument("--capability", help="override target capability")
    args = parser.parse_args()

    with open(args.body_file) as fh:
        body = fh.read()

    headers = _headers(args.provider, body, args.secret, args.ts, args.header_name)

    # Default target: slack provider → slack.verify_request, else webhook.ingest.
    if args.capability:
        capability = args.capability
    elif args.provider == "slack":
        capability = "chp.adapters.slack.verify_request"
    else:
        capability = "chp.adapters.webhook.ingest"

    payload: dict = {"body": body, "headers": headers}
    if capability.startswith("chp.adapters.webhook."):
        payload["provider"] = args.provider

    print("Signed headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print(f"\ncapability: {capability}\n")
    envelope = json.dumps({"capability_id": capability, "payload": payload})
    print("curl (single line — pipe through `sh` or eval to run):")
    # Single line so it can be captured and eval'd directly.
    print(f"curl -s -X POST {args.url} -H 'content-type: application/json' -d {json.dumps(envelope)}")


if __name__ == "__main__":
    main()
