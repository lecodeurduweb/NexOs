#!/usr/bin/env python3
"""Secure host-side gateway for NexOS AI agents.

The Raspberry Pi never hosts or authenticates a remote model. This process runs
on another trusted machine and sends only an explicit diagnostic context plus
the administrator prompt to a local Ollama or OpenAI-compatible endpoint.
Write operations to NexOS require an explicit approval token for this process.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def http_json(method: str, url: str, token: str = "", body=None, timeout: float = 8.0, extra_headers=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8", errors="replace"))


class Gateway:
    def __init__(self, args):
        self.nexos_url = args.nexos_url.rstrip("/")
        self.nexos_token = args.nexos_token
        self.provider = args.provider
        self.provider_url = args.provider_url.rstrip("/")
        self.gateway_token = args.gateway_token or os.getenv("NEXOS_AI_GATEWAY_TOKEN")
        self.provider_api_key = os.getenv("NEXOS_AI_PROVIDER_API_KEY", "")
        self.request_timeout = args.timeout
        if not self.gateway_token:
            raise SystemExit("Set --gateway-token or NEXOS_AI_GATEWAY_TOKEN")
        self.approvals = {}

    def authorized(self, handler):
        auth = handler.headers.get("Authorization", "")
        expected = f"Bearer {self.gateway_token}"
        return hmac.compare_digest(auth, expected)

    def context(self):
        result = {}
        for name, path in (
            ("system", "/api/v1/system"),
            ("network", "/api/v1/network"),
            ("tasks", "/api/v1/tasks"),
            ("services", "/api/v1/services"),
            ("storage", "/api/v1/storage"),
            ("ai_agents", "/api/v1/ai/agents"),
            ("ai_status", "/api/v1/ai/status"),
            ("ai_memory", "/api/v1/ai/memory"),
            ("audit", "/api/v1/audit"),
        ):
            try:
                result[name] = http_json("GET", self.nexos_url + path, self.nexos_token)
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
                result[name] = {"error": str(exc)}
        return result

    def provider_reply(self, prompt: str, context):
        system = (
            "You are the NexOS administration assistant. Use only supplied system facts. "
            "Never claim to have performed an action. Identify risk and require explicit approval "
            "before restart, stop, user, file or network modifications."
        )
        if self.provider == "ollama":
            body = {
                "model": os.getenv("NEXOS_OLLAMA_MODEL", "llama3.2"),
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps({"prompt": prompt, "context": context})},
                ],
                "stream": False,
            }
            response = http_json(
                "POST",
                self.provider_url + "/api/chat",
                body=body,
                timeout=self.request_timeout,
                extra_headers={"X-NexOS-Gateway": "1"},
            )
            return response.get("message", {}).get("content", "")
        body = {
            "model": os.getenv("NEXOS_AI_MODEL", "local-model"),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps({"prompt": prompt, "context": context})},
            ],
        }
        headers = {"X-NexOS-Gateway": "1"}
        if self.provider_api_key:
            headers["Authorization"] = f"Bearer {self.provider_api_key}"
        response = http_json(
            "POST",
            self.provider_url + "/v1/chat/completions",
            body=body,
            timeout=self.request_timeout,
            extra_headers=headers,
        )
        choices = response.get("choices", [])
        if not choices:
            raise RuntimeError("The AI provider returned no choices")
        return choices[0].get("message", {}).get("content", "")

    def request_repair(self, service: str):
        now = int(time.time())
        if not service or len(service) > 48:
            raise ValueError("invalid service name")
        if not all(ch.isascii() and (ch.isalnum() or ch in "-_.") for ch in service):
            raise ValueError("invalid service name")
        token = secrets.token_urlsafe(24)
        digest = hashlib.sha256((token + "\0" + service).encode()).hexdigest()
        self.approvals[digest] = {"service": service, "expires": now + 300}
        return {"approval_required": True, "approval_id": digest, "approval_token": token, "expires_seconds": 300}

    def approve_repair(self, approval_id: str, approval_token: str):
        entry = self.approvals.get(approval_id)
        if not entry or entry["expires"] < int(time.time()):
            raise PermissionError("approval expired or unknown")
        expected = hashlib.sha256((approval_token + "\0" + entry["service"]).encode()).hexdigest()
        if not hmac.compare_digest(approval_id, expected):
            raise PermissionError("invalid approval")
        del self.approvals[approval_id]
        return http_json(
            "POST",
            f"{self.nexos_url}/api/v1/services/restart?name={urllib.parse.quote(entry['service'])}",
            self.nexos_token,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--nexos-url", default=os.getenv("NEXOS_URL", "https://127.0.0.1:18443"))
    parser.add_argument("--nexos-token", default=os.getenv("NEXOS_TOKEN", ""))
    parser.add_argument("--gateway-token")
    parser.add_argument("--provider", choices=("ollama", "openai"), default=os.getenv("NEXOS_AI_PROVIDER", "ollama"))
    parser.add_argument("--provider-url", default=os.getenv("NEXOS_AI_PROVIDER_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("NEXOS_AI_TIMEOUT", "8")))
    args = parser.parse_args()
    gateway = Gateway(args)

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, body):
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 65536:
                raise ValueError("request too large")
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8")) if raw else {}

        def do_POST(self):
            if not gateway.authorized(self):
                return self.send_json(401, {"error": "unauthorized"})
            try:
                body = self.read_json()
                if self.path == "/v1/chat":
                    prompt = str(body.get("prompt", ""))[:1024]
                    if not prompt:
                        return self.send_json(400, {"error": "missing_prompt"})
                    context = gateway.context()
                    answer = gateway.provider_reply(prompt, context)
                    return self.send_json(200, {"answer": answer, "context_fresh": True})
                if self.path == "/v1/repair/request":
                    result = gateway.request_repair(str(body.get("service", "")))
                    return self.send_json(202, result)
                if self.path == "/v1/repair/approve":
                    result = gateway.approve_repair(str(body.get("approval_id", "")), str(body.get("approval_token", "")))
                    return self.send_json(200, result)
                return self.send_json(404, {"error": "not_found"})
            except PermissionError as exc:
                return self.send_json(403, {"error": str(exc)})
            except (ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError) as exc:
                return self.send_json(502, {"error": str(exc)})

        def do_GET(self):
            if not gateway.authorized(self):
                return self.send_json(401, {"error": "unauthorized"})
            if self.path == "/health":
                return self.send_json(200, {"status": "ready", "provider": gateway.provider})
            return self.send_json(404, {"error": "not_found"})

        def log_message(self, format, *args):
            return

    print(f"NexOS AI gateway listening on http://{args.listen}:{args.port}")
    ThreadingHTTPServer((args.listen, args.port), Handler).serve_forever()


if __name__ == "__main__":
    import urllib.parse
    main()
