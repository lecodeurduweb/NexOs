#!/usr/bin/env python3

import importlib.util
import os
import sys
import types
import unittest


SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "nexos_ai_gateway.py")
spec = importlib.util.spec_from_file_location("nexos_ai_gateway", SCRIPT)
gateway_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway_module)


class Args:
    nexos_url = "https://127.0.0.1:18443"
    nexos_token = "test-token"
    provider = "ollama"
    provider_url = "http://127.0.0.1:11434"
    gateway_token = "gateway-test-secret"
    timeout = 2.0


class TestGateway(unittest.TestCase):
    def setUp(self):
        os.environ["NEXOS_AI_GATEWAY_TOKEN"] = "gateway-test-secret"
        self.gateway = gateway_module.Gateway(Args())

    def test_repair_request_and_wrong_approval_are_safe(self):
        request = self.gateway.request_repair("health-svc")
        self.assertTrue(request["approval_required"])
        self.assertEqual(request["expires_seconds"], 300)
        with self.assertRaises(PermissionError):
            self.gateway.approve_repair(request["approval_id"], "wrong-token")

    def test_invalid_repair_service_rejected(self):
        with self.assertRaises(ValueError):
            self.gateway.request_repair("")
        with self.assertRaises(ValueError):
            self.gateway.request_repair("../health")

    def test_authorization_uses_constant_time_bearer_match(self):
        class Handler:
            headers = {"Authorization": "Bearer gateway-test-secret"}
        self.assertTrue(self.gateway.authorized(Handler()))

        class Wrong:
            headers = {"Authorization": "Bearer wrong"}
        self.assertFalse(self.gateway.authorized(Wrong()))


if __name__ == "__main__":
    unittest.main()
