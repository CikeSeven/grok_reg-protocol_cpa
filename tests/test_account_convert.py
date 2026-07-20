from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import account_convert as ac


class AccountConvertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def native_samples() -> list[dict[str, object]]:
        return [
            {
                "type": "xai",
                "access_token": "xai-access",
                "refresh_token": "xai-refresh",
                "email": "xai@example.com",
                "base_url": "https://api.x.ai/v1",
                "custom_xai": "keep-me",
                "proxy_url": "http://user:p%40ss@127.0.0.1:8080",
            },
            {
                "type": "codex",
                "access_token": "codex-access",
                "refresh_token": "codex-refresh",
                "email": "codex@example.com",
                "account_id": "acct-codex",
            },
            {
                "type": "claude",
                "access_token": "claude-access",
                "refresh_token": "claude-refresh",
                "email": "claude@example.com",
            },
            {
                "type": "gemini",
                "token": {
                    "access_token": "gemini-access",
                    "refresh_token": "gemini-refresh",
                    "token_type": "Bearer",
                    "expiry": "2030-01-01T00:00:00Z",
                },
                "project_id": "gemini-project",
                "email": "gemini@example.com",
                "auto": True,
                "checked": True,
            },
            {
                "type": "antigravity",
                "access_token": "ag-access",
                "refresh_token": "ag-refresh",
                "project_id": "ag-project",
                "email": "ag@example.com",
                "timestamp": 1_900_000_000_000,
            },
            {
                "type": "kimi",
                "access_token": "kimi-access",
                "refresh_token": "kimi-refresh",
                "device_id": "kimi-device",
            },
            {
                "type": "qwen",
                "access_token": "qwen-access",
                "refresh_token": "qwen-refresh",
                "resource_url": "https://portal.qwen.ai",
                "email": "qwen@example.com",
            },
            {
                "type": "iflow",
                "access_token": "iflow-access",
                "refresh_token": "iflow-refresh",
                "api_key": "iflow-key",
                "cookie": "iflow-cookie",
                "email": "iflow@example.com",
            },
            {
                "type": "vertex",
                "service_account": {
                    "type": "service_account",
                    "project_id": "vertex-project",
                    "client_email": "vertex@example.iam.gserviceaccount.com",
                    "private_key": "private-key",
                },
                "project_id": "vertex-project",
                "email": "vertex@example.iam.gserviceaccount.com",
            },
            {
                "type": "kiro",
                "access_token": "kiro-access",
                "refresh_token": "kiro-refresh",
                "profile_arn": "arn:aws:codewhisperer:profile/test",
                "auth_method": "builder-id",
                "expires_at": "2030-01-01T00:00:00Z",
            },
            {
                "type": "future-plugin",
                "api_key": "plugin-key",
                "tenant": "tenant-a",
                "disabled": True,
            },
        ]

    def make_native_zip(self) -> Path:
        path = self.root / "native.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index, item in enumerate(self.native_samples()):
                archive.writestr(f"accounts/account-{index}.json", json.dumps(item))
            archive.writestr("conversion-report.json", json.dumps({"summary": "not an account"}))
            archive.writestr("__MACOSX/._account.json", "{}")
        return path

    def test_mixed_provider_round_trip_preserves_provider_fields(self) -> None:
        native_zip = self.make_native_zip()
        preview = ac.inspect_input(native_zip)
        self.assertEqual(preview["kind"], "native")
        self.assertEqual(preview["account_count"], 11)
        self.assertEqual(preview["providers"]["xai"], 1)
        self.assertEqual(preview["providers"]["future-plugin"], 1)
        self.assertGreaterEqual(preview["warning_count"], 1)

        sub2_result = ac.native_to_sub2(native_zip, self.root / "sub2", note="roundtrip")
        sub2_payload = json.loads(Path(sub2_result["json"]).read_text(encoding="utf-8"))
        self.assertEqual(len(sub2_payload["accounts"]), 11)
        self.assertEqual(len(sub2_payload["proxies"]), 1)
        self.assertEqual(sub2_payload["proxies"][0]["password"], "p@ss")
        providers = {account["extra"]["_cliproxy"]["provider"] for account in sub2_payload["accounts"]}
        self.assertIn("vertex", providers)
        self.assertIn("future-plugin", providers)
        self.assertTrue(all(account["name"] for account in sub2_payload["accounts"]))

        native_result = ac.sub2_to_native(Path(sub2_result["json"]), self.root / "native-out", note="roundtrip", keep_dir=False)
        self.assertEqual(native_result["count"], 11)
        self.assertEqual(len(native_result["packs"]), 11)

        packs = {pack["provider"]: Path(pack["zip"]) for pack in native_result["packs"]}
        with zipfile.ZipFile(packs["xai"]) as archive:
            xai = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(xai["type"], "xai")
        self.assertEqual(xai["custom_xai"], "keep-me")
        self.assertEqual(xai["proxy_url"], "http://user:p%40ss@127.0.0.1:8080")

        with zipfile.ZipFile(packs["gemini"]) as archive:
            gemini = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(gemini["type"], "gemini")
        self.assertEqual(gemini["token"]["refresh_token"], "gemini-refresh")
        self.assertEqual(gemini["project_id"], "gemini-project")

        with zipfile.ZipFile(packs["vertex"]) as archive:
            vertex = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(vertex["service_account"]["private_key"], "private-key")

        with zipfile.ZipFile(packs["future-plugin"]) as archive:
            plugin = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(plugin["type"], "future-plugin")
        self.assertEqual(plugin["api_key"], "plugin-key")
        self.assertTrue(plugin["disabled"])

    def test_nested_provider_zip_is_recognized(self) -> None:
        sub2_source = self.write_json(
            "sub2.json",
            {
                "accounts": [
                    {
                        "name": "openai@example.com",
                        "platform": "openai",
                        "type": "oauth",
                        "credentials": {
                            "access_token": "access",
                            "refresh_token": "refresh",
                            "email": "openai@example.com",
                        },
                    },
                    {
                        "name": "claude@example.com",
                        "platform": "anthropic",
                        "type": "oauth",
                        "credentials": {
                            "access_token": "access",
                            "refresh_token": "refresh",
                            "email": "claude@example.com",
                        },
                    },
                ],
                "proxies": [],
            },
        )
        result = ac.sub2_to_native(sub2_source, self.root / "packs", keep_dir=False)
        bundle = self.root / "bundle.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for pack in result["packs"]:
                archive.write(pack["zip"], arcname=Path(pack["zip"]).name)
        preview = ac.inspect_input(bundle)
        self.assertEqual(preview["account_count"], 2)
        self.assertEqual(preview["providers"], {"claude": 1, "codex": 1})

    def test_sub2_api_wrappers_and_specific_provider_export(self) -> None:
        account = {
            "name": "codex@example.com",
            "platform": "openai",
            "type": "oauth",
            "credentials": {
                "access_token": "access",
                "refresh_token": "refresh",
                "email": "codex@example.com",
            },
            "concurrency": 3,
            "priority": 10,
            "proxy_key": "socks5h|2001:db8::1|1080|user|pass",
        }
        proxy = {
            "proxy_key": "socks5h|2001:db8::1|1080|user|pass",
            "name": "ipv6",
            "protocol": "socks5h",
            "host": "2001:db8::1",
            "port": 1080,
            "username": "user",
            "password": "pass",
            "status": "active",
        }
        response_path = self.write_json("response.json", {"code": 0, "data": {"accounts": [account], "proxies": [proxy]}})
        self.assertEqual(ac.detect_input_kind(response_path), "sub2")
        result = ac.sub2_to_provider(response_path, self.root / "out", "codex", keep_dir=False)
        self.assertEqual(result["provider"], "codex")
        self.assertEqual(result["count"], 1)
        with zipfile.ZipFile(result["zip"]) as archive:
            output = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(output["proxy_url"], "socks5h://user:pass@[2001:db8::1]:1080")

        request_path = self.write_json(
            "request.json",
            {"data": {"type": "sub2api-data", "version": 1, "accounts": [account], "proxies": []}, "skip_default_group_bind": True},
        )
        self.assertEqual(ac.inspect_input(request_path)["account_count"], 1)

    def test_client_credential_shapes_are_normalized(self) -> None:
        codex = self.write_json(
            "auth.json",
            {"OPENAI_API_KEY": None, "tokens": {"access_token": "access", "refresh_token": "refresh", "account_id": "acct"}},
        )
        codex_account = ac.sub2_account_from_native(ac.load_native_items(codex)[0])
        self.assertEqual(ac.account_provider(codex_account), "codex")
        self.assertEqual(codex_account["credentials"]["account_id"], "acct")

        claude = self.write_json(
            "claude-credentials.json",
            {"claudeAiOauth": {"accessToken": "access", "refreshToken": "refresh", "expiresAt": 1_900_000_000_000}},
        )
        claude_item = ac.load_native_items(claude)[0]
        self.assertEqual(claude_item["type"], "claude")
        self.assertEqual(claude_item["refresh_token"], "refresh")

        gemini = self.write_json(
            "oauth_creds.json",
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "expiry_date": 1_900_000_000_000,
            },
        )
        self.assertEqual(ac.detect_input_kind(gemini), "gemini")

    def test_ambiguous_bare_oauth_is_not_guessed(self) -> None:
        path = self.write_json(
            "account.json",
            {"access_token": "access", "refresh_token": "refresh", "email": "unknown@example.com"},
        )
        with self.assertRaisesRegex(ac.ConvertError, "无法识别"):
            ac.inspect_input(path)

    def test_non_oauth_account_type_survives_round_trip(self) -> None:
        source = self.write_json(
            "apikey-sub2.json",
            {
                "accounts": [
                    {
                        "name": "anthropic-key",
                        "platform": "anthropic",
                        "type": "apikey",
                        "credentials": {"api_key": "sk-test", "base_url": "https://api.anthropic.com"},
                    }
                ],
                "proxies": [],
            },
        )
        native = ac.sub2_to_native(source, self.root / "apikey-native", keep_dir=False)
        pack = Path(native["packs"][0]["zip"])
        with zipfile.ZipFile(pack) as archive:
            item = json.loads(archive.read(archive.namelist()[0]))
        self.assertEqual(item["type"], "claude")
        self.assertEqual(item["sub2api_account_type"], "apikey")
        self.assertEqual(item["api_key"], "sk-test")

        back = ac.native_to_sub2(pack, self.root / "apikey-sub2-back")
        payload = json.loads(Path(back["json"]).read_text(encoding="utf-8"))
        self.assertEqual(payload["accounts"][0]["type"], "apikey")


if __name__ == "__main__":
    unittest.main()
