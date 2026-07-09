"""Publisher key pinning (chp-v0.2.md §9) — the known_hosts model for the
supply chain."""

from __future__ import annotations

from chp_host import publishers


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(publishers, "publishers_path",
                        lambda: tmp_path / "publishers.json")


class TestPublisherPins:
    def test_first_verified_install_pins(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        status, key = publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB")
        assert status == "pinned" and key == "aaaa"
        assert publishers.load_publishers()["publishers"]["chp-adapter-x"]["trust"] == "tofu"

    def test_matching_key_is_ok(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB")
        assert publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB")[0] == "ok"

    def test_different_key_is_mismatch(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB")
        status, pinned = publishers.pin_or_check_publisher("chp-adapter-x", "bbbb", "EVIL")
        assert status == "mismatch" and pinned == "aaaa"
        # the pin is untouched by the failed attempt
        assert publishers.load_publishers()["publishers"]["chp-adapter-x"]["key_id"] == "aaaa"

    def test_trust_upgrades_but_never_downgrades(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB", trust="tofu")
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB", trust="anchored")
        assert publishers.load_publishers()["publishers"]["chp-adapter-x"]["trust"] == "anchored"
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB", trust="tofu")
        assert publishers.load_publishers()["publishers"]["chp-adapter-x"]["trust"] == "anchored"

    def test_reset_allows_repin(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        publishers.pin_or_check_publisher("chp-adapter-x", "aaaa", "PUB")
        assert publishers.reset_publisher("chp-adapter-x") is True
        assert publishers.pin_or_check_publisher("chp-adapter-x", "bbbb", "NEW")[0] == "pinned"

    def test_reset_unknown_package_is_false(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        assert publishers.reset_publisher("never-pinned") is False


class TestRegistryPrePin:
    def _registry(self, tmp_path, key_id="cafecafecafecafe"):
        import json
        reg = tmp_path / "registry"
        reg.mkdir()
        (reg / "adapters.json").write_text(json.dumps({
            "official": [{"id": "chp-adapter-x", "pypi": "chp-adapter-x",
                          "publisher_key_id": key_id}]}))
        return tmp_path

    def test_local_registry_lookup(self, tmp_path, monkeypatch):
        from chp_host.cli import _registry_publisher_pin
        monkeypatch.chdir(self._registry(tmp_path))
        assert _registry_publisher_pin("chp-adapter-x", lambda m: None) == "cafecafecafecafe"

    def test_unknown_package_returns_none(self, tmp_path, monkeypatch):
        from chp_host.cli import _registry_publisher_pin
        monkeypatch.chdir(self._registry(tmp_path))
        monkeypatch.setenv("CHP_REGISTRY_URL", "http://127.0.0.1:9/none")  # no network fallback
        assert _registry_publisher_pin("chp-adapter-unknown", lambda m: None) is None

    def test_walks_up_from_subdirectory(self, tmp_path, monkeypatch):
        from chp_host.cli import _registry_publisher_pin
        root = self._registry(tmp_path)
        sub = root / "a" / "b"; sub.mkdir(parents=True)
        monkeypatch.chdir(sub)
        assert _registry_publisher_pin("chp-adapter-x", lambda m: None) == "cafecafecafecafe"
