"""Config-driven serve: build_adapter_host, available_adapters, HostProfile."""

from __future__ import annotations

import json

import pytest

from chp_host import HostProfile, available_adapters, build_adapter_host


class TestAvailableAdapters:
    def test_lists_installed_adapters(self):
        names = available_adapters()
        # The router's own test env has the full adapter set installed.
        assert "aws" in names
        assert "vector" in names
        assert names == sorted(names)


class TestBuildAdapterHost:
    def test_registers_exactly_named_adapters(self):
        host, result = build_adapter_host(["aws"], host_id="t", store_path=":memory:")
        assert result.registered == ["aws"]
        assert result.skipped == {}
        cap_ids = [c["id"] for c in host.discover()["capabilities"]]
        # every capability belongs to the aws adapter namespace
        assert cap_ids
        assert all(cid.startswith("chp.adapters.aws.") for cid in cap_ids)

    def test_multiple_adapters(self):
        host, result = build_adapter_host(
            ["aws", "vector"], host_id="t", store_path=":memory:"
        )
        assert set(result.registered) == {"aws", "vector"}
        namespaces = {c["id"].rsplit(".", 1)[0] for c in host.discover()["capabilities"]}
        assert "chp.adapters.aws" in namespaces
        assert "chp.adapters.vector" in namespaces

    def test_unknown_adapter_is_skipped_not_fatal(self):
        with pytest.warns(UserWarning):
            host, result = build_adapter_host(
                ["aws", "does-not-exist"], host_id="t", store_path=":memory:"
            )
        assert result.registered == ["aws"]
        assert "does-not-exist" in result.skipped
        assert result.skipped["does-not-exist"] == "not installed"
        # host still built and serves the aws adapter
        assert host.discover()["capabilities"]

    def test_summary_mentions_registered_and_skipped(self):
        with pytest.warns(UserWarning):
            _, result = build_adapter_host(
                ["aws", "nope"], host_id="t", store_path=":memory:"
            )
        summary = result.summary()
        assert "aws" in summary
        assert "nope" in summary


class TestHostProfile:
    def test_from_dict(self):
        profile = HostProfile.from_dict(
            {"host_id": "cloud", "adapters": ["aws", "gcp"], "port": 8801}
        )
        assert profile.host_id == "cloud"
        assert profile.adapters == ["aws", "gcp"]
        assert profile.port == 8801
        assert profile.store == ".chp/cloud.sqlite"

    def test_defaults(self):
        profile = HostProfile.from_dict({"host_id": "h", "adapters": ["aws"]})
        assert profile.bind == "127.0.0.1"
        assert profile.port == 8765

    def test_missing_host_id_raises(self):
        with pytest.raises(ValueError):
            HostProfile.from_dict({"adapters": ["aws"]})

    def test_missing_adapters_raises(self):
        with pytest.raises(ValueError):
            HostProfile.from_dict({"host_id": "h"})

    def test_load_from_file(self, tmp_path):
        path = tmp_path / "cloud.json"
        path.write_text(json.dumps({"host_id": "cloud", "adapters": ["aws"], "port": 9001}))
        profile = HostProfile.load(path)
        assert profile.host_id == "cloud"
        assert profile.port == 9001
