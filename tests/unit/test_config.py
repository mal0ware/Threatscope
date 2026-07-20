"""Tests for settings construction from environment variables."""

from pathlib import Path

from agent.config import get_settings


class TestLogSources:
    def test_default_sources(self, monkeypatch):
        monkeypatch.delenv("THREATSCOPE_LOG_SOURCES", raising=False)
        settings = get_settings()

        assert Path("/var/log/auth.log") in settings.log_sources
        assert Path("/var/log/syslog") in settings.log_sources
        assert Path("/var/log/dnsmasq.log") in settings.log_sources

    def test_env_override_comma_separated(self, monkeypatch):
        monkeypatch.setenv(
            "THREATSCOPE_LOG_SOURCES",
            "/srv/logs/auth.log, /srv/logs/dnsmasq.log",
        )
        settings = get_settings()

        assert settings.log_sources == [
            Path("/srv/logs/auth.log"),
            Path("/srv/logs/dnsmasq.log"),
        ]

    def test_blank_env_falls_back_to_defaults(self, monkeypatch):
        monkeypatch.setenv("THREATSCOPE_LOG_SOURCES", "   ")
        settings = get_settings()

        assert len(settings.log_sources) == 3
