"""Keep tests off the developer AWS environment and IMDS."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_aws_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Drop ambient AWS settings so a provider cannot see this machine."""
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    aws_dir = home / ".aws"
    aws_dir.mkdir(parents=True)
    config = aws_dir / "config"
    credentials = aws_dir / "credentials"
    config.write_text("", encoding="utf-8")
    credentials.write_text("", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
