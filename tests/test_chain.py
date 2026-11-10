"""Shared profiles resolve through the standard chain."""

from pathlib import Path

import pytest

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import CredentialsNotFoundError
from lupaxa.aws_authenticate.session import AuthenticatedSession


def _aws_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    credentials = tmp_path / "credentials"
    credentials.write_text(body, encoding="utf-8")
    config = tmp_path / "config"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))


def test_profile_and_chain_return_the_same_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _aws_files(
        tmp_path,
        monkeypatch,
        "[prod]\naws_access_key_id = AKIA_PROD\naws_secret_access_key = prod-secret\n",
    )
    via_profile = AuthenticatedSession.from_profile("prod")
    via_chain = AuthenticatedSession.from_chain(profile="prod")
    expected = AwsCredentials("AKIA_PROD", "prod-secret", None)
    assert via_profile.method == "shared-credentials-file"
    assert via_profile.credentials == expected
    assert via_chain.method == "shared-credentials-file"
    assert via_chain.credentials == expected


def test_padded_profile_name_matches_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _aws_files(
        tmp_path,
        monkeypatch,
        "[prod]\naws_access_key_id = AKIA_PROD\naws_secret_access_key = prod-secret\n",
    )
    exact = AuthenticatedSession.from_profile("prod")
    padded = AuthenticatedSession.from_profile(" prod ")
    expected = AwsCredentials("AKIA_PROD", "prod-secret", None)
    assert padded.method == "shared-credentials-file"
    assert padded.credentials == expected
    assert exact.credentials == padded.credentials


def test_unknown_profile_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _aws_files(
        tmp_path,
        monkeypatch,
        "[prod]\naws_access_key_id = AKIA_PROD\naws_secret_access_key = prod-secret\n",
    )
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_profile("missing")


def test_empty_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(tmp_path, monkeypatch, "")
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_chain()
