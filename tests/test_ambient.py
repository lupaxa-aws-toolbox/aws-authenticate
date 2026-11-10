"""Explicit ambient providers do not consult other sources."""

import json

import pytest

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import CredentialsNotFoundError
from lupaxa.aws_authenticate.session import AuthenticatedSession


def test_process_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")

    def fake_popen(args: list[str], stdout: object, stderr: object) -> object:
        assert args == ["issue-keys", "--json"]

        class _Proc:
            returncode = 0

            def communicate(self) -> tuple[bytes, bytes]:
                payload = {
                    "Version": 1,
                    "AccessKeyId": "AKIA_PROC",
                    "SecretAccessKey": "proc-secret",
                    "SessionToken": "proc-token",
                }
                return json.dumps(payload).encode(), b""

        return _Proc()

    monkeypatch.setattr("lupaxa.aws_authenticate.session.subprocess.Popen", fake_popen)
    session = AuthenticatedSession.from_process("issue-keys --json")
    assert session.method == "custom-process"
    expected = AwsCredentials("AKIA_PROC", "proc-secret", "proc-token")
    assert session.credentials == expected


def test_process_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_popen(args: list[str], stdout: object, stderr: object) -> object:
        class _Proc:
            returncode = 1

            def communicate(self) -> tuple[bytes, bytes]:
                return b"", b"boom"

        return _Proc()

    monkeypatch.setattr("lupaxa.aws_authenticate.session.subprocess.Popen", fake_popen)
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_process("issue-keys")


def test_process_requires_a_command() -> None:
    with pytest.raises(ValueError, match="command"):
        AuthenticatedSession.from_process("  ")


def test_instance_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_EC2_METADATA_DISABLED", raising=False)

    class _Fetcher:
        def retrieve_iam_role_credentials(self) -> dict[str, str]:
            return {
                "role_name": "app",
                "access_key": "ASIA_IMDS",
                "secret_key": "imds-secret",
                "token": "imds-token",
                "expiry_time": "2999-01-01T00:00:00Z",
            }

    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.InstanceMetadataFetcher",
        lambda: _Fetcher(),
    )
    session = AuthenticatedSession.from_instance_metadata()
    assert session.method == "iam-role"
    expected = AwsCredentials("ASIA_IMDS", "imds-secret", "imds-token")
    assert session.credentials == expected


def test_instance_metadata_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_EC2_METADATA_DISABLED", raising=False)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.InstanceMetadataFetcher",
        lambda: type("F", (), {"retrieve_iam_role_credentials": lambda self: {}})(),
    )
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_instance_metadata()


def test_container(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "http://169.254.170.2/creds",
    )

    class _Fetcher:
        def retrieve_full_uri(self, uri: str, headers: object = None) -> dict[str, str]:
            assert uri == "http://169.254.170.2/creds"
            return {
                "AccessKeyId": "ASIA_ECS",
                "SecretAccessKey": "ecs-secret",
                "Token": "ecs-token",
                "Expiration": "2999-01-01T00:00:00Z",
            }

    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.ContainerMetadataFetcher",
        lambda: _Fetcher(),
    )
    session = AuthenticatedSession.from_container()
    assert session.method == "container-role"
    assert session.credentials == AwsCredentials("ASIA_ECS", "ecs-secret", "ecs-token")


def test_container_without_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", raising=False)
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_container()
