<p align="center">
  <a href="https://github.com/lupaxa-aws-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/aws-toolbox/readme-logo.png" alt="AWS Toolbox" />
  </a>
</p>

<h1 align="center">Aws Authenticate</h1>

Resolve AWS credentials and hand back one boto3 session. Callers do not branch on how the keys were obtained. Every constructor returns an `AuthenticatedSession`.

The session is a boto3 `Session`. It adds two attributes:

- `method` is the credential source that won. It is fixed when the session is created. A later refresh does not change it.
- `credentials` is a fresh `AwsCredentials` snapshot: `access_key_id`, `secret_access_key`, and `token` (`None` when there is no session token). Read it again after a refresh.

`method` is one of `explicit`, `env`, `shared-credentials-file`, `assume-role`, `assume-role-with-web-identity`, `sso`, `saml`, `custom-process`, `iam-role`, or `container-role`.
`from_chain` and `from_profile` keep whichever of those botocore selects.

An explicit constructor uses only the source you name. `from_chain` and `from_profile` use botocore's standard chain, and they open a browser once when an IAM Identity Center token is missing or expired.

Requires Python 3.13 or newer.

## Install

```bash
pip install lupaxa-aws-authenticate
```

```python
from lupaxa.aws_authenticate import AuthenticatedSession
```

Pass `region=` when the source does not already carry one. EC2 and RDS clients need a region.

## Errors

Authentication failures subclass `AuthenticationError`. The original botocore or STS error is `__cause__`.
A missing or blank argument raises `ValueError` before any AWS call.
API calls you make afterwards raise boto3's own errors.
This library does not call `sts:GetCallerIdentity`.

- `CredentialsNotFoundError` means the source has no keys: unknown profile, empty chain, blank SAML assertion, missing web identity file, unreachable instance metadata or container endpoint, or a credential process with no keys.
- `LoginError` means IAM Identity Center login is denied, cancelled, or times out, or no browser can be opened.
- `MfaRequiredError` means assume-role was given `mfa_serial` and no code, and there is no terminal or the answer is empty. It also means STS says MFA is required and no code was sent.
- `RoleAssumptionError` means STS or IAM Identity Center rejects the role, including a wrong MFA code, external id, or duration.
- `ValueError` means a required argument is missing or blank, such as a role ARN, a source session, an access key, or a process command. It is also raised when web identity is given both `token` and `token_file`, or neither.

## Static Keys

`method` is `explicit`. Only the keys you pass are used.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_keys(
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    session_token=None,
    region="eu-west-1",
)
```

### Config

No config file and no environment variables. A whitespace-only `session_token` is stored as `None`.

## Environment Variables

`method` is `env`. Only `EnvProvider` is consulted.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_environment(region="eu-west-1")
```

### Config

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=          # optional
export AWS_DEFAULT_REGION=eu-west-1
```

`AWS_PROFILE` and the shared credentials file are ignored by this constructor.

## Shared Profile and the Default Chain

`from_profile` checks the name, strips surrounding spaces, and calls `from_chain`.
`from_chain()` with no profile uses the default credential chain: environment variables, the shared credentials file, a web identity token, IAM Identity Center, a credential process, container credentials, then instance metadata.

When the winning provider is a shared credentials profile, `method` is `shared-credentials-file`. Otherwise `method` is whatever botocore sets.

If the profile's IAM Identity Center token is missing or expired, the library opens a browser, waits up to 10 minutes, writes `~/.aws/sso/cache`, and resolves once more.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_profile("prod", region="eu-west-1")
default_session = AuthenticatedSession.from_chain(region="eu-west-1")
```

`region=` overrides the region on the botocore session. Omit it to keep the region from the profile or from `AWS_DEFAULT_REGION`.

### Config

Default files are `~/.aws/credentials` and `~/.aws/config`. Override them with `AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE`.

`~/.aws/credentials`:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2VjEExample
```

`~/.aws/config`:

```ini
[default]
region = eu-west-1

[profile prod]
region = eu-west-1
```

A profile that assumes a role, uses SSO, or runs a credential process is valid here too. Those shapes are shown under Assume Role, IAM Identity Center, and Credential Process. `from_profile("prod")` follows whichever shape that profile has.

## Assume Role

`method` is `assume-role`. The source session supplies the keys that call STS. This constructor does not read `~/.aws/config`.

Omitted `role_session_name` is `aws-authenticate`. Omitted `duration_seconds` is left out of the STS call, so AWS applies its default. `ExternalId` and `SerialNumber` are sent only when you pass them.

If `mfa_serial` is set and `mfa_code` is omitted, the library prompts on the terminal.
A code without `mfa_serial` raises `ValueError`.
The code is not placed in the STS arguments up front. Botocore asks the prompter when `SerialNumber` is set.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

source = AuthenticatedSession.from_profile("prod")
session = AuthenticatedSession.from_assume_role(
    source,
    "arn:aws:iam::123456789012:role/Admin",
    mfa_serial="arn:aws:iam::111122223333:mfa/ada",
    external_id="outside",
    duration_seconds=3600,
    role_session_name="inventory",
    region="eu-west-1",
)
```

Pass `mfa_code="123456"` when the process has no terminal.

### Config

Use this profile with `from_profile` when you want botocore to assume the role from the config file instead of calling `from_assume_role`:

```ini
[profile prod-admin]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = prod
mfa_serial = arn:aws:iam::111122223333:mfa/ada
external_id = outside
duration_seconds = 3600
role_session_name = inventory
region = eu-west-1
```

## Web Identity

`method` is `assume-role-with-web-identity`. Pass exactly one of `token` or `token_file`.
The file is read as UTF-8 at construction, and later refreshes read it again.
An empty file, a missing file, or an unreadable path raises `CredentialsNotFoundError`.

Omitted `role_session_name` is `aws-authenticate`. Omitted `duration_seconds` is left out of the STS call.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_web_identity(
    "arn:aws:iam::123456789012:role/Eks",
    token_file="/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    region="eu-west-1",
)
```

A token you already hold:

```python
session = AuthenticatedSession.from_web_identity(
    "arn:aws:iam::123456789012:role/Eks",
    token=open("token.jwt", encoding="utf-8").read(),
    region="eu-west-1",
)
```

### Config

This constructor ignores `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. The default chain does honour them, so `from_chain()` on EKS picks them up with no arguments.

The same data as a profile, for `from_profile`:

```ini
[profile eks]
role_arn = arn:aws:iam::123456789012:role/Eks
web_identity_token_file = /var/run/secrets/eks.amazonaws.com/serviceaccount/token
role_session_name = eks
region = eu-west-1
```

## SAML

`method` is `saml`. You pass a base64 SAML assertion, the role ARN, and the SAML provider ARN.
There is no identity-provider browser.
A blank assertion raises `CredentialsNotFoundError` before STS is called.
Omitted `duration_seconds` is left out of the STS call.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

assertion = open("assertion.txt", encoding="utf-8").read()
session = AuthenticatedSession.from_saml(
    "arn:aws:iam::123456789012:role/SamlAdmin",
    "arn:aws:iam::123456789012:saml-provider/Example",
    assertion,
    duration_seconds=3600,
    region="eu-west-1",
)
```

### Config

No config file. The assertion comes from your identity provider. The two ARNs are the role and the IAM SAML provider that trusts that provider.

## Credential Process

`method` is `custom-process`. The command is the only source. Environment keys set beside it are ignored.

The process must print a JSON document on stdout:

```json
{
  "Version": 1,
  "AccessKeyId": "ASIAEXAMPLE",
  "SecretAccessKey": "secret",
  "SessionToken": "token",
  "Expiration": "2999-01-01T00:00:00Z"
}
```

`SessionToken` and `Expiration` are optional. A failing process, or JSON with no keys, raises `CredentialsNotFoundError`.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_process(
    "/usr/local/bin/issue-keys --json",
    region="eu-west-1",
)
```

### Config

The same command as a profile, for `from_profile`:

```ini
[profile tools]
credential_process = /usr/local/bin/issue-keys --json
region = eu-west-1
```

## Instance Metadata

`method` is `iam-role`. The session uses the IAM role attached to the EC2 instance. An empty response from the metadata service raises `CredentialsNotFoundError`.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_instance_metadata(region="eu-west-1")
```

### Config

No config file. The instance needs an instance profile. Leave `AWS_EC2_METADATA_DISABLED` unset. This constructor does not change that variable. `from_chain()` skips instance metadata when `AWS_EC2_METADATA_DISABLED=true`.

## Container Credentials

`method` is `container-role`. Used for ECS, EKS pods that use the container credential endpoint, and App Runner. If neither URI variable is set, this raises `CredentialsNotFoundError`.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_container(region="eu-west-1")
```

### Config

The runtime sets one of these. A relative URI is the path on `169.254.170.2`. A full URI is an absolute URL, and it may need an authorization token.

```bash
export AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/task-id
# or
export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.2/v1/credentials
export AWS_CONTAINER_AUTHORIZATION_TOKEN=token
# or, instead of the token value:
export AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token
```

## IAM Identity Center

`method` is `sso`. `from_sso` takes the start URL, the Identity Center region, the account id, and the role name. It does not read your config file. It writes a temporary profile, then resolves only the SSO provider.

When `~/.aws/sso/cache` has no usable token, the library registers a public client and opens the browser for an authorization-code login with PKCE.
It waits on `127.0.0.1` for up to 10 minutes.
The token is cached under `~/.aws/sso/cache`. The next call reuses it until it expires, then logs in again.
A denied, cancelled, or timed-out login raises `LoginError`.

`from_profile` and `from_chain` do the same login when the profile they resolve is an SSO profile.

### Example

```python
from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_sso(
    "https://my-org.awsapps.com/start",
    "eu-west-1",
    "123456789012",
    "ReadOnly",
    region="eu-west-1",
)
```

### Config

No config file is required for `from_sso`. To select the same role with `from_profile`, use an `sso-session` block:

```ini
[sso-session work]
sso_start_url = https://my-org.awsapps.com/start
sso_region = eu-west-1
sso_registration_scopes = sso:account:access

[profile work-readonly]
sso_session = work
sso_account_id = 123456789012
sso_role_name = ReadOnly
region = eu-west-1
```

A legacy profile without an `sso-session` block also works with `from_profile`:

```ini
[profile work-readonly]
sso_start_url = https://my-org.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 123456789012
sso_role_name = ReadOnly
region = eu-west-1
```

## Example Scripts

Any constructor can replace the session line. The client calls are ordinary boto3 calls.

### List EC2 Instances

Uses a shared profile. Swap `from_profile` for `from_environment`, `from_instance_metadata`, or `from_container` when the process is already running with those credentials.

```python
"""List running EC2 instances."""

from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_profile("prod", region="eu-west-1")
ec2 = session.client("ec2")
pages = ec2.get_paginator("describe_instances").paginate(
    Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
)
for page in pages:
    for reservation in page["Reservations"]:
        for instance in reservation["Instances"]:
            name = next(
                (
                    tag["Value"]
                    for tag in instance.get("Tags", [])
                    if tag["Key"] == "Name"
                ),
                "",
            )
            print(
                instance["InstanceId"],
                name,
                instance.get("PrivateIpAddress", ""),
            )
```

### List RDS Instances

Uses IAM Identity Center. The first run opens a browser when the cached token is missing or expired.

```python
"""List RDS DB instances."""

from lupaxa.aws_authenticate import AuthenticatedSession

session = AuthenticatedSession.from_sso(
    "https://my-org.awsapps.com/start",
    "eu-west-1",
    "123456789012",
    "ReadOnly",
    region="eu-west-1",
)
rds = session.client("rds")
pages = rds.get_paginator("describe_db_instances").paginate()
for page in pages:
    for database in page["DBInstances"]:
        print(
            database["DBInstanceIdentifier"],
            database["Engine"],
            database["DBInstanceStatus"],
        )
```

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
