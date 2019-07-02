# conjur-api-powershell
Powershell-based API SDK for [Conjur OSS](https://www.conjur.org/).

---

### **Status**: Alpha

#### **Warning: Naming and APIs are still subject to breaking changes!**

---

## Installing the code

### From source

```powershell
PS C:\> Import-Module .\CyberarkConjur.psm1
```

## Usage

### Setting environment variables
#### Conjur authentication
```powershell
PS C:\> $env:CONJUR_ACCOUNT="dev"
PS C:\> $env:CONJUR_AUTHN_LOGIN="admin"
PS C:\> $env:CONJUR_AUTHN_API_KEY="adminPassword"
PS C:\> $env:CONJUR_APPLIANCE_URL="https://conjur.yourorg.com:443"
```

#### IAM Authentication
```powershell
PS C:\> $env:CONJUR_ACCOUNT="dev"
PS C:\> $env:CONJUR_AUTHN_LOGIN="host/cust-portal/622703825757/ubuntu-client-conjur-identity"
PS C:\> $env:CONJUR_IAM_AUTHN_BRANCH="authnBranchName"
PS C:\> $env:CONJUR_APPLIANCE_URL="https://conjur.yourorg.com:443"
```

### Available Functions
#### Get-ConjurSecret

```powershell
PS C:\> Get-ConjurSecret -SecretIdentifier "secrets/db-password"
secretPasswordHere
```

#### Set-ConjurSecret

```powershell
PS C:\> Set-ConjurSecret -SecretIdentifier "secrets/db-password" -SecretValue "brandNewSecret"
```

#### Get-ConjurHealth

```powershell
PS C:\> Get-ConjurHealth

services                                database                                                                     ok
--------                                --------                                                                     --
@{possum=ok; ui=ok; ok=True}            @{ok=True; connect=; free_space=; re...                                    True
```

#### Update-ConjurPolicy

```powershell
PS C:\> Update-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4
```

#### Get-ConjurResources

```powershell
PS C:\> Get-ConjurResources

created_at      : 2019-05-29T16:42:56.284+00:00
id              : dev:policy:root
owner           : dev:user:admin
permissions     : {}
annotations     : {}
policy_versions : {@{version=1; created_at=2019-05-29T16:42:56.284+00:00; policy_text=---       
```

#### Get-Help
You can Get-Help on all of the functions mentioned above.

```powershell
PS C:\> Get-Help Update-ConjurPolicy

NAME
    Update-ConjurPolicy

SYNOPSIS
    Update a policy in conjur


SYNTAX
    Update-ConjurPolicy [-PolicyIdentifier] <String> [-PolicyFilePath] <String> [-ConjurAccount <Object>]
    [-ConjurUsername <Object>] [-ConjurPassword <Object>] [-ConjurApplianceUrl <Object>] [-IgnoreSsl]
    [<CommonParameters>]


DESCRIPTION
    Modifies an existing Conjur policy. Data may be explicitly deleted using the !delete, !revoke, and !deny
    statements.
    Unlike “replace” mode, no data is ever implicitly deleted.


RELATED LINKS
    https://www.conjur.org/api.html#policies-update-a-policy-patch

REMARKS
    To see the examples, type: "get-help Update-ConjurPolicy -examples".
    For more information, type: "get-help Update-ConjurPolicy -detailed".
    For technical information, type: "get-help Update-ConjurPolicy -full".
    For online help, type: "get-help Update-ConjurPolicy -online"
```

## Contributing

We store instructions for development and guidelines for how to build and test this
project in the [CONTRIBUTING.md](CONTRIBUTING.md) - please refer to that document
if you would like to contribute.

## License

This project is [licensed under Apache License v2.0](LICENSE.md)
