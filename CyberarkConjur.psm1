Function Write-Log
{
    param(
        $Message,
        $Level = "INFO"
    )
    Write-Verbose "$Level :: $Message" 
}

Function Disable-SslVerification
{
try
{

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

}
catch
{
# Ignore if error is thrown, an error is thrown if we Disaable-SSL twice in the same pwoershell session
}
}

Function Get-ResponseBodyFromException()
{
    param(
        $Exception
    )

    $responseBody = $null

    if ($Exception.Response -ne $null)
    {
        $result = $Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
    }

    return $responseBody;
}

Function Get-HeaderAsString()
{
    param(
        $Header
    )

    $headerAsString = ""

    if ($Header -ne $null)
    {
        foreach ($kv in $Header.GetEnumerator())
        {
            $headerAsString += "$($kv.Name)=$($kv.Value);"
        }
    }

    return $headerAsString
}

Function Send-HttpMethod()
{
    param(
        $Url, 
        $Method, 
        $Header, 
        $Body = $null,
        $LogResponse = $true,
        $Certificate = $null
    )
    Write-Log "URL: $Url"
    Write-Log "Method: $Method"
    Write-Log "Default Header: $(Get-HeaderAsString -Header $Header)"
    Write-Log "Body: $Body"
    $res = $null


    try
    {
        if ($Certificate -eq $null)
        {
            if ($body -eq $null)
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header
            }
            else
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Body $body
            }
        }
        else
        {
            if ($body -eq $null)
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Certificate $Certificate -CertificateThumbprint $Certificate.Thumbprint
            }
            else
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Body $body -Certificate $Certificate -CertificateThumbprint $Certificate.Thumbprint
            }
        }
    }
    catch
    {
        $exception = $_.Exception
        $responseBody = Get-ResponseBodyFromException($exception)
        Write-Log -Message "Response Body: `n $($responseBody | ConvertFrom-Json | ConvertTo-Json)" -Level "ERROR"
        throw $_
        break
    }
    
    if ($LogResponse)
    {
        Write-Log "HTTP Response: $($res | ConvertTo-Json)"
    }

    return $res
}

Function Test-MandatoryParameter
{
    param(
        $EnvironmentVariableName,
        $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value))
    {
        Write-Host -ForegroundColor RED "Mandatory parameter is empty or missing: $EnvironmentVariableName"
        return $false
    }
    else
    {
        Write-Log "$EnvironmentVariableName=$Value"
    }

    return $true
}

Function Test-MandatoryParameters
{
    param (
        $OmitEnvironmentVariables = @()
    )

    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_ACCOUNT" -Value $ConjurAccount)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_AUTHN_LOGIN" -Value $ConjurUsername)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_AUTHN_API_KEY" -Value $ConjurPassword)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_APPLIANCE_URL" -Value $ConjurApplianceUrl)) { return $false; }
    # if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_CERT" -Value $ConjurCert)) { return $false; }
    return $true
}

Function Test-MandatoryParametersIam
{
    param (
        $OmitEnvironmentVariables = @()
    )

    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_ACCOUNT" -Value $ConjurAccount)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_AUTHN_LOGIN" -Value $ConjurUsername)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_IAM_AUTHN_BRANCH" -Value $ConjurPassword)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_APPLIANCE_URL" -Value $ConjurApplianceUrl)) { return $false; }
    # if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_CERT" -Value $ConjurCert)) { return $false; }
    return $true
}


Function Get-SessionTokenHeader
{
    param(
        $SessionToken
    )
    $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((($SessionToken | ConvertTo-Json))))
    $header = @{"Authorization"= "Token token=`"$base64`""}
    return $header
}

$api_authn_iam_branch = "prod"
$host_id = "host/949316202723/Conjur-EC2-Test"

$region = "us-east-1"
$sts_host = "sts.amazonaws.com"
$service = "sts"

#Add-Type -TypeDefinition $helperClass -Language CSharp

Function Enable-HelperNamespace{
add-type @"
    namespace HelperNamespace {
        public static class HelperClass {
            public static string ToHexString(byte[] array) {
                var hex = new System.Text.StringBuilder(array.Length * 2);
                foreach(byte b in array) {
                    hex.AppendFormat("{0:x2}", b);
                }
                return hex.ToString();
            }
            public static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
            {
                byte[] kDate = HmacSHA256(System.Text.Encoding.UTF8.GetBytes("AWS4" + key), dateStamp);
                byte[] kRegion = HmacSHA256(kDate, regionName);
                byte[] kService = HmacSHA256(kRegion, serviceName);
                byte[] kSigning = HmacSHA256(kService, "aws4_request");
                return kSigning;
            }
            
            public static byte[] HmacSHA256(byte[] key, string data)
            {
                var hashAlgorithm = new System.Security.Cryptography.HMACSHA256(key);
                return hashAlgorithm.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
            }
        }
    }
"@
}

function Get-IamAuthorizationHeader {
  param (
    $cHost, 
    $cDate, 
    $cToken,
    $cRegion,
    $cService,
    $cAccessKeyId,
    $cSecretAccessKey
    )
    Enable-HelperNamespace

    $empty_body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    $algorithm = "AWS4-HMAC-SHA256"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()

    $canonical_request = "GET`n"
    $canonical_request += "/`n"
    $canonical_request += "Action=GetCallerIdentity&Version=2011-06-15`n"
    $canonical_request += "host:$cHost`n"
    $canonical_request += "x-amz-content-sha256:$empty_body_hash`n"
    $canonical_request += "x-amz-date:$cDate`n"
    $canonical_request += "x-amz-security-token:$cToken`n"
    $canonical_request += "`n"
    $canonical_request += "$signed_headers`n"
    $canonical_request += "$empty_body_hash"

    $datestamp = $cDate.Split('T')[0]

    $cred_scope = "$($datestamp)/$($cRegion)/$($cService)/aws4_request"

    $string_to_sign = "$($algorithm)`n$($cDate)`n$($cred_scope)`n"
    $string_to_sign += [HelperNamespace.HelperClass]::ToHexString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical_request.ToString())))

    $signing_key = [HelperNamespace.HelperClass]::GetSignatureKey($cSecretAccessKey, $datestamp, $cRegion, $cService)
    $signature = [HelperNamespace.HelperClass]::ToHexString([HelperNamespace.HelperClass]::HmacSHA256($signing_key, $string_to_sign))


    "$($algorithm) Credential=$($cAccessKeyId)/$($cred_scope), SignedHeaders=$($signed_headers), Signature=$($signature)"
}

function Get-AwsRegion {
    $region = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone"
    return $region.Substring(0, $region.Length -1)
}

Function Get-IamConjurApiKey {
    $region = Get-AwsRegion

    $t = [DateTimeOffset]::UtcNow
    $x_amz_date = $t.ToString("yyyyMMddTHHmmssZ")

    $uri_role = "http://169.254.169.254/latest/meta-data/iam/security-credentials"
    $role = Send-HttpMethod -Url $uri_role -Method GET

    $uri_creds = "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role"
    $cred_results = Send-HttpMethod -Url $uri_creds -Method GET
    $access_key_id = $cred_results.AccessKeyId
    $secret_access_key = $cred_results.SecretAccessKey
    $x_amz_security_token = $cred_results.Token

    $output = Get-IamAuthorizationHeader $sts_host $x_amz_date $x_amz_security_token $region $service $access_key_id $secret_access_key
    #Write-Host $output

    $empty_body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    $conjurToken = [pscustomobject]@{
    "host"="$sts_host"
    "x-amz-content-sha256"="$empty_body_hash"
    "x-amz-date"="$x_amz_date"
    "x-amz-security-token"="$x_amz_security_token"
    "authorization"="$output"
    }|ConvertTo-Json

    return $conjurToken 

    #Write-Host "==================`n$body`n======================="
    #Write-Host $authn_url
    # $authn_url = "https://$api_endpoint/authn-iam/$api_authn_iam_branch/$api_account/$conjur_host_id/authenticate"
    # $authn_result = Invoke-RestMethod -Method POST -uri $authn_url -Body $body
    # Write-Host $authn_result
}

Function Get-ConjurApiKey
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        $IgnoreSsl = $false
    )

    $iamAuthn = Test-MandatoryParameter -EnvironmentVariableName "CONJUR_IAM_AUTHN_BRANCH" -Value $IamAuthnBranch

    if ($iamAuthn)
    {
        if (!(Test-MandatoryParametersIam)) { return }
        if (($IgnoreSsl)) { Disable-SslVerification }
        return Get-IamConjurApiKey
    }
    else
    {
        if (!(Test-MandatoryParameters)) { return }
        if (($IgnoreSsl)) { Disable-SslVerification }
        $url = "$ConjurApplianceUrl/authn/$ConjurAccount/login"

        $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $ConjurUsername, $ConjurPassword)))
        $basicAuthHeader = @{"Authorization"="Basic $base64"}
        return Send-HttpMethod -Url $url -Method GET -Header $basicAuthHeader
    }
    
}

# This is required because powershell will automatically decode %2F to / to avoid that we must run this method on the uri that contains %2F
function FixUri($uri){
    $UnEscapeDotsAndSlashes = 0x2000000;
    $SimpleUserSyntax = 0x20000;

    $type = $uri.GetType();
    $fieldInfo = $type.GetField("m_Syntax", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic));

    $uriParser = $fieldInfo.GetValue($uri);
    $typeUriParser = $uriParser.GetType().BaseType;
    $fieldInfo = $typeUriParser.GetField("m_Flags", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::FlattenHierarchy));
    $uriSyntaxFlags = $fieldInfo.GetValue($uriParser);

    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot $UnEscapeDotsAndSlashes);
    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot $SimpleUserSyntax);
    $fieldInfo.SetValue($uriParser, $uriSyntaxFlags);
}

Function Get-ConjurSessionToken
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        $IgnoreSsl = $false
    )

    $apiKey = Get-ConjurApiKey -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl

    $iamAuthn = Test-MandatoryParameter -EnvironmentVariableName "CONJUR_IAM_AUTHN_BRANCH" -Value $IamAuthnBranch
    $ConjurUsername = [uri]::EscapeDataString($ConjurUsername)

    $url = ([uri]"$ConjurApplianceUrl/authn/$ConjurAccount/$ConjurUsername/authenticate")

    if ($iamAuthn)
    {
        $url = ([uri]"$ConjurApplianceUrl/authn-iam/$IamAuthnBranch/$ConjurAccount/$ConjurUsername/authenticate")
    }

    fixuri $url

    return Send-HttpMethod -Url $url -Method POST -Body $apiKey
}

<#
.SYNOPSIS

Get health of a conjur instance

.DESCRIPTION

Get health of a conjur instance

.INPUTS

None. You cannot pipe objects to Get-ConjurHealth.

.OUTPUTS

System.Collections.Hashtable. The health of the conjur instance.

.EXAMPLE

PS> Get-ConjurHealth
services                                database                                                                     ok
--------                                --------                                                                     --
@{possum=ok; ui=ok; ok=True}            @{ok=True; connect=; free_space=; re...                                    True


.LINK

https://www.conjur.org/api.html#health-get-health


#>
Function Get-ConjurHealth
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        # $ConjurCert = $env:CONJUR_CERT,
        $IgnoreSsl = $false
    )

    if (!(Test-MandatoryParameters)) { return }
    if (($IgnoreSsl)) { Disable-SslVerification }

    $url = "$ConjurApplianceUrl/health"
    return Send-HttpMethod -Url $url -Method "GET"
}

<#
.SYNOPSIS

Retrieve a secret from conjur

.DESCRIPTION

Retrieve a secret from conjur
Takes a Secret identifier

.PARAMETER SecretIdentifier
The identifier used to retrieve the secret

.INPUTS

None. You cannot pipe objects to Get-ConjurSecret.

.OUTPUTS

System.String. The secret retrieved.

.EXAMPLE

PS> Get-ConjurSecret -SecretIdentifier "path/to/secret"
AHfdkrjeb81hs6ah

.LINK

https://www.conjur.org/api.html#secrets-retrieve-a-secret-get


#>
Function Get-ConjurSecret()
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$SecretIdentifier,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl,
        $SecretKind = "variable"
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    # $SecretIdentifier = [uri]::EscapeDataString($SecretIdentifier)
    $url = "$ConjurApplianceUrl/secrets/$ConjurAccount/$SecretKind/$SecretIdentifier"
    # FixUri $url

    return Send-HttpMethod -Url $url -Method GET -Header $header
}

<#
.SYNOPSIS

Set a secret in conjur

.DESCRIPTION

Set a secret in conjur
Takes a secret identifier and secret value

.PARAMETER SecretIdentifier
The identifier used to set the secret

.PARAMETER SecretValue
The value of the secret

.INPUTS

None. You cannot pipe objects to Set-ConjurSecret.

.OUTPUTS

None.

.EXAMPLE

PS> Set-ConjurSecret -SecretIdentifier "path/to/secret" -SecretValue "newPasswordHere"


.LINK

https://www.conjur.org/api.html#secrets-add-a-secret-post


#>
Function Set-ConjurSecret
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$SecretIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$SecretValue,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl,
        $SecretKind = "variable"
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/secrets/$ConjurAccount/$SecretKind/$SecretIdentifier"

    return Send-HttpMethod -Url $url -Method POST -Header $header -Body $SecretValue
}

<#
.SYNOPSIS

Update a policy in conjur

.DESCRIPTION

Modifies an existing Conjur policy. Data may be explicitly deleted using the !delete, !revoke, and !deny statements. 
Unlike “replace” mode, no data is ever implicitly deleted.

.PARAMETER PolicyIdentifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Update-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Update-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://www.conjur.org/api.html#policies-update-a-policy-patch


#>
Function Update-ConjurPolicy
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$PolicyFilePath,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/policies/$ConjurAccount/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Send-HttpMethod -Url $url -Header $header -Method PATCH -Body $policyContent
}

<#
.SYNOPSIS

Loads or replaces a Conjur policy document.

.DESCRIPTION

Any policy data which already exists on the server but is not explicitly specified in the new policy file will be deleted.

.PARAMETER PolicyIdentifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Update-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Replace-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://www.conjur.org/api.html#policies-replace-a-policy


#>
Function Replace-ConjurPolicy
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$PolicyFilePath,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/policies/$ConjurAccount/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Send-HttpMethod -Url $url -Header $header -Method PUT -Body $policyContent
}


<#
.SYNOPSIS

Loads a Conjur policy document.

.DESCRIPTION

Adds data to the existing Conjur policy. Deletions are not allowed. Any policy objects that exist on the server but are omitted from the policy file will not be deleted and any explicit deletions in the policy file will result in an error.

.PARAMETER PolicyIdentifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Update-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Append-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://www.conjur.org/api.html#policies-append-to-a-policy


#>
Function Append-ConjurPolicy
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$PolicyFilePath,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/policies/$ConjurAccount/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Send-HttpMethod -Url $url -Header $header -Method PUT -Body $policyContent
}


<#
.SYNOPSIS

List resource within an organization account

.DESCRIPTION

List resource within an organization account

.INPUTS

None. You cannot pipe objects to Get-ConjurResources.

.OUTPUTS

System.Collections.Hashtable. All the resources the user has access to

.EXAMPLE

PS> Get-ConjurResources

created_at      : 2019-05-29T16:42:56.284+00:00
id              : dev:policy:root
owner           : dev:user:admin
permissions     : {}
annotations     : {}
policy_versions : {@{version=1; created_at=2019-05-29T16:42:56.284+00:00; policy_text=---                                                                               4


.LINK

https://www.conjur.org/api.html#role-based-access-control-list-resources-get


#>
Function Get-ConjurResources
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IamAuthnBranch = $env:CONJUR_IAM_AUTHN_BRANCH,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IamAuthnBranch $IamAuthnBranch -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/resources/$ConjurAccount"

    return Send-HttpMethod -Url $url -Header $header -Method GET
}


Export-ModuleMember -Function Get-ConjurHealth
Export-ModuleMember -Function Get-ConjurSecret
Export-ModuleMember -Function Set-ConjurSecret
Export-ModuleMember -Function Update-ConjurPolicy
Export-ModuleMember -Function Replace-ConjurPolicy
Export-ModuleMember -Function Append-ConjurPolicy
Export-ModuleMember -Function Get-ConjurResources