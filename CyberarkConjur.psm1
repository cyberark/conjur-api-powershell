
###############################
# Module Variables
###############################

$CCConfig = @{
	AWS_MetaData				= "169.254.169.254"
	CONJUR_ACCOUNT				= $null
    CONJUR_AUTHAURITY_NAME		= $null
	CONJUR_AUTHAURITY_NAME_WR	= $null
    CONJUR_IAM_AUTHN_BRANCH		= $null
	Certificate					= $null # This has not been explained in the former Module
	Token						= $null
	TokenTTL					= 6 * 60 
	# maybe this can be fetched : https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Developer/Conjur_API_whoami.htm?tocpath=Developer%7CREST%C2%A0APIs%7C_____3
    Credential					= $null
	TokenExpireDate				= $null
}

###############################
# Invoke & Config Conjur
###############################
Function Invoke-Conjur {
   [CmdletBinding()]
   param(
        [Parameter(Position=0,Mandatory)][string]$API, 
        [Parameter(Position=1)][string]$Command, 
        [Parameter(Position=2)][string]$Body,
		[string]$Method = "GET"
	)
	process { 	
		##############################
		# Initialization 
		##############################
		$CalledBy = (Get-PSCallStack)[1].command
		if(!$PsBoundParameters.containskey("Method")) {
			switch -regex ($CalledBy) {
				"^Remove-" 						{ $method 	= "DELETE" 	}
				"^Update-" 						{ $method 	= "PATCH" 	}
				# "^(Set|add)-"					{ $method 	= "PUT"		}
				"^(Set|New|Submit|Write)-" 		{ $method 	= "POST" 	}
			}
		}
		
		$Authority = $CCConfig.CONJUR_AUTHAURITY_NAME
		if ($Method -notlike "GET" -and $CCConfig.CONJUR_AUTHAURITY_NAME_WR) {
			Write-verbose "Switching to WRITE" 
			$Authority = $CCConfig.CONJUR_AUTHAURITY_NAME_WR
		}		
		
		if ($API -match "WhoAmI|health") {
			$URL = ($Authority,$API) -join "/"
		} else { 
			$URL = ($Authority,$API,$CCConfig.CONJUR_ACCOUNT,$Command ) -join "/"
		}
		$URL = "https://" + ($URL -replace "//+","/" -replace '/$')
		
		
		$RestMethod = @{
			Method	= $Method
			Headers = @{}
			URI		= [uri]$URL
		}
		
		if ($Command -match "^authn") { fixUri $RestMethod.URI }
		
		##############################
		# Authentication verification
		##############################
		if ((!$CCConfig.Token -or ((get-date) -gt $CCConfig.TokenExpireDate))-and $API -notmatch 'authn') {
			Write-Verbose "Invoke-Conjur : Authentication verification called by $CalledBy"
			$ConjurUsername	= [uri]::EscapeDataString($CCConfig.Credential.username)

			# Checking inputs
			$MissingConfig = @()
			"CONJUR_ACCOUNT","CONJUR_AUTHAURITY_NAME","Credential" | % { 
				if (!$CCConfig[$_]) { $MissingConfig += $_ }
			}
			if ($MissingConfig) { 
				write-Warning "The Conjur Module is not configured. Please run the [Initialize-ConjurConfiguration] command to configure the module. You can also run [get-help Initialize-ConjurConfiguration] for more information."
				return
			}
			
			# Getting the API Key
			$StartTime = Get-date
			if ($CCConfig.CONJUR_IAM_AUTHN_BRANCH) {
				Get-IamConjurApiKey
			} else {
				$ApiKey	= Invoke-Conjur authn login -verbose
				Write-Verbose "API key = $ApiKey" # $($API.SubString(0,10))..."
			}
			
			if (!$ApiKey) { 
				write-Warning "The Conjur Module was not able retrieve the API Key. Please run the [Initialize-ConjurConfiguration] command to configure the module. You can also run [get-help Initialize-ConjurConfiguration] for more information."
				throw "failed"
			}
			
			# Getting the Token
			$TokenAPI = "authn"
			$TokenCommand = ""
			if ($CCConfig.CONJUR_IAM_AUTHN_BRANCH) {
				$TokenAPI = "authn-iam"
				$TokenCommand += "$($CCConfig.CONJUR_IAM_AUTHN_BRANCH)/" 
			} 
			$TokenCommand += "$ConjurUsername/authenticate"
			write-verbose "TokenCommand : $TokenCommand"
			$CCConfig.Token = Invoke-Conjur $TokenAPI $TokenCommand -Body $apiKey -Method POST
			if (!$CCConfig.Token) {
				write-Warning "The Conjur Module was not able to authenticate. Please run the [Initialize-ConjurConfiguration] command to configure the module. You can also run [get-help Initialize-ConjurConfiguration] for more information."
				return 
			}
			$CCConfig.TokenExpireDate = $StartTime.AddSeconds($CCConfig.TokenTTL)
		}
		
		##############################
		# Headers 
		##############################
		if ($API -match 'authn') {
			Write-Verbose "Generating Headers for $($CCConfig.Credential.UserName) "
			$base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $CCConfig.Credential.UserName, $CCConfig.Credential.GetNetworkCredential().password)))
			$RestMethod.Headers.add("Authorization","Basic $base64")
		} else {
			$base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((($CCConfig.Token | ConvertTo-Json))))
			$RestMethod.Headers.add("Authorization","Token token=""$base64""")
		}
		
		##############################
		# Additional parameters 
		##############################
		Switch ($PsBoundParameters.keys) {
			"Body"	{ $RestMethod.add("body",$body) }
		}
		
		if ($CCConfig.Certificate) { 
			$RestMethod.add("Certificate",$CCConfig.Certificate)
			$RestMethod.add("CertificateThumbprint",$CCConfig.Certificate.Thumbprint)
		}
		
		##############################
		# Sending Rest API Request 
		##############################
		Write-verbose ($RestMethod | out-string -Width ($host.UI.RawUI.BufferSize.Width -2 ))
		# Write-verbose ($RestMethod["Headers"] | out-string -Width ($host.UI.RawUI.BufferSize.Width -2 ))
		
		# Write-Verbose "Invoke-Conjur : URL : $URL"
		try { 
			$Result =  Invoke-RestMethod @RestMethod
		} catch {
			$exception = $_.Exception
			$responseBody = Get-ResponseBodyFromException($exception)
			Write-Verbose -Message "Response Body: `n $($responseBody | out-string)"
			# Write-Verbose -Message "Response Body: `n $($responseBody | ConvertFrom-Json | ConvertTo-Json)"
			throw $_
			break
		}
		
		return $Result
    }
}
Export-ModuleMember -Function Invoke-Conjur
	
Function Initialize-Conjur {
	[CmdletBinding(DefaultParameterSetName="Credential")]
	Param(
		[string]$CONJUR_ACCOUNT,
		[parameter(ParameterSetName='Login',mandatory)][string]$CONJUR_AUTHN_LOGIN,
		[parameter(ParameterSetName='Login',mandatory)][string]$CONJUR_AUTHN_API_KEY,
		[parameter(ParameterSetName='Credential')][PSCredential]$Credential,
		[string]$CONJUR_AUTHAURITY_NAME,
		[string]$CONJUR_AUTHAURITY_NAME_WR,
		[string]$CONJUR_IAM_AUTHN_BRANCH,
		[string]$AWS_MetaData,
        [Switch]$IgnoreSsl
	)
	Process {
		$ParamatersToIgnore = ([System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters) 
		$ParamatersToIgnore += @('CONJUR_AUTHN_LOGIN','CONJUR_AUTHN_API_KEY',"IgnoreSsl")
		
		$PsBoundParameters.keys | ? {  $_ -notin $ParamatersToIgnore } | % {
			Switch ($_) {
				"IgnoreSsl" { 
					try {
						add-type "
							using System.Net;
							using System.Security.Cryptography.X509Certificates;
							
							public class IDontCarePolicy : ICertificatePolicy {
								public IDontCarePolicy() {}
								public bool CheckValidationResult(
									ServicePoint sPoint, X509Certificate cert,
									WebRequest wRequest, int certProb) {
									return true;
								}
							}"
						[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
						[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
					} catch { }
				}
				CONJUR_IAM_AUTHN_BRANCH { 
					$CCConfig[$_]			= $PsBoundParameters.item($_)
					$CCConfig["Credential"] = $null
				}
				CONJUR_AUTHAURITY_NAME{ 
					$CCConfig[$_]			= $PsBoundParameters.item($_) -replace "http.://"
				}
				
				
				default { 
					$CCConfig[$_] 			= $PsBoundParameters.item($_) 
				}
			}
		}
		
		if ($PsCmdlet.ParameterSetName -like "Login") {
			write-warning "Please note that manipulating Credential object is always more secure. Please consider using the -Credential $CredObject instead"
			[securestring]$SS = ConvertTo-SecureString $CONJUR_AUTHN_API_KEY -AsPlainText -Force

			$CCConfig["Credential"] = New-Object System.Management.Automation.PSCredential ($CONJUR_AUTHN_LOGIN, $SS)
			$CCConfig["CONJUR_IAM_AUTHN_BRANCH"] = $null
		}
	}
}
Export-ModuleMember -Function Initialize-Conjur


###############################
# Internal Functions
###############################

Function Get-ResponseBodyFromException {
   [CmdletBinding()]
   param(
        $Exception
    )

    $responseBody = $null

    if ($Exception.Response) {
        $result = $Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
    }

    return $responseBody
}

Function Get-HeaderAsString() {
    [CmdletBinding()]
	param(
        $Header
    )
    $headerAsString = ""

    if ($Header -ne $null) {
        foreach ($kv in $Header.GetEnumerator()) {
            $headerAsString += "$($kv.Name)=$($kv.Value);"
        }
    }
    return $headerAsString
}


Function Test-MandatoryParameter {
   [CmdletBinding()]
	param(
        $EnvironmentVariableName,
        $Value,
        $Ignore = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        if (!$Ignore) {
            Write-Host -ForegroundColor RED "Mandatory parameter is empty or missing: $EnvironmentVariableName"
        }
        return $false
    } else {
        Write-Verbose "$EnvironmentVariableName=$Value"
    }

    return $true
}

###############################
# Internal IAM Functions
###############################

Function Invoke-ConjurIam {
    [CmdletBinding()]
	param(
        [Parameter(Position=0, Mandatory=$true)][string]$Command, 
        [string]$Method = "get",
        [string]$Body
		
	)
	process { 	
		$URL = 
		
		$RestMethod = @{
			Method	= $Method
			URI		= "http://$($CCConfig.AWS_MetaData)/" + $Command
		}
	
		try { 
			$Result =  Invoke-RestMethod @RestMethod
		} catch {
			$exception = $_.Exception
			$responseBody = Get-ResponseBodyFromException($exception)
			Write-Verbose -Message "Response Body: `n $($responseBody | ConvertFrom-Json | ConvertTo-Json)" -Level "ERROR"
			throw $_
			break
		}
		
		return $Result
    }
}

Function Enable-HelperNamespace{
	[CmdletBinding()]
	param()
	add-type "
    namespace HelperNamespace {
        public static class HelperClass {
            public static string ToHexString(byte[] array) {
                var hex = new System.Text.StringBuilder(array.Length * 2);
                foreach(byte b in array) {
                    hex.AppendFormat(""{0:x2}"", b);
                }
                return hex.ToString();
            }
            public static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
            {
                byte[] kDate = HmacSHA256(System.Text.Encoding.UTF8.GetBytes(""AWS4"" + key), dateStamp);
                byte[] kRegion = HmacSHA256(kDate, regionName);
                byte[] kService = HmacSHA256(kRegion, serviceName);
                byte[] kSigning = HmacSHA256(kService, ""aws4_request"");
                return kSigning;
            }
            
            public static byte[] HmacSHA256(byte[] key, string data)
            {
                var hashAlgorithm = new System.Security.Cryptography.HMACSHA256(key);
                return hashAlgorithm.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
            }
        }
    }"
}

function Get-IamAuthorizationHeader {
	[CmdletBinding()]
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


    return "$($algorithm) Credential=$($cAccessKeyId)/$($cred_scope), SignedHeaders=$($signed_headers), Signature=$($signature)"
}

Function Get-IamConjurApiKey {
	[CmdletBinding()]
	param()
	
	$region			= Invoke-ConjurIam -command "latest/meta-data/placement/availability-zone"
    $role			= Invoke-ConjurIam "/latest/meta-data/iam/security-credentials" 
    $cred_results	= Invoke-Conjur "latest/meta-data/iam/security-credentials/$role"


    $region			= $region.Substring(0, $region.Length -1)
    $t 				= [DateTimeOffset]::UtcNow
    $x_amz_date 	= $t.ToString("yyyyMMddTHHmmssZ")
    $access_key_id	= $cred_results.AccessKeyId
    $secret_access_key		= $cred_results.SecretAccessKey
    $x_amz_security_token	= $cred_results.Token

    $output = Get-IamAuthorizationHeader $sts_host $x_amz_date $x_amz_security_token $region $service $access_key_id $secret_access_key

    $empty_body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    $conjurToken = [pscustomobject]@{
    "host"="$sts_host"
    "x-amz-content-sha256"="$empty_body_hash"
    "x-amz-date"="$x_amz_date"
    "x-amz-security-token"="$x_amz_security_token"
    "authorization"="$output"
    }|ConvertTo-Json

    return $conjurToken 
}

   
# This is required because powershell will automatically decode %2F to / to avoid that we must run this method on the uri that contains %2F
function FixUri {
    [CmdletBinding()]
	param($uri)
	
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

###############################
# Exported Functions
###############################

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
Function Get-ConjurHealth {
    [CmdletBinding()]
	param( )
    return Invoke-Conjur health
}
Export-ModuleMember -Function Get-ConjurHealth

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
Function Get-ConjurSecret {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$SecretIdentifier,
        $SecretKind = "variable"
    )
    return Invoke-Conjur secrets "$SecretKind/$SecretIdentifier"
}
Export-ModuleMember -Function Get-ConjurSecret

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
Function Set-ConjurSecret {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory)][string]$SecretIdentifier,
        [Parameter(Position=1,mandatory)][string]$SecretValue,
		[Parameter(Position=2)][string]$SecretKind = "variable"
    )
    return Invoke-Conjur secrets "$SecretKind/$SecretIdentifier" -Body $SecretValue
}
Export-ModuleMember -Function Set-ConjurSecret

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
Function Update-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )

  
    $url = "policies/$($CCConfig.CONJUR_ACCOUNT)/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Invoke-Conjur policies "policy/$PolicyIdentifier"  -Body $policyContent
}
Export-ModuleMember -Function Update-ConjurPolicy

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
Function Set-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )
    $policyContent = Get-Content -Path $PolicyFilePath -Raw
    return Invoke-Conjur policies "policy/$PolicyIdentifier" -Method PUT -Body $policyContent
}
New-Alias Replace-ConjurPolicy Set-ConjurPolicy
Export-ModuleMember -Function Set-ConjurPolicy -Alias Replace-ConjurPolicy

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
Function Write-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )

    $url = "$ConjurApplianceUrl/policies/$($CCConfig.CONJUR_ACCOUNT)/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Invoke-Conjur policies "policy/$PolicyIdentifier" -Url $url -Header $header -Method POST -Body $policyContent
}
New-Alias Append-ConjurPolicy Write-ConjurPolicy
Export-ModuleMember -Function Write-ConjurPolicy -Alias Append-ConjurPolicy
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
Function Get-ConjurResources {
    [CmdletBinding()]
	Param()
	return Invoke-Conjur resources
}
Export-ModuleMember -Function Get-ConjurResources






Export-ModuleMember -Function Replace-ConjurPolicy

