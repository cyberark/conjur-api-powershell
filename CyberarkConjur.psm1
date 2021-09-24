
###############################
# Module Variables
###############################

$CCConfig = @{
	AWS_MetaData			= "169.254.169.254"
	Account					= $null
    AuthaurityName			= $null
	AuthaurityName_WR		= $null
    IamAuthnBranch			= $null
	Certificate				= $null # This has not been explained in the former Module
	Token					= $null
	APIKey					= $null
	TokenTTL				= 6 * 60 
    Credential				= $null
	TokenExpireDate			= $null
}

###############################
# Invoke & Config Conjur
###############################
Function Invoke-Conjur {
   [CmdletBinding()]
   param(
        [Parameter(Position=0,Mandatory)][string]$API, 
        [Parameter(Position=1)][string[]]$Command, 
        [Parameter(Position=2)][string[]]$Search, 
        [Parameter(Position=3)][string]$Body,
		[string]$Method = "GET",
		# [Hashtable]$Headers = @{ "Content-Type" = "application/json" },
		[Hashtable]$Headers = @{  },
		[switch]$FixUri
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
				"^(add|Update)-"				{ $method 	= "POST"	}
				"^(Set|New|Submit|Write)-" 		{ $method 	= "PUT" 	}
			}
		}
		
		$Authority = $CCConfig.AuthaurityName
		if ($Method -notlike "GET" -and $CCConfig.AuthaurityName_WR -and $API -notmatch 'authn') {
			Write-verbose "Switching to WRITE" 
			$Authority = $CCConfig.AuthaurityName_WR
		}
		
		$Commands = (@($Authority,$API) + $Command)  | ? { $_ }
		Write-verbose "#### $($commands -join '||')"
		$Commands = ( $Commands -join "/") -replace "//+","/" -replace '/$'
		$Commands = $Commands  -replace "/!a","/$($CCConfig.Account)"
		if ($PsBoundParameters.containskey("search")) {
			$commands = ($Commands -replace '/?$' ) + "?" + ($Search -join ',')
		}
		$URL = "https://$Commands" 
		
		
		$RestMethod = @{
			Method	= $Method
			Headers = $Headers
			URI		= [uri]$URL
		}
		
		##############################
		# Fixing URI the URI contains \ that should not be interpreted as URI path but as data 
		##############################
		if ($PsBoundParameters.containskey("FixUri")) { 	
			$UnEscapeDotsAndSlashes		= 0x2000000;
			$SimpleUserSyntax			= 0x20000;

			$type						= $RestMethod.uri.GetType();
			$fieldInfo = $type.GetField("m_Syntax", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic));

			$uriParser					= $fieldInfo.GetValue($RestMethod.uri);
			$typeUriParser				= $uriParser.GetType().BaseType;
			$fieldInfo	= $typeUriParser.GetField("m_Flags", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::FlattenHierarchy));
			$uriSyntaxFlags				= $fieldInfo.GetValue($uriParser);

			$uriSyntaxFlags				= $uriSyntaxFlags -band (-bnot $UnEscapeDotsAndSlashes);
			$uriSyntaxFlags				= $uriSyntaxFlags -band (-bnot $SimpleUserSyntax);
			$fieldInfo.SetValue($uriParser, $uriSyntaxFlags);
		}
				
		##############################
		# Authentication verification
		##############################
	
		if ( $API -notmatch 'authn') {
			if ($CCConfig.IamAuthnBranch) {
				$ApiKey = Get-IamConjurApiKey
			} else {
				$ApiKey	= Receive-ConjurLogin
			}
			
			if (!$ApiKey) { throw "CyberArkConjour Module Failed to retrieve an API Key" }
			if ($CCConfig.IamAuthnBranch) {
					# $TokenAPI = "authn-iam"
					# $TokenCommand += "$($CCConfig.IamAuthnBranch)/" 
				# $TokenCommand += "$ConjurUsername/authenticate"
			} else { 
				$Auth = Receive-ConjurAuthenticate -ApiKey $ApiKey
			}
			if (!$Auth) {
				throw "CyberArkConjour Module Failed to Authenticate (the API Key was generated)"
			}
		}
		
		##############################
		# Headers (Token)
		##############################
		if (!$PsBoundParameters.containskey("Headers")) {
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
		[string]$Account,
		[parameter(ParameterSetName='Login',mandatory)][string]$AuthnLogin,
		[parameter(ParameterSetName='Login',mandatory)][string]$AuthnApiKey,
		[parameter(ParameterSetName='Credential')][PSCredential]$Credential,
		[string]$AuthaurityName,
		[string]$AuthaurityName_WR,
		[string]$IamAuthnBranch,
		[string]$AWS_MetaData,
        [Switch]$IgnoreSsl
	)
	Process {
		$ParamatersToIgnore = ([System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters) 
		$ParamatersToIgnore += @('AuthnLogin','AuthnApiKey',"IgnoreSsl")
		
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
				IamAuthnBranch { 
					$CCConfig[$_]			= $PsBoundParameters.item($_)
					$CCConfig["Credential"] = $null
				}
				AuthaurityName{ 
					$CCConfig[$_]			= $PsBoundParameters.item($_) -replace "http.://"
				}
				
				
				default { 
					$CCConfig[$_] 			= $PsBoundParameters.item($_) 
				}
			}
		}
		
		if ($PsCmdlet.ParameterSetName -like "Login") {
			write-warning "Please note that manipulating Credential object is always more secure. Please consider using the -Credential $CredObject instead"
			[securestring]$SS = ConvertTo-SecureString $AuthnApiKey -AsPlainText -Force

			$CCConfig["Credential"] = New-Object System.Management.Automation.PSCredential ($AuthnLogin, $SS)
			$CCConfig["IamAuthnBranch"] = $null
		}
	}
}
Export-ModuleMember -Function Initialize-Conjur

Function Show-ConjurConfiguration {
	return $CCConfig 
}
Export-ModuleMember -Function Show-ConjurConfiguration


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

Function Receive-ConjurIamLogin {
	[CmdletBinding()]
	param()
	
	$region			= Invoke-ConjurIam -command "latest/meta-data/placement/availability-zone"
    $role			= Invoke-ConjurIam "/latest/meta-data/iam/security-credentials" 
    $cred_results	= Invoke-Conjur "latest/meta-data/iam/security-credentials/$role"


    $region					= $region.Substring(0, $region.Length -1)
    $t 						= [DateTimeOffset]::UtcNow
    $x_amz_date 			= $t.ToString("yyyyMMddTHHmmssZ")
    $access_key_id			= $cred_results.AccessKeyId
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
set-alias Get-IamConjurApiKey Receive-ConjurIamLogin
   


###############################
# Exported Functions
###############################
<#
.SYNOPSIS

Gets the API key of a user given the username and password via HTTP Basic Authentication & Stores the information in memory.

.DESCRIPTION

Passwords are stored in the Conjur database using bcrypt with a work factor of 12. Therefore, login is a fairly expensive operation. However, once the API key is obtained, it may be used to inexpensively obtain access tokens by calling the Authenticate method. An access token is required to use most other parts of the Conjur API.

Your HTTP/REST client probably provides HTTP basic authentication support. For example, curl and all of the Conjur client libraries provide this.

.PARAMETER Force
Will force to renew the APIKey, even if it has already been stored in memory.

.PARAMETER Silent
Will not return the APIKey, but will store it in memory.

.INPUTS

None. You cannot pipe objects to Receive-ConjurLogin.

.OUTPUTS

String. The API key.

.EXAMPLE

PS> $APIKey = Receive-ConjurLogin


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Login.htm


#>
Function Receive-ConjurLogin {
	[CmdletBinding()]
	param( 
		[switch]$Force 
	)
	process {
		if ( !$CCConfig.APIKey  -or $PsBoundParameters.containskey("force")  ) {
			$MissingConfig = "Account","AuthaurityName","Credential" | ? { !$CCConfig[$_] }
			if ($MissingConfig) { 
				write-Warning "The Conjur Module is is missing information : [$($MissingConfig -join ',')] . Please run the [Initialize-ConjurConfiguration] command with the above switches. You can also run [get-help Initialize-ConjurConfiguration] for more information."
				return
			}
			$base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $CCConfig.Credential.UserName, $CCConfig.Credential.GetNetworkCredential().password)))
			$CCConfig.APIKey = Invoke-Conjur authn !a,login -headers @{ Authorization = "Basic $base64" }
		} 
		return $CCConfig.APIKey
	}
}
Export-ModuleMember -Function Receive-ConjurLogin

<#
.SYNOPSIS

Gets a short-lived access token, which is required in the header of most subsequent API requests. A client can obtain an access token by presenting a valid login name and API key.



.DESCRIPTION

The access token is used to communicate to the REST API that the bearer of the token has been authorized to access the API and perform specific actions specified by the scope that was granted during authorization.

The login must be URL encoded. For example, alice@devops must be encoded as alice%40devops.

For host authentication, the login is the host ID with the prefix host/. For example, the host webserver would login as host/webserver, and would be encoded as host%2Fwebserver.


.INPUTS

None. You cannot pipe objects to Receive-ConjurAuthenticate.

.OUTPUTS

String. The Authentication Token.

.EXAMPLE

PS> $Token = Receive-ConjurAuthenticate


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Authenticate.htm


#>
Function Receive-ConjurAuthenticate {
	[CmdletBinding()]
	param( 
		[string]$ApiKey = $CCConfig.APIKey,
		[Switch]$Force
	)
	process {
		if (!$CCConfig.Token -or $PsBoundParameters.containskey("force") -or ((get-date) -gt $CCConfig.TokenExpireDate)) {		
			$StartTime = Get-date
			if ( !$APIKey ) { 
				write-warning "No API Key was generated, you need to run [Receive-ConjurLogin | out-null] first"
			}
			$ConjurUsername	= [uri]::EscapeDataString($CCConfig.Credential.username)
			
			$CCConfig.Token = Invoke-Conjur authn !a,$ConjurUsername,authenticate -Body $APIKey -Method POST -FixUri -Headers @{  }
			
			if (!$CCConfig.Token) {
				write-Warning "The Conjur Module was not able to authenticate. Please run the [Initialize-ConjurConfiguration] command to configure the module. You can also run [get-help Initialize-ConjurConfiguration] for more information."
				return 
			} else { 
				$CCConfig.TokenExpireDate = $StartTime.AddSeconds($CCConfig.TokenTTL)
			}
		}
	
		return $CCConfig.Token
	}
}
Export-ModuleMember -Function Receive-ConjurAuthenticate


<#
.SYNOPSIS

The Conjur IAM Authenticator allows an AWS resource to use its AWS IAM role to authenticate with Conjur



.DESCRIPTION

The Conjur IAM Authenticator allows an AWS resource to use its AWS IAM role to authenticate with Conjur. This approach enables EC2 instances and Lambda functions to access credentials stored in Conjur without a pre-configured Conjur identity.

To learn more, see IAM roles in the AWS Documentation.

To enable an IAM Authenticator, for example, prod, set the following environment variable when you start a Conjur with the [Initialize-Conjur -IamAuthnBranch BranchName] Command

.INPUTS

None. You cannot pipe objects to Receive-ConjurIAMAuthenticate.

.OUTPUTS

To Be completed 

.EXAMPLE

To Be Completed

.LINK

https://docs.conjur.org/Latest/en/Content/Operations/Services/AWS_IAM_Authenticator.htm


#>
Function Receive-ConjurIAMAuthenticate {
	[CmdletBinding()]
	param( 	)
	process {
		$region			= Invoke-ConjurIam -command "latest/meta-data/placement/availability-zone"
		$role			= Invoke-ConjurIam "/latest/meta-data/iam/security-credentials" 
		$cred_results	= Invoke-Conjur "latest/meta-data/iam/security-credentials/$role"
	}
}
Export-ModuleMember -Function Receive-ConjurAuthenticate


<#
.SYNOPSIS

WhoAmI provides information about the client making an API request

.DESCRIPTION

It can be used to help troubleshoot configuration by verifying authentication and the client IP address for audit and network access restrictions. For more information, see Host Attributes.


.INPUTS

None. You cannot pipe objects to Receive-ConjurLogin.

.OUTPUTS

String. The API key.

.EXAMPLE

PS> $APIKey = Receive-ConjurLogin


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Login.htm


#>
Function Get-ConjurWhoAmI {
	[CmdletBinding()]
	param(  )
	process {
		return Invoke-Conjur whoami
	}
}
Export-ModuleMember -Function Get-ConjurWhoAmI

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

Retrieve one or multiple secrets from conjur

.DESCRIPTION

Retrieve one or multiple secret from conjur
If one Identifier is selected, the returned object will be the value of the secret
If Multiple Identifier, the returned object will a PsObject with all the secrets in a single query

.PARAMETER Identifier
The identifier used to retrieve the secret

.INPUTS

None. You cannot pipe objects to Get-ConjurSecret.

.OUTPUTS

System.String. The secret retrieved.

.EXAMPLE

PS> Get-ConjurSecret -Identifier "path/to/secret/username"
AHfdkrjeb81hs6ah

PS> Get-ConjurSecret -Identifier "path/to/secret/S1", "path/to/secret/S2"
Account:variable:path/to/secret/S1 Account:variable:path/to/secret/S2
---------------------------------- ----------------------------------
TestS1                             TestS2


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Retrieve_Secret.htm
https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Batch_Retrieve.htm
#>
Function Get-ConjurSecret {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string[]]$Identifier,
        $SecretKind = "variable"
    )
	
	if ($Identifier.count -gt 1) {
		$ModifiedSI = "variable_ids="
		$ModifiedSI += ($Identifier | % { ($CCConfig.Account,$SecretKind,$_) -join ":" }) -join ','
		return Invoke-Conjur secrets -Search $ModifiedSI
	} else {
		return Invoke-Conjur secrets !a,$SecretKind,($Identifier | select -first 1)
	}
}
Export-ModuleMember -Function Get-ConjurSecret

<#
.SYNOPSIS

Get-ConjurSecretCredential is an helper function that will directly retrieve a credential object from Conjur

.DESCRIPTION

If you add to a single path 2 secrets, one called username and the other called password, you will directly retrieve the PsCredential object from it
for example, if you have those 2 keys : 
myhome\subpath\username
myhome\subpath\password  
You will be able to directly retrieve the PsCredential Object using the command [Get-ConjurSecretCredential variable\myhome\subpath]
 

.PARAMETER IdentifierPath
The path to a pair of username/password couple

.INPUTS
None. You cannot pipe objects to Get-ConjurSecret.

.OUTPUTS
PsCredential. The PsCredential object.

.EXAMPLE

PS> Get-ConjurSecretCredential "path/to/secret"

UserName      Password
--------      --------
TheUserName   System.Security.SecureString


#>
Function Get-ConjurSecretCredential {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string[]]$IdentifierPath
    )
	$ToRetrieve = $IdentifierPath | % { @(($_ + "/username"),($_ + "/password")) }
	$ToRetrieve = $ToRetrieve -replace "//+","/"
	$AllSecrets = Get-ConjurSecret $ToRetrieve
	$AllSP = $AllSecrets.psobject.Members | ? { $_.membertype -like "noteproperty" } | select -ExpandProperty name
	$AllSP = $allSP -replace '/(password|username)$' | select -unique
	$Results = $AllSp | % { 
		[securestring]$SS = ConvertTo-SecureString $AllSecrets."$_/password" -AsPlainText -Force
		New-Object System.Management.Automation.PSCredential ($AllSecrets."$_/username", $SS )
	}
	return $results
}
Export-ModuleMember -Function Get-ConjurSecretCredential

<#
.SYNOPSIS

Set a secret in conjur

.DESCRIPTION

Set a secret in conjur
Takes a secret identifier and secret value

.PARAMETER Identifier
The identifier used to set the secret

.PARAMETER SecretValue
The value of the secret

.INPUTS

None. You cannot pipe objects to Update-ConjurSecret.

.OUTPUTS

None.

.EXAMPLE

PS> Update-ConjurSecret -Identifier "path/to/secret" -SecretValue "newPasswordHere"


.LINK

https://www.conjur.org/api.html#secrets-add-a-secret-post


#>
Function Update-ConjurSecret {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory)][string]$Identifier,
        [Parameter(Position=1,mandatory)][string]$SecretValue,
		[Parameter(Position=2)][string]$SecretKind = "variable"
    )
    return Invoke-Conjur secrets !A,$SecretKind,$Identifier -Body $SecretValue
}
New-Alias Set-ConjurSecret Update-ConjurSecret
Export-ModuleMember -Function Update-ConjurSecret -Alias Set-ConjurSecret

<#
.SYNOPSIS

Modifies an existing Conjur policy

.DESCRIPTION

Data may be explicitly deleted using the !delete, !revoke, and !deny statements. Unlike “replace” mode, no data is ever implicitly deleted.

.PARAMETER Identifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Update-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Update-ConjurPolicy -Identifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Update_Policy.htm


#>
Function Update-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )
  
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Invoke-Conjur policies !A,policy,$Identifier  -Body $policyContent
}
Export-ModuleMember -Function Update-ConjurPolicy 

<#
.SYNOPSIS

Loads or replaces a Conjur policy document.

.DESCRIPTION

Any policy data which already exists on the server but is not explicitly specified in the new policy file will be deleted.

.PARAMETER Identifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Set-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Set-ConjurPolicy -Identifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://www.conjur.org/api.html#policies-replace-a-policy


#>
Function Set-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )
    $policyContent = Get-Content -Path $PolicyFilePath -Raw
    return Invoke-Conjur policies !A,policy,$Identifier -Body $policyContent
}
New-Alias Replace-ConjurPolicy Set-ConjurPolicy
Export-ModuleMember -Function Set-ConjurPolicy -Alias Replace-ConjurPolicy

<#
.SYNOPSIS

Adds data to the existing Conjur policy.

.DESCRIPTION

Deletions are not allowed. Any policy objects that exist on the server but are omitted from the policy file will not be deleted and any explicit deletions in the policy file will result in an error

.PARAMETER Identifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Add-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Add-ConjurPolicy -Identifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Append_Policy.htm


#>
Function Add-ConjurPolicy {
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true)][string]$PolicyFilePath
    )

    $policyContent = Get-Content -Path $PolicyFilePath -Raw
    return Invoke-Conjur policies !A,policy,$Identifier -Body $policyContent
}
New-Alias Append-ConjurPolicy Add-ConjurPolicy
Export-ModuleMember -Function Add-ConjurPolicy -Alias Append-ConjurPolicy

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
	return Invoke-Conjur resources !A
}
Export-ModuleMember -Function Get-ConjurResources


<#
.SYNOPSIS
Gets detailed information about a specific role, including the role members.

.DESCRIPTION
If a role A is granted to a role B, then role A is said to have role B as a member. These relationships are described in the “members” portion of the returned JSON

.INPUTS
None. You cannot pipe objects to Get-ConjurRole.

.OUTPUTS
PsObject. All the resources the user has access to

.EXAMPLE
PS> Get-ConjurRole user alice

created_at : 2017-08-02T18:18:42.346+00:00
id         : myorg:user:alice
policy     : myorg:policy:root
members    : {@{admin_option=True; ownership=True; role=myorg:user:alice; member=myorg:policy:root; policy=myorg:policy:root}}

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Show_Role.htm
#>
Function Get-ConjurRole {
	[CmdletBinding()]
	param(
		[ValidateSet("user","host","layer","group","policy")] [Parameter(Position=0,mandatory=$true)][string]$kind,
        [Parameter(Position=1,mandatory=$true)][string]$identifier
    )
	return Invoke-Conjur roles !A,$kind,$identifier
}
Export-ModuleMember -Function Get-ConjurRole

