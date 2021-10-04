
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
	CommonParameters		= ([System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters) 
}

###############################
# Invoke & Config Conjur
###############################

<#
.SYNOPSIS
This is the main fonction that does all the API calls.
Please don't use it unless you want to test it 

.DESCRIPTION
Does what it needs to do to parse API request 

.PARAMETER API
[Mandatory] the main API branch you are calling

.PARAMETER Command
additional path that is added to the URI 

.PARAMETER Identifier
adds to the URI the Identifier

.PARAMETER Body
The Body sent within the query

.PARAMETER Method
The used method

.PARAMETER Headers
Specific headers can be added (no authentication headers will be added if used)

.PARAMETER FixUri
Fixing URI issues

.PARAMETER Credential
Credential object that is passed directly to the Rest method call


.INPUTS

None 

.OUTPUTS

Too many outputs are possible to describe them here.

#>
Function Invoke-Conjur {
   [CmdletBinding()]
   param(
        [Parameter(Position=0,Mandatory)][string]$API, 
        [Parameter(Position=1)][string[]]$Command, 
        [Parameter(Position=2)][string]$Identifier, 
        [string[]]$query, 
        [string]$Body,
		[string]$Method = "GET",
		# [Hashtable]$Headers = @{ "Content-Type" = "application/json" },
		[Hashtable]$Headers = @{  },
		[switch]$FixUri,
		[PsCredential]$Credential
	)
	process {	
		##############################
		# Initialization 
		##############################
		$CalledBy = (Get-PSCallStack)[1].command
		if(!$PsBoundParameters.containskey("Method")) {
			switch -regex ($CalledBy) {
				"^(Remove|Revoke)-" 		{ $method 	= "DELETE" 	}
				"^(Update)-" 				{ $method 	= "PATCH" 	}
				"^(Set|add|Grant)-"			{ $method 	= "POST"	}
				"^(New|Submit|Write)-" 		{ $method 	= "PUT" 	}
			}
		}
		
		##############################
		# Changing to the Write instance if required
		##############################
		$Authority = $CCConfig.AuthaurityName
		if ($Method -notlike "GET" -and $CCConfig.AuthaurityName_WR -and $API -notmatch 'authn') {
			Write-verbose "Switching to WRITE" 
			$Authority = $CCConfig.AuthaurityName_WR
		}
		
		##############################
		# Building the URI 
		##############################
		$Commands = (@($Authority,$API) + $Command)  | ? { $_ }	
		$Commands = ( $Commands -join "/") -replace "//+","/" -replace '/$'
		$Commands = $Commands  -replace "/!a","/$($CCConfig.Account)"
		if ($PsBoundParameters.containskey("query")) {
			$commands = ($Commands -replace '/?$' ) + "?" + ($query -join '&')
		}
		$URL = "https://$Commands" 
		
		
		$RestMethod = @{
			Method	= $Method
			Headers = $Headers
			URI		= [uri]$URL
		}
		
		if ($PsBoundParameters.containskey("Credential")) {
			$RestMethod.add("Credential",$Credential)
		}
		
		##############################
		# Fixing URI the URI contains \ that should not be interpreted as URI path but as data 
		##############################
		if ($PsBoundParameters.containskey("FixUri") -and $PSVersionTable.PSVersion.Major -le 5) { 	

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
		
		# Write-Verbose "Invoke-Conjur : URL : $URL"
		$ClearError = $false
		try { 
			$Result =  Invoke-RestMethod @RestMethod
		} catch {
			Write-warning "Message : $($_.Exception.Response.StatusCode)"
			if ($_.Exception.Response.StatusCode -notin @("NotFound")) {
				Write-warning "Error   : $($_.ErrorDetails.Message)"
				throw $_
				break
			} else { 
				$ClearError = $true 	
			}
		}
		if ($ClearError) {$global:Error.Remove($global:Error[0])}
		return $Result
    }
}
Export-ModuleMember -Function Invoke-Conjur
	
<#
.SYNOPSIS

This command is required prior to running any other one. This will configure the module with the required settings.

.DESCRIPTION

Please check all the parameters in the help file.
Mandatory parameters are : 
Account	: Organization account name
Credential : Will store the API key that will grant you access to Conjur 
AuthaurityName : DNS authority name of your Conjur instance


.PARAMETER Account
[Mandatory] Will set the Organization account for the repository you are reaching to

.PARAMETER Credential
[Mandatory] A Credential object that will be stored in memory containing your API key, that will be used to authenticate your access to Conjur. See the examples below

.PARAMETER AuthnLogin (deprecated | use credential instead)
Will set the indentifier of the host API key (requires AuthnApiKey)

.PARAMETER AuthnApiKey (deprecated | use credential instead)
Will set the API key of the indentifier (requires AuthnLogin)

.PARAMETER AuthaurityName
[Mandatory] Will set the name of your conjur instance. Example, if your site is https://eval.conjur.org then you need to set AuthaurityName = eval.conjur.org 

.PARAMETER AuthaurityName_WR
In some configurations, you have read only instances of Conjur. By adding this parameter, you will consider the AuthaurityName as read only instances, while any modification will call  AuthaurityName_WR as DNS name 

.PARAMETER IamAuthnBranch 
[AWS IAM integration] This parameter is for Iam authentication plugin, and has not been tested yet

.PARAMETER AWS_MetaData
[AWS IAM integration] This parameter is for Iam authentication plugin, and has not been tested yet

.PARAMETER IgnoreSsl
This will ignore any SSL issues for all the Conjur queries.

.INPUTS

[PsCredential]Credential. You can set the credentials using a credential object is input

.OUTPUTS

Null

.EXAMPLE

PS> $HostApiIdentifier = "host/some/application"
PS> $Cred = (Get-credential -Message "Please enter your Conjur API key" -UserName $ApiIdentifier)
PS> Initialize-Conjur -Credential $Cred -Account MyOrg -AuthaurityName eval.conjur.org

.EXAMPLE
PS> $Cred | Initialize-Conjur -Account MyOrg -AuthaurityName readeval.conjur.org -AuthaurityName_WR writeeval.conjur.org


#>
Function Initialize-Conjur {
	[CmdletBinding(DefaultParameterSetName="Credential")]
	Param(
		[string]$Account,
		[parameter(ParameterSetName='Login',mandatory)][string]$AuthnLogin,
		[parameter(ParameterSetName='Login',mandatory)][string]$AuthnApiKey,
		[parameter(ParameterSetName='Credential',ValueFromPipeline)][PSCredential]$Credential,
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

<#
.SYNOPSIS

This command will return you the actual configuration as set in memory. Modifying this variable will modify the Conjur configuration

.DESCRIPTION

Returns the hastable used to configure the Conjur module


.INPUTS

None. You cannot pipe objects to this function.


.OUTPUTS

HashTable. The configuration variables for this module

.EXAMPLE

PS> $HostApiIdentifier = "host/some/application"
PS> $Cred = (Get-credential -Message "Please enter your Conjur API key" -UserName $ApiIdentifier)
PS> Initialize-Conjur -Credential $Cred -Account MyOrg -AuthaurityName eval.conjur.org

.EXAMPLE
PS>  Show-ConjurConfiguration

Name                           Value
----                           -----
TokenTTL                       360
AWS_MetaData                   169.254.169.254
TokenExpireDate                10/1/2021 10:11:39 AM
Account                        MyOrg
Credential                     System.Management.Automation.PSCredential
Token                          @{protected=***** Hidden ******
Certificate                    
AuthaurityName                 read.eval.conjur.org
AuthaurityName_WR              write.eval.conjur.org
IamAuthnBranch
APIKey                         ***** Hidden ******
#>
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

#### THIS FUNCTION HAS NOT BEEN TESTED
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

#### THIS FUNCTION HAS NOT BEEN TESTED
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

#### THIS FUNCTION HAS NOT BEEN TESTED
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
# Login / Authenticate
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

None. You cannot pipe objects to this function.

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

None. You cannot pipe objects to this function.

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

The Conjur IAM Authenticator allows an AWS resource to use its AWS IAM role to authenticate with Conjur #### THIS FUNCTION HAS NOT BEEN TESTED



.DESCRIPTION

The Conjur IAM Authenticator allows an AWS resource to use its AWS IAM role to authenticate with Conjur. This approach enables EC2 instances and Lambda functions to access credentials stored in Conjur without a pre-configured Conjur identity.

To learn more, see IAM roles in the AWS Documentation.

To enable an IAM Authenticator, for example, prod, set the following environment variable when you start a Conjur with the [Initialize-Conjur -IamAuthnBranch BranchName] Command

.INPUTS

None. You cannot pipe objects to this function.

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
#### This function has not been tested yet ####
Changes a user’s password

.DESCRIPTION

Changes a user’s password. You must provide the login name and current password or API key of the user whose password is to be updated in an HTTP Basic Authentication header. Also replaces the user’s API key with a new securely generated random value. You can fetch the new API key by using Login.

Your HTTP/REST client probably provides HTTP basic authentication support. For example, curl and all of the Conjur client libraries provide this.

Note : machine roles (Hosts) do not have passwords. They authenticate using their API keys, while passwords are only used by human users.

.PARAMETER Credential
The user accout/password

.PARAMETER Password
The new password 

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

NULL 

.EXAMPLE

Not Tested Yet

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_change_Password.htm


#>
Function New-ConjurUserPassword { # PUT
	[CmdletBinding()]
	param( 
		[string]$Credential,
		[string]$Password 
	)
	process {
		return Invoke-Conjur authn !A,"password" -Body $Password -Credential $Credential -Headers @{}
	}
}
Export-ModuleMember -Function New-ConjurUserPassword


<#
.SYNOPSIS
#### This function has not been tested yet ####
Rotate Personal API Key 
	Or
Replaces the API key of another role that you can update with a new, securely random API key. The new API key is returned as the response body.



.DESCRIPTION

Replaces your own API key with a new, securely random API key. The new API key is returned as the response body.

For User API key , Any role can rotate its own API key. The name and password or current API key of the role must be provided via HTTP Basic Authorization. Your HTTP/REST client probably provides HTTP

.PARAMETER Credential
The Credential object that contains the personal API Key as username and the API Key as password 

.PARAMETER Identifier
The identifier of the Role 

.PARAMETER Kind
The Kind API key you want to rotate.
Possible values are : user,host,layer,group,policy,variable,webservice
Default = host

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

The new personal API Key 

.EXAMPLE

Not Tested Yet

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Rotate_Personal_API_Key.htm
https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Rotate_Other_API_Key


#>
Function New-ConjurApiKey { # PUT
	[CmdletBinding(DefaultParameterSetName="User")]
	param( 
		[Parameter(Position=0,mandatory,ParameterSetName='User')][string]$Credential,
		[Parameter(Position=0,mandatory,ParameterSetName='Kind')][string]$Identifier,
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(Position=1,ParameterSetName='Kind')][string]$Kind='host'
	)
	process {
		$Switches = @{}
		if ($PsCmdlet.ParameterSetName -like "User") {
			$Switches.add("Credential",$Credential)
			$Switches.add("Headers",@{})
		} else {
			$Switches.add("query",("role=$Kind" + ":" + $identifier))
		}
		return Invoke-Conjur authn !a,api_key -Body "" @Switches
	}
}
Export-ModuleMember -Function New-ConjurApiKey



<#
.SYNOPSIS
#### This function has not been tested yet ####
OIDC Authenticator

.DESCRIPTION
Once the OIDC Authenticator is configured, you can send an authentication request.

For more information about the OIDC Authenticator, see OpenID Connect (OIDC) Authenticator.

.PARAMETER serviceid
The ID of the OIDC Provider, for example okta

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

String. The Authentication Token.

.EXAMPLE

PS> $Token = Receive-ConjurOIDCAuthenticator

eyJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSmpiMjVxZFhJdWIzSm5MM05zYjNOcGJHOHZkaklpTENKcmFXUWlPaUkyTXpka05HWTFZMlU1WVdJd05ESTVOR0ZpWkRNNFptTmhPV00zWW1Nek5qWTVaak16TWprNU5UUXdZamhsTm1ZeU5tRTBNVGM1T0RFeE1HSm1aRGcwSW4wPSIsInBheWxvYWQiOiJleUp6ZFdJaU9pSmhaRzFwYmlJc0ltbGhkQ0k2TVRVNU9EYzJPVFUwTUgwPSIsInNpZ25hdHVyZSI6Ik5ya25FQTc2MnoweC1GVmRRakZHZVRUbkJzeXFBdlBHSWEyZUxZV3IyYVVGZDU5dHk0aGMxSlRsVGptdmpGNWNtVDNMUnFGbDhYYzNwMDhabEhjbVc0cTdiVnFtM21odmZEdVNVaE13RzhKUk4yRFZQVHZKbkFiT1NPX0JGdWhKdmk2OGJEVGxZSFFmUF81WHY1VWtuWHlLUDR2dGNoSjloMHJuVXN0T0F1YWlkM0RyQW5RV1c2dDRaMzRQajJhT2JrTkZ1TlMxNDBsamNwZ1A1dHdfU19ISzB6d1dlSXF4cjh6eUpTbk5aNjJ1WlhZV25zU051WGZtSWdtVVo2cTJFeVZWWUJ1Zk5SZTNVUmFkU09OYjRIcnFyX21UaGctWHUzMjA2N1h3QmNWZ3lWQ0JrcWtybktuRW1vRzlMRWs2ZjdNQVpDX1BXZnA4NXQ1VFFhVm1iZFlqT2lDTW9GMFoxYkhyZGN2MC1LRnpNRGxHa0pCS1Jxb0xYYkFGakhjMCJ9

.LINK
https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_OIDC_Authenticator.htm


#>
Function Receive-ConjurOIDCAuthenticator {
	[CmdletBinding()]
	param( 
		[Parameter(Position=0,mandatory)][string]$serviceid,
		[Parameter(Position=1,mandatory)][string]$APIKey,
		[switch]$force
	)
	process {
		if (!$CCConfig.Token -or $PsBoundParameters.containskey("force") -or ((get-date) -gt $CCConfig.TokenExpireDate)) {		
			$StartTime = Get-date
			if ( !$APIKey ) { 
				write-warning "No API Key was generated, you need to run [Receive-ConjurLogin | out-null] first"
			}
			$Headers = @{ 
				"Content-Type" =  "application/x-www-form-urlencoded"
				"Accept-Encoding" = "base64"
			}
			$Body = "id_token: ""$APIKey"""
			$CCConfig.Token = Invoke-Conjur authn-oidc !a,$ConjurUsername,authenticate -Body $Body  -Headers $Headers
			
			
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
Export-ModuleMember -Function Receive-ConjurOIDCAuthenticator


###############################
# Various Types of API
###############################

<#
.SYNOPSIS

WhoAmI provides information about the client making an API request

.DESCRIPTION

It can be used to help troubleshoot configuration by verifying authentication and the client IP address for audit and network access restrictions. For more information, see Host Attributes.


.INPUTS

None. You cannot pipe objects to this function.

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
#### This function has not been tested yet ####
Get the Authenticator Status

.DESCRIPTION

Once the status webservice has been properly configured and the relevant user groups have been given permissions to access the status webservice, the users in those groups can check the status of the authenticator.

.PARAMETER AuthenticatorType
The type of authenticator, for example authn-oidc

.PARAMETER ServiceId
The ID of the authenticator provider, for example okta

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

PsObject. The status of the Authenticator

.EXAMPLE

PS> Get-ConjurAuthenticatorStatus authn-oidc okta

status
------
ok

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_authenticator_status.htm

#>
Function Get-ConjurAuthenticatorStatus {
	[CmdletBinding()]
	param( 
		[string]$AuthenticatorType,
		[string]$ServiceId
	)
	process {
		return Invoke-Conjur $AuthenticatorType $ServiceId,!A,status
	}
}
Export-ModuleMember -Function Get-ConjurAuthenticatorStatus

<#
.SYNOPSIS
Get health of a conjur instance

.DESCRIPTION
Get health of a conjur instance

.INPUTS
None. You cannot pipe objects to this function.

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
#### This function has not been tested yet ####
Show Public Keys

.DESCRIPTION
Shows all public keys for a resource as newline delimited string for compatibility with the authorized_keys SSH format.

Returns an empty string if the resource does not exist, to prevent attackers from determining whether a resource exists.

.PARAMETER Kind
kind of resource of which to show public keys. Possible values are : user,host,layer,group,policy,variable,webservice

.PARAMETER identifier
The identifier of the object

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS

System.Collections.Hashtable. The health of the conjur instance.

.EXAMPLE

PS> Get-ConjurHealth
ssh-rsa AAAAB3Nzabc2 admin@alice.com
ssh-rsa AAAAB3Nza3nx alice@example.com

.LINK
https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Show_Public_Keys.htm


#>
Function Get-ConjurPublicKeys {
    [CmdletBinding()]
	param(
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(Position=0,mandatory)][string]$Kind,
		[Parameter(Position=1,mandatory)][string]$identifier
	)
    return Invoke-Conjur public_keys !a,$Kind,$identifier
}
Export-ModuleMember -Function Get-ConjurPublicKeys



###############################
# Secrets API
###############################
<#
.SYNOPSIS
Retrieve one or multiple secrets from conjur

.DESCRIPTION
Retrieve one or multiple secret from conjur
If one Identifier is selected, the returned object will be the value of the secret
If Multiple Identifier, the returned object will a PsObject with all the secrets in a single query

.PARAMETER Identifier
The identifier used to retrieve the secret

.PARAMETER Kind
The Kind of secret you want to retrieve.
Possible values are : user,host,layer,group,policy,variable,webservice
Default = variable

.PARAMETER variable_ids
List the secrets you want to retrieve in the Comma-delimited resource IDs format


.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

System.String. The secret retrieved.

.EXAMPLE

PS> Get-ConjurSecret -Identifier "path/to/secret/username"
AHfdkrjeb81hs6ah

.EXAMPLE

PS> Get-ConjurSecret -Identifier "path/to/secret/S1", "path/to/secret/S2"
Account:variable:path/to/secret/S1 Account:variable:path/to/secret/S2
---------------------------------- ----------------------------------
TestS1                             TestS2

.EXAMPLE

PS> Get-ConjurSecret -variable_ids "Account:variable:path/to/secret/S1", "Account:variable:path/to/secret/S2"
Account:variable:path/to/secret/S1 Account:variable:path/to/secret/S2
---------------------------------- ----------------------------------
TestS1                             TestS2



.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Retrieve_Secret.htm
https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Batch_Retrieve.htm
#>
Function Get-ConjurSecret {
    [CmdletBinding(DefaultParameterSetName="Identifier")]
	param(
        [Parameter(Position=0,ParameterSetName='Identifier',mandatory=$true)][string[]]$Identifier,
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
        [Parameter(Position=1,ParameterSetName='Identifier')]$Kind = "variable",
		[string[]]$variable_ids
    )
	process {		
		if ($PsCmdlet.ParameterSetName -like "Identifier" -and $Identifier.count -eq 1 ) {
			$Result = Invoke-Conjur secrets !a,$Kind -Identifier ($Identifier | select -first 1)
		} else {
			$ModifiedSI = "variable_ids="
			if ($PsCmdlet.ParameterSetName -like "Identifier") {
				$ModifiedSI += ($Identifier | % { ($CCConfig.Account,$Kind,$_) -join ":" }) -join ','	
			} else {
				$ModifiedSI += $variable_ids  -join ','	
			}
			$Result =  Invoke-Conjur secrets -query $ModifiedSI
		}
		return $Result
	}
}
Export-ModuleMember -Function Get-ConjurSecret

<#
.SYNOPSIS

Get-ConjurSecretCredential is an helper function that will call Get-ConjurSecret and directly retrieve a PsCredential object based on the policy name.

.DESCRIPTION

If you add to a policy 2 secrets, one called username and the other called password, you will be able to use this function.
for example, if you have those 2 variables : 
myhome\subpath\username
myhome\subpath\password  
You will be able to directly retrieve the PsCredential Object using the command [Get-ConjurSecretCredential variable\myhome\subpath]
 

.PARAMETER IdentifierPath
The path to a pair of username/password couple

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
PsCredential. The PsCredential object.

.EXAMPLE

PS> Get-ConjurSecretCredential "policy/to/secret"

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
	Write-Verbose "Get-ConjurSecretCredential : Calling [Get-ConjurSecret $ToRetrieve]"
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

.PARAMETER Kind
The Kind of secret you want to retrieve.
Possible values are : user,host,layer,group,policy,variable,webservice
Default = variable

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

None.

.EXAMPLE

PS> Update-ConjurSecret -Identifier "path/to/secret" -SecretValue "newPasswordHere"


.LINK

https://www.conjur.org/api.html#secrets-add-a-secret-post


#>
Function Set-ConjurSecret { # POST | Set a Secret
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory)][string]$Identifier,
        [Parameter(Position=1,mandatory)][string]$SecretValue,
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(Position=2)][string]$Kind = "variable"
    )
    return Invoke-Conjur secrets !A,$Kind -identifier $Identifier -Body $SecretValue
}
New-Alias Set-ConjurSecret Update-ConjurSecret
Export-ModuleMember -Function Update-ConjurSecret -Alias Set-ConjurSecret

###############################
# Policies API
###############################
<#
.SYNOPSIS
#### This function has not been tested yet ####
Modifies an existing Conjur policy

.DESCRIPTION
Data may be explicitly deleted using the !delete, !revoke, and !deny statements. Unlike “replace” mode, no data is ever implicitly deleted.

.PARAMETER Identifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The YAML policy file path (can not be used with Policy)

.PARAMETER Policy
The YAML policy  (can not be used with PolicyFilePath)

.INPUTS
[string]Policy : The Yaml configuration of a Policy

.OUTPUTS
None.

.EXAMPLE
PS> Get-content .\test-policy.yml | Update-ConjurPolicy -Identifier root 

created_roles                           version
-------------                           -------
@{cucumber:host:database/another-host=}       3

.EXAMPLE

PS> Update-ConjurPolicy -Identifier root  ".\test-policy.yml"

created_roles                           version
-------------                           -------
@{cucumber:host:database/another-host=}       3

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Update_Policy.htm


#>
Function Update-ConjurPolicy { # PATCH | Update a Policy
    [CmdletBinding(DefaultParameterSetName="File")]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true,ParameterSetName='File')][string]$PolicyFilePath,
        [Parameter(Position=1,mandatory=$true,ValueFromPipeline,ParameterSetName='Policy')][string]$Policy
    )
	if ($PsCmdlet.ParameterSetName -like "File" ) { $Policy = get-content $PolicyFilePath }
    return Invoke-Conjur policies !A,policy -Identifier $Identifier  -Body $Policy
}
Export-ModuleMember -Function Update-ConjurPolicy 

<#
.SYNOPSIS
#### This function has not been tested yet ####
Loads or replaces a Conjur policy document.

.DESCRIPTION
Any policy data which already exists on the server but is not explicitly specified in the new policy file will be deleted.

.PARAMETER Identifier
The identifier used to update the policy


.PARAMETER PolicyFilePath
The YAML policy file path (can not be used with Policy)

.PARAMETER Policy
The YAML policy  (can not be used with PolicyFilePath)


.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

None.

.EXAMPLE

PS> Get-content .\test-policy.yml | Set-ConjurPolicy -Identifier root

created_roles                   version
-------------                   -------
@{myorg:host:database/db-host=}       1

.EXAMPLE

PS> Set-ConjurPolicy -Identifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                   version
-------------                   -------
@{myorg:host:database/db-host=}       1

.LINK

https://www.conjur.org/api.html#policies-replace-a-policy


#>
Function Write-ConjurPolicy { # PUT | Replace a Policy
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true,ParameterSetName='File')][string]$PolicyFilePath,
        [Parameter(Position=1,mandatory=$true,ValueFromPipeline,ParameterSetName='Policy')][string]$Policy
    )
	if ($PsCmdlet.ParameterSetName -like "File" ) { $Policy = get-content $PolicyFilePath }
    return Invoke-Conjur policies !A,policy -Identifier $Identifier -Body $Policy
}
New-Alias Replace-ConjurPolicy Write-ConjurPolicy
Export-ModuleMember -Function Write-ConjurPolicy -Alias Replace-ConjurPolicy

<#
.SYNOPSIS

Adds data to the existing Conjur policy.

.DESCRIPTION

Deletions are not allowed. Any policy objects that exist on the server but are omitted from the policy file will not be deleted and any explicit deletions in the policy file will result in an error

.PARAMETER Identifier
The identifier used to update the policy


.PARAMETER PolicyFilePath
The YAML policy file path (can not be used with Policy)

.PARAMETER Policy
The YAML policy  (can not be used with PolicyFilePath)

.INPUTS

None. You cannot pipe objects to this function.

.OUTPUTS

None.

.EXAMPLE

PS> Get-content test-policy.yml | Add-ConjurPolicy root

created_roles                       version
-------------                       -------
@{cucumber:host:database/new-host=}       2

.EXAMPLE

PS> Add-ConjurPolicy -Identifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                       version
-------------                       -------
@{cucumber:host:database/new-host=}       3


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Append_Policy.htm


#>
Function Add-ConjurPolicy {  # POST  |  Load a Policy (add)
    [CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory=$true)][string]$Identifier,
        [Parameter(Position=1,mandatory=$true,ParameterSetName='File')][string]$PolicyFilePath,
        [Parameter(Position=1,mandatory=$true,ValueFromPipeline,ParameterSetName='Policy')][string]$Policy
    )
	if ($PsCmdlet.ParameterSetName -like "File" ) { $Policy = get-content $PolicyFilePath }
    return Invoke-Conjur policies !A,policy,$Identifier -Body $Policy
}
New-Alias Append-ConjurPolicy Add-ConjurPolicy
Export-ModuleMember -Function Add-ConjurPolicy -Alias Append-ConjurPolicy

###############################
# Resources API
###############################
<#
.SYNOPSIS
List resource within an organization account

.DESCRIPTION
If a kind query parameter is given, narrows results to only resources of that kind.

If a limit is given, returns no more than that number of results. Providing an offset skips a number of resources before returning the rest. In addition, providing an offset will give limit a default value of 10 if none other is provided. These two parameters can be combined to page through results.

If the parameter count is true, returns only the number of items in the list.

If the role or acting_as query parameter is given, then the resource list can be retrieved for a different role (as long as the authenticated role has access).



.PARAMETER Kind
Filters on the Kinds of resources. Valid Kinds are : user,host,layer,group,policy,variable,webservice

.PARAMETER search
search term used to narrow results

.PARAMETER limit
maximum number of results to return

.PARAMETER offset
number of results to skip

.PARAMETER count
if true, return only the number of items in the list

.PARAMETER acting_as
The fully qualified identifier for the role whose resource list you want to view. It should be entered as {account}:{kind}:{identifier} where the identifier is URL-encoded. For more information about URL encoding, see URI.

Example: cucumber:user:alice

.INPUTS
None. You cannot pipe objects to this function.

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


.EXAMPLE

PS> Get-ConjurResources
created_at  : 2017-07-25T06:30:38.768+00:00
id          : myorg:variable:app-prod/db-password
owner       : myorg:policy:app-prod
policy      : myorg:policy:root
permissions : {}
annotations : {}
secrets     : {@{version=1}}

created_at      : 2017-07-25T06:30:38.768+00:00
id              : myorg:policy:app-prod
owner           : myorg:user:admin
policy          : myorg:policy:root
permissions     : {}
annotations     : {}
policy_versions : {}


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_List_Resources.htm


#>
Function Get-ConjurResources {
    [CmdletBinding(DefaultParameterSetName="None")]
	Param(
		[Parameter(ParameterSetName='filter',mandatory)]
		[ValidateSet("user","host","layer","group","policy","variable","webservice")][string]$kind,
		[string]$search,
		[int]$limit,
		[int]$offset,
		[int]$count,
		[string]$acting_as
	)
	process {
		$Command = @()
		$psboundparameters.keys  | ? { $_ -notin $CCConfig.CommonParameters } | % { 
			$Command += "$_=$($psboundparameters.item($_))"
		}
		return Invoke-Conjur resources !A -query $Command
	}
}
Export-ModuleMember -Function Get-ConjurResources

<#
.SYNOPSIS
Show a Resource

.DESCRIPTION
Show a Resource

.PARAMETER Kind
Filters on the Kinds of resources. Valid Kinds are : user,host,layer,group,policy,variable,webservice

.PARAMETER identifier
The identifier (path) of the object 

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
PsObject of the resource

.EXAMPLE
PS> Get-ConjurResources

created_at      : 2019-05-29T16:42:56.284+00:00
id              : dev:policy:root
owner           : dev:user:admin
permissions     : {}
annotations     : {}
policy_versions : {@{version=1; created_at=2019-05-29T16:42:56.284+00:00; policy_text=---                                                                               4


.EXAMPLE
PS> Get-ConjurResource

created_at      : 7/25/2017 8:30:38 AM
id              : myorg:variable:db/password
owner           : myorg:user:admin
policy          : myorg:policy:root
permissions     : {}
annotations     : {}
policy_versions : {}

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Show_Resources.htm


#>
Function Get-ConjurResource {
    [CmdletBinding(DefaultParameterSetName="None")]
	Param(
		[Parameter(position=0,mandatory)][string]$identifier,
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(position=1)][string]$kind="variable"
	)
	process {
		return Invoke-Conjur resources !A,$kind,$identifier
	}
}
Export-ModuleMember -Function Get-ConjurResource

<#
.SYNOPSIS
Show Permitted Roles

.DESCRIPTION
Lists the roles which have the named permission on a resource

.PARAMETER Kind
kind of resource requested. Valid Kinds are : user,host,layer,group,policy,variable,webservice

.PARAMETER identifier
The identifier of the resource

.PARAMETER privilege
roles permitted to exercise this privilege are shown
Example: execute


.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS

PsObject


.EXAMPLE

PS> Get-ConjurPermittedRoles variable db execute

myorg:policy:database
myorg:user:db-admin
myorg:host:database/db-host

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Show_Permitted_Roles.htm


#>
Function Get-ConjurPermittedRoles {
    [CmdletBinding(DefaultParameterSetName="None")]
	Param(
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(position=0,mandatory)][string]$kind,
		[Parameter(position=1,mandatory)][string]$identifier,
		[Parameter(position=2,mandatory)][string]$privilege
	)
	process {
		return Invoke-Conjur resources !A,$kind,$identifier -query "permitted_roles=true",$privilege
	}
}
Export-ModuleMember -Function Get-ConjurPermittedRoles

<#
.SYNOPSIS
Check Permission

.DESCRIPTION
Checks whether a role has a privilege on a resource. For example, is this Host authorized to execute (fetch the value of) this Secret?

.PARAMETER Kind
kind of resource requested. Valid Kinds are : user,host,layer,group,policy,variable,webservice

.PARAMETER identifier
The identifier of the resource (Example : db )

.PARAMETER privilege
the fully qualified identifier of the role to test (Example: myorg:host:application)

.PARAMETER privilege
roles permitted to exercise this privilege are shown (Example: execute)


.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS

PsObject


.EXAMPLE

PS> Test-ConjurPermission variable db "myorg:host:application" execute


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Check_Permission.htm


#>
Function Test-ConjurPermission {
    [CmdletBinding(DefaultParameterSetName="None")]
	Param(
		[ValidateSet("user","host","layer","group","policy","variable","webservice")]
		[Parameter(position=0,mandatory)][string]$kind,
		[Parameter(position=1,mandatory)][string]$identifier,
		[Parameter(position=2,mandatory)][string]$role,
		[Parameter(position=3,mandatory)][string]$privilege
	)
	process {
		$Query = @("check=true","role=$role","privilege=$privilege")
		return Invoke-Conjur resources !A,$kind,$identifier -query $Query
	}
}
Export-ModuleMember -Function Test-ConjurPermission


###############################
# Roles API
###############################
<#
.SYNOPSIS
Gets detailed information about a specific role, including the role members.

.DESCRIPTION
If a role A is granted to a role B, then role A is said to have role B as a member. These relationships are described in the “members” portion of the returned JSON

.PARAMETER kind
[Mandatory] The Kind of role.
Possible values are : user,host,layer,group,policy

.PARAMETER identifier
[Mandatory] The identifier of the Role

.INPUTS
None. You cannot pipe objects to this function.

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


<#
.SYNOPSIS
List a Role's Members

.DESCRIPTION
List members within a role.

If a kind query parameter is used, the results are narrowed to only resources of that kind.

If a limit is provided, the results return up to the number specified. Providing an offset skips a number of resources before returning the rest. In addition, providing an offset gives limit a default value of 10 if no other limit is provided. These two parameters can be combined to page through results.

If the parameter count is true, the number of items in the list are returned.

Text search

If the search parameter is provided, the results are narrowed to those pertaining to the search query. Search works across resource IDs and the values of annotations. It weighs results so that those with matching id or a matching value of an annotation called name appear first, then those with another matching annotation value, and finally those with a matching kind.


.PARAMETER search 
Search string

.PARAMETER kind
kind of role requested

.PARAMETER limit
maximum number of results to return

.PARAMETER offset
number of results to skip

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
PsObject

.EXAMPLE
PS> Get-ConjurRoleMember devs

admin_option : True
ownership    : True
role         : myorg:group:devs
member       : myorg:user:admin
policy       : myorg:policy:root

admin_option : False
ownership    : False
role         : myorg:group:devs
member       : myorg:user:alice
policy       : myorg:policy:root

admin_option : False
ownership    : False
role         : myorg:group:devs
member       : myorg:user:bob
policy       : myorg:policy:root

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_List_Role_Members.htm
#>
Function Get-ConjurRoleMember {
	[CmdletBinding()]
	param(
        [Parameter(Position=1)][string]$search,
		[Parameter(Position=2)][ValidateSet("user","host","layer","group","policy")][string]$kind,
		[int]$limit,
		[int]$offset
    )
	return Invoke-Conjur roles !A,$kind,$identifier, -query members
}
Export-ModuleMember -Function Get-ConjurRoleMember


<#
.SYNOPSIS
List a Role's Memberships

.DESCRIPTION
Allows you to view the memberships of a role, including a list of groups of which a specific host or user is a member.

If a kind query parameter is used, the results are narrowed to only resources of that kind.

If a limit is provided, the results return up to the number specified. Providing an offset skips a number of resources before returning the rest. In addition, providing an offset gives limit a default value of 10 if no other limit is provided. These two parameters can be combined to page through results.

If the parameter count is true, the number of items in the list are returned.

.PARAMETER identifier 
[Mandatory] identifier of the role

.PARAMETER kind 
[Mandatory] kind of role requested
Possible values are : user,host,layer,group,policy

.PARAMETER limit
maximum number of results to return

.PARAMETER offset
number of results to skip

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
PsObject

.EXAMPLE
PS> Get-ConjurRoleMemberships devs

admin_option : False
ownership    : False
role         : myorg:group:devs
member       : myorg:user:alice
policy       : myorg:policy:root

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Show_Role.htm
#>
Function Get-ConjurRoleMemberships {
	[CmdletBinding()]
	param(
        [Parameter(Position=1,mandatory)][string]$identifier,
		[Parameter(Position=2,mandatory)][ValidateSet("user","host","layer","group","policy")][string]$kind,
		[int]$limit,
		[int]$offset
    )
	return Invoke-Conjur roles !A,$kind,$identifier -query memberships
}
Export-ModuleMember -Function Get-ConjurRoleMemberships

###############################
# Host Factories API 
###############################

<#
.SYNOPSIS
#### This function has not been tested yet ####
Creates one or more tokens which can be used to bootstrap host identity 

.DESCRIPTION
Creates one or more tokens which can be used to bootstrap host identity. Responds with a JSON document containing the tokens and their restrictions.

If the tokens are created with a CIDR restriction, Conjur will only accept them from the allowlisted IP ranges.

.PARAMETER expiration 
[Mandatory] Expiration date of the token

.PARAMETER host_factory
[Mandatory] Fully qualified Host Factory id

.PARAMETER count
Number of tokens to create

.PARAMETER cidr
CIDR restriction(s) on token usage

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
PsObject

.EXAMPLE
PS> Grant-ConjurNewToken devs

expiration           cidr                         token
----------           ----                         -----
8/5/2017 12:27:20 AM {127.0.0.1/32, 127.0.0.2/32} 281s2ag1g8s7gd2ezf6td3d619b52t9gaak3w8rj0p38124n384sq7x
8/5/2017 12:27:20 AM {127.0.0.1/32, 127.0.0.2/32} 2c0vfj61pmah3efbgpcz2x9vzcy1ycskfkyqy0kgk1fv014880f4


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Create_Tokens.htm
#>
Function Grant-ConjurNewToken {
	[CmdletBinding()]
	param(
        [Parameter(Position=1,mandatory)][datetime]$expiration,
        [Parameter(Position=2,mandatory)][string]$host_factory,
        [Parameter(Position=3)][int]$count,
        [Parameter(Position=3)][string[]]$cidr
    )
	process {
		$Query = @("expiration=$expiration","host_factory=$host_factory")
		switch ($psboundparameters.keys) { 
			count	{ $Query += "count=$count"}
			cidr	{ $cidr | % {  $Query += "cidr[]=$_"} }
		}
		$Query = $Query | % { [System.Web.HttpUtility]::UrlEncode($_)  } 
		return Invoke-Conjur host_factory_tokens -query $Query
	}
}
Export-ModuleMember -Function Grant-ConjurNewToken

<#
.SYNOPSIS
#### This function has not been tested yet ####
Revoke Tokens 

.DESCRIPTION
Revokes a token, immediately disabling it.

If the tokens are created with a CIDR restriction, Conjur will only accept them from the allowlisted IP ranges.

.PARAMETER token
[Mandatory] Token you want to revoke.

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
None

.EXAMPLE
PS> Revoke-ConjurNewToken 281s2ag1g8s7gd2ezf6td3d619b52t9gaak3w8rj0p38124n384sq7x


.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Revoke_Tokens.htm
#>
Function Revoke-ConjurToken {
	[CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory)][string]$token
    )
	process {
		return Invoke-Conjur host_factory_tokens $token
	}
}
Export-ModuleMember -Function Revoke-ConjurToken


<#
.SYNOPSIS
#### This function has not been tested yet ####
Create a Host

.DESCRIPTION
Creates a Host using the Host Factory and returns a JSON description of it.

Requires a Host Factory Token, which can be created using the Create Tokens API. In practice, this token is usually provided automatically as part of Conjur integration with your host provisioning infrastructure.

.PARAMETER id
Identifier of the Host to be created. It will be created within the account of the Host Factory. (Example: brand-new-host)

.PARAMETER annotations
Json Annotations to apply to the new Host (Example: {"puppet": "true", "description": "new db host"})

.INPUTS
None. You cannot pipe objects to this function.

.OUTPUTS
None

.EXAMPLE
PS> Add-ConjurHost -id brand-new-host

created_at  : 8/8/2017 12:30:00 AM
id          : myorg:host:brand-new-host
owner       : myorg:host_factory:hf-db
permissions : {}
annotations : {}
api_key     : rq5bk73nwjnm52zdj87993ezmvx3m75k3whwxszekvmnwdqek0r

.LINK

https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Create_Host.htm
#>
Function Add-ConjurHost {
	[CmdletBinding()]
	param(
        [Parameter(Position=0,mandatory)][string]$id,
        [Parameter(Position=1)][string]$annotations
    )
	process {
		$Query = @("id=$id")
		switch ($psboundparameters.keys) { 
			annotations	{ $Query += "annotations=$annotations"}
		}
		$Query = $Query | % { [System.Web.HttpUtility]::UrlEncode($_)  }
		write-verbose $query
		return Invoke-Conjur host_factory_tokens hosts -query $query
	}
}
Export-ModuleMember -Function Add-ConjurHost