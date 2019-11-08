function New-ScpSession
{
<#
	.SYNOPSIS
		A brief description of the New-ScpSession function.
	
	.DESCRIPTION
		A detailed description of the New-ScpSession function.
	
	.PARAMETER RemoteHost
		A string representing the remote host to connect to.
	
	.PARAMETER NoSshKeyCheck
		When parameter is used will PowerScp will skip verification of remote host SSH key for example when connecting to a known host.
		
		Switch should be used only in exceptional cases when connecting to known or internal hosts as it will compromise connection security.
	
	.PARAMETER NoTlsCheck
		When parameter is used PowerScp will skip vericication of remote host TLS/SSL Certificate for example wehn connecting to a known host.
		
		Switch should be used only in exceptional cases when connecting to known or internal hosts as it will compromise connection security.
		
		Use when connecting to FTPS/WebDAVS servers.
	
	.PARAMETER ServerPort
		An Int number representing the port number to use establish the connection if not specified default value of 22 (SCP) will be used.
		
		Allowed values are 0 - 65535
	
	.PARAMETER SshKeyPath
		A description of the SshKeyPath parameter.
	
	.PARAMETER Protocol
		When parameter is used a protocol to be used in the connection can be specified. If parameter is not used default protocol is set to SCP
	
	.PARAMETER FtpMode
		Specify the FTP operation mdoe either Active or Passive.
		
		If not specified it will default to Passive.
		
		Valid values are:
		
		- Active
		- Passive (Default)
	
	.PARAMETER FtpSecure
		By default set to None specifies the type of security the client should used to FTPS servers.
		
		Valid values are:
		
		- None (Default)
		- Implicit
		- Explicit
	
	.PARAMETER ConnectionTimeOut
		A description of the ConnectionTimeOut parameter.
	
	.PARAMETER WebDavSecure
		A description of the WebDavSecure parameter.
	
	.PARAMETER WebDavRoot
		A string representing the WebDAV root path.
	
	.PARAMETER UserName
		A string representing the username that will be used to authenticate agains the remote host.
	
	.PARAMETER UserPassword
		A string representing the password used to connect to the remote host.
	
	.PARAMETER SshHostKeyFingerprint
		A description of the SshHostKeyFingerprint parameter.
	
	.PARAMETER Credentials
		A description of the Credentials parameter.
	
	.PARAMETER SshKeyPassword
		A description of the SshKeyPassword parameter.
	
	.PARAMETER PrivateKeyPath
		A string representing the path to a file containing an SSH private key used for authentication with remote host.
	
	.EXAMPLE
		PS C:\> New-ScpSession -RemoteHost 'Value1'
	
	.OUTPUTS
		WinSCP.Session
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding(DefaultParameterSetName = 'UsernamePassword')]
	[OutputType([WinSCP.Session], ParameterSetName = 'UsernamePassword')]
	[OutputType([WinSCP.Session], ParameterSetName = 'Credentials')]
	[OutputType([WinSCP.Session], ParameterSetName = 'AcceptAnyKey')]
	[OutputType([WinSCP.Session])]
	param
	(
		[Parameter(ParameterSetName = 'UsernamePassword',
				   Mandatory = $true)]
		[Parameter(ParameterSetName = 'Credentials',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('Host', 'HostName')]
		[string]
		$RemoteHost,
		[Parameter(ParameterSetName = 'Credentials',
				   Mandatory = $false)]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[Alias('GiveUpSecurityAndAcceptAnySshHostKey', 'AnySshKey', 'SshCheck', 'AcceptAnySshKey')]
		[switch]
		$NoSshKeyCheck,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[Alias('GiveUpSecurityAndAcceptAnyTlsHostCertificate', 'AnyTlsCertificte', 'AcceptAnyCertificate')]
		[switch]
		$NoTlsCheck,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[ValidateRange(0, 65535)]
		[Alias('Port', 'RemoteHostPort')]
		[int]
		$ServerPort = 22,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[ValidateNotNullOrEmpty()]
		[Alias('SshPrivateKey', 'SshPrivateKeyPath')]
		[string]
		$SshKeyPath,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[ValidateSet('Ftp', 'Scp', 'Webdav', 'S3', IgnoreCase = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('ConnectionProtocol')]
		[WinSCP.Protocol]
		$Protocol,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[WinSCP.FtpMode]
		$FtpMode,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[ValidateNotNullOrEmpty()]
		[Alias('FtpSecureMode', 'SecureFtpMode')]
		[WinSCP.FtpSecure]
		$FtpSecure,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[Timespan]
		$ConnectionTimeOut = (New-TimeSpan -Seconds 15),
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[switch]
		$WebDavSecure,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[ValidateNotNullOrEmpty()]
		[Alias('RootPath')]
		[string]
		$WebDavRoot,
		[Parameter(ParameterSetName = 'UsernamePassword',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$UserName,
		[Parameter(ParameterSetName = 'UsernamePassword',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$UserPassword,
		[string[]]
		$SshHostKeyFingerprint,
		[Parameter(ParameterSetName = 'Credentials',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$Credentials,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UsernamePassword')]
		[string]
		$SshKeyPassword
	)
	
	# Add assembly
	Add-Type -Path "$PSScriptRoot\..\lib\WinSCPnet.dll"
	
	# Instantiate Session Options hash
	[hashtable]$sessionOptions = @{ }
	
	# Create WinSCP.Session and WinSCP.SessionOptions Objects
	$paramNewObject = @{
		TypeName = 'WinSCP.Session'
		Property = @{ ExecutablePath = "$PSScriptRoot\..\bin\winscp.exe" }
	}
	
	[WinSCP.Session]$sessionObject = New-Object @paramNewObject
	
	# Create session options object
	$paramNewObject = @{
		TypeName = 'WinSCP.SessionOptions'
	}
	
	$scpSessionOptions = New-Object @paramNewObject
	
	# Get parameterset
	switch ($PsCmdlet.ParameterSetName)
	{
		'UsernamePassword'
		{
			# Add paramters to object
			$sessionOptions.Add('UserName', $UserName)
			$sessionOptions.Add('Password', $UserPassword)
			
			break
		}
		
		'Credentials'
		{
			# Extract username and password and add to hash
			$PSBoundParameters.Add('UserName', $Credentials.UserName)
			$PSBoundParameters.Add('SecurePassword', $Credentials.Password)
			
			break
		}
	}
	
	switch ($PSBoundParameters.Keys)
	{
		'NoSshKeyCheck'
		{
			# Skip host fingerprint check
			$sessionOptions.Add('GiveUpSecurityAndAcceptAnySshHostKey', $true)
			
			break
		}
		'NoTlsCheck'
		{
			# Skip host TLS check
			$sessionOptions.Add('GiveUpSecurityAndAcceptAnyTlsHostCertificate', $true)
			
			break
		}
		'SshKeyPath'
		{
			if ([string]::IsNullOrEmpty($SshKeyPassword) -eq $true)
			{
				Write-Host 'Parameter -PrivateKeyPassphrase is mandatory with -SshPrivateKeyPath' -ForegroundColor Red
				
				return $null
			}
			else
			{
				# Specify SshKeyPath and password
				$sessionOptions.Add('SshPrivateKeyPath', $SshKeyPath)
				$sessionOptions.Add('PrivateKeyPassphrase', $SshKeyPassword)
			}
			
			break
		}
		'SshKeyPassword'
		{
			#TODO:  Implement Secure String version of this parameter
			# Convert SSH password string to clear text
			#[string]$sshPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SshKeyPassword))
			
			if ([string]::IsNullOrEmpty($SshKeyPath) -eq $true)
			{
				Write-Host 'Parameter -SshKeyPath is mandatory with -SshKeyPassword' -ForegroundColor Red
				
				return $null
			}
			else
			{
				# Specify SSH Key passphrase
				$sessionOptions.Add('PrivateKeyPassphrase', $SshKeyPassword)
				$sessionOptions.Add('SshPrivateKeyPath', $SshKeyPath)
			}
			
			break
		}
		'WebDavSecure'
		{
			# Add to options hash
			$sessionOptions.Add('WebdavSecure', $true)
			
			break
		}
	}
	
	# Add mandatory options
	$sessionOptions.Add('HostName', $RemoteHost)
	$sessionOptions.Add('PortNumber', $ServerPort)
	$sessionOptions.Add('Timeout', $ConnectionTimeOut)
	
	# Setup session options
	foreach ($option in $sessionOptions.GetEnumerator())
	{
		# Get values in hash
		[string]$optionKey = $option.Key
		[string]$optionValue = $option.Value
		
		# Add values SCP Session object
		$scpSessionOptions.$optionKey = $optionValue
	}
	
	try
	{
		# Open session
		$sessionObject.Open($scpSessionOptions)
		
		return $sessionObject
	}
	catch
	{
		Write-Error -Message $_.ToString()
		return $null
	}
}