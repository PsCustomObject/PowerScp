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
		A description of the WebDavRoot parameter.
	
	.PARAMETER UserName
		A string representing the username that will be used to authenticate agains the remote host.
	
	.PARAMETER UserPassword
		A string representing the password used to connect to the remote host.
	
	.PARAMETER PrivateKeyPath
		A string representing the path to a file containing an SSH private key used for authentication with remote host.
	
	.EXAMPLE
		PS C:\> New-ScpSession -RemoteHost 'Value1'
	
	.OUTPUTS
		WinSCP.Session
	
	.NOTES
		Additional information about the function.
#>
function New-ScpSession {
	[CmdletBinding(DefaultParameterSetName = 'UserName Password')]
	[OutputType([WinSCP.Session], ParameterSetName = 'UserName Password')]
	[OutputType([WinSCP.Session], ParameterSetName = 'Credentials')]
	[OutputType([WinSCP.Session])]
	param
	(
		[Parameter(ParameterSetName = 'UserName Password',
			Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('Host', 'HostName')]
		[string]$RemoteHost,
		[Parameter(Mandatory = $false)]
		[Alias('GiveUpSecurityAndAcceptAnySshHostKey', 'AnySshKey', 'SshCheck', 'AcceptAnySshKey')]
		[switch]$NoSshKeyCheck,
		[Alias('GiveUpSecurityAndAcceptAnyTlsHostCertificate', 'AnyTlsCertificte', 'AcceptAnyCertificate')]
		[switch]$NoTlsCheck,
		[ValidateRange(0, 65535)]
		[Alias('Port', 'RemoteHostPort')]
		[int]$ServerPort = 22,
		[ValidateNotNullOrEmpty()]
		[Alias('SshPrivateKey', 'SshPrivateKeyPath', 'SsheKeyPath')]
		[string]$SshKeyPath = $null,
		[ValidateNotNullOrEmpty()]
		[Alias('ConnectionProtocol')]
		[WinSCP.Protocol]$Protocol,
		[WinSCP.FtpMode]$FtpMode,
		[ValidateNotNullOrEmpty()]
		[Alias('FtpSecureMode', 'SecureFtpMode')]
		[WinSCP.FtpSecure]$FtpSecure,
		[Timespan]$ConnectionTimeOut = (New-TimeSpan -Seconds 15),
		[switch]$WebDavSecure,
		[ValidateNotNullOrEmpty()]
		[string]$WebDavRoot,
		[Parameter(ParameterSetName = 'UserName Password',
			Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserName,
		[Parameter(ParameterSetName = 'UserName Password',
			Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserPassword
	)
	
	# TODO: Create parameter for custom DLL path
	# TODO: Create parameter for custom exe path
	# TODO: Create paramterset for secure password

	# Add assembly
	Add-Type -Path "$PSScriptRoot\..\lib\WinSCPnet.dll"
	
	# Instantiate Session Options hash
	[hashtable]$sessionOptions = @{ }

	# Instantiate Session object hash
	[hashtable]$sessionObject = @{ }

	# Create WinSCP.Session and WinSCP.SessionOptions Objects
	$paramNewObject = @{
		TypeName = 'WinSCP.Session'
		Property = @{ ExecutablePath = "$PSScriptRoot\..\bin\winscp.exe" }
	}
	
	$sessionObject = New-Object @paramNewObject
	
	# Get parameterset
	switch ($PsCmdlet.ParameterSetName) {
		'UserName Password' 
		{
			# Add paramters to object
			$sessionOptions.Add('UserName', $UserName)
			$sessionOptions.Add('Password', $UserPassword)
			
			break
		}
		'Credentials' 
		{
			
			# Convert PSCredential Object to match names of the WinSCP.SessionOptions Object.
			$PSBoundParameters.Add('UserName', $Credential.UserName)
			$PSBoundParameters.Add('SecurePassword', $Credential.Password)
			
			#TODO: Place script here
			break
		}
	}

	switch ($PSBoundParameters.Keys) {
		'NoSshKeyCheck' 
		{
			# Add to options hash
			$sessionOptions.Add('GiveUpSecurityAndAcceptAnySshHostKey', $true)
		}
	}
}


New-ScpSession