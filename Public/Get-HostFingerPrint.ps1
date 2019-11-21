function Get-HostFingerPrint
{
	<#
	.SYNOPSIS
		Will retrieve fingerprint of a remote host
	
	.DESCRIPTION
		Will retrieve fingerprint of a remote host so that is can be used in other cmdlets to open an WinSCP Session validating remote host identity.
	
	.PARAMETER RemoteHost
		A string representing the host to connect to
	
	.PARAMETER Password
		A string representing the password to use to connect to the remote host.
	
	.PARAMETER UserName
		A string representing the username to use while opening connection to the remote host.
	
	.PARAMETER PortNumber
		An integer representing the port used to establish the connection. 
		
		Will default to 21 if not specified.
	
	.PARAMETER ConnectionTimeOut
		A timespan representing the timeout, in secods, before dropping connection. 
		
		If not specified it will default to 15 seconds.
	
	.PARAMETER Algorithm
		Specifies the host fingerprint to retrive, possible values are:
		
		- SHA-256
		- MD5
	
	.PARAMETER Protocol
		A string representing the protocol to use to open connection possible values are:
		
		- Ftp
		- Scp
		- Webdav
	
	.EXAMPLE
				PS C:\> Get-HostFingerPrint -RemoteHost 'Value1' -Password 'Value2' -UserName 'Value3'
	
	.OUTPUTS
		string, string
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding(DefaultParameterSetName = 'UserNamePassword')]
	[OutputType([string], ParameterSetName = 'UserNamePassword')]
	[OutputType([string], ParameterSetName = 'Credentials')]
	[OutputType([string])]
	param
	(
		[Parameter(ParameterSetName = 'Credentials',
				   Mandatory = $true)]
		[Parameter(ParameterSetName = 'UserNamePassword',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('Host', 'Server', 'RemoteServer')]
		[string]$RemoteHost,
		[Parameter(ParameterSetName = 'UserNamePassword',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password,
		[Parameter(ParameterSetName = 'UserNamePassword',
				   Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserName,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UserNamePassword')]
		[ValidateNotNullOrEmpty()]
		[int]$PortNumber = 21,
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UserNamePassword')]
		[timespan]$ConnectionTimeOut = (New-TimeSpan -Seconds 15),
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UserNamePassword')]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('SHA-256', 'MD5', IgnoreCase = $true)]
		[string]$Algorithm = 'SHA-256',
		[Parameter(ParameterSetName = 'Credentials')]
		[Parameter(ParameterSetName = 'UserNamePassword')]
		[ValidateSet('Ftp', 'Scp', 'Webdav', IgnoreCase = $true)]
		[string]$Protocol = 'Scp'
	)
	
	# Add assembly
	Add-Type -Path "$PSScriptRoot\..\lib\WinSCPnet.dll"
	
	# Create Session Options hash
	[hashtable]$sessionOptions = @{ }
	
	# Create Session Object hash
	[hashtable]$sesionObjectParameters = @{ }
	
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
			$sessionOptions.Add('UserName', $Credentials.UserName)
			$sessionOptions.Add('SecurePassword', $Credentials.Password)
			
			break
		}
	}
	
	# Add mandatory parameters to Session Options
	$sessionOptions.Add('HostName', $RemoteHost)
	$sessionOptions.Add('PortNumber', $ServerPort)
	$sessionOptions.Add('Timeout', $ConnectionTimeOut)
	
	# Add mandatory paramters to Session Object
	$sesionObjectParameters.Add('ExecutablePath', "$PSScriptRoot\..\bin\winscp.exe")
	
	# Create session options object
	$paramNewObject = @{
		TypeName = 'WinSCP.SessionOptions'
		Property = $sessionOptions
	}
	
	[WinSCP.SessionOptions]$scpSessionOptions = New-Object @paramNewObject
	
	# # Create Session Object
	$paramNewObject = @{
		TypeName = 'WinSCP.Session'
		Property = $sesionObjectParameters
	}
	
	[WinSCP.Session]$sessionObject = New-Object @paramNewObject
	
	try
	{
		return $sessionObject.ScanFingerprint($scpSessionOptions, $Algorithm)
	}
	catch
	{
		# Save exception message
		[string]$reportedException = $_.Exception.Message
		
		Write-Error -Message $reportedException
		
		return $null
	}
	finally
	{
		$sessionObject.Dispose()
	}
}