function Get-HostFingerPrint
{
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
		[ValidateSet('SHA-256', 'MD5', IgnoreCase = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Algorithm = 'SHA-256',
		[ValidateSet('Ftp', 'Scp', 'Webdav', IgnoreCase = $true)]
		$Protocol
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
		[string]$reportedException = $Error[0].Exception.Message
		
		Write-Error -Message $reportedException
		
		return $null
	}
	finally
	{
		$sessionObject.Dispose()
	}
}

Get-HostFingerPrint -UserName 'wdtransf.prod@extranet.sybrondental.com' -Password 'wdtransf.prod@extranet.sybrondental.com' -RemoteHost 'na-ftp.kavokerrgroup.com'