function Format-StringPath
{
<#
	.SYNOPSIS
		Will format string in SCP format.
	
	.DESCRIPTION
		Will format string in SCP format replacing backslashes to slashes.
	
	.PARAMETER Path
		A string representing the path(s) to format.
	
	.EXAMPLE
		PS C:\> Format-StringPath -Path $value1
#>
    
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path
    )
    
    process
    {
        foreach ($item in $Path)
        {
            # Sanitize input
            if ($item.Contains('\'))
            {
                $item = $item.Replace('\', '/')
            }
            
            $item
        }
    }
}

function Get-HostFingerPrint
{
	<#
	.SYNOPSIS
		Cmdlet will retrieve fingerprint of a remote host
	
	.DESCRIPTION
		Cmdlet will retrieve fingerprint of a remote host so that is can be used in other cmdlets to open an WinSCP Session validating remote host identity.
	
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
        [string]
        $RemoteHost,
        [Parameter(ParameterSetName = 'UserNamePassword',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password,
        [Parameter(ParameterSetName = 'UserNamePassword',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserName,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UserNamePassword')]
        [ValidateNotNullOrEmpty()]
        [int]
        $PortNumber = 21,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UserNamePassword')]
        [timespan]
        $ConnectionTimeOut = (New-TimeSpan -Seconds 15),
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UserNamePassword')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('SHA-256', 'MD5', IgnoreCase = $true)]
        [string]
        $Algorithm = 'SHA-256',
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UserNamePassword')]
        [ValidateSet('Ftp', 'Scp', 'Webdav', IgnoreCase = $true)]
        [string]
        $Protocol = 'Scp'
    )
    
    # Add assembly
    Add-Type -Path "$PSScriptRoot\lib\WinSCPnet.dll"
    
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
    $sesionObjectParameters.Add('ExecutablePath', "$PSScriptRoot\bin\winscp.exe")
    
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

function Get-ScpChildItem
{
    <#
        .SYNOPSIS
            Cmdlet will return items on a remote server.
        
        .DESCRIPTION
            Cmdlet will return items on a remote session where an SCP Session has been established.
        
        .PARAMETER Session
            A WinSCP.Session object containing information about the remote host.
        
        .PARAMETER RemotePath
            A string representing a folder on the remote server. If path does not exist script will return a $null value and print an error.
        
        .PARAMETER Filter
            Windows wildcard to filter files, if not spcecified will default to $null returning all files. If a filename is specified only that item will be returned.
        
        .PARAMETER Recurse
            When specified it will cause function to recurse in any subfolder in the remote path
        
        .PARAMETER Depth
            Paramter can only be used when the -Recurse parameter is also specified and is used to limite the number of levels, folder, function will recurse in.
            
            If -Recurse is used and -Depth is not specified it will default to 0 meaning no recursion limit will be applied.
        
        .PARAMETER FilesOnly
            When specified it will list/return files only omitting any matching directory.
        
        .EXAMPLE
            PS C:\> Get-ScpChildItem -Session $scpSession -FilesOnly
        
        .OUTPUTS
            WinSCP.RemoteFileInfo, System.Null
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'NoRecurse')]
    [OutputType([array], ParameterSetName = 'Recurse')]
    [OutputType([array], ParameterSetName = 'NoRecurse')]
    [OutputType([WinSCP.RemoteFileInfo])]
    param
    (
        [Parameter(ParameterSetName = 'NoRecurse',
                   Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Recurse')]
        [SupportsWildcards()]
        [WinSCP.Session]
        $Session,
        [Parameter(ParameterSetName = 'NoRecurse',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Recurse')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,
        [Parameter(ParameterSetName = 'NoRecurse')]
        [Parameter(ParameterSetName = 'Recurse')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Filter = $null,
        [Parameter(ParameterSetName = 'Recurse')]
        [switch]
        $Recurse,
        [Parameter(ParameterSetName = 'Recurse')]
        [int]
        $Depth = 0,
        [Parameter(ParameterSetName = 'Recurse')]
        [Parameter(ParameterSetName = 'NoRecurse')]
        [switch]
        $FilesOnly
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    process
    {
        switch ($PsCmdlet.ParameterSetName)
        {
            'Recurse'
            {
                # Recurse into subfolders
                [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::AllDirectories -bor [WinSCP.EnumerationOptions]::MatchDirectories
            }
            'NoRecurse'
            {
                # Enumerate matching directories without recursing
                [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None -bor [WinSCP.EnumerationOptions]::MatchDirectories
            }
        }
        
        foreach ($path in $RemotePath)
        {
            # Format path for SCP session
            [string]$path = Format-StringPath -Path $path
            
            # Validate path exists
            if (!(Test-ScpPath -RemotePath $path -Session $Session))
            {
                Write-Error -Message "Cannot find path: $path because it does not exist"
                
                continue
            }
            
            switch ($PSBoundParameters)
            {
                'FilesOnly'
                {
                    # Enumerate files only
                    [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None
                }
            }
            
            try
            {
                # Get matching items
                $Session.EnumerateRemoteFiles($path, $Filter, $enumOptions)
            }
            catch
            {
                # Save exception message
                [string]$reportedException = $_.Exception.Message
                
                Write-Error -Message $reportedException
                
                return $null
            }
        }
    }
}

function Get-ScpItem
{
    <#
        .SYNOPSIS
            Cmdlet will return items on a remote server.
        
        .DESCRIPTION
            Cmdlet will return items on a remote session where an SCP Session has been established.
        
        .PARAMETER Session
            A WinSCP.Session object containing information about the remote host. 
        
            Session must be in open state or an exception will be thrown.
        
        .PARAMETER RemotePath
            A string representing a folder on the remote server. If path does not exist script will return a $null value and print an error.
        
        .PARAMETER Filter
            Windows wildcard to filter files, if not spcecified will default to $null returning all files. If a filename is specified only that item will be returned.
        
        .PARAMETER Recurse
            When specified it will cause cmdlet to recurse in any subfolder in the remote path
        
        .PARAMETER Depth
            Paramter can only be used when the -Recurse parameter is also specified and is used to limite the number of levels, folder, cmdlet will recurse in.
            
            If -Recurse is used and -Depth is not specified it will default to 0 meaning no recursion limit will be applied.
        
        .PARAMETER FilesOnly
            When specified it will list/return files only omitting any matching directory.
        
        .EXAMPLE
            PS C:\> Get-ScpChildItem -Session $scpSession -FilesOnly
        
        .OUTPUTS
            WinSCP.RemoteFileInfo, System.Null
        
        .NOTES
            Additional information about the function.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Recurse')]
    [OutputType([array], ParameterSetName = 'Recurse')]
    [OutputType([array], ParameterSetName = 'NoRecurse')]
    [OutputType([WinSCP.RemoteFileInfo])]
    param
    (
        [Parameter(ParameterSetName = 'NoRecurse',
                   Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Recurse')]
        [SupportsWildcards()]
        [WinSCP.Session]
        $Session,
        [Parameter(ParameterSetName = 'NoRecurse',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Recurse',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,
        [Parameter(ParameterSetName = 'NoRecurse')]
        [Parameter(ParameterSetName = 'Recurse')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Filter = $null,
        [Parameter(ParameterSetName = 'Recurse')]
        [switch]
        $Recurse,
        [Parameter(ParameterSetName = 'Recurse')]
        [int]
        $Depth = 0,
        [Parameter(ParameterSetName = 'Recurse')]
        [Parameter(ParameterSetName = 'NoRecurse')]
        [switch]
        $FilesOnly
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    process
    {
        switch ($PsCmdlet.ParameterSetName)
        {
            'Recurse'
            {
                # Recurse into subfolders
                [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::AllDirectories -bor [WinSCP.EnumerationOptions]::MatchDirectories
            }
            'NoRecurse'
            {
                # Enumerate matching directories without recursing
                [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None -bor [WinSCP.EnumerationOptions]::MatchDirectories
            }
        }
        
        foreach ($path in $RemotePath)
        {
            # Format path for SCP session
            [string]$path = Format-StringPath -Path $path
            
            # Validate path exists
            if (!(Test-ScpPath -RemotePath $path -Session $Session))
            {
                Write-Warning -Message "Cannot process $path because it does not exist"
                
                continue
            }
            
            switch ($PSBoundParameters)
            {
                'FilesOnly'
                {
                    # Enumerate files only
                    [WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None
                }
            }
            
            try
            {
                # Get matching items
                $Session.EnumerateRemoteFiles($path, $Filter, $enumOptions)
            }
            catch
            {
                # Save exception message
                [string]$reportedException = $_.Exception.Message
                
                Write-Error -Message $reportedException
                
                return $null
            }
        }
    }
}

function Get-ScpItemCheckSum
{
	<#
	.SYNOPSIS
		Cmdlet will get checksum of an item on remote host.
	
	.DESCRIPTION
		Cmdlet will get checksum of an item on remote host to which an SCP session has been established.
	
	.PARAMETER Session
		A WinSCP.Session object containing information about the remote host. Session must be in open state.
	
	.PARAMETER HashAlgorithm
		Specifies the algorithm to use when calculating item checksum.
	
	.PARAMETER ItemName
		A string representing the name of the item for which checksum should be calculated.
	
	.EXAMPLE
		PS C:\> Get-ScpItemCheckSum -Session $value1
#>
    
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [WinSCP.Session]
        $Session,
        [SupportsWildcards()]
        [ValidateSet('md2', 'md5', 'sha-1', 'sha-224', 'sha-256', 'sha-384', 'sha-512', 'shake128', 'shake256', IgnoreCase = $true)]
        [string]
        $HashAlgorithm = 'md5',
        [Parameter(Mandatory = $true)]
        [string]
        $ItemName
    )
    
    begin
    {
        # Check a session is open
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    process
    {
        # Format path for SCP session
        [string]$path = Format-StringPath -Path $path
        
        # Validate path is valid
        if (!(Test-ScpPath -RemotePath $path -Session $Session))
        {
            Write-Error -Message "Cannot find path: $path because it does not exist"
            
            return $null
        }
        
        # Check path exists
        if (Test-ScpPath -Session $Session -RemotePath $ItemName)
        {
            try
            {
                # Return item checksum
                return ($Session.CalculateFileChecksum($HashAlgorithm, $path))
            }
            catch
            {
                # Save exception message
                [string]$reportedException = $_.Exception.Message
                
                Write-Error -Message $reportedException
                
                return $null
            }
        }
        else
        {
            Write-Error -Message "Cannot find item because $ItemName does not exist"
        }
    }
}

function New-ScpSession
{
	<#
	.SYNOPSIS
		Cmdlet will create a new WinSCP.Session object.
	
	.DESCRIPTION
		Cmdlet is used to create a new WinSCP.Session via one of the supported protocols.
	
	.PARAMETER RemoteHost
		A string representing the remote host to connect to.
		
		Parameter is mandatory and cannot be omitted.
	
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
		A timespan, in seconds, representing the connection timeout. If not specified will defaul to 15 seconds.
	
	.PARAMETER WebDavSecure
		Use WebDAVS (WebDAV over TLS/SSL), instead of WebDAV.
	
	.PARAMETER WebDavRoot
		A string representing the WebDAV root path. This will be deprecated in a future release.
	
	.PARAMETER UserName
		A string representing the username that will be used to authenticate agains the remote host.
	
	.PARAMETER UserPassword
		A string representing the password used to connect to the remote host.
	
	.PARAMETER SshHostKeyFingerprint
		A string representing ingerprint of SSH server host key (or several alternative fingerprints separated by semicolon).
		
		It makes WinSCP automatically accept host key with the fingerprint. Use SHA-256 fingerprint of the host key.
		
		Mandatory for SFTP/SCP protocol unless the -NoSshKeyCheck parameter is used.
	
	.PARAMETER Credentials
		A credential object to be used to authenticate against the remote host in place of the clear text Username and Password
	
	.PARAMETER SshKeyPassword
		Passphrase for encrypted private keys and client certificates. Must be specified when using -PrivateKeyPath parameter.
	
	.PARAMETER SessionLogPath
		A string representing the path to store session log file to. Default null means no session log file is created.
	
	.PARAMETER DebugLevel
		An integer representing verbosity of debug log. If not specified default to 0 which means no debug logging.
		
		Possible values are 0 (No logging), 1 (Medium logging) and 2 (Verbose logging).
	
	.PARAMETER DebugLogPath
		A string representing path to store assembly debug log to. Default null means no debug log file is created.
	
	.PARAMETER ReconnectTime
		Time, in seconds, to try reconnecting broken sessions. Default is 120 seconds.
	
	.PARAMETER NoSSHKeyPassword
		A description of the NoSSHKeyPassword parameter.
	
	.PARAMETER PrivateKeyPath
		A string representing the path to a file containing an SSH private key used for authentication with remote host.
	
	.EXAMPLE
		PS C:\> New-ScpSession -RemoteHost 'Value1'
	
	.OUTPUTS
		WinSCP.Session
	
	.NOTES
		Function is intended as helper for other module's function creating the WinSCP.Session object used by all other functions for 
        donwload/upload/management of data on remote hosts.
#>
    
    [CmdletBinding(DefaultParameterSetName = 'UsernamePassword',
                   HelpUri = 'https://github.com/PsCustomObject/PowerScp/wiki/New-ScpSession')]
    [OutputType([WinSCP.Session], ParameterSetName = 'UsernamePassword')]
    [OutputType([WinSCP.Session], ParameterSetName = 'Credentials')]
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
        [ValidateScript({ Test-Path $_ })]
        [ValidateNotNullOrEmpty()]
        [Alias('SshPrivateKey', 'SshPrivateKeyPath', 'SsheKeyPath')]
        [string]
        $SshKeyPath = $null,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Ftp', 'Scp', 'Webdav', 'S3', IgnoreCase = $true)]
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
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
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
        $SshKeyPassword,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [ValidateNotNullOrEmpty()]
        [string]
        $SessionLogPath = $null,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [ValidateSet('0', '1', '2', IgnoreCase = $true)]
        [int]
        $DebugLevel = 0,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DebugLogPath,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [ValidateNotNullOrEmpty()]
        [timespan]
        $ReconnectTime = 120,
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [switch]
        $NoSSHKeyPassword
    )
    
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
    
    # Get cmdlet parameters
    foreach ($key in $PSBoundParameters.Keys)
    {
        switch ($key)
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
                # Check additional mandatory parameter is present
                if (([string]::IsNullOrEmpty($SshKeyPassword) -eq $true) -and
                    (-not $NoSSHKeyPassword))
                {
                    throw 'Parameter -PrivateKeyPassphrase is mandatory with -SshPrivateKeyPath'
                    
                    return $null
                }
                elseif ($NoSSHKeyPassword -eq $true)
                {
                    # Specify SshKeyPath
                    $sessionOptions.Add('SshPrivateKeyPath', $SshKeyPath)
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
                # Check additional mandatory parameter is present
                if ([string]::IsNullOrEmpty($SshKeyPath) -eq $true)
                {
                    throw 'Parameter -SshKeyPath is mandatory with -SshKeyPassword'
                    
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
            'SshHostKeyFingerprint'
            {
                $sessionOptions.Add('SshHostKeyFingerprint', $SshHostKeyFingerprint)
            }
            
            'WebDavSecure'
            {
                if (($Protocol -ne 'Webdav') -or
                    ($Protocol -ne 'S3'))
                {
                    Write-Error -Message 'WebDavSecure can only specified with Protocol WebDav or S3'
                    
                    return $null
                }
                else
                {
                    # Add to options hash
                    $sessionOptions.Add('WebdavSecure', $true)
                }
                
                break
            }
            'WebDavRoot'
            {
                if (($Protocol -ne 'Webdav') -or
                    ($Protocol -ne 'S3'))
                {
                    Write-Error -Message 'WebDavSecure can only specified with Protocol WebDav or S3'
                    
                    return $null
                }
                else
                {
                    # Add to options hash
                    $sessionOptions.Add('WebDavRoot', $true)
                }
                
                break
            }
            'SessionLogPath'
            {
                $sesionObjectParameters.Add('SessionLogPath', $SessionLogPath)
                
                break
            }
            'DebugLogPath'
            {
                $sesionObjectParameters.Add('DebugLogPath', $DebugLogPath)
                
                break
            }
        }
    }
    
    # Add mandatory parameters to Session Options
    $sessionOptions.Add('HostName', $RemoteHost)
    $sessionOptions.Add('PortNumber', $ServerPort)
    $sessionOptions.Add('Timeout', $ConnectionTimeOut)
    
    # Add mandatory paramters to Session Object
    $sesionObjectParameters.Add('ExecutablePath', "$PSScriptRoot\bin\winscp.exe")
    
    # Create session options object
    $paramNewObject = @{
        TypeName = 'WinSCP.SessionOptions'
        Property = $sessionOptions
    }
    
    [WinSCP.SessionOptions]$scpSessionOptions = New-Object @paramNewObject
    
    # Create Session Object
    $paramNewObject = @{
        TypeName = 'WinSCP.Session'
        Property = $sesionObjectParameters
    }
    
    [WinSCP.Session]$sessionObject = New-Object @paramNewObject
    
    try
    {
        # Open session
        $sessionObject.Open($scpSessionOptions)
        
        return $sessionObject
    }
    catch
    {
        # Save exception message
        [string]$reportedException = $_.Exception.Message
        
        Write-Error -Message $reportedException
        
        return $null
    }
}

function Remove-ScpItem
{
    <#
        .SYNOPSIS
            A brief description of the Remove-ScpItem function.
        
        .DESCRIPTION
            A detailed description of the Remove-ScpItem function.
        
        .PARAMETER RemotePath
            A string representing a folder on the remote server. If path does not exist script will return a $null value and print an error.
        
        .PARAMETER Session
            A WinSCP.Session object containing information about the remote host. 
        
            Session must be in open state or an exception will be thrown.
        
        .EXAMPLE
            PS C:\> Remove-ScpItem -RemotePath 'value1' -Session $Session
    #>
    
    [CmdletBinding(ConfirmImpact = 'High',
                   SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,
        [Parameter(Mandatory = $true)]
        [WinSCP.Session]
        $Session
    )
    
    begin
    {
        # Check session status
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        foreach ($item in $RemotePath)
        {
            # Format path for SCP session
            [string]$item = Format-StringPath -Path $item
            
            # Validate path exists
            if (!(Test-ScpPath -RemotePath $item -Session $Session))
            {
                Write-Warning -Message "Cannot process $item because it does not exist"
                
                continue
            }
            
            if ($PSCmdlet.ShouldProcess($item))
            {
                try
                {
                    # Remove item
                    [void]($Session.RemoveFiles($item))
                }
                catch
                {
                    # Save exception message
                    [string]$reportedException = $_.Exception.Message
                    
                    Write-Error -Message $reportedException
                }
            }
        }
    }
}

function Remove-ScpSession
{
    <#
    	.SYNOPSIS
    		Cmdlet will close an SCP Session
    	
    	.DESCRIPTION
    		Cmdlet will close an SCP Session using dispoe() method. A disposed sesison cannot be re-used or re-opened.
    	
    	.PARAMETER Session
    		A WinSCP.Session object.
    	
    	.EXAMPLE
    		PS C:\> Close-ScpSession -Session $value1
    #>
    
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [WinSCP.Session]
        $Session
    )
    
    begin
    {
        # Get arguments from pipeline
        $sessionValueFromPipeLine = $PSBoundParameters.ContainsKey('Session')
    }
    process
    {
        try
        {
            # Close session
            $Session.Dispose()
            
            return $true
        }
        catch
        {
            # Save exception
            [string]$reportedException = $Error[0].Exception.Message
            
            Write-Verbose -Message "Reported exeption: $reportedException"
            
            return $false
        }
    }
}

function Start-WinScpConsole
{
<#
	.SYNOPSIS
		Cmdlet will open WinSCP Console.
	
	.DESCRIPTION
		Cmdlet will invoke WinSCP console and will wait till the window is closed before terminating execution.
	
	.EXAMPLE
		PS C:\> Start-WinScpConsole
#>
    
    [OutputType([void])]
    param ()
    
    # Define WinSCP exe path
    [string]$exePath = "$PSScriptRoot\bin\WinSCP.exe"
    
    # Define exe arguments
    [string]$scpArgs = '/Console'
    
    # Launch WinSCP console
    $paramStartProcess = @{
        FilePath     = $exePath
        ArgumentList = $scpArgs
        Wait         = $true
    }
    
    Start-Process @paramStartProcess
}

function Test-ScpSession
{
    <#
    	.SYNOPSIS
    		Test if a WinSCP.Session object is in oppen state.
    	
    	.DESCRIPTION
    		Helper function to test test if a WinSCP.Session object is in open state.
    	
    	.PARAMETER Session
    		A WinSCP.Session object for which status should be checked.
    	
    	.EXAMPLE
    		PS C:\> Test-ScpSession -Session $Session
    #>
    
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [Alias('SCpSession', 'WinScpSession')]
        [WinSCP.Session]
        $Session
    )
    
    if ($Session.Opened)
    {
        Write-Verbose -Message 'Session is open'
        
        return $true
    }
    else
    {
        Write-Verbose -Message 'Session is not open or session not found'
        
        return $false
    }
}

function Test-ScpPath
{
<#
	.SYNOPSIS
		Cmdlet will check if path on a remote WinSCP Session exists.
	
	.DESCRIPTION
		Cmdlet will check if path on a remote WinSCP Session exists.
	
	.PARAMETER Session
		A valid WinSCP.Session object. Requires connection to be in open state.
	
	.PARAMETER RemotePath
		A string representing path on the remote host.
	
	.EXAMPLE
		PS C:\> Test-ScpPath -Session $value1 -RemotePath $value2
#>
    
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [WinSCP.Session]
        $Session,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath
    )
    
    begin
    {
        # Check session state
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        # Sanitize input path
        $RemotePath = Format-StringPath -Path $RemotePath
        
        try
        {
            # Check if file exists
            $Session.FileExists($RemotePath)
        }
        catch
        {
            if ($PSBoundParameters.ContainsKey('Verbose'))
            {
                # Save exception message
                [string]$reportedException = $_.Exception.Message
                
                Write-Error -Message $reportedException
            }
            
            return $false
        }
    }
}

function Send-ScpItem
{
    <#
        .SYNOPSIS
            Cmdlet will upload one or more items to a remote host.
        
        .DESCRIPTION
            Cmdlet will upload one or more items to a remote host.
        
        .PARAMETER LocalPath
            A string representing the path on the local machine containing files/folders that will be uploaded to remote host.
        
        .PARAMETER TransferOptions
            A WinSCP.TransferOptions object containing transfer options that will be aplied to current session.
            
            Use New-ScpTrnasferOptions to initialize an object of the appropriate type.
            
            All transfer options can be applied at runtime via appropriate parameters.
        
        .PARAMETER SpeedLimit
            An integer representing the speed limit that will be applied when transferring data to the remote host.
        
        .PARAMETER FileMask
            Allows the use of wildcard mask to specify relevant file extensions/names.
        
        .PARAMETER Permissions
            An int between 0 and 777 representing permissions that will be applied to uploaded files.
            
            Default behavior is inheriting permissions from remote host folder.
            
            Permissions are in UNIX octal format for example 400 or 440
        
        .PARAMETER OverWriteMode
            By default if a file with the same name exists on the remote host it will be overwritten.
            
            Possible values are:
            
            - Overwrite
            - Resume
            - Append
        
        .PARAMETER PreserveTimeStamp
            By default timestamp of uploaded files is retained, paramter allows to change this behavior.
        
        .PARAMETER TransferMode
            Parameter allows to specify the type of transfer that will be used.
        
        .PARAMETER Session
            A valid WinSCP.Session object. Requires connection to be in open state.
        
        .PARAMETER RemotePath
            A string representing remote path where files/folders will be uploaded.
        
        .PARAMETER TransferFilesOnly
            By default cmdlet will copy the enter folder structure when a directory is specified. When parameter is used
            only files contained in the specified directory will be transferred to the remote host recursively.
        
        .EXAMPLE
            PS C:\> Send-ScpItem -Session $Session -RemotePath 'value2'
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'RuntimeTransferOptions',
                   SupportsShouldProcess = $true)]
    param
    (
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [Parameter(ParameterSetName = 'TransferOptionsObject',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $LocalPath,
        [Parameter(ParameterSetName = 'TransferOptionsObject')]
        [ValidateNotNullOrEmpty()]
        [WinSCP.TransferOptions]
        $TransferOptions,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [int]
        $SpeedLimit = 0,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [string]
        $FileMask,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, 777)]
        [int]
        $Permissions,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Overwrite', 'Resume', 'Append', IgnoreCase = $true)]
        [string]
        $OverWriteMode,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [bool]
        $PreserveTimeStamp = $True,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Automatic', 'Binary', 'Text', IgnoreCase = $true)]
        [string]
        $TransferMode = 'Automatic',
        [Parameter(ParameterSetName = 'RuntimeTransferOptions',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'TransferOptionsObject')]
        [WinSCP.Session]
        $Session,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'TransferOptionsObject')]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,
        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [Parameter(ParameterSetName = 'TransferOptionsObject')]
        [switch]
        $TransferFilesOnly
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        switch ($PsCmdlet.ParameterSetName)
        {
            'TransferOptionsObject'
            {
                $TransferOptions = $TransferOptions
                
                break
            }
            'RuntimeTransferOptions'
            {
                # Create new object
                $TransferOptions = New-Object -TypeName 'WinSCP.TransferOptions'
                
                switch ($PSBoundParameters.Keys)
                {
                    'SpeedLimit'
                    {
                        # Set specified speed limit
                        $TransferOptions.'SpeedLimit' = $SpeedLimit
                        
                        break
                    }
                    'PreserveTimeStamp'
                    {
                        # Preserve file TimeStamp
                        $TransferOptions.'PreserveTimestamp' = $PreserveTimeStamp
                        
                        break
                    }
                    'OverWriteMode'
                    {
                        # Overwrite destination if exists
                        $TransferOptions.'OverWriteMode' = $OverWriteMode
                        
                        break
                    }
                    'Permissions'
                    {
                        # Set UNIX style permissions
                        $TransferOptions.'FilePermissions'.'Octal' = $Permissions
                        
                        break
                    }
                    'FileMask'
                    {
                        # Set specified filemask
                        $TransferOptions.'FileMask' = $FileMask
                        
                        break
                    }
                }
            }
        }
        
        # Validate local paths
        foreach ($item in $LocalPath)
        {
            if (!(Test-Path $item))
            {
                Write-Warning -Message "Cannot find path $item because it does not exist"
                
                continue
            }
            else
            {
                if ($isValidPath -eq $false)
                {
                    New-ScpDirectory -Session $session -RemotePath
                }
                
                if ($RemotePath.EndsWith('/') -eq $false)
                {
                    # Check if destination path exists
                    [bool]$isValidPath = Test-ScpPath -Session $session -RemotePath $RemotePath
                    
                    if ($isValidPath -eq $true)
                    {
                        # Check if path is a directory
                        $paramGetScpItemType = @{
                            RemotePath = $RemotePath
                            Session    = $Session
                        }
                        
                        # Check if we should sanitize input string
                        [bool]$isDirectory = (Get-ScpItemType @paramGetScpItemType).'IsDirectory'
                        
                        if ($isDirectory -eq $true)
                        {
                            # Append trailing character
                            $RemotePath = '{0}{1}' -f $RemotePath, '/'
                        }
                    }
                    else
                    {
                        if ($RemotePath.EndsWith('/') -eq $false)
                        {
                            # Append trailing character
                            $RemotePath = '{0}{1}' -f $RemotePath, '/'
                        }
                        
                        # Format path for WinSCP
                        $RemotePath = Format-StringPath -Path $RemotePath
                        
                        # Create remote directory
                        $paramNewScpDirectory = @{
                            Session        = $session
                            RemotePath     = $RemotePath
                            SuppressOutput = $true
                        }
                        
                        New-ScpDirectory @paramNewScpDirectory
                    }
                }
                
                try
                {
                    # Format path for WinSCP
                    $RemotePath = Format-StringPath -Path $RemotePath
                    
                    if ($PSBoundParameters.ContainsKey('TransferFilesOnly'))
                    {
                        # Get local item type
                        [bool]$isDirectory = (Get-Item -Path $item).'PSIsContainer'
                        
                        if ($isDirectory)
                        {
                            # Get all files in the tree
                            [array]$filesToTransfer = Get-ChildItem -Path $item -Recurse
                            
                            foreach ($file in $filesToTransfer)
                            {
                                # Run upload and store job status
                                $jobStatus = $Session.PutFiles($file.FullName, $RemotePath, $OverWriteMode, $TransferOptions)
                                
                                if ($jobStatus.IsSuccess)
                                {
                                    Write-Output -InputObject $jobStatus
                                }
                                else
                                {
                                    Write-Error -Message $jobStatus.Failures[0]
                                }
                            }
                        }
                        else
                        {
                            # Run upload and store job status
                            $jobStatus = $Session.PutFiles($file, $RemotePath, $OverWriteMode, $TransferOptions)
                            
                            if ($jobStatus.IsSuccess)
                            {
                                Write-Output -InputObject $jobStatus
                            }
                            else
                            {
                                Write-Error -Message $jobStatus.Failures[0]
                            }
                        }
                    }
                }
                catch
                {
                    Write-Error -Message $Error.Exception.Message
                }
            }
        }
    }
}

function Test-ScpPath
{
    <#
        .SYNOPSIS
            Cmdlet will check if a specified path/file exists on the remote host.
        
        .DESCRIPTION
            Cmdlet will check if a specified path/file exists on the remote host.
        
        .PARAMETER Session
            A valid WinSCP.Session object. Requires connection to be in open state.
        
        .PARAMETER RemotePath
            A string representing a valid path on the remote host.
        
        .EXAMPLE
            PS C:\> Test-ScpPath -Session $Session -RemotePath 'value2'
    #>
    
    [CmdletBinding(ConfirmImpact = 'High',
                   SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [WinSCP.Session]
        $Session,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        return $session.FileExists($RemotePath)
    }
}

function Get-ScpItemType
{
    <#
        .SYNOPSIS
            Cmdlet will return SCP path properties.
        
        .DESCRIPTION
            Cmdlet will return detailed information about items in the specified remote path.
            
        .PARAMETER Session
            A description of the Session parameter.
        
        .PARAMETER RemotePath
            A description of the RemotePath parameter.
        
        .PARAMETER Filter
            A description of the Filter parameter.
        
        .EXAMPLE
            PS C:\> Get-ScpItemType -Session $value1 -RemotePath 'Value2'
    #>
    
    param
    (
        [Parameter(Mandatory = $true)]
        [WinSCP.Session]
        $Session,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,
        [AllowNull()]
        [string]
        $Filter
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        return $session.GetFileInfo($RemotePath)
    }
}

function New-ScpDirectory
{
    <#
        .SYNOPSIS
            Cmdlet will create a new directory on the remote host in the specified path.
        
        .DESCRIPTION
            Cmdlet will create a new directory on the remote host in the specified path if the specified directory exists no action will be taken.
        
        .PARAMETER Session
            A valid WinSCP.Session object. Requires connection to be in open state.
        
        .PARAMETER RemotePath
            A string representing the full path underneath which the directory will be created.
        
        .PARAMETER SuppressOutput
            When parameter is specified any error output will be suppressed.
        
        .EXAMPLE
            PS C:\> New-ScpDirectory -Session $Session -RemotePath 'value2'
    #>
    
    param
    (
        [Parameter(Mandatory = $true)]
        [WinSCP.Session]
        $Session,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,
        [switch]
        $SuppressOutput
    )
    
    begin
    {
        if (Test-ScpSession -Session $Session)
        {
            Write-Verbose -Message 'Session is in open state we can continue'
        }
        else
        {
            throw 'The WinSCP Session is not in an open state'
        }
    }
    
    process
    {
        # Check if path already exists
        if (Test-ScpPath -Session $Session -RemotePath $RemotePath)
        {
            Write-Warning -Message "Directory $RemotePath already exists on remote host - No action will be taken"
            
            return
        }
        else
        {
            try
            {
                # Create directory
                $Session.CreateDirectory($RemotePath)
                
                Write-Verbose -Message 'Directory correctly created'
                
                return $true
            }
            catch
            {
                
                if ($PSBoundParameters.ContainsKey('SuppressOutput'))
                {
                    return $false
                }
                
                Write-Error -Message $Error.Exception.Message
                
                return $false
            }
        }
    }
}