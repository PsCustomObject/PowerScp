# Load the build appropriate to the PowerShell runtime before resolving WinSCP types.
$assemblyPath = Join-Path $PSScriptRoot 'lib/WinSCPnet.dll'
if ($PSEdition -eq 'Core') {
    $assemblyPath = Join-Path $PSScriptRoot 'lib/netstandard2.0/WinSCPnet.dll'
}
if (!(Test-Path -LiteralPath $assemblyPath)) { throw "Missing WinSCP assembly: $assemblyPath. See README.md for dependency setup." }
Add-Type -Path $assemblyPath -ErrorAction Stop

function Assert-ScpPlatform {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'WinSCP transfers require Windows. PowerShell 7 is supported on Windows.'
    }
}
function Assert-ScpSession {
    param($Session)
    if ($null -eq $Session -or !$Session.Opened) { throw 'The WinSCP Session is not in an open state' }
}
$script:ScpSessions = @{}
# Release resources when Remove-Module or Import-Module -Force unloads this instance.
$ExecutionContext.SessionState.Module.OnRemove = {
    foreach ($session in @($script:ScpSessions.Values)) {
        try { $session.Dispose() } catch { Write-Warning "Could not dispose a tracked WinSCP session: $_" }
    }
    $script:ScpSessions.Clear()
}

function Format-StringPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, ValueFromPipeline)][string[]]$Path)
    process { foreach ($item in $Path) { $item.Replace('\', '/') } }
}
function New-ScpSessionObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding()]
    param([string]$SessionLogPath, [string]$DebugLogPath, [int]$DebugLevel = 0,
          [timespan]$ReconnectTime = [timespan]::FromSeconds(120))
    Assert-ScpPlatform
    $session = New-Object WinSCP.Session
    $session.ExecutablePath = Join-Path $PSScriptRoot 'bin/WinSCP.exe'
    $session.ReconnectTime = $ReconnectTime
    $session.DebugLogLevel = $DebugLevel
    if ($SessionLogPath) { $session.SessionLogPath = $SessionLogPath }
    if ($DebugLogPath) { $session.DebugLogPath = $DebugLogPath }
    $session
}
function New-ScpSessionOptions {
    <# .SYNOPSIS
    Build reusable connection options without opening a connection.
    .DESCRIPTION
    Credentials are a username/password for most protocols or an access key/secret
    for S3. S3 uses TLS by default. SessionUrl accepts WinSCP session URLs; avoid
    embedding passwords in URLs. Explicit parameters override parsed URL settings.
    .PARAMETER S3CredentialsFromEnvironment
    Let WinSCP read AWS environment variables or its supported AWS credential files.
    .PARAMETER Scan
    Build options for fingerprint scanning without requiring a trusted SSH key.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification='Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Established public API mirrors the WinSCP SessionOptions and TransferOptions type names.')]
    [CmdletBinding()]
    [OutputType([WinSCP.SessionOptions])]
    param(
        [Alias('Host','HostName')][string]$RemoteHost,
        [string]$UserName, [AllowEmptyString()][string]$UserPassword,
        [Alias('Credential')][pscredential]$Credentials,
        [WinSCP.Protocol]$Protocol = 'Scp',
        [Alias('Port','PortNumber')][ValidateRange(0,65535)][int]$ServerPort = 0,
        [Alias('Timeout')][timespan]$ConnectionTimeOut = [timespan]::FromSeconds(15),
        [switch]$NoSshKeyCheck, [switch]$NoTlsCheck, [string[]]$SshHostKeyFingerprint,
        [WinSCP.SshHostKeyPolicy]$SshHostKeyPolicy = 'Check',
        [Alias('SshPrivateKeyPath')][string]$SshKeyPath, [string]$SshKeyPassword,
        [securestring]$SecurePrivateKeyPassphrase, [switch]$NoSSHKeyPassword,
        [WinSCP.FtpMode]$FtpMode = 'Passive', [WinSCP.FtpSecure]$FtpSecure = 'None',
        [switch]$WebDavSecure, [Alias('RootPath')][string]$WebDavRoot,
        [bool]$Secure, [string]$TlsHostCertificateFingerprint,
        [string]$TlsClientCertificatePath, [hashtable]$RawSettings,
        [string]$SessionUrl, [switch]$Scan,
        [ValidateNotNullOrEmpty()][string]$S3Bucket,
        [ValidateNotNullOrEmpty()][string]$S3Region,
        [securestring]$S3SessionToken,
        [ValidateSet('VirtualHost','Path')][string]$S3UrlStyle,
        [switch]$S3CredentialsFromEnvironment, [string]$S3Profile
    )
    if ($Credentials -and ($PSBoundParameters.ContainsKey('UserName') -or $PSBoundParameters.ContainsKey('UserPassword'))) {
        throw 'Use Credentials or UserName/UserPassword, not both.'
    }
    if ($SshKeyPassword -and $SecurePrivateKeyPassphrase) { throw 'Use one private-key passphrase parameter.' }
    if ($ConnectionTimeOut -le [timespan]::Zero) { throw 'ConnectionTimeOut must be positive.' }
    $options = New-Object WinSCP.SessionOptions
    if ($SessionUrl) { $options.ParseUrl($SessionUrl) }
    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('Protocol')) { $options.Protocol = $Protocol }
    # Set protocol before hostname: the assembly supplies the AWS endpoint for S3.
    if ($RemoteHost) { $options.HostName = $RemoteHost }
    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('ServerPort')) { $options.PortNumber = $ServerPort }
    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('ConnectionTimeOut')) { $options.Timeout = $ConnectionTimeOut }
    if ($Credentials) { $options.UserName = $Credentials.UserName; $options.SecurePassword = $Credentials.Password }
    else {
        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('UserName')) { $options.UserName = $UserName }
        if ($PSBoundParameters.ContainsKey('UserPassword')) { $options.Password = $UserPassword }
    }
    if ($PSBoundParameters.ContainsKey('SshHostKeyPolicy')) { $options.SshHostKeyPolicy = $SshHostKeyPolicy }
    if ($NoSshKeyCheck) {
        if ($PSBoundParameters.ContainsKey('SshHostKeyPolicy') -and $SshHostKeyPolicy -ne 'GiveUpSecurityAndAcceptAny') {
            throw 'NoSshKeyCheck conflicts with SshHostKeyPolicy.'
        }
        $options.SshHostKeyPolicy = 'GiveUpSecurityAndAcceptAny'
    }
    elseif ($PSBoundParameters.ContainsKey('NoSshKeyCheck')) { $options.SshHostKeyPolicy = 'Check' }
    if ($PSBoundParameters.ContainsKey('NoTlsCheck')) { $options.GiveUpSecurityAndAcceptAnyTlsHostCertificate = [bool]$NoTlsCheck }
    if ($SshHostKeyFingerprint) { $options.SshHostKeyFingerprint = $SshHostKeyFingerprint -join ';' }
    if (!$Scan -and $options.Protocol -in @('Scp','Sftp') -and $options.SshHostKeyPolicy -eq 'Check' -and !$options.SshHostKeyFingerprint) {
        throw 'Specify SshHostKeyFingerprint or choose an explicit SshHostKeyPolicy.'
    }
    if ($SshKeyPassword -and !$SshKeyPath) { throw 'SshKeyPassword requires SshKeyPath.' }
    if ($SshKeyPath) { $options.SshPrivateKeyPath = (Resolve-Path -LiteralPath $SshKeyPath -ErrorAction Stop).ProviderPath }
    if ($SshKeyPassword) { $options.PrivateKeyPassphrase = $SshKeyPassword }
    if ($SecurePrivateKeyPassphrase) { $options.SecurePrivateKeyPassphrase = $SecurePrivateKeyPassphrase }
    if ($TlsClientCertificatePath) { $options.TlsClientCertificatePath = (Resolve-Path -LiteralPath $TlsClientCertificatePath -ErrorAction Stop).ProviderPath }
    if ($TlsHostCertificateFingerprint) { $options.TlsHostCertificateFingerprint = $TlsHostCertificateFingerprint }
    if (($PSBoundParameters.ContainsKey('FtpMode') -or $PSBoundParameters.ContainsKey('FtpSecure')) -and $options.Protocol -ne 'Ftp') {
        throw 'FtpMode and FtpSecure require Protocol Ftp.'
    }
    if ($options.Protocol -eq 'Ftp') {
        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('FtpMode')) { $options.FtpMode = $FtpMode }
        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('FtpSecure')) { $options.FtpSecure = $FtpSecure }
    }
    if ($WebDavSecure -and $options.Protocol -ne 'Webdav') { throw 'WebDavSecure requires Protocol Webdav.' }
    if (($WebDavRoot -or $PSBoundParameters.ContainsKey('Secure')) -and $options.Protocol -notin @('Webdav','S3')) {
        throw 'RootPath and Secure require Protocol Webdav or S3.'
    }
    if ($PSBoundParameters.ContainsKey('Secure')) { $options.Secure = $Secure }
    elseif ($PSBoundParameters.ContainsKey('WebDavSecure')) { $options.Secure = [bool]$WebDavSecure }
    elseif ($options.Protocol -eq 'S3' -and (!$SessionUrl -or $PSBoundParameters.ContainsKey('Protocol'))) { $options.Secure = $true }
    if ($WebDavSecure -and $PSBoundParameters.ContainsKey('Secure') -and !$Secure) { throw 'WebDavSecure conflicts with Secure false.' }
    if ($WebDavRoot) { $options.RootPath = Format-StringPath $WebDavRoot }
    $settings = @{}
    foreach ($key in $RawSettings.Keys) { $settings[$key] = [string]$RawSettings[$key] }
    $s3Parameters = @('S3Bucket','S3Region','S3SessionToken','S3UrlStyle','S3CredentialsFromEnvironment','S3Profile')
    if (@($PSBoundParameters.Keys | Where-Object { $_ -in $s3Parameters }).Count -and $options.Protocol -ne 'S3') {
        throw 'S3 settings require Protocol S3.'
    }
    if ($S3Bucket) {
        if ($S3Bucket -match '[/\\]') { throw 'S3Bucket must be a bucket name, without a path.' }
        if ($WebDavRoot) { throw 'Use S3Bucket or RootPath, not both.' }
        $options.RootPath = '/' + $S3Bucket
    }
    if ($S3Region) { $settings['S3DefaultRegion'] = $S3Region }
    if ($S3UrlStyle) { $settings['S3UrlStyle'] = [string][int]($S3UrlStyle -eq 'Path') }
    if ($S3Profile) {
        if ($PSBoundParameters.ContainsKey('S3CredentialsFromEnvironment') -and !$S3CredentialsFromEnvironment) { throw 'S3Profile requires environment credential lookup.' }
        $S3CredentialsFromEnvironment = $true
        $settings['S3Profile'] = $S3Profile
    }
    if ($S3CredentialsFromEnvironment -and ($Credentials -or $options.UserName -or $options.Password)) {
        throw 'Use AWS environment/profile credentials or explicit access keys, not both.'
    }
    if ($PSBoundParameters.ContainsKey('S3CredentialsFromEnvironment') -or $S3Profile) {
        $settings['S3CredentialsEnv'] = [string][int][bool]$S3CredentialsFromEnvironment
    }
    if ($S3SessionToken) {
        # WinSCP raw settings require a string. Clear the temporary plaintext copy afterwards.
        $token = [System.Net.NetworkCredential]::new('', $S3SessionToken).Password
        try { $options.AddRawSettings('S3SessionToken', $token) } finally { $token = $null }
        $settings.Remove('S3SessionToken')
    }
    foreach ($key in $settings.Keys) { $options.AddRawSettings([string]$key, $settings[$key]) }
    $options
}
function Get-HostFingerPrint {
    <# .SYNOPSIS
    Scan a fingerprint; verify it independently before trusting it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification='Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [CmdletBinding(DefaultParameterSetName='Connection')]
    param(
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Options')][WinSCP.SessionOptions]$SessionOptions,
        [Parameter(Mandatory,ParameterSetName='Connection')][Alias('Host','Server','RemoteServer')][string]$RemoteHost,
        [Parameter(ParameterSetName='Connection')][string]$UserName,
        [Parameter(ParameterSetName='Connection')][Alias('UserPassword')][string]$Password,
        [Parameter(ParameterSetName='Connection')][pscredential]$Credentials,
        [Parameter(ParameterSetName='Connection')][ValidateRange(0,65535)][int]$PortNumber=0,
        [Parameter(ParameterSetName='Connection')][timespan]$ConnectionTimeOut=[timespan]::FromSeconds(15),
        [ValidateSet('SHA-256','MD5')][string]$Algorithm='SHA-256',
        [Parameter(ParameterSetName='Connection')][WinSCP.Protocol]$Protocol='Scp',
        [Parameter(ParameterSetName='Connection')][WinSCP.FtpSecure]$FtpSecure='None',
        [Parameter(ParameterSetName='Connection')][switch]$WebDavSecure
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Options') { $options = $SessionOptions }
        else {
            $arguments = @{ RemoteHost=$RemoteHost; ServerPort=$PortNumber; Protocol=$Protocol; ConnectionTimeOut=$ConnectionTimeOut; Scan=$true }
            if ($Credentials) { $arguments.Credentials=$Credentials }
            else {
                if ($UserName) { $arguments.UserName=$UserName }
                if ($PSBoundParameters.ContainsKey('Password')) { $arguments.UserPassword=$Password }
            }
            foreach ($key in @('FtpSecure','WebDavSecure')) { if ($PSBoundParameters.ContainsKey($key)) { $arguments[$key]=$PSBoundParameters[$key] } }
            $options = New-ScpSessionOptions @arguments
        }
        $session = New-ScpSessionObject
        try { $session.ScanFingerprint($options,$Algorithm) } finally { $session.Dispose() }
    }
}
function New-ScpSession {
    <# .SYNOPSIS
    Open a session from connection parameters or reusable SessionOptions.
    .PARAMETER Name
    Optional name for retrieving this session with Get-ScpSession. Names must be unique.
    .DESCRIPTION
    Opens and registers a connection. Windows is required. Use verified fingerprints
    for SSH connections and dispose sessions in a finally block. Module removal
    also disposes tracked sessions. WhatIf builds options without opening a connection.
    .EXAMPLE
    $session = New-ScpSession -RemoteHost sftp.example.org -Protocol Sftp -Credentials (Get-Credential) -SshHostKeyFingerprint $verifiedFingerprint
    Opens an SFTP connection using a fingerprint verified with the server administrator.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification='Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='Connection')]
    [OutputType([WinSCP.Session])]
    param(
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Options')]
        [Alias('SessionOption')][WinSCP.SessionOptions]$SessionOptions,
        [Parameter(ParameterSetName='Connection')][Alias('Host','HostName')][string]$RemoteHost,
        [Parameter(ParameterSetName='Connection')][string]$UserName,
        [Parameter(ParameterSetName='Connection')][AllowEmptyString()][string]$UserPassword,
        [Parameter(ParameterSetName='Connection')][Alias('Credential')][pscredential]$Credentials,
        [Parameter(ParameterSetName='Connection')][Alias('ConnectionProtocol')][WinSCP.Protocol]$Protocol='Scp',
        [Parameter(ParameterSetName='Connection')][Alias('Port','RemoteHostPort')][ValidateRange(0,65535)][int]$ServerPort=0,
        [Parameter(ParameterSetName='Connection')][timespan]$ConnectionTimeOut=[timespan]::FromSeconds(15),
        [Parameter(ParameterSetName='Connection')][Alias('GiveUpSecurityAndAcceptAnySshHostKey','AnySshKey','SshCheck','AcceptAnySshKey')][switch]$NoSshKeyCheck,
        [Parameter(ParameterSetName='Connection')][Alias('GiveUpSecurityAndAcceptAnyTlsHostCertificate','AnyTlsCertificte','AcceptAnyCertificate')][switch]$NoTlsCheck,
        [Parameter(ParameterSetName='Connection')][string[]]$SshHostKeyFingerprint,
        [Parameter(ParameterSetName='Connection')][WinSCP.SshHostKeyPolicy]$SshHostKeyPolicy='Check',
        [Parameter(ParameterSetName='Connection')][Alias('SshPrivateKey','SshPrivateKeyPath','SsheKeyPath')][string]$SshKeyPath,
        [Parameter(ParameterSetName='Connection')][string]$SshKeyPassword,
        [Parameter(ParameterSetName='Connection')][securestring]$SecurePrivateKeyPassphrase,
        [Parameter(ParameterSetName='Connection')][switch]$NoSSHKeyPassword,
        [Parameter(ParameterSetName='Connection')][WinSCP.FtpMode]$FtpMode='Passive',
        [Parameter(ParameterSetName='Connection')][Alias('FtpSecureMode','SecureFtpMode')][WinSCP.FtpSecure]$FtpSecure='None',
        [Parameter(ParameterSetName='Connection')][switch]$WebDavSecure,
        [Parameter(ParameterSetName='Connection')][Alias('RootPath')][string]$WebDavRoot,
        [Parameter(ParameterSetName='Connection')][bool]$Secure,
        [Parameter(ParameterSetName='Connection')][string]$TlsHostCertificateFingerprint,
        [Parameter(ParameterSetName='Connection')][string]$TlsClientCertificatePath,
        [Parameter(ParameterSetName='Connection')][hashtable]$RawSettings,
        [Parameter(ParameterSetName='Connection')][string]$SessionUrl,
        [Parameter(ParameterSetName='Connection')][string]$S3Bucket,
        [Parameter(ParameterSetName='Connection')][string]$S3Region,
        [Parameter(ParameterSetName='Connection')][securestring]$S3SessionToken,
        [Parameter(ParameterSetName='Connection')][ValidateSet('VirtualHost','Path')][string]$S3UrlStyle,
        [Parameter(ParameterSetName='Connection')][switch]$S3CredentialsFromEnvironment,
        [Parameter(ParameterSetName='Connection')][string]$S3Profile,
        [string]$Name,
        [string]$SessionLogPath, [string]$DebugLogPath,
        [Alias('DebugLogLevel')][ValidateRange(-1,2)][int]$DebugLevel=0,
        [timespan]$ReconnectTime=[timespan]::FromSeconds(120),
        [string]$XmlLogPath, [switch]$XmlLogPreserve, [hashtable]$RawConfiguration
    )
    process {
        if ($Name -and $script:ScpSessions.ContainsKey($Name)) { throw "A session named '$Name' already exists. Remove it first." }
        if ($PSCmdlet.ParameterSetName -eq 'Options') { $options = $SessionOptions }
        else {
            $arguments = @{}
            $optionParameters = (Get-Command New-ScpSessionOptions).Parameters.Keys
            foreach ($key in $PSBoundParameters.Keys) {
                if ($key -in $optionParameters -and $key -notin @('WhatIf','Confirm','Verbose','Debug','ErrorAction','WarningAction','InformationAction','ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer','PipelineVariable','ProgressAction')) {
                    $arguments[$key] = $PSBoundParameters[$key]
                }
            }
            $options = New-ScpSessionOptions @arguments
        }
        if (!$options.HostName) { throw 'RemoteHost is required except when Protocol S3 supplies the AWS endpoint.' }
        if ($PSCmdlet.ShouldProcess($options.HostName,'Open WinSCP session')) {
            $sessionObject = New-ScpSessionObject -SessionLogPath $SessionLogPath -DebugLogPath $DebugLogPath -DebugLevel $DebugLevel -ReconnectTime $ReconnectTime
            try {
                if ($XmlLogPath) { $sessionObject.XmlLogPath = $XmlLogPath }
                $sessionObject.XmlLogPreserve = [bool]$XmlLogPreserve
                foreach ($key in $RawConfiguration.Keys) { $sessionObject.AddRawConfiguration([string]$key,[string]$RawConfiguration[$key]) }
                $sessionObject.Open($options)
                if (!$Name) { $sessionName = [guid]::NewGuid().ToString() } else { $sessionName = $Name }
                $sessionObject | Add-Member -NotePropertyName ScpSessionName -NotePropertyValue $sessionName -Force
                $sessionObject | Add-Member -NotePropertyName RemoteHost -NotePropertyValue $options.HostName -Force
                $script:ScpSessions[$sessionName] = $sessionObject
                $sessionObject
            }
            catch { $sessionObject.Dispose(); $PSCmdlet.ThrowTerminatingError($_) }
        }
    }
}

function Test-ScpSession {
    <# .SYNOPSIS
    Return whether a WinSCP session is open.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory,ValueFromPipeline)][AllowNull()][WinSCP.Session]$Session)
    process { $null -ne $Session -and $Session.Opened }
}
function Remove-ScpSession {
    <# .SYNOPSIS
    Dispose a session; disposed sessions cannot be reused.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session)
    process { if ($PSCmdlet.ShouldProcess('WinSCP session','Dispose')) {
            $Session.Dispose()
            foreach ($key in @($script:ScpSessions.Keys)) {
                if ([object]::ReferenceEquals($script:ScpSessions[$key],$Session)) { $script:ScpSessions.Remove($key) }
            }
            $true
        } }
}
function Test-ScpPath {
    <# .SYNOPSIS
    Test existence of a literal remote file or directory.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) { $Session.FileExists((Format-StringPath $path)) }
    }
}
function Get-ScpItemType {
    <# .SYNOPSIS
    Return metadata for literal remote paths, optionally filtering their names.
    #>
    [CmdletBinding()]
    [OutputType([WinSCP.RemoteFileInfo])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [string]$Filter)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            $item = $Session.GetFileInfo((Format-StringPath $path))
            if (!$Filter -or $item.Name -like $Filter) { $item }
        }
    }
}
function Get-ScpChildItem {
    <# .SYNOPSIS
    List remote directory contents, with optional recursion and file filtering.
    .PARAMETER Depth
    Maximum subdirectory levels. Zero means unlimited when Recurse is set.
    #>
    [CmdletBinding()]
    [OutputType([WinSCP.RemoteFileInfo])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [ValidateNotNullOrEmpty()][string[]]$RemotePath=@('.'),
          [string]$Filter = '*', [switch]$Recurse,
          [ValidateRange(0,2147483647)][int]$Depth = 0, [Alias('File')][switch]$FilesOnly,
          [Alias('Directory')][switch]$DirectoriesOnly, [switch]$Name)
    process {
        Assert-ScpSession $Session
        if ($FilesOnly -and $DirectoriesOnly) { throw 'Use FilesOnly or DirectoriesOnly, not both.' }
        if ($Depth -gt 0 -and !$Recurse) { throw 'Depth requires Recurse.' }
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            $options = [WinSCP.EnumerationOptions]::None
            if ($Recurse) { $options = $options -bor [WinSCP.EnumerationOptions]::AllDirectories }
            if (!$FilesOnly) { $options = $options -bor [WinSCP.EnumerationOptions]::MatchDirectories }
            if ($Recurse -and $Depth -gt 0) { $root = $Session.GetFileInfo($path).FullName.TrimEnd('/') + '/' }
            foreach ($item in $Session.EnumerateRemoteFiles($path, $Filter, $options)) {
                if ($FilesOnly -and $item.IsDirectory) { continue }
                if ($DirectoriesOnly -and !$item.IsDirectory) { continue }
                if ($Recurse -and $Depth -gt 0) {
                    $relative = $item.FullName.Substring($root.Length)
                    if (($relative.Trim('/').Split('/').Length - 1) -gt $Depth) { continue }
                }
                if ($Name) { $item.Name } else { $item }
            }
        }
    }
}
function Get-ScpItem {
    <# .SYNOPSIS
    List remote items. Retains the legacy enumeration behavior of Get-ScpItem.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [string[]]$RemotePath=@('.'), [string]$Filter='*',
          [switch]$Recurse, [ValidateRange(0,2147483647)][int]$Depth=0, [switch]$FilesOnly, [switch]$DirectoriesOnly, [switch]$Name, [switch]$LiteralPath)
    process {
        if ($LiteralPath) {
            if ($Recurse -or $Depth -or $FilesOnly -or $DirectoriesOnly -or $Name) { throw 'LiteralPath metadata lookup cannot be combined with listing switches.' }
            Get-ScpItemType -Session $Session -RemotePath $RemotePath -Filter $Filter
        } else {
            $arguments = @{}
            foreach ($key in $PSBoundParameters.Keys) { if ($key -ne 'LiteralPath') { $arguments[$key]=$PSBoundParameters[$key] } }
            $arguments.Session=$Session
            Get-ScpChildItem @arguments
        }
    }
}
function Get-ScpItemCheckSum {
    <# .SYNOPSIS
    Calculate a remote file checksum using a server-supported algorithm.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][Alias('RemotePath')][ValidateNotNullOrEmpty()][string[]]$ItemName,
          [ValidateSet('md2','md5','sha-1','sha-224','sha-256','sha-384','sha-512','shake128','shake256')][string]$HashAlgorithm='sha-256')
    process {
        Assert-ScpSession $Session
        foreach ($path in $ItemName) { $Session.CalculateFileChecksum($HashAlgorithm,(Format-StringPath $path)) }
    }
}
function New-ScpTransferOptions {
    <# .SYNOPSIS
    Construct reusable WinSCP transfer options.
    .PARAMETER Permissions
    Unix octal permissions, such as 644, 755 or 0755. Each digit must be 0 through 7.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Established public API mirrors the WinSCP SessionOptions and TransferOptions type names.')]
    [CmdletBinding()]
    [OutputType([WinSCP.TransferOptions])]
    param([ValidateRange(0,2147483647)][int]$SpeedLimit=0, [string]$FileMask,
          [ValidatePattern('^[0-7]{3,4}$')][string]$Permissions,
          [ValidateSet('Overwrite','Resume','Append')][string]$OverWriteMode='Overwrite',
          [bool]$PreserveTimeStamp=$true,
          [ValidateSet('Automatic','Binary','Ascii','Text')][string]$TransferMode='Binary',
          [hashtable]$RawSettings,
          [WinSCP.FilePermissions]$FilePermissions,
          [WinSCP.TransferResumeSupport]$ResumeSupport)
    if ($FilePermissions -and $PSBoundParameters.ContainsKey('Permissions')) { throw 'Use Permissions or FilePermissions, not both.' }
    $options = New-Object WinSCP.TransferOptions
    $options.SpeedLimit = $SpeedLimit
    $options.FileMask = $FileMask
    $options.OverwriteMode = $OverWriteMode
    $options.PreserveTimestamp = $PreserveTimeStamp
    if ($TransferMode -eq 'Text') { $TransferMode = 'Ascii' }
    $options.TransferMode = $TransferMode
    if ($PSBoundParameters.ContainsKey('Permissions')) {
        $options.FilePermissions = New-Object WinSCP.FilePermissions
        $options.FilePermissions.Octal = $Permissions
    }
    if ($FilePermissions) { $options.FilePermissions = $FilePermissions }
    if ($ResumeSupport) { $options.ResumeSupport = $ResumeSupport }
    foreach ($key in $RawSettings.Keys) { $options.AddRawSettings([string]$key,[string]$RawSettings[$key]) }
    $options
}
function Resolve-ScpTransferOption {
    param([System.Collections.IDictionary]$Parameters)
    if (($Parameters.Keys -contains 'TransferOptions')) { return $Parameters['TransferOptions'] }
    $arguments = @{}
    foreach ($key in @('SpeedLimit','FileMask','Permissions','OverWriteMode','PreserveTimeStamp','TransferMode')) {
        if (($Parameters.Keys -contains $key)) { $arguments[$key] = $Parameters[$key] }
    }
    New-ScpTransferOptions @arguments
}
function New-ScpDirectory {
    <# .SYNOPSIS
    Create remote directories. Force creates missing parents.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [switch]$Force, [switch]$SuppressOutput)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            try {
                if ($Session.FileExists($path)) {
                    if (!$Session.GetFileInfo($path).IsDirectory) { throw "Remote path is a file: $path" }
                    if (!$SuppressOutput) { $true }
                    continue
                }
                if ($PSCmdlet.ShouldProcess($path,'Create remote directory')) {
                    if ($Force) {
                        $parent = [WinSCP.RemotePath]::GetDirectoryName($path.TrimEnd('/'))
                        if ($parent -and $parent -ne $path -and !$Session.FileExists($parent)) {
                            New-ScpDirectory -Session $Session -RemotePath $parent -Force -SuppressOutput -ErrorAction Stop
                        }
                    }
                    $Session.CreateDirectory($path)
                    if (!$SuppressOutput) { $true }
                }
            } catch { $PSCmdlet.WriteError($_) }
        }
    }
}
function Send-ScpItem {
    <# .SYNOPSIS
    Upload literal local files or directories to a remote destination directory.
    .PARAMETER TransferFilesOnly
    Flatten all files from a local directory tree into the destination. Duplicate names are rejected.
    .PARAMETER Remove
    Delete local source files after a successful transfer. Disabled by default.
    .DESCRIPTION
    Local paths are literal. RemotePath is a directory; missing parents are created.
    Source removal is opt-in. Failed operations terminate. WhatIf prevents both
    transfer and remote directory creation. TransferFilesOnly flattens directory
    trees and rejects duplicate names before transferring.
    .PARAMETER DestinationFileName
    Renames a single local file during upload. Supply the destination directory
    separately through RemotePath. Cannot be combined with TransferFilesOnly.
    .EXAMPLE
    Send-ScpItem -Session $session -LocalPath './report[1].csv' -RemotePath '/incoming' -WhatIf
    Previews an upload without interpreting brackets as a local wildcard.
    .EXAMPLE
    Send-ScpItem -Session $session -LocalPath './report.csv' -RemotePath '/incoming' -DestinationFileName 'ready.csv'
    Uploads one file under a new remote name, retaining the local source.
    #>
    [CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='RuntimeTransferOptions')]
    [OutputType([WinSCP.TransferOperationResult])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$LocalPath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
        [Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
        [Parameter(Mandatory,ParameterSetName='TransferOptionsObject')][ValidateNotNull()][WinSCP.TransferOptions]$TransferOptions,
        [Parameter(ParameterSetName='RuntimeTransferOptions')][ValidateRange(0,2147483647)][int]$SpeedLimit=0,
        [Parameter(ParameterSetName='RuntimeTransferOptions')][string]$FileMask,
        [Parameter(ParameterSetName='RuntimeTransferOptions')][ValidatePattern('^[0-7]{3,4}$')][string]$Permissions,
        [Parameter(ParameterSetName='RuntimeTransferOptions')][ValidateSet('Overwrite','Resume','Append')][string]$OverWriteMode='Overwrite',
        [Parameter(ParameterSetName='RuntimeTransferOptions')][bool]$PreserveTimeStamp=$true,
        [Parameter(ParameterSetName='RuntimeTransferOptions')][ValidateSet('Automatic','Binary','Ascii','Text')][string]$TransferMode='Binary',
        [switch]$TransferFilesOnly, [switch]$Remove, [string]$DestinationFileName
    )
    process {
        Assert-ScpSession $Session
        $options = Resolve-ScpTransferOption $PSBoundParameters
        $destination = (Format-StringPath $RemotePath).TrimEnd('/') + '/'
        $sources = @(foreach ($path in $LocalPath) {
            $item = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($item.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must use the FileSystem provider.' }
            if ($TransferFilesOnly -and $item.PSIsContainer) { Get-ChildItem -LiteralPath $item.FullName -File -Recurse -ErrorAction Stop }
            else { $item }
        })
        if ($DestinationFileName) {
            Assert-ScpLeafName $DestinationFileName
            if ($TransferFilesOnly -or $sources.Count -ne 1 -or $sources[0].PSIsContainer) { throw 'DestinationFileName requires one local file without TransferFilesOnly.' }
            $target = [WinSCP.RemotePath]::EscapeOperationMask([WinSCP.RemotePath]::Combine($destination,$DestinationFileName))
        } else { $target = $destination }
        if ($TransferFilesOnly) {
            $duplicates = $sources | Group-Object Name | Where-Object Count -gt 1
            if ($duplicates) { throw 'TransferFilesOnly would overwrite duplicate filenames in the flattened destination.' }
        }
        foreach ($item in $sources) {
            $action = 'Upload'
            if ($Remove) { $action = 'Upload and remove local source' }
            if ($PSCmdlet.ShouldProcess("$($item.FullName) -> $target", $action)) {
                New-ScpDirectory -Session $Session -RemotePath $destination -Force -SuppressOutput -ErrorAction Stop
                $result = $Session.PutFiles([WinSCP.RemotePath]::EscapeFileMask($item.FullName),$target,[bool]$Remove,$options)
                $result.Check()
                $result
            }
        }
    }
}
function Receive-ScpItem {
    <# .SYNOPSIS
    Download remote file masks into an existing local directory.
    .PARAMETER Remove
    Remove remote sources after successful download. Disabled by default.
    .DESCRIPTION
    Remote paths are WinSCP masks unless LiteralPath is set. LocalPath must be an
    existing filesystem directory. Sources are retained unless Remove is set.
    .PARAMETER LiteralPath
    Escapes remote mask characters so a specific file or directory is selected.
    .PARAMETER DestinationFileName
    A valid Windows leaf filename. Requires one literal remote file, not a directory.
    .EXAMPLE
    Receive-ScpItem -Session $session -RemotePath '/outgoing/*.csv' -LocalPath './downloads'
    Downloads matching CSV files without removing remote sources.
    .EXAMPLE
    Receive-ScpItem -Session $session -RemotePath '/report[1].txt' -LiteralPath -LocalPath './downloads' -DestinationFileName 'saved.txt'
    Downloads a literal bracket filename under a new local name.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([WinSCP.TransferOperationResult])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LocalPath,
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions), [switch]$Remove,
          [switch]$LiteralPath, [string]$DestinationFileName)
    process {
        Assert-ScpSession $Session
        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop
        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must be an existing filesystem directory.' }
        $destination = $directory.FullName.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar
        if ($DestinationFileName) {
            if (!$LiteralPath -or $RemotePath.Count -ne 1) { throw 'DestinationFileName requires one literal remote file.' }
            Assert-ScpLeafName $DestinationFileName
            Assert-ScpLocalLeafName $DestinationFileName
            $destination = Join-Path $directory.FullName $DestinationFileName
        }
        foreach ($path in $RemotePath) {
            $source = Format-StringPath $path
            if ($DestinationFileName -and $Session.GetFileInfo($source).IsDirectory) {
                throw 'DestinationFileName requires a remote file, not a directory.'
            }
            if ($LiteralPath) { $source = [WinSCP.RemotePath]::EscapeFileMask($source) }
            $action = 'Download'
            if ($Remove) { $action = 'Download and remove remote source' }
            if ($PSCmdlet.ShouldProcess("$path -> $destination",$action)) {
                $result = $Session.GetFiles($source,$destination,[bool]$Remove,$TransferOptions)
                $result.Check()
                $result
            }
        }
    }
}
function Remove-ScpItem {
    <# .SYNOPSIS
    Remove remote files or directories. Paths are literal unless UseFileMask is set.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    [OutputType([WinSCP.RemovalOperationResult])]
    param([Parameter(Mandatory,ValueFromPipeline)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][WinSCP.Session]$Session, [switch]$UseFileMask)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            $mask = $path
            if (!$UseFileMask) { $mask = [WinSCP.RemotePath]::EscapeFileMask($path) }
            if ($PSCmdlet.ShouldProcess($path,'Remove remote item')) {
                $result = $Session.RemoveFiles($mask)
                $result.Check()
                $result
            }
        }
    }
}
function Move-ScpItem {
    <# .SYNOPSIS
    Move remote items; Force permits replacement of existing files and PassThru returns metadata.
    .DESCRIPTION
    An existing destination directory receives the source's original name. Multiple
    sources require an existing destination directory. Force replaces files only;
    the previous target is preserved for restoration if replacement fails. A partial
    target prevents automatic restoration; the error reports the retained backup.
    .EXAMPLE
    Move-ScpItem -Session $session -RemotePath '/incoming/report.csv' -Destination '/archive' -PassThru
    Moves a file into an existing archive directory and returns metadata.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Destination,
          [switch]$Force, [switch]$PassThru)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            if ($PSCmdlet.ShouldProcess("$path -> $Destination",'Move remote item')) {
                if ($RemotePath.Count -gt 1 -and (!$Session.FileExists($Destination) -or !$Session.GetFileInfo($Destination).IsDirectory)) {
                    throw 'Multiple source items require an existing destination directory.'
                }
                Invoke-ScpRelocation -Session $Session -RemotePath $path -Destination $Destination -Copy:$false -Force:$Force -PassThru:$PassThru
            }
        }
    }
}
function Copy-ScpItem {
    <# .SYNOPSIS
    Copy remote items; Force permits replacement of existing files and PassThru returns metadata.
    .DESCRIPTION
    Copies files on the server where the protocol/server supports it. Directories
    are not supported. Force preserves an existing target using a sibling backup
    before replacement; it requires server rename and delete permissions as well
    as copying support. Failed restoration reports the backup path for recovery.
    .EXAMPLE
    Copy-ScpItem -Session $session -RemotePath '/incoming/report.csv' -Destination '/archive/report.csv' -Force
    Replaces an archived file while preserving the old file until copying succeeds.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Destination,
          [switch]$Force, [switch]$PassThru)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            if ($PSCmdlet.ShouldProcess("$path -> $Destination",'Copy remote item')) {
                if ($RemotePath.Count -gt 1 -and (!$Session.FileExists($Destination) -or !$Session.GetFileInfo($Destination).IsDirectory)) {
                    throw 'Multiple source items require an existing destination directory.'
                }
                Invoke-ScpRelocation -Session $Session -RemotePath $path -Destination $Destination -Copy:$true -Force:$Force -PassThru:$PassThru
            }
        }
    }
}
function Invoke-ScpCommand {
    <# .SYNOPSIS
    Execute a command on a server supporting shell commands.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([WinSCP.CommandExecutionResult])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Command)
    process {
        Assert-ScpSession $Session
        foreach ($item in $Command) {
            if ($PSCmdlet.ShouldProcess($item,'Execute remote command')) {
                $result = $Session.ExecuteCommand($item)
                $result.Check()
                $result
            }
        }
    }
}
function Sync-ScpDirectory {
    <# .SYNOPSIS
    Synchronize local and remote directories. Removal requires the explicit Remove switch.
    .PARAMETER Mode
    Remote uploads changes; Local downloads changes; Both synchronizes in both directions.
    .DESCRIPTION
    LocalPath must exist. Remove and Mirror are invalid with Both. WhatIf describes
    the operation; use Compare-ScpDirectory to inspect individual planned changes.
    .EXAMPLE
    Sync-ScpDirectory -Session $session -LocalPath './data' -RemotePath '/data' -Mode Remote -WhatIf
    Previews an upload synchronization without transferring or deleting files.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([WinSCP.SynchronizationResult])]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LocalPath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [ValidateSet('Local','Remote','Both')][string]$Mode='Remote',
          [switch]$Remove, [switch]$Mirror,
          [WinSCP.SynchronizationCriteria]$Criteria=[WinSCP.SynchronizationCriteria]::Time,
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions))
    process {
        Assert-ScpSession $Session
        if ($Mode -eq 'Both' -and ($Remove -or $Mirror)) { throw 'Remove and Mirror cannot be used with Mode Both.' }
        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop
        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must be an existing filesystem directory.' }
        if ($PSCmdlet.ShouldProcess("$LocalPath <-> $RemotePath", "Synchronize ($Mode, Remove=$Remove, Mirror=$Mirror)")) {
            $result = $Session.SynchronizeDirectories([WinSCP.SynchronizationMode]$Mode,$directory.FullName,(Format-StringPath $RemotePath),[bool]$Remove,[bool]$Mirror,$Criteria,$TransferOptions)
            $result.Check()
            $result
        }
    }
}
function Start-WinScpConsole {
    <# .SYNOPSIS
    Launch the bundled WinSCP console and wait for it to exit.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Assert-ScpPlatform
    $path = Join-Path $PSScriptRoot 'bin/WinSCP.exe'
    if ($PSCmdlet.ShouldProcess($path,'Start console')) { Start-Process -FilePath $path -ArgumentList '/console' -Wait }
}

function Get-ScpSession {
    <# .SYNOPSIS
    Retrieve sessions opened by this module, optionally by their assigned name.
    #>
    [CmdletBinding()]
    [OutputType([WinSCP.Session])]
    param([string]$Name, [switch]$OpenedOnly)
    if ($Name) {
        if (!$script:ScpSessions.ContainsKey($Name)) { throw "No session named '$Name' exists in this module instance." }
        $sessions = @($script:ScpSessions[$Name])
    } else { $sessions = @($script:ScpSessions.Values) }
    foreach ($session in $sessions) { if (!$OpenedOnly -or $session.Opened) { $session } }
}
function Close-ScpSession {
    <# .SYNOPSIS
    Close a connection without disposing its Session object.
    .DESCRIPTION
    The returned object can be reopened through its Open method. Remove-ScpSession
    disposes it permanently and removes it from the module's session list.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session)
    process { if ($PSCmdlet.ShouldProcess('WinSCP session','Close connection')) { $Session.Close() } }
}
function ConvertTo-ScpEscapedString {
    <# .SYNOPSIS
    Escape literal paths for use inside WinSCP file masks.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory,ValueFromPipeline)][AllowEmptyString()][string[]]$Path)
    process { foreach ($item in $Path) { [WinSCP.RemotePath]::EscapeFileMask($item) } }
}
function New-ScpItemPermission {
    <# .SYNOPSIS
    Create Unix permissions from octal, numeric or symbolic notation, or individual flags.
    .PARAMETER Numeric
    Decimal bitmask, for example 420 for octal 644.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding(DefaultParameterSetName='Octal')]
    [OutputType([WinSCP.FilePermissions])]
    param(
        [Parameter(Mandatory,ParameterSetName='Octal')][ValidatePattern('^[0-7]{3,4}$')][string]$Octal,
        [Parameter(Mandatory,ParameterSetName='Numeric')][ValidateRange(0,4095)][int]$Numeric,
        [Parameter(Mandatory,ParameterSetName='Text')][ValidateNotNullOrEmpty()][string]$Text,
        [Parameter(ParameterSetName='Flags')][switch]$UserRead,
        [Parameter(ParameterSetName='Flags')][switch]$UserWrite,
        [Parameter(ParameterSetName='Flags')][switch]$UserExecute,
        [Parameter(ParameterSetName='Flags')][switch]$GroupRead,
        [Parameter(ParameterSetName='Flags')][switch]$GroupWrite,
        [Parameter(ParameterSetName='Flags')][switch]$GroupExecute,
        [Parameter(ParameterSetName='Flags')][switch]$OtherRead,
        [Parameter(ParameterSetName='Flags')][switch]$OtherWrite,
        [Parameter(ParameterSetName='Flags')][switch]$OtherExecute,
        [Parameter(ParameterSetName='Flags')][switch]$SetUid,
        [Parameter(ParameterSetName='Flags')][switch]$SetGid,
        [Parameter(ParameterSetName='Flags')][switch]$Sticky
    )
    $permissions = New-Object WinSCP.FilePermissions
    if ($PSCmdlet.ParameterSetName -eq 'Flags') {
        $permissions.Numeric = 0
        foreach ($key in $PSBoundParameters.Keys) {
            if ($key -in @('UserRead','UserWrite','UserExecute','GroupRead','GroupWrite','GroupExecute','OtherRead','OtherWrite','OtherExecute','SetUid','SetGid','Sticky')) {
                $permissions.$key = [bool]$PSBoundParameters[$key]
            }
        }
    } else { $permissions.($PSCmdlet.ParameterSetName) = $PSBoundParameters[$PSCmdlet.ParameterSetName] }
    $permissions
}
function New-ScpTransferResumeSupport {
    <# .SYNOPSIS
    Configure automatic resume and uploads through temporary filenames.
    .PARAMETER Threshold
    Minimum size in KB. Threshold selects Smart mode; combine it only with State Smart.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding()]
    [OutputType([WinSCP.TransferResumeSupport])]
    param([WinSCP.TransferResumeSupportState]$State='Default',
          [ValidateRange(0,2147483647)][int]$Threshold)
    if ($PSBoundParameters.ContainsKey('Threshold') -and $PSBoundParameters.ContainsKey('State') -and $State -ne 'Smart') {
        throw 'Threshold can only be combined with State Smart.'
    }
    $resume = New-Object WinSCP.TransferResumeSupport
    $resume.State = $State
    if ($PSBoundParameters.ContainsKey('Threshold')) { $resume.Threshold = $Threshold }
    $resume
}
function Assert-ScpLeafName {
    param([string]$Name)
    if (!$Name -or $Name -in @('.','..') -or $Name -match '[/\\]' -or $Name.IndexOf([char]0) -ge 0) {
        throw 'The new name must be a single filename, without a directory path.'
    }
}
function Rename-ScpItem {
    <# .SYNOPSIS
    Rename a remote item within its current directory.
    .DESCRIPTION
    NewName is an exact leaf name, never a destination directory. Existing
    directories are rejected. Force permits file replacement with backup recovery.
    .PARAMETER Force
    Preserves an existing target file under a unique sibling backup name, then
    replaces it. On failure, restores it if the target is absent; otherwise reports
    the retained backup path. This process is not atomic and needs server rename support.
    .EXAMPLE
    Rename-ScpItem -Session $session -RemotePath '/incoming/report.tmp' -NewName 'report.csv' -PassThru
    Renames within the same directory and returns the resulting metadata.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$NewName,
          [switch]$Force, [switch]$PassThru)
    process {
        Assert-ScpSession $Session
        Assert-ScpLeafName $NewName
        $source = Format-StringPath $RemotePath
        $parent = [WinSCP.RemotePath]::GetDirectoryName($source)
        $destination = [WinSCP.RemotePath]::Combine($parent,$NewName)
        if ($PSCmdlet.ShouldProcess("$source -> $destination",'Rename remote item')) {
            Invoke-ScpRelocation -Session $Session -RemotePath $source -Destination $destination -ExactDestination -Force:$Force -PassThru:$PassThru
        }
    }
}
function Invoke-ScpRelocation {
    [CmdletBinding()]
    param([WinSCP.Session]$Session, [string]$RemotePath, [string]$Destination,
          [switch]$Copy, [switch]$Force, [switch]$PassThru, [switch]$ExactDestination)
    $source = Format-StringPath $RemotePath
    $target = Format-StringPath $Destination
    $sourceInfo = $Session.GetFileInfo($source)
    if ($Copy -and $sourceInfo.IsDirectory) { throw 'Remote copy supports files only.' }
    if (!$ExactDestination -and $Session.FileExists($target) -and $Session.GetFileInfo($target).IsDirectory) {
        $target = [WinSCP.RemotePath]::Combine($target,$sourceInfo.Name)
    }
    if ($source -ceq $target) { throw 'Source and destination refer to the same item.' }
    $backup = $null
    if ($Session.FileExists($target)) {
        $targetInfo = $Session.GetFileInfo($target)
        if ($sourceInfo.FullName -ceq $targetInfo.FullName) { throw 'Source and destination refer to the same item.' }
        if ($targetInfo.IsDirectory) { throw 'Cannot replace an existing destination directory.' }
        if (!$Force) { throw "Destination already exists: $target. Use Force to replace a file." }
        if ($sourceInfo.IsDirectory) { throw 'Cannot replace a file with a directory.' }
        $parent = [WinSCP.RemotePath]::GetDirectoryName($target)
        do {
            $backup = [WinSCP.RemotePath]::Combine($parent,('.powerscp-backup-' + [guid]::NewGuid().ToString('N')))
        } while ($Session.FileExists($backup))
        # Preserve the old destination until the replacement has completed.
        $Session.MoveFile($target,$backup)
    }
    try {
        if ($Copy) { $Session.DuplicateFile($source,$target) }
        else { $Session.MoveFile($source,$target) }
    } catch {
        $operationError = $_
        if ($backup) {
            try {
                # Do not destroy a partial target or another client's new file.
                if ($Session.FileExists($target)) { throw "Destination now exists: $target" }
                $Session.MoveFile($backup,$target)
            } catch {
                throw "Replacement failed: $($operationError.Exception.Message). Restoration failed: $($_.Exception.Message). Original destination retained at '$backup'; recover it manually."
            }
        }
        $PSCmdlet.ThrowTerminatingError($operationError)
    }
    if ($backup) {
        try { $Session.RemoveFile($backup) }
        catch { Write-Warning "Replacement succeeded, but original destination remains at '$backup': $_" }
    }
    if ($PassThru) { $Session.GetFileInfo($target) }
}
function Assert-ScpLocalLeafName {
    param([string]$Name)
    # Downloads run on Windows even when offline tests run elsewhere.
    Assert-ScpLeafName $Name
    if ($Name -match '[<>:"|?*\x00-\x1f]' -or $Name -match '[ .]$' -or
        $Name -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
        throw 'DestinationFileName must be a valid Windows filename without wildcard characters, device names or alternate data streams.'
    }
}
function Write-ScpByte {
    # Unique temporary file supports file creation on all protocols, including S3.
    param([WinSCP.Session]$Session, [string]$RemotePath, [byte[]]$Bytes,
          [WinSCP.TransferOptions]$TransferOptions)
    if ($RemotePath.EndsWith('/') -or [WinSCP.RemotePath]::GetFileName($RemotePath) -in @('','.','..')) {
        throw 'A content write requires a file path, not a directory path.'
    }
    if ($Session.FileExists($RemotePath) -and $Session.GetFileInfo($RemotePath).IsDirectory) {
        throw 'Cannot replace a directory with file content.'
    }
    $temporaryPath = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllBytes($temporaryPath,$Bytes)
        $result = $Session.PutFiles([WinSCP.RemotePath]::EscapeFileMask($temporaryPath),[WinSCP.RemotePath]::EscapeOperationMask($RemotePath),$false,$TransferOptions)
        $result.Check()
        $result
    } finally { [IO.File]::Delete($temporaryPath) }
}
function New-ScpItem {
    <# .SYNOPSIS
    Create a remote directory or a file containing UTF-8 text.
    .DESCRIPTION
    Existing files require Force before replacement. Missing parents are created
    for directories with Force. File parents must already exist.
    .PARAMETER TransferOptions
    Content writes require Binary transfer mode, Overwrite mode and no FileMask.
    These constraints prevent text conversion and accidental filtering.
    .EXAMPLE
    New-ScpItem -Session $session -RemotePath '/incoming/ready.flag'
    Creates an empty remote file. An existing file requires Force.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [ValidateSet('File','Directory')][string]$ItemType='File',
          [AllowEmptyString()][string]$Value='', [switch]$Force,
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions))
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            if ($PSCmdlet.ShouldProcess($path,"Create remote $ItemType")) {
                if ($ItemType -eq 'Directory') {
                    if ($PSBoundParameters.ContainsKey('Value')) { throw 'Value applies to files only.' }
                    New-ScpDirectory -Session $Session -RemotePath $path -Force:$Force -SuppressOutput -ErrorAction Stop
                } else {
                    if ($Session.FileExists($path)) {
                        if (!$Force) { throw "Remote item already exists: $path. Use Force to replace it." }
                        if ($Session.GetFileInfo($path).IsDirectory) { throw 'Cannot replace a directory with a file.' }
                    }
                    $options = Resolve-ScpContentTransferOption $TransferOptions
                    Write-ScpByte -Session $Session -RemotePath $path -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Value)) -TransferOptions $options | Out-Null
                }
                $Session.GetFileInfo($path)
            }
        }
    }
}
function Resolve-ScpContentTransferOption {
    param([WinSCP.TransferOptions]$TransferOptions)
    if ($TransferOptions.OverwriteMode -ne 'Overwrite') { throw 'Content writes require Overwrite mode.' }
    if ($TransferOptions.FileMask) { throw 'Content writes do not accept a FileMask.' }
    if ($TransferOptions.TransferMode -ne 'Binary') { throw 'Content writes require Binary transfer mode to preserve exact bytes.' }
    # Resume/temporary settings on a fresh unique local file are not needed.
    $TransferOptions
}
function Get-ScpContent {
    <# .SYNOPSIS
    Read a remote text file over SFTP or FTP/FTPS, without a local temporary file.
    .PARAMETER Raw
    Return the entire file as one string instead of separate lines.
    .PARAMETER Encoding
    Text encoding name. UTF-8 is the default; a byte order mark is detected on read.
    .EXAMPLE
    Get-ScpContent -Session $session -RemotePath '/config/settings.json' -Raw
    Reads the entire remote text file and disposes its download stream.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [string]$Encoding='utf-8', [switch]$Raw)
    process {
        Assert-ScpSession $Session
        $textEncoding = [Text.Encoding]::GetEncoding($Encoding)
        foreach ($path in $RemotePath) {
            $stream = $Session.GetFile((Format-StringPath $path),(New-ScpTransferOptions))
            $reader = $null
            try {
                $reader = [IO.StreamReader]::new($stream,$textEncoding,$true)
                if ($Raw) { $reader.ReadToEnd() }
                else { while (!$reader.EndOfStream) { $reader.ReadLine() } }
            } finally { if ($reader) { $reader.Dispose() } else { $stream.Dispose() } }
        }
    }
}
function Set-ScpContent {
    <# .SYNOPSIS
    Replace a remote file with text, using UTF-8 without a BOM by default.
    .DESCRIPTION
    Works through ordinary file transfer on all protocols. It does not add a newline.
    .PARAMETER TransferOptions
    Requires Binary transfer mode, Overwrite mode and no FileMask. Local temporary
    files are removed even when transfer fails. File parents must already exist.
    .EXAMPLE
    Set-ScpContent -Session $session -RemotePath '/config/settings.json' -Value $json
    Replaces text using UTF-8 without a BOM or an added newline.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
          [string]$Encoding='utf-8',
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions))
    process {
        Assert-ScpSession $Session
        $options = Resolve-ScpContentTransferOption $TransferOptions
        $bytes = [Text.Encoding]::GetEncoding($Encoding).GetBytes($Value)
        if ($PSCmdlet.ShouldProcess($RemotePath,'Replace remote file content')) {
            Write-ScpByte -Session $Session -RemotePath (Format-StringPath $RemotePath) -Bytes $bytes -TransferOptions $options
        }
    }
}
function Compare-ScpDirectory {
    <# .SYNOPSIS
    Return the changes a directory synchronization would make, without transferring files.
    .EXAMPLE
    Compare-ScpDirectory -Session $session -LocalPath './data' -RemotePath '/data' -Mode Remote
    Returns planned synchronization differences without modifying either directory.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LocalPath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [ValidateSet('Local','Remote','Both')][string]$Mode='Remote',
          [switch]$Remove, [switch]$Mirror,
          [WinSCP.SynchronizationCriteria]$Criteria=[WinSCP.SynchronizationCriteria]::Time,
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions))
    process {
        Assert-ScpSession $Session
        if ($Mode -eq 'Both' -and ($Remove -or $Mirror)) { throw 'Remove and Mirror cannot be used with Mode Both.' }
        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop
        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must be an existing filesystem directory.' }
        $Session.CompareDirectories([WinSCP.SynchronizationMode]$Mode,$directory.FullName,(Format-StringPath $RemotePath),[bool]$Remove,[bool]$Mirror,$Criteria,$TransferOptions)
    }
}
