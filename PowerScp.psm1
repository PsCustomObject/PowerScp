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
function Format-StringPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, ValueFromPipeline)][string[]]$Path)
    process { foreach ($item in $Path) { $item.Replace('\', '/') } }
}
function New-ScpSessionObject {
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
    # Shared by connection creation and fingerprint scanning. Extra common parameters are ignored.
    param([string]$RemoteHost, [string]$UserName, [string]$UserPassword, [pscredential]$Credentials,
          [WinSCP.Protocol]$Protocol = 'Scp', [int]$ServerPort = 0,
          [timespan]$ConnectionTimeOut = [timespan]::FromSeconds(15),
          [switch]$NoSshKeyCheck, [switch]$NoTlsCheck, [string[]]$SshHostKeyFingerprint,
          [string]$SshKeyPath, [string]$SshKeyPassword, [switch]$NoSSHKeyPassword,
          [WinSCP.FtpMode]$FtpMode = 'Passive', [WinSCP.FtpSecure]$FtpSecure = 'None',
          [switch]$WebDavSecure, [string]$WebDavRoot,
          [string]$SessionLogPath, [string]$DebugLogPath, [int]$DebugLevel,
          [timespan]$ReconnectTime, [switch]$Scan,
          [string]$TlsHostCertificateFingerprint, [hashtable]$RawSettings)
    if ($ConnectionTimeOut -le [timespan]::Zero) { throw 'ConnectionTimeOut must be positive.' }
    if ($SshKeyPassword -and !$SshKeyPath) { throw 'SshKeyPassword requires SshKeyPath.' }
    if (($WebDavSecure -or $WebDavRoot) -and $Protocol -ne 'Webdav') { throw 'WebDAV options require Protocol Webdav.' }
    if (!$Scan -and $Protocol -in @('Scp','Sftp') -and !$NoSshKeyCheck -and !$SshHostKeyFingerprint) {
        throw 'Specify SshHostKeyFingerprint or explicitly opt out with NoSshKeyCheck.'
    }
    $options = New-Object WinSCP.SessionOptions
    $options.HostName = $RemoteHost
    $options.Protocol = $Protocol
    $options.PortNumber = $ServerPort
    $options.Timeout = $ConnectionTimeOut
    if ($Credentials) { $options.UserName = $Credentials.UserName; $options.SecurePassword = $Credentials.Password }
    else { $options.UserName = $UserName; $options.Password = $UserPassword }
    $options.GiveUpSecurityAndAcceptAnySshHostKey = [bool]$NoSshKeyCheck
    $options.GiveUpSecurityAndAcceptAnyTlsHostCertificate = [bool]$NoTlsCheck
    if ($SshHostKeyFingerprint) { $options.SshHostKeyFingerprint = $SshHostKeyFingerprint -join ';' }
    if ($SshKeyPath) { $options.SshPrivateKeyPath = (Resolve-Path -LiteralPath $SshKeyPath -ErrorAction Stop).ProviderPath }
    if ($SshKeyPassword) { $options.PrivateKeyPassphrase = $SshKeyPassword }
    if ($TlsHostCertificateFingerprint) { $options.TlsHostCertificateFingerprint = $TlsHostCertificateFingerprint }
    foreach ($key in $RawSettings.Keys) { $options.AddRawSettings([string]$key,[string]$RawSettings[$key]) }
    $options.FtpMode = $FtpMode
    $options.FtpSecure = $FtpSecure
    $options.WebdavSecure = [bool]$WebDavSecure
    if ($WebDavRoot) { $options.RootPath = $WebDavRoot }
    $options
}
function Get-HostFingerPrint {
    <# .SYNOPSIS
    Scan a host fingerprint. Verify it independently before trusting it for a connection.
    #>
    [CmdletBinding(DefaultParameterSetName='UserNamePassword')]
    param(
        [Parameter(Mandatory)][Alias('Host','Server','RemoteServer')][string]$RemoteHost,
        [Parameter(ParameterSetName='UserNamePassword')][string]$UserName,
        [Parameter(ParameterSetName='UserNamePassword')][Alias('UserPassword')][string]$Password,
        [Parameter(Mandatory,ParameterSetName='Credentials')][pscredential]$Credentials,
        [ValidateRange(0,65535)][int]$PortNumber = 0,
        [timespan]$ConnectionTimeOut = [timespan]::FromSeconds(15),
        [ValidateSet('SHA-256','MD5')][string]$Algorithm = 'SHA-256',
        [ValidateSet('Sftp','Scp','Ftp','Webdav','S3')][string]$Protocol = 'Scp',
        [WinSCP.FtpSecure]$FtpSecure = 'None', [switch]$WebDavSecure
    )
    $options = New-ScpSessionOptions -RemoteHost $RemoteHost -UserName $UserName -UserPassword $Password -Credentials $Credentials -ServerPort $PortNumber -Protocol $Protocol -ConnectionTimeOut $ConnectionTimeOut -FtpSecure $FtpSecure -WebDavSecure:$WebDavSecure -Scan
    $session = New-ScpSessionObject
    try { $session.ScanFingerprint($options, $Algorithm) } finally { $session.Dispose() }
}
function New-ScpSession
{
    <# .SYNOPSIS
    Open a Windows WinSCP session using credentials or a username and password.
    .DESCRIPTION
    Supports SFTP, SCP, FTP/FTPS, WebDAV/WebDAVS and S3. SSH connections require
    a verified fingerprint unless NoSshKeyCheck is explicitly enabled. Port zero
    selects the protocol default. Unencrypted private keys require no passphrase.
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
        $ServerPort = 0,
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
        [ValidateSet('Sftp', 'Ftp', 'Scp', 'Webdav', 'S3', IgnoreCase = $true)]
        [Alias('ConnectionProtocol')]
        [WinSCP.Protocol]
        $Protocol = 'Scp',
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
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [AllowEmptyString()]
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
        $ReconnectTime = [timespan]::FromSeconds(120),
        [Parameter(ParameterSetName = 'Credentials')]
        [Parameter(ParameterSetName = 'UsernamePassword')]
        [switch]
        $NoSSHKeyPassword,
        [string]$TlsHostCertificateFingerprint,
        [hashtable]$RawSettings
    )

    $options = New-ScpSessionOptions @PSBoundParameters
    $sessionObject = New-ScpSessionObject -SessionLogPath $SessionLogPath -DebugLogPath $DebugLogPath -DebugLevel $DebugLevel -ReconnectTime $ReconnectTime
    try { $sessionObject.Open($options); $sessionObject }
    catch { $sessionObject.Dispose(); $PSCmdlet.ThrowTerminatingError($_) }
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
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session)
    process { if ($PSCmdlet.ShouldProcess('WinSCP session','Dispose')) { $Session.Dispose(); $true } }
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
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [string]$Filter = '*', [switch]$Recurse,
          [ValidateRange(0,2147483647)][int]$Depth = 0, [switch]$FilesOnly)
    process {
        Assert-ScpSession $Session
        if ($Depth -gt 0 -and !$Recurse) { throw 'Depth requires Recurse.' }
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            $options = [WinSCP.EnumerationOptions]::None
            if ($Recurse) { $options = $options -bor [WinSCP.EnumerationOptions]::AllDirectories }
            if (!$FilesOnly) { $options = $options -bor [WinSCP.EnumerationOptions]::MatchDirectories }
            if ($Recurse -and $Depth -gt 0) { $root = $Session.GetFileInfo($path).FullName.TrimEnd('/') + '/' }
            foreach ($item in $Session.EnumerateRemoteFiles($path, $Filter, $options)) {
                if ($FilesOnly -and $item.IsDirectory) { continue }
                if ($Recurse -and $Depth -gt 0) {
                    $relative = $item.FullName.Substring($root.Length)
                    if (($relative.Trim('/').Split('/').Length - 1) -gt $Depth) { continue }
                }
                $item
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
          [Parameter(Mandatory)][string[]]$RemotePath, [string]$Filter='*',
          [switch]$Recurse, [ValidateRange(0,2147483647)][int]$Depth=0, [switch]$FilesOnly)
    process { Get-ScpChildItem @PSBoundParameters }
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
    [CmdletBinding()]
    [OutputType([WinSCP.TransferOptions])]
    param([ValidateRange(0,2147483647)][int]$SpeedLimit=0, [string]$FileMask,
          [ValidatePattern('^[0-7]{3,4}$')][string]$Permissions,
          [ValidateSet('Overwrite','Resume','Append')][string]$OverWriteMode='Overwrite',
          [bool]$PreserveTimeStamp=$true,
          [ValidateSet('Automatic','Binary','Ascii','Text')][string]$TransferMode='Binary',
          [hashtable]$RawSettings)
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
    foreach ($key in $RawSettings.Keys) { $options.AddRawSettings([string]$key,[string]$RawSettings[$key]) }
    $options
}
function Resolve-ScpTransferOptions {
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
    #>
    [CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='RuntimeTransferOptions')]
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
        [switch]$TransferFilesOnly, [switch]$Remove
    )
    process {
        Assert-ScpSession $Session
        $options = Resolve-ScpTransferOptions $PSBoundParameters
        $destination = (Format-StringPath $RemotePath).TrimEnd('/') + '/'
        $sources = @(foreach ($path in $LocalPath) {
            $item = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($item.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must use the FileSystem provider.' }
            if ($TransferFilesOnly -and $item.PSIsContainer) { Get-ChildItem -LiteralPath $item.FullName -File -Recurse -ErrorAction Stop }
            else { $item }
        })
        if ($TransferFilesOnly) {
            $duplicates = $sources | Group-Object Name | Where-Object Count -gt 1
            if ($duplicates) { throw 'TransferFilesOnly would overwrite duplicate filenames in the flattened destination.' }
        }
        foreach ($item in $sources) {
            $action = 'Upload'
            if ($Remove) { $action = 'Upload and remove local source' }
            if ($PSCmdlet.ShouldProcess("$($item.FullName) -> $destination", $action)) {
                New-ScpDirectory -Session $Session -RemotePath $destination -Force -SuppressOutput -ErrorAction Stop
                $result = $Session.PutFiles([WinSCP.RemotePath]::EscapeFileMask($item.FullName),$destination,[bool]$Remove,$options)
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
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LocalPath,
          [WinSCP.TransferOptions]$TransferOptions=(New-ScpTransferOptions), [switch]$Remove)
    process {
        Assert-ScpSession $Session
        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop
        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem') { throw 'LocalPath must be an existing filesystem directory.' }
        $destination = $directory.FullName.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar
        foreach ($path in $RemotePath) {
            $action = 'Download'
            if ($Remove) { $action = 'Download and remove remote source' }
            if ($PSCmdlet.ShouldProcess("$path -> $destination",$action)) {
                $result = $Session.GetFiles((Format-StringPath $path),$destination,[bool]$Remove,$TransferOptions)
                $result.Check()
                $result
            }
        }
    }
}
function Remove-ScpItem {
    <# .SYNOPSIS
    Remove literal remote files or directories, including their contents.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param([Parameter(Mandatory,ValueFromPipeline)][ValidateNotNullOrEmpty()][string[]]$RemotePath,
          [Parameter(Mandatory)][WinSCP.Session]$Session)
    process {
        Assert-ScpSession $Session
        foreach ($path in $RemotePath) {
            $path = Format-StringPath $path
            if ($PSCmdlet.ShouldProcess($path,'Remove remote item')) {
                $result = $Session.RemoveFiles([WinSCP.RemotePath]::EscapeFileMask($path))
                $result.Check()
                $result
            }
        }
    }
}
function Move-ScpItem {
    <# .SYNOPSIS
    Move or rename a literal remote item.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Destination)
    process {
        Assert-ScpSession $Session
        if ($PSCmdlet.ShouldProcess("$RemotePath -> $Destination",'Move remote item')) {
            $Session.MoveFile((Format-StringPath $RemotePath),(Format-StringPath $Destination))
        }
    }
}
function Copy-ScpItem {
    <# .SYNOPSIS
    Copy a remote file on servers supporting server-side duplication.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RemotePath,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Destination)
    process {
        Assert-ScpSession $Session
        if ($PSCmdlet.ShouldProcess("$RemotePath -> $Destination",'Copy remote file')) {
            $Session.DuplicateFile((Format-StringPath $RemotePath),(Format-StringPath $Destination))
        }
    }
}
function Invoke-ScpCommand {
    <# .SYNOPSIS
    Execute a command on a server supporting shell commands.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory,ValueFromPipeline)][WinSCP.Session]$Session,
          [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Command)
    process {
        Assert-ScpSession $Session
        if ($PSCmdlet.ShouldProcess($Command,'Execute remote command')) {
            $result = $Session.ExecuteCommand($Command)
            $result.Check()
            $result
        }
    }
}
function Sync-ScpDirectory {
    <# .SYNOPSIS
    Synchronize local and remote directories. Removal requires the explicit Remove switch.
    .PARAMETER Mode
    Remote uploads changes; Local downloads changes; Both synchronizes in both directions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
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
