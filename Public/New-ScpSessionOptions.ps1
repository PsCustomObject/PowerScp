function New-ScpSessionOptions
{
    <#
        .SYNOPSIS
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

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Established public API mirrors the WinSCP SessionOptions and TransferOptions type names.')]
    [CmdletBinding()]
    [OutputType([WinSCP.SessionOptions])]
    param
    (
        [Alias('Host', 'HostName')]
        [string]
        $RemoteHost,

        [string]
        $UserName,

        [AllowEmptyString()]
        [string]
        $UserPassword,

        [Alias('Credential')]
        [pscredential]
        $Credentials,

        [WinSCP.Protocol]
        $Protocol = 'Scp',

        [Alias('Port', 'PortNumber')]
        [ValidateRange(0, 65535)]
        [int]
        $ServerPort = 0,

        [Alias('Timeout')]
        [timespan]
        $ConnectionTimeOut = [timespan]::FromSeconds(15),

        [switch]
        $NoSshKeyCheck,

        [switch]
        $NoTlsCheck,

        [string[]]
        $SshHostKeyFingerprint,

        [WinSCP.SshHostKeyPolicy]
        $SshHostKeyPolicy = 'Check',

        [Alias('SshPrivateKeyPath')]
        [string]
        $SshKeyPath,

        [string]
        $SshKeyPassword,

        [securestring]
        $SecurePrivateKeyPassphrase,

        [switch]
        $NoSSHKeyPassword,

        [WinSCP.FtpMode]
        $FtpMode = 'Passive',

        [WinSCP.FtpSecure]
        $FtpSecure = 'None',

        [switch]
        $WebDavSecure,

        [Alias('RootPath')]
        [string]
        $WebDavRoot,

        [bool]
        $Secure,

        [string]
        $TlsHostCertificateFingerprint,

        [string]
        $TlsClientCertificatePath,

        [hashtable]
        $RawSettings,

        [string]
        $SessionUrl,

        [switch]
        $Scan,

        [ValidateNotNullOrEmpty()]
        [string]
        $S3Bucket,

        [ValidateNotNullOrEmpty()]
        [string]
        $S3Region,

        [securestring]
        $S3SessionToken,

        [ValidateSet('VirtualHost', 'Path')]
        [string]
        $S3UrlStyle,

        [switch]
        $S3CredentialsFromEnvironment,

        [string]
        $S3Profile
    )

    if ($Credentials -and ($PSBoundParameters.ContainsKey('UserName') -or $PSBoundParameters.ContainsKey('UserPassword')))
    {
        throw 'Use Credentials or UserName/UserPassword, not both.'
    }

    if ($SshKeyPassword -and $SecurePrivateKeyPassphrase)
    {
        throw 'Use one private-key passphrase parameter.'
    }

    if ($ConnectionTimeOut -le [timespan]::Zero)
    {
        throw 'ConnectionTimeOut must be positive.'
    }

    $options = New-Object WinSCP.SessionOptions

    # Parse the URL first; explicitly bound parameters can then override its values.
    if ($SessionUrl)
    {
        $options.ParseUrl($SessionUrl)
    }

    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('Protocol'))
    {
        $options.Protocol = $Protocol
    }

    # Set protocol before hostname: the assembly supplies the AWS endpoint for S3.
    if ($RemoteHost)
    {
        $options.HostName = $RemoteHost
    }

    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('ServerPort'))
    {
        $options.PortNumber = $ServerPort
    }

    if (!$SessionUrl -or $PSBoundParameters.ContainsKey('ConnectionTimeOut'))
    {
        $options.Timeout = $ConnectionTimeOut
    }

    if ($Credentials)
    {
        $options.UserName = $Credentials.UserName
        $options.SecurePassword = $Credentials.Password
    }
    else
    {
        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('UserName'))
        {
            $options.UserName = $UserName
        }

        if ($PSBoundParameters.ContainsKey('UserPassword'))
        {
            $options.Password = $UserPassword
        }
    }

    if ($PSBoundParameters.ContainsKey('SshHostKeyPolicy'))
    {
        $options.SshHostKeyPolicy = $SshHostKeyPolicy
    }

    if ($NoSshKeyCheck)
    {
        if ($PSBoundParameters.ContainsKey('SshHostKeyPolicy') -and $SshHostKeyPolicy -ne 'GiveUpSecurityAndAcceptAny')
        {
            throw 'NoSshKeyCheck conflicts with SshHostKeyPolicy.'
        }

        $options.SshHostKeyPolicy = 'GiveUpSecurityAndAcceptAny'
    }
    elseif ($PSBoundParameters.ContainsKey('NoSshKeyCheck'))
    {
        $options.SshHostKeyPolicy = 'Check'
    }

    # Check whether the switch was bound so an explicit false value is applied too.
    if ($PSBoundParameters.ContainsKey('NoTlsCheck'))
    {
        $options.GiveUpSecurityAndAcceptAnyTlsHostCertificate = [bool]$NoTlsCheck
    }

    if ($SshHostKeyFingerprint)
    {
        $options.SshHostKeyFingerprint = $SshHostKeyFingerprint -join ';'
    }

    if (!$Scan -and $options.Protocol -in @('Scp', 'Sftp') -and $options.SshHostKeyPolicy -eq 'Check' -and !$options.SshHostKeyFingerprint)
    {
        throw 'Specify SshHostKeyFingerprint or choose an explicit SshHostKeyPolicy.'
    }

    if ($SshKeyPassword -and !$SshKeyPath)
    {
        throw 'SshKeyPassword requires SshKeyPath.'
    }

    if ($SshKeyPath)
    {
        $options.SshPrivateKeyPath = (Resolve-Path -LiteralPath $SshKeyPath -ErrorAction Stop).ProviderPath
    }

    if ($SshKeyPassword)
    {
        $options.PrivateKeyPassphrase = $SshKeyPassword
    }

    if ($SecurePrivateKeyPassphrase)
    {
        $options.SecurePrivateKeyPassphrase = $SecurePrivateKeyPassphrase
    }

    if ($TlsClientCertificatePath)
    {
        $options.TlsClientCertificatePath = (Resolve-Path -LiteralPath $TlsClientCertificatePath -ErrorAction Stop).ProviderPath
    }

    if ($TlsHostCertificateFingerprint)
    {
        $options.TlsHostCertificateFingerprint = $TlsHostCertificateFingerprint
    }

    if (($PSBoundParameters.ContainsKey('FtpMode') -or $PSBoundParameters.ContainsKey('FtpSecure')) -and $options.Protocol -ne 'Ftp')
    {
        throw 'FtpMode and FtpSecure require Protocol Ftp.'
    }

    if ($options.Protocol -eq 'Ftp')
    {
        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('FtpMode'))
        {
            $options.FtpMode = $FtpMode
        }

        if (!$SessionUrl -or $PSBoundParameters.ContainsKey('FtpSecure'))
        {
            $options.FtpSecure = $FtpSecure
        }
    }

    if ($WebDavSecure -and $options.Protocol -ne 'Webdav')
    {
        throw 'WebDavSecure requires Protocol Webdav.'
    }

    if (($WebDavRoot -or $PSBoundParameters.ContainsKey('Secure')) -and $options.Protocol -notin @('Webdav', 'S3'))
    {
        throw 'RootPath and Secure require Protocol Webdav or S3.'
    }

    if ($PSBoundParameters.ContainsKey('Secure'))
    {
        $options.Secure = $Secure
    }
    elseif ($PSBoundParameters.ContainsKey('WebDavSecure'))
    {
        $options.Secure = [bool]$WebDavSecure
    }
    elseif ($options.Protocol -eq 'S3' -and (!$SessionUrl -or $PSBoundParameters.ContainsKey('Protocol')))
    {
        $options.Secure = $true
    }

    if ($WebDavSecure -and $PSBoundParameters.ContainsKey('Secure') -and !$Secure)
    {
        throw 'WebDavSecure conflicts with Secure false.'
    }

    if ($WebDavRoot)
    {
        $options.RootPath = Format-StringPath $WebDavRoot
    }

    # Copy raw settings before applying named S3 options, which take precedence.
    $settings = @{}

    foreach ($key in $RawSettings.Keys)
    {
        $settings[$key] = [string]$RawSettings[$key]
    }

    $s3Parameters = @('S3Bucket', 'S3Region', 'S3SessionToken', 'S3UrlStyle', 'S3CredentialsFromEnvironment', 'S3Profile')

    if (@($PSBoundParameters.Keys | Where-Object `
            {
                $_ -in $s3Parameters
            }).Count -and $options.Protocol -ne 'S3')
    {
        throw 'S3 settings require Protocol S3.'
    }

    if ($S3Bucket)
    {
        if ($S3Bucket -match '[/\\]')
        {
            throw 'S3Bucket must be a bucket name, without a path.'
        }

        if ($WebDavRoot)
        {
            throw 'Use S3Bucket or RootPath, not both.'
        }

        $options.RootPath = '/' + $S3Bucket
    }

    if ($S3Region)
    {
        $settings['S3DefaultRegion'] = $S3Region
    }

    if ($S3UrlStyle)
    {
        # WinSCP expects the URL style as a numeric string: 1 for path, 0 for virtual host.
        $settings['S3UrlStyle'] = [string][int]($S3UrlStyle -eq 'Path')
    }

    if ($S3Profile)
    {
        if ($PSBoundParameters.ContainsKey('S3CredentialsFromEnvironment') -and !$S3CredentialsFromEnvironment)
        {
            throw 'S3Profile requires environment credential lookup.'
        }

        $S3CredentialsFromEnvironment = $true
        $settings['S3Profile'] = $S3Profile
    }

    if ($S3CredentialsFromEnvironment -and ($Credentials -or $options.UserName -or $options.Password))
    {
        throw 'Use AWS environment/profile credentials or explicit access keys, not both.'
    }

    if ($PSBoundParameters.ContainsKey('S3CredentialsFromEnvironment') -or $S3Profile)
    {
        $settings['S3CredentialsEnv'] = [string][int][bool]$S3CredentialsFromEnvironment
    }

    if ($S3SessionToken)
    {
        # WinSCP raw settings require a string. Clear the temporary plaintext copy afterwards.
        $token = [System.Net.NetworkCredential]::new('', $S3SessionToken).Password

        try
        {
            $options.AddRawSettings('S3SessionToken', $token)
        }
        finally
        {
            $token = $null
        }

        $settings.Remove('S3SessionToken')
    }

    foreach ($key in $settings.Keys)
    {
        $options.AddRawSettings([string]$key, $settings[$key])
    }

    $options
}
