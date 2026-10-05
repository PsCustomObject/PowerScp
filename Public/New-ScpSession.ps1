function New-ScpSession
{
    <#
        .SYNOPSIS
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

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Connection')]
    [OutputType([WinSCP.Session])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Options')]
        [Alias('SessionOption')]
        [WinSCP.SessionOptions]
        $SessionOptions,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('Host', 'HostName')]
        [string]
        $RemoteHost,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $UserName,

        [Parameter(ParameterSetName = 'Connection')]
        [AllowEmptyString()]
        [string]
        $UserPassword,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('Credential')]
        [pscredential]
        $Credentials,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('ConnectionProtocol')]
        [WinSCP.Protocol]
        $Protocol = 'Scp',

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('Port', 'RemoteHostPort')]
        [ValidateRange(0, 65535)]
        [int]
        $ServerPort = 0,

        [Parameter(ParameterSetName = 'Connection')]
        [timespan]
        $ConnectionTimeOut = [timespan]::FromSeconds(15),

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('GiveUpSecurityAndAcceptAnySshHostKey', 'AnySshKey', 'SshCheck', 'AcceptAnySshKey')]
        [switch]
        $NoSshKeyCheck,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('GiveUpSecurityAndAcceptAnyTlsHostCertificate', 'AnyTlsCertificte', 'AcceptAnyCertificate')]
        [switch]
        $NoTlsCheck,

        [Parameter(ParameterSetName = 'Connection')]
        [string[]]
        $SshHostKeyFingerprint,

        [Parameter(ParameterSetName = 'Connection')]
        [WinSCP.SshHostKeyPolicy]
        $SshHostKeyPolicy = 'Check',

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('SshPrivateKey', 'SshPrivateKeyPath', 'SsheKeyPath')]
        [string]
        $SshKeyPath,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $SshKeyPassword,

        [Parameter(ParameterSetName = 'Connection')]
        [securestring]
        $SecurePrivateKeyPassphrase,

        [Parameter(ParameterSetName = 'Connection')]
        [switch]
        $NoSSHKeyPassword,

        [Parameter(ParameterSetName = 'Connection')]
        [WinSCP.FtpMode]
        $FtpMode = 'Passive',

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('FtpSecureMode', 'SecureFtpMode')]
        [WinSCP.FtpSecure]
        $FtpSecure = 'None',

        [Parameter(ParameterSetName = 'Connection')]
        [switch]
        $WebDavSecure,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('RootPath')]
        [string]
        $WebDavRoot,

        [Parameter(ParameterSetName = 'Connection')]
        [bool]
        $Secure,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $TlsHostCertificateFingerprint,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $TlsClientCertificatePath,

        [Parameter(ParameterSetName = 'Connection')]
        [hashtable]
        $RawSettings,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $SessionUrl,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $S3Bucket,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $S3Region,

        [Parameter(ParameterSetName = 'Connection')]
        [securestring]
        $S3SessionToken,

        [Parameter(ParameterSetName = 'Connection')]
        [ValidateSet('VirtualHost', 'Path')]
        [string]
        $S3UrlStyle,

        [Parameter(ParameterSetName = 'Connection')]
        [switch]
        $S3CredentialsFromEnvironment,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $S3Profile,

        [string]
        $Name,

        [string]
        $SessionLogPath,

        [string]
        $DebugLogPath,

        [Alias('DebugLogLevel')]
        [ValidateRange(-1, 2)]
        [int]
        $DebugLevel = 0,

        [timespan]
        $ReconnectTime = [timespan]::FromSeconds(120),

        [string]
        $XmlLogPath,

        [switch]
        $XmlLogPreserve,

        [hashtable]
        $RawConfiguration
    )

    process
    {
        if ($Name -and $script:ScpSessions.ContainsKey($Name))
        {
            throw "A session named '$Name' already exists. Remove it first."
        }

        if ($PSCmdlet.ParameterSetName -eq 'Options')
        {
            $options = $SessionOptions
        }
        else
        {
            $arguments = @{}
            $optionParameters = (Get-Command New-ScpSessionOptions).Parameters.Keys

            # Forward connection settings while keeping common parameters on this command.
            foreach ($key in $PSBoundParameters.Keys)
            {
                if ($key -in $optionParameters -and $key -notin @('WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction'))
                {
                    $arguments[$key] = $PSBoundParameters[$key]
                }
            }

            $options = New-ScpSessionOptions @arguments
        }

        if (!$options.HostName)
        {
            throw 'RemoteHost is required except when Protocol S3 supplies the AWS endpoint.'
        }

        if ($PSCmdlet.ShouldProcess($options.HostName, 'Open WinSCP session'))
        {
            $sessionObject = New-ScpSessionObject -SessionLogPath $SessionLogPath -DebugLogPath $DebugLogPath -DebugLevel $DebugLevel -ReconnectTime $ReconnectTime

            try
            {
                if ($XmlLogPath)
                {
                    $sessionObject.XmlLogPath = $XmlLogPath
                }

                $sessionObject.XmlLogPreserve = [bool]$XmlLogPreserve
                foreach ($key in $RawConfiguration.Keys)
                {
                    $sessionObject.AddRawConfiguration([string]$key, [string]$RawConfiguration[$key])
                }

                $sessionObject.Open($options)
                if (!$Name)
                {
                    $sessionName = [guid]::NewGuid().ToString()
                }
                else
                {
                    $sessionName = $Name
                }

                $sessionObject | Add-Member -NotePropertyName ScpSessionName -NotePropertyValue $sessionName -Force
                $sessionObject | Add-Member -NotePropertyName RemoteHost -NotePropertyValue $options.HostName -Force

                # Track only successfully opened sessions for lookup and module unload cleanup.
                $script:ScpSessions[$sessionName] = $sessionObject
                $sessionObject
            }
            catch
            {
                # Opening can fail after resources have been allocated; dispose before rethrowing.
                $sessionObject.Dispose()
                $PSCmdlet.ThrowTerminatingError($_)
            }
        }
    }
}
