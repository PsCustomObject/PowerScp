function Get-HostFingerPrint
{
    <#
        .SYNOPSIS
            Scan a fingerprint; verify it independently before trusting it.
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Legacy username/password parameters are retained for compatibility; PSCredential is the recommended alternative.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Legacy string passwords are retained for compatibility; use Credentials and SecurePrivateKeyPassphrase instead.')]
    [CmdletBinding(DefaultParameterSetName = 'Connection')]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Options')]
        [WinSCP.SessionOptions]
        $SessionOptions,

        [Parameter(Mandatory, ParameterSetName = 'Connection')]
        [Alias('Host', 'Server', 'RemoteServer')]
        [string]
        $RemoteHost,

        [Parameter(ParameterSetName = 'Connection')]
        [string]
        $UserName,

        [Parameter(ParameterSetName = 'Connection')]
        [Alias('UserPassword')]
        [string]
        $Password,

        [Parameter(ParameterSetName = 'Connection')]
        [pscredential]
        $Credentials,

        [Parameter(ParameterSetName = 'Connection')]
        [ValidateRange(0, 65535)]
        [int]
        $PortNumber = 0,

        [Parameter(ParameterSetName = 'Connection')]
        [timespan]
        $ConnectionTimeOut = [timespan]::FromSeconds(15),

        [ValidateSet('SHA-256', 'MD5')]
        [string]
        $Algorithm = 'SHA-256',

        [Parameter(ParameterSetName = 'Connection')]
        [WinSCP.Protocol]
        $Protocol = 'Scp',

        [Parameter(ParameterSetName = 'Connection')]
        [WinSCP.FtpSecure]
        $FtpSecure = 'None',

        [Parameter(ParameterSetName = 'Connection')]
        [switch]
        $WebDavSecure
    )

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Options')
        {
            $options = $SessionOptions
        }
        else
        {
            $arguments = @{
                RemoteHost = $RemoteHost
                ServerPort = $PortNumber
                Protocol = $Protocol
                ConnectionTimeOut = $ConnectionTimeOut
                Scan = $true
            }

            if ($Credentials)
            {
                $arguments.Credentials = $Credentials
            }
            else
            {
                if ($UserName)
                {
                    $arguments.UserName = $UserName
                }

                if ($PSBoundParameters.ContainsKey('Password'))
                {
                    $arguments.UserPassword = $Password
                }
            }

            foreach ($key in @('FtpSecure', 'WebDavSecure'))
            {
                if ($PSBoundParameters.ContainsKey($key))
                {
                    $arguments[$key] = $PSBoundParameters[$key]
                }
            }

            $options = New-ScpSessionOptions @arguments
        }

        $session = New-ScpSessionObject

        try
        {
            $session.ScanFingerprint($options, $Algorithm)
        }
        finally
        {
            $session.Dispose()
        }
    }
}
