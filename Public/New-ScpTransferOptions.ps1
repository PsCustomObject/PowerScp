function New-ScpTransferOptions
{
    <#
        .SYNOPSIS
            Construct reusable WinSCP transfer options.

        .PARAMETER Permissions
            Unix octal permissions, such as 644, 755 or 0755. Each digit must be 0 through 7.
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Established public API mirrors the WinSCP SessionOptions and TransferOptions type names.')]
    [CmdletBinding()]
    [OutputType([WinSCP.TransferOptions])]
    param
    (
        [ValidateRange(0, 2147483647)]
        [int]
        $SpeedLimit = 0,

        [string]
        $FileMask,

        [ValidatePattern('^[0-7]{3,4}$')]
        [string]
        $Permissions,

        [ValidateSet('Overwrite', 'Resume', 'Append')]
        [string]
        $OverWriteMode = 'Overwrite',

        [bool]
        $PreserveTimeStamp = $true,

        [ValidateSet('Automatic', 'Binary', 'Ascii', 'Text')]
        [string]
        $TransferMode = 'Binary',

        [hashtable]
        $RawSettings,

        [WinSCP.FilePermissions]
        $FilePermissions,

        [WinSCP.TransferResumeSupport]
        $ResumeSupport
    )

    if ($FilePermissions -and $PSBoundParameters.ContainsKey('Permissions'))
    {
        throw 'Use Permissions or FilePermissions, not both.'
    }

    $options = New-Object WinSCP.TransferOptions

    $options.SpeedLimit = $SpeedLimit
    $options.FileMask = $FileMask
    $options.OverwriteMode = $OverWriteMode
    $options.PreserveTimestamp = $PreserveTimeStamp

    if ($TransferMode -eq 'Text')
    {
        $TransferMode = 'Ascii'
    }

    $options.TransferMode = $TransferMode

    if ($PSBoundParameters.ContainsKey('Permissions'))
    {
        $options.FilePermissions = New-Object WinSCP.FilePermissions
        $options.FilePermissions.Octal = $Permissions
    }

    if ($FilePermissions)
    {
        $options.FilePermissions = $FilePermissions
    }

    if ($ResumeSupport)
    {
        $options.ResumeSupport = $ResumeSupport
    }

    foreach ($key in $RawSettings.Keys)
    {
        $options.AddRawSettings([string]$key, [string]$RawSettings[$key])
    }

    $options
}
