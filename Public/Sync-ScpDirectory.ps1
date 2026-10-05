function Sync-ScpDirectory
{
    <#
        .SYNOPSIS
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
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LocalPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,

        [ValidateSet('Local', 'Remote', 'Both')]
        [string]
        $Mode = 'Remote',

        [switch]
        $Remove,

        [switch]
        $Mirror,

        [WinSCP.SynchronizationCriteria]
        $Criteria = [WinSCP.SynchronizationCriteria]::Time,

        [WinSCP.TransferOptions]
        $TransferOptions = (New-ScpTransferOptions)
    )

    process
    {
        Assert-ScpSession $Session

        if ($Mode -eq 'Both' -and ($Remove -or $Mirror))
        {
            throw 'Remove and Mirror cannot be used with Mode Both.'
        }

        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop

        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem')
        {
            throw 'LocalPath must be an existing filesystem directory.'
        }

        if ($PSCmdlet.ShouldProcess("$LocalPath <-> $RemotePath", "Synchronize ($Mode, Remove=$Remove, Mirror=$Mirror)"))
        {
            $result = $Session.SynchronizeDirectories([WinSCP.SynchronizationMode]$Mode, $directory.FullName, (Format-StringPath $RemotePath), [bool]$Remove, [bool]$Mirror, $Criteria, $TransferOptions)

            $result.Check()
            $result
        }
    }
}
