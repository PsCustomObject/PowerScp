function Copy-ScpItem
{
    <#
        .SYNOPSIS
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
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Destination,

        [switch]
        $Force,

        [switch]
        $PassThru
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            if ($PSCmdlet.ShouldProcess("$path -> $Destination", 'Copy remote item'))
            {
                if ($RemotePath.Count -gt 1 -and (!$Session.FileExists($Destination) -or !$Session.GetFileInfo($Destination).IsDirectory))
                {
                    throw 'Multiple source items require an existing destination directory.'
                }

                Invoke-ScpRelocation -Session $Session -RemotePath $path -Destination $Destination -Copy:$true -Force:$Force -PassThru:$PassThru
            }
        }
    }
}
