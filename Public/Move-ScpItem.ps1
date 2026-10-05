function Move-ScpItem
{
    <#
        .SYNOPSIS
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
            if ($PSCmdlet.ShouldProcess("$path -> $Destination", 'Move remote item'))
            {
                if ($RemotePath.Count -gt 1 -and (!$Session.FileExists($Destination) -or !$Session.GetFileInfo($Destination).IsDirectory))
                {
                    throw 'Multiple source items require an existing destination directory.'
                }

                Invoke-ScpRelocation -Session $Session -RemotePath $path -Destination $Destination -Copy:$false -Force:$Force -PassThru:$PassThru
            }
        }
    }
}
