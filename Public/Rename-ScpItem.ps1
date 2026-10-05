function Rename-ScpItem
{
    <#
        .SYNOPSIS
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
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewName,

        [switch]
        $Force,

        [switch]
        $PassThru
    )

    process
    {
        Assert-ScpSession $Session
        Assert-ScpLeafName $NewName
        $source = Format-StringPath $RemotePath
        $parent = [WinSCP.RemotePath]::GetDirectoryName($source)
        $destination = [WinSCP.RemotePath]::Combine($parent, $NewName)

        if ($PSCmdlet.ShouldProcess("$source -> $destination", 'Rename remote item'))
        {
            Invoke-ScpRelocation -Session $Session -RemotePath $source -Destination $destination -ExactDestination -Force:$Force -PassThru:$PassThru
        }
    }
}
