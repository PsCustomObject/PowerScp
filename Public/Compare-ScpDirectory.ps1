function Compare-ScpDirectory
{
    <#
        .SYNOPSIS
            Return the changes a directory synchronization would make, without transferring files.

        .EXAMPLE
            Compare-ScpDirectory -Session $session -LocalPath './data' -RemotePath '/data' -Mode Remote
            Returns planned synchronization differences without modifying either directory.
    #>

    [CmdletBinding()]
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

        $Session.CompareDirectories([WinSCP.SynchronizationMode]$Mode, $directory.FullName, (Format-StringPath $RemotePath), [bool]$Remove, [bool]$Mirror, $Criteria, $TransferOptions)
    }
}
