function Send-ScpItem
{
    <#
        .SYNOPSIS
            Upload literal local files or directories to a remote destination directory.

        .PARAMETER TransferFilesOnly
            Flatten all files from a local directory tree into the destination. Duplicate names are rejected.

        .PARAMETER Remove
            Delete local source files after a successful transfer. Disabled by default.

        .DESCRIPTION
            Local paths are literal. RemotePath is a directory; missing parents are created.
            Source removal is opt-in. Failed operations terminate. WhatIf prevents both
            transfer and remote directory creation. TransferFilesOnly flattens directory
            trees and rejects duplicate names before transferring.

        .PARAMETER DestinationFileName
            Renames a single local file during upload. Supply the destination directory
            separately through RemotePath. Cannot be combined with TransferFilesOnly.

        .EXAMPLE
            Send-ScpItem -Session $session -LocalPath './report[1].csv' -RemotePath '/incoming' -WhatIf
            Previews an upload without interpreting brackets as a local wildcard.

        .EXAMPLE
            Send-ScpItem -Session $session -LocalPath './report.csv' -RemotePath '/incoming' -DestinationFileName 'ready.csv'
            Uploads one file under a new remote name, retaining the local source.
    #>

    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'RuntimeTransferOptions')]
    [OutputType([WinSCP.TransferOperationResult])]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $LocalPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,

        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory, ParameterSetName = 'TransferOptionsObject')]
        [ValidateNotNull()]
        [WinSCP.TransferOptions]
        $TransferOptions,

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateRange(0, 2147483647)]
        [int]
        $SpeedLimit = 0,

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [string]
        $FileMask,

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidatePattern('^[0-7]{3,4}$')]
        [string]
        $Permissions,

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateSet('Overwrite', 'Resume', 'Append')]
        [string]
        $OverWriteMode = 'Overwrite',

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [bool]
        $PreserveTimeStamp = $true,

        [Parameter(ParameterSetName = 'RuntimeTransferOptions')]
        [ValidateSet('Automatic', 'Binary', 'Ascii', 'Text')]
        [string]
        $TransferMode = 'Binary',

        [switch]
        $TransferFilesOnly,

        [switch]
        $Remove,

        [string]
        $DestinationFileName
    )

    process
    {
        Assert-ScpSession $Session
        $options = Resolve-ScpTransferOption $PSBoundParameters
        $destination = (Format-StringPath $RemotePath).TrimEnd('/') + '/'
        $sources = @(foreach ($path in $LocalPath)
            {
                $item = Get-Item -LiteralPath $path -ErrorAction Stop

                if ($item.PSProvider.Name -ne 'FileSystem')
                {
                    throw 'LocalPath must use the FileSystem provider.'
                }

                if ($TransferFilesOnly -and $item.PSIsContainer)
                {
                    Get-ChildItem -LiteralPath $item.FullName -File -Recurse -ErrorAction Stop
                }
                else
                {
                    $item
                }
            })

        if ($DestinationFileName)
        {
            Assert-ScpLeafName $DestinationFileName

            if ($TransferFilesOnly -or $sources.Count -ne 1 -or $sources[0].PSIsContainer)
            {
                throw 'DestinationFileName requires one local file without TransferFilesOnly.'
            }

            $target = [WinSCP.RemotePath]::EscapeOperationMask([WinSCP.RemotePath]::Combine($destination, $DestinationFileName))
        }
        else
        {
            $target = $destination
        }

        # Flattening removes parent directories, so detect filename collisions before any upload.
        if ($TransferFilesOnly)
        {
            $duplicates = $sources | Group-Object Name | Where-Object Count -GT 1

            if ($duplicates)
            {
                throw 'TransferFilesOnly would overwrite duplicate filenames in the flattened destination.'
            }
        }

        foreach ($item in $sources)
        {
            $action = 'Upload'

            if ($Remove)
            {
                $action = 'Upload and remove local source'
            }

            if ($PSCmdlet.ShouldProcess("$($item.FullName) -> $target", $action))
            {
                New-ScpDirectory -Session $Session -RemotePath $destination -Force -SuppressOutput -ErrorAction Stop
                $result = $Session.PutFiles([WinSCP.RemotePath]::EscapeFileMask($item.FullName), $target, [bool]$Remove, $options)

                # WinSCP records transfer failures in the result; raise them before returning it.
                $result.Check()
                $result
            }
        }
    }
}
