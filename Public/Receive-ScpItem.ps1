function Receive-ScpItem
{
    <#
        .SYNOPSIS
            Download remote file masks into an existing local directory.

        .PARAMETER Remove
            Remove remote sources after successful download. Disabled by default.

        .DESCRIPTION
            Remote paths are WinSCP masks unless LiteralPath is set. LocalPath must be an
            existing filesystem directory. Sources are retained unless Remove is set.

        .PARAMETER LiteralPath
            Escapes remote mask characters so a specific file or directory is selected.

        .PARAMETER DestinationFileName
            A valid Windows leaf filename. Requires one literal remote file, not a directory.

        .EXAMPLE
            Receive-ScpItem -Session $session -RemotePath '/outgoing/*.csv' -LocalPath './downloads'
            Downloads matching CSV files without removing remote sources.

        .EXAMPLE
            Receive-ScpItem -Session $session -RemotePath '/report[1].txt' -LiteralPath -LocalPath './downloads' -DestinationFileName 'saved.txt'
            Downloads a literal bracket filename under a new local name.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([WinSCP.TransferOperationResult])]
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
        $LocalPath,

        [WinSCP.TransferOptions]
        $TransferOptions = (New-ScpTransferOptions),

        [switch]
        $Remove,

        [switch]
        $LiteralPath,

        [string]
        $DestinationFileName
    )

    process
    {
        Assert-ScpSession $Session
        $directory = Get-Item -LiteralPath $LocalPath -ErrorAction Stop

        if (!$directory.PSIsContainer -or $directory.PSProvider.Name -ne 'FileSystem')
        {
            throw 'LocalPath must be an existing filesystem directory.'
        }

        # A trailing separator tells WinSCP to preserve source filenames inside this directory.
        $destination = $directory.FullName.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar

        if ($DestinationFileName)
        {
            if (!$LiteralPath -or $RemotePath.Count -ne 1)
            {
                throw 'DestinationFileName requires one literal remote file.'
            }

            Assert-ScpLeafName $DestinationFileName
            Assert-ScpLocalLeafName $DestinationFileName
            $destination = Join-Path $directory.FullName $DestinationFileName
        }

        foreach ($path in $RemotePath)
        {
            $source = Format-StringPath $path

            if ($DestinationFileName -and $Session.GetFileInfo($source).IsDirectory)
            {
                throw 'DestinationFileName requires a remote file, not a directory.'
            }

            if ($LiteralPath)
            {
                $source = [WinSCP.RemotePath]::EscapeFileMask($source)
            }

            $action = 'Download'

            if ($Remove)
            {
                $action = 'Download and remove remote source'
            }

            if ($PSCmdlet.ShouldProcess("$path -> $destination", $action))
            {
                $result = $Session.GetFiles($source, $destination, [bool]$Remove, $TransferOptions)

                $result.Check()
                $result
            }
        }
    }
}
