function New-ScpItem
{
    <#
        .SYNOPSIS
            Create a remote directory or a file containing UTF-8 text.

        .DESCRIPTION
            Existing files require Force before replacement. Missing parents are created
            for directories with Force. File parents must already exist.

        .PARAMETER TransferOptions
            Content writes require Binary transfer mode, Overwrite mode and no FileMask.
            These constraints prevent text conversion and accidental filtering.

        .EXAMPLE
            New-ScpItem -Session $session -RemotePath '/incoming/ready.flag'
            Creates an empty remote file. An existing file requires Force.
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

        [ValidateSet('File', 'Directory')]
        [string]
        $ItemType = 'File',

        [AllowEmptyString()]
        [string]
        $Value = '',

        [switch]
        $Force,

        [WinSCP.TransferOptions]
        $TransferOptions = (New-ScpTransferOptions)
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            $path = Format-StringPath $path

            if ($PSCmdlet.ShouldProcess($path, "Create remote $ItemType"))
            {
                if ($ItemType -eq 'Directory')
                {
                    if ($PSBoundParameters.ContainsKey('Value'))
                    {
                        throw 'Value applies to files only.'
                    }

                    New-ScpDirectory -Session $Session -RemotePath $path -Force:$Force -SuppressOutput -ErrorAction Stop
                }
                else
                {
                    if ($Session.FileExists($path))
                    {
                        if (!$Force)
                        {
                            throw "Remote item already exists: $path. Use Force to replace it."
                        }

                        if ($Session.GetFileInfo($path).IsDirectory)
                        {
                            throw 'Cannot replace a directory with a file.'
                        }
                    }

                    $options = Resolve-ScpContentTransferOption $TransferOptions

                    Write-ScpByte -Session $Session -RemotePath $path -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Value)) -TransferOptions $options | Out-Null
                }

                $Session.GetFileInfo($path)
            }
        }
    }
}
