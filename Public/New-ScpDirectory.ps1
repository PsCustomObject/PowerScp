function New-ScpDirectory
{
    <#
        .SYNOPSIS
            Create remote directories. Force creates missing parents.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,

        [switch]
        $Force,

        [switch]
        $SuppressOutput
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            $path = Format-StringPath $path

            try
            {
                if ($Session.FileExists($path))
                {
                    if (!$Session.GetFileInfo($path).IsDirectory)
                    {
                        throw "Remote path is a file: $path"
                    }

                    if (!$SuppressOutput)
                    {
                        $true
                    }

                    continue
                }

                if ($PSCmdlet.ShouldProcess($path, 'Create remote directory'))
                {
                    if ($Force)
                    {
                        $parent = [WinSCP.RemotePath]::GetDirectoryName($path.TrimEnd('/'))

                        if ($parent -and $parent -ne $path -and !$Session.FileExists($parent))
                        {
                            # Create parents first and suppress their output so only the requested path reports success.
                            New-ScpDirectory -Session $Session -RemotePath $parent -Force -SuppressOutput -ErrorAction Stop
                        }
                    }

                    $Session.CreateDirectory($path)

                    if (!$SuppressOutput)
                    {
                        $true
                    }
                }
            }
            catch
            {
                $PSCmdlet.WriteError($_)
            }
        }
    }
}
