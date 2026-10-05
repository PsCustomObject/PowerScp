function Get-ScpChildItem
{
    <#
        .SYNOPSIS
            List remote directory contents, with optional recursion and file filtering.

        .PARAMETER Depth
            Maximum subdirectory levels. Zero means unlimited when Recurse is set.
    #>

    [CmdletBinding()]
    [OutputType([WinSCP.RemoteFileInfo])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath = @('.'),

        [string]
        $Filter = '*',

        [switch]
        $Recurse,

        [ValidateRange(0, 2147483647)]
        [int]
        $Depth = 0,

        [Alias('File')]
        [switch]
        $FilesOnly,

        [Alias('Directory')]
        [switch]
        $DirectoriesOnly,

        [switch]
        $Name
    )

    process
    {
        Assert-ScpSession $Session

        if ($FilesOnly -and $DirectoriesOnly)
        {
            throw 'Use FilesOnly or DirectoriesOnly, not both.'
        }

        if ($Depth -gt 0 -and !$Recurse)
        {
            throw 'Depth requires Recurse.'
        }

        foreach ($path in $RemotePath)
        {
            $path = Format-StringPath $path
            $options = [WinSCP.EnumerationOptions]::None

            if ($Recurse)
            {
                $options = $options -bor [WinSCP.EnumerationOptions]::AllDirectories
            }

            if (!$FilesOnly)
            {
                $options = $options -bor [WinSCP.EnumerationOptions]::MatchDirectories
            }

            if ($Recurse -and $Depth -gt 0)
            {
                $root = $Session.GetFileInfo($path).FullName.TrimEnd('/') + '/'
            }

            foreach ($item in $Session.EnumerateRemoteFiles($path, $Filter, $options))
            {
                if ($FilesOnly -and $item.IsDirectory)
                {
                    continue
                }

                if ($DirectoriesOnly -and !$item.IsDirectory)
                {
                    continue
                }

                if ($Recurse -and $Depth -gt 0)
                {
                    # Count parent segments relative to the root; immediate children have depth zero.
                    $relative = $item.FullName.Substring($root.Length)

                    if (($relative.Trim('/').Split('/').Length - 1) -gt $Depth)
                    {
                        continue
                    }
                }

                if ($Name)
                {
                    $item.Name
                }
                else
                {
                    $item
                }
            }
        }
    }
}
