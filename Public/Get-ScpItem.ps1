function Get-ScpItem
{
    <#
        .SYNOPSIS
            List remote items. Retains the legacy enumeration behavior of Get-ScpItem.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [string[]]
        $RemotePath = @('.'),

        [string]
        $Filter = '*',

        [switch]
        $Recurse,

        [ValidateRange(0, 2147483647)]
        [int]
        $Depth = 0,

        [switch]
        $FilesOnly,

        [switch]
        $DirectoriesOnly,

        [switch]
        $Name,

        [switch]
        $LiteralPath
    )

    process
    {
        if ($LiteralPath)
        {
            if ($Recurse -or $Depth -or $FilesOnly -or $DirectoriesOnly -or $Name)
            {
                throw 'LiteralPath metadata lookup cannot be combined with listing switches.'
            }

            Get-ScpItemType -Session $Session -RemotePath $RemotePath -Filter $Filter
        }
        else
        {
            $arguments = @{}

            foreach ($key in $PSBoundParameters.Keys)
            {
                if ($key -ne 'LiteralPath')
                {
                    $arguments[$key] = $PSBoundParameters[$key]
                }
            }

            $arguments.Session = $Session
            Get-ScpChildItem @arguments
        }
    }
}
