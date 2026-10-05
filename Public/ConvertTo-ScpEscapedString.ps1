function ConvertTo-ScpEscapedString
{
    <#
        .SYNOPSIS
            Escape literal paths for use inside WinSCP file masks.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string[]]
        $Path
    )

    process
    {
        foreach ($item in $Path)
        {
            [WinSCP.RemotePath]::EscapeFileMask($item)
        }
    }
}
