function Format-StringPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Path
    )

    process
    {
        foreach ($item in $Path)
        {
            $item.Replace('\', '/')
        }
    }
}
