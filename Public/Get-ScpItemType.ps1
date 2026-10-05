function Get-ScpItemType
{
    <#
        .SYNOPSIS
            Return metadata for literal remote paths, optionally filtering their names.
    #>

    [CmdletBinding()]
    [OutputType([WinSCP.RemoteFileInfo])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,

        [string]
        $Filter
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            $item = $Session.GetFileInfo((Format-StringPath $path))

            if (!$Filter -or $item.Name -like $Filter)
            {
                $item
            }
        }
    }
}
