function Get-ScpItemCheckSum
{
    <#
        .SYNOPSIS
            Calculate a remote file checksum using a server-supported algorithm.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [Alias('RemotePath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ItemName,

        [ValidateSet('md2', 'md5', 'sha-1', 'sha-224', 'sha-256', 'sha-384', 'sha-512', 'shake128', 'shake256')]
        [string]
        $HashAlgorithm = 'sha-256'
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $ItemName)
        {
            $Session.CalculateFileChecksum($HashAlgorithm, (Format-StringPath $path))
        }
    }
}
