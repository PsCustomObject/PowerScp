function Set-ScpContent
{
    <#
        .SYNOPSIS
            Replace a remote file with text, using UTF-8 without a BOM by default.

        .DESCRIPTION
            Works through ordinary file transfer on all protocols. It does not add a newline.

        .PARAMETER TransferOptions
            Requires Binary transfer mode, Overwrite mode and no FileMask. Local temporary
            files are removed even when transfer fails. File parents must already exist.

        .EXAMPLE
            Set-ScpContent -Session $session -RemotePath '/config/settings.json' -Value $json
            Replaces text using UTF-8 without a BOM or an added newline.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemotePath,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]
        $Value,

        [string]
        $Encoding = 'utf-8',

        [WinSCP.TransferOptions]
        $TransferOptions = (New-ScpTransferOptions)
    )

    process
    {
        Assert-ScpSession $Session
        $options = Resolve-ScpContentTransferOption $TransferOptions
        $bytes = [Text.Encoding]::GetEncoding($Encoding).GetBytes($Value)

        if ($PSCmdlet.ShouldProcess($RemotePath, 'Replace remote file content'))
        {
            Write-ScpByte -Session $Session -RemotePath (Format-StringPath $RemotePath) -Bytes $bytes -TransferOptions $options
        }
    }
}
