function Get-ScpContent
{
    <#
        .SYNOPSIS
            Read a remote text file over SFTP or FTP/FTPS, without a local temporary file.

        .PARAMETER Raw
            Return the entire file as one string instead of separate lines.

        .PARAMETER Encoding
            Text encoding name. UTF-8 is the default; a byte order mark is detected on read.

        .EXAMPLE
            Get-ScpContent -Session $session -RemotePath '/config/settings.json' -Raw
            Reads the entire remote text file and disposes its download stream.
    #>

    [CmdletBinding()]
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
        $Encoding = 'utf-8',

        [switch]
        $Raw
    )

    process
    {
        Assert-ScpSession $Session
        $textEncoding = [Text.Encoding]::GetEncoding($Encoding)

        foreach ($path in $RemotePath)
        {
            $stream = $Session.GetFile((Format-StringPath $path), (New-ScpTransferOptions))
            $reader = $null

            try
            {
                # Detect a byte order mark before falling back to the requested encoding.
                $reader = [IO.StreamReader]::new($stream, $textEncoding, $true)

                if ($Raw)
                {
                    $reader.ReadToEnd()
                }
                else
                {
                    while (!$reader.EndOfStream)
                    {
                        $reader.ReadLine()
                    }
                }
            }
            finally
            {
                # Disposing the reader closes its stream; close the stream directly if construction failed.
                if ($reader)
                {
                    $reader.Dispose()
                }
                else
                {
                    $stream.Dispose()
                }
            }
        }
    }
}
