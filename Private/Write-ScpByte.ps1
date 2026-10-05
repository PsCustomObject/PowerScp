function Write-ScpByte
{
    # Unique temporary file supports file creation on all protocols, including S3.
    param
    (
        [WinSCP.Session]
        $Session,

        [string]
        $RemotePath,

        [byte[]]
        $Bytes,

        [WinSCP.TransferOptions]
        $TransferOptions
    )

    if ($RemotePath.EndsWith('/') -or [WinSCP.RemotePath]::GetFileName($RemotePath) -in @('', '.', '..'))
    {
        throw 'A content write requires a file path, not a directory path.'
    }

    if ($Session.FileExists($RemotePath) -and $Session.GetFileInfo($RemotePath).IsDirectory)
    {
        throw 'Cannot replace a directory with file content.'
    }

    $temporaryPath = [IO.Path]::GetTempFileName()

    try
    {
        [IO.File]::WriteAllBytes($temporaryPath, $Bytes)

        # Escape source masks and destination rename masks separately to preserve literal filenames.
        $result = $Session.PutFiles([WinSCP.RemotePath]::EscapeFileMask($temporaryPath), [WinSCP.RemotePath]::EscapeOperationMask($RemotePath), $false, $TransferOptions)

        $result.Check()
        $result
    }
    finally
    {
        [IO.File]::Delete($temporaryPath)
    }
}
