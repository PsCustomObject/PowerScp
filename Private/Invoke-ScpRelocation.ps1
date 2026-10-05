function Invoke-ScpRelocation
{
    [CmdletBinding()]
    param
    (
        [WinSCP.Session]
        $Session,

        [string]
        $RemotePath,

        [string]
        $Destination,

        [switch]
        $Copy,

        [switch]
        $Force,

        [switch]
        $PassThru,

        [switch]
        $ExactDestination
    )

    $source = Format-StringPath $RemotePath
    $target = Format-StringPath $Destination
    $sourceInfo = $Session.GetFileInfo($source)

    if ($Copy -and $sourceInfo.IsDirectory)
    {
        throw 'Remote copy supports files only.'
    }

    # Move and copy can target a directory; rename requires the exact destination name.
    if (!$ExactDestination -and $Session.FileExists($target) -and $Session.GetFileInfo($target).IsDirectory)
    {
        $target = [WinSCP.RemotePath]::Combine($target, $sourceInfo.Name)
    }

    if ($source -ceq $target)
    {
        throw 'Source and destination refer to the same item.'
    }

    $backup = $null

    if ($Session.FileExists($target))
    {
        $targetInfo = $Session.GetFileInfo($target)

        if ($sourceInfo.FullName -ceq $targetInfo.FullName)
        {
            throw 'Source and destination refer to the same item.'
        }

        if ($targetInfo.IsDirectory)
        {
            throw 'Cannot replace an existing destination directory.'
        }

        if (!$Force)
        {
            throw "Destination already exists: $target. Use Force to replace a file."
        }

        if ($sourceInfo.IsDirectory)
        {
            throw 'Cannot replace a file with a directory.'
        }

        $parent = [WinSCP.RemotePath]::GetDirectoryName($target)

        do
        {
            $backup = [WinSCP.RemotePath]::Combine($parent, ('.powerscp-backup-' + [guid]::NewGuid().ToString('N')))
        }

        while ($Session.FileExists($backup))

        # Preserve the old destination until the replacement has completed.
        $Session.MoveFile($target, $backup)
    }

    try
    {
        if ($Copy)
        {
            $Session.DuplicateFile($source, $target)
        }
        else
        {
            $Session.MoveFile($source, $target)
        }
    }
    catch
    {
        $operationError = $_

        if ($backup)
        {
            try
            {
                # Do not destroy a partial target or another client's new file.
                if ($Session.FileExists($target))
                {
                    throw "Destination now exists: $target"
                }

                $Session.MoveFile($backup, $target)
            }
            catch
            {
                throw "Replacement failed: $($operationError.Exception.Message). Restoration failed: $($_.Exception.Message). Original destination retained at '$backup'; recover it manually."
            }
        }

        $PSCmdlet.ThrowTerminatingError($operationError)
    }

    # Backup cleanup failure must not turn a completed replacement into a failed operation.
    if ($backup)
    {
        try
        {
            $Session.RemoveFile($backup)
        }
        catch
        {
            Write-Warning "Replacement succeeded, but original destination remains at '$backup': $_"
        }
    }

    if ($PassThru)
    {
        $Session.GetFileInfo($target)
    }
}
