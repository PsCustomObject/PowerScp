function Resolve-ScpContentTransferOption
{
    param
    (
        [WinSCP.TransferOptions]
        $TransferOptions
    )

    if ($TransferOptions.OverwriteMode -ne 'Overwrite')
    {
        throw 'Content writes require Overwrite mode.'
    }

    if ($TransferOptions.FileMask)
    {
        throw 'Content writes do not accept a FileMask.'
    }

    if ($TransferOptions.TransferMode -ne 'Binary')
    {
        throw 'Content writes require Binary transfer mode to preserve exact bytes.'
    }

    # Resume/temporary settings on a fresh unique local file are not needed.
    $TransferOptions
}
