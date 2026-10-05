function Resolve-ScpTransferOption
{
    param
    (
        [System.Collections.IDictionary]
        $Parameters
    )

    # A supplied options object takes precedence over individual transfer settings.
    if (($Parameters.Keys -contains 'TransferOptions'))
    {
        return $Parameters['TransferOptions']
    }

    $arguments = @{}

    # Forward only bound values so omitted parameters retain the factory defaults.
    foreach ($key in @('SpeedLimit', 'FileMask', 'Permissions', 'OverWriteMode', 'PreserveTimeStamp', 'TransferMode'))
    {
        if (($Parameters.Keys -contains $key))
        {
            $arguments[$key] = $Parameters[$key]
        }
    }

    New-ScpTransferOptions @arguments
}
