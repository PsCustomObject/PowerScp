function Assert-ScpLocalLeafName
{
    param
    (
        [string]
        $Name
    )

    # Downloads run on Windows even when offline tests run elsewhere.
    Assert-ScpLeafName $Name

    if ($Name -match '[<>:"|?*\x00-\x1f]' -or $Name -match '[ .]$' -or
        $Name -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)')
    {
        throw 'DestinationFileName must be a valid Windows filename without wildcard characters, device names or alternate data streams.'
    }
}
