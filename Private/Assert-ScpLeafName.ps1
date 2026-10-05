function Assert-ScpLeafName
{
    param
    (
        [string]
        $Name
    )

    if (!$Name -or $Name -in @('.', '..') -or $Name -match '[/\\]' -or $Name.IndexOf([char]0) -ge 0)
    {
        throw 'The new name must be a single filename, without a directory path.'
    }
}
