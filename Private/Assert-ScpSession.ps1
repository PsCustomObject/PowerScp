function Assert-ScpSession
{
    param
    (
        $Session
    )

    if ($null -eq $Session -or !$Session.Opened)
    {
        throw 'The WinSCP Session is not in an open state'
    }
}
