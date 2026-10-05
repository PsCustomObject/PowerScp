function Get-ScpSession
{
    <#
        .SYNOPSIS
            Retrieve sessions opened by this module, optionally by their assigned name.
    #>

    [CmdletBinding()]
    [OutputType([WinSCP.Session])]
    param
    (
        [string]
        $Name,

        [switch]
        $OpenedOnly
    )

    if ($Name)
    {
        if (!$script:ScpSessions.ContainsKey($Name))
        {
            throw "No session named '$Name' exists in this module instance."
        }

        $sessions = @($script:ScpSessions[$Name])
    }
    else
    {
        $sessions = @($script:ScpSessions.Values)
    }

    foreach ($session in $sessions)
    {
        if (!$OpenedOnly -or $session.Opened)
        {
            $session
        }
    }
}
