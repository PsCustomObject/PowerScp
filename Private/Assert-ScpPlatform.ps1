function Assert-ScpPlatform
{
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT)
    {
        throw 'WinSCP transfers require Windows. PowerShell 7 is supported on Windows.'
    }
}
