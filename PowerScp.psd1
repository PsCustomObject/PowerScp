@{
    RootModule = 'PowerScp.psm1'
    ModuleVersion = '1.2.1'
    GUID = '3c42657a-e9fa-4358-a934-170727493e6c'
    Author = 'PsCustomObject - Daniele Catanesi'
    CompanyName = 'https://PsCustomObject.github.io'
    Copyright = '(c) 2019. All rights reserved.'
    Description = 'Windows PowerShell and PowerShell 7 automation for WinSCP file transfers and remote management.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Format-StringPath'
        'Get-HostFingerPrint'
        'New-ScpSession'
        'Test-ScpSession'
        'Remove-ScpSession'
        'Test-ScpPath'
        'Get-ScpItemType'
        'Get-ScpChildItem'
        'Get-ScpItem'
        'Get-ScpItemCheckSum'
        'New-ScpTransferOptions'
        'New-ScpDirectory'
        'Send-ScpItem'
        'Receive-ScpItem'
        'Remove-ScpItem'
        'Move-ScpItem'
        'Copy-ScpItem'
        'Invoke-ScpCommand'
        'Sync-ScpDirectory'
        'Start-WinScpConsole'
        'New-ScpSessionOptions'
        'Get-ScpSession'
        'Close-ScpSession'
        'ConvertTo-ScpEscapedString'
        'New-ScpItemPermission'
        'New-ScpTransferResumeSupport'
        'Rename-ScpItem'
        'New-ScpItem'
        'Get-ScpContent'
        'Set-ScpContent'
        'Compare-ScpDirectory'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('WinSCP', 'SFTP', 'SCP', 'FTP', 'WebDAV', 'S3')
            LicenseUri = 'https://github.com/PsCustomObject/PowerScp/blob/master/LICENSE'
            ProjectUri = 'https://github.com/PsCustomObject/PowerScp'
        }
    }
}
