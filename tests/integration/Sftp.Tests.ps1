# Opt-in only. The root must be a dedicated writable test directory on the server.
BeforeDiscovery {
    $enabled = $env:POWERSCP_LIVE_TESTS -eq '1' -and [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}
Describe 'Live SFTP transfers' -Tag Integration -Skip:(!$enabled) {
    BeforeAll {
        Import-Module (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'PowerScp.psd1') -Force -ErrorAction Stop
        foreach ($name in @('POWERSCP_SFTP_HOST','POWERSCP_SFTP_USER','POWERSCP_SFTP_KEY','POWERSCP_SFTP_FINGERPRINT','POWERSCP_SFTP_ROOT')) {
            if (![Environment]::GetEnvironmentVariable($name)) { throw "Required environment variable: $name" }
        }
        $arguments = @{
            RemoteHost=$env:POWERSCP_SFTP_HOST; UserName=$env:POWERSCP_SFTP_USER
            SshKeyPath=$env:POWERSCP_SFTP_KEY; SshHostKeyFingerprint=$env:POWERSCP_SFTP_FINGERPRINT
            Protocol='Sftp'; ErrorAction='Stop'
        }
        if ($env:POWERSCP_SFTP_PORT) { $arguments.ServerPort=[int]$env:POWERSCP_SFTP_PORT }
        $session=New-ScpSession @arguments
        $runRoot=$env:POWERSCP_SFTP_ROOT.TrimEnd('/') + '/powerscp-' + [guid]::NewGuid().ToString('N')
        New-ScpDirectory -Session $session -RemotePath $runRoot -ErrorAction Stop | Out-Null
    }
    AfterAll {
        if ($session) {
            try {
                if ($runRoot) { Remove-ScpItem -Session $session -RemotePath $runRoot -Confirm:$false -ErrorAction Stop | Out-Null }
            } finally { Remove-ScpSession -Session $session -Confirm:$false | Out-Null }
        }
    }
    BeforeEach {
        $remote=$runRoot + '/' + [guid]::NewGuid().ToString('N')
        New-ScpDirectory -Session $session -RemotePath $remote -ErrorAction Stop | Out-Null
        $local=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $local | Out-Null
    }
    It 'round trips bracket filenames and exact UTF-8 bytes with permissions' {
        $file=Join-Path $local 'report[1].txt'
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes("caffè`none`r`ntwo")
        [IO.File]::WriteAllBytes($file,$bytes)
        Send-ScpItem -Session $session -LocalPath $file -RemotePath $remote -Permissions 600 | Out-Null
        (Get-ScpItemType -Session $session -RemotePath "$remote/report[1].txt").FilePermissions.Octal | Should -Be '600'
        $downloads=New-Item -ItemType Directory -Path (Join-Path $local downloads)
        Receive-ScpItem -Session $session -RemotePath "$remote/report[1].txt" -LiteralPath -LocalPath $downloads.FullName -DestinationFileName 'saved[1].txt' | Out-Null
        [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $downloads.FullName 'saved[1].txt'))) | Should -Be ([Convert]::ToBase64String($bytes))
    }
    It 'keeps folder structure and previews synchronization without mutation' {
        $tree=New-Item -ItemType Directory -Path (Join-Path $local tree)
        $child=New-Item -ItemType Directory -Path (Join-Path $tree.FullName child)
        [IO.File]::WriteAllText((Join-Path $child.FullName file.txt),'contents')
        Send-ScpItem -Session $session -LocalPath $tree.FullName -RemotePath $remote -WhatIf
        Test-ScpPath -Session $session -RemotePath "$remote/tree" | Should -BeFalse
        Send-ScpItem -Session $session -LocalPath $tree.FullName -RemotePath $remote | Out-Null
        Test-ScpPath -Session $session -RemotePath "$remote/tree/child/file.txt" | Should -BeTrue
        [IO.File]::WriteAllText((Join-Path $tree.FullName new.txt),'new')
        @(Compare-ScpDirectory -Session $session -LocalPath $tree.FullName -RemotePath "$remote/tree").Count | Should -BeGreaterThan 0
        Sync-ScpDirectory -Session $session -LocalPath $tree.FullName -RemotePath "$remote/tree" -WhatIf
        Test-ScpPath -Session $session -RemotePath "$remote/tree/new.txt" | Should -BeFalse
    }
    It 'requires explicit source removal and safely replaces and renames files' {
        $file=Join-Path $local source.txt
        [IO.File]::WriteAllText($file,'new')
        Send-ScpItem -Session $session -LocalPath $file -RemotePath $remote | Out-Null
        Test-Path -LiteralPath $file | Should -BeTrue
        New-ScpItem -Session $session -RemotePath "$remote/dest.txt" -Value old | Out-Null
        Copy-ScpItem -Session $session -RemotePath "$remote/source.txt" -Destination "$remote/dest.txt" -Force
        Get-ScpContent -Session $session -RemotePath "$remote/dest.txt" -Raw | Should -Be new
        Rename-ScpItem -Session $session -RemotePath "$remote/dest.txt" -NewName renamed.txt
        Test-ScpPath -Session $session -RemotePath "$remote/renamed.txt" | Should -BeTrue
        Send-ScpItem -Session $session -LocalPath $file -RemotePath $remote -Remove | Out-Null
        Test-Path -LiteralPath $file | Should -BeFalse
    }
    It 'writes exact content and refuses rename into an existing directory' {
        $text="caffè`none`r`ntwo"
        Set-ScpContent -Session $session -RemotePath "$remote/content.txt" -Value $text | Out-Null
        Get-ScpContent -Session $session -RemotePath "$remote/content.txt" -Raw | Should -Be $text
        New-ScpDirectory -Session $session -RemotePath "$remote/archive" | Out-Null
        { Rename-ScpItem -Session $session -RemotePath "$remote/content.txt" -NewName archive -Force } | Should -Throw '*directory*'
        Test-ScpPath -Session $session -RemotePath "$remote/content.txt" | Should -BeTrue
    }
}
