BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'PowerScp.psd1') -Force }
BeforeAll { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'PowerScp.psd1') -Force }
Describe 'Reusable settings and protocol support' {
    It 'keeps S3 encrypted for AWS and custom endpoints' {
        $aws = New-ScpSessionOptions -Protocol S3 -S3Bucket backups -S3CredentialsFromEnvironment
        $aws.HostName | Should -Be s3.amazonaws.com
        $aws.Secure | Should -BeTrue
        $aws.RootPath | Should -Be '/backups'
        $custom = New-ScpSessionOptions -Protocol S3 -RemoteHost minio.example.org -UserName key -UserPassword secret
        $custom.Secure | Should -BeTrue
        $custom.HostName | Should -Be minio.example.org
        (New-ScpSessionOptions -Protocol S3 -Secure $false).Secure | Should -BeFalse
    }
    It 'maps named S3 settings to the pinned assembly raw settings' {
        $token = ConvertTo-SecureString 'temporary-token' -AsPlainText -Force
        $options = New-ScpSessionOptions -Protocol S3 -S3Region eu-central-1 -S3SessionToken $token -S3UrlStyle Path -S3Profile backup -RawSettings @{ S3DefaultRegion='ignored'; S3UrlStyle='0' }
        $settings = $options.GetType().GetField('<RawSettings>k__BackingField',[Reflection.BindingFlags]'NonPublic,Instance').GetValue($options)
        $settings['S3DefaultRegion'] | Should -Be eu-central-1
        $settings['S3SessionToken'] | Should -Be temporary-token
        $settings['S3UrlStyle'] | Should -Be '1'
        $settings['S3Profile'] | Should -Be backup
        $settings['S3CredentialsEnv'] | Should -Be '1'
    }
    It 'serializes AWS profile connections through the real pinned assembly without a username' {
        $options=New-ScpSessionOptions -Protocol S3 -S3Profile backup -S3Bucket backups -S3Region eu-central-1
        $session=New-Object WinSCP.Session
        try {
            # Exercise the real connection command builder without launching the Windows executable.
            $method=[WinSCP.Session].GetMethod('SessionOptionsToUrlAndSwitches',[Reflection.BindingFlags]'NonPublic,Instance')
            $arguments=[object[]]@($options.PSObject.BaseObject,$false,$null,$null)
            $method.Invoke($session,$arguments)
            $arguments[2] | Should -Match 's3://'
            $arguments[2] | Should -Match 'backups'
            $arguments[3] | Should -Match 'S3CredentialsEnv'
            $arguments[3] | Should -Match 'S3DefaultRegion'
        } finally { $session.Dispose() }
    }
    It 'rejects settings for the wrong protocol and ambiguous credentials' {
        { New-ScpSessionOptions -Protocol Ftp -S3Bucket backups } | Should -Throw '*S3 settings*'
        { New-ScpSessionOptions -Protocol S3 -FtpSecure Explicit } | Should -Throw '*Protocol Ftp*'
        { New-ScpSessionOptions -Protocol S3 -S3Bucket 'bucket/path' } | Should -Throw '*bucket name*'
        { New-ScpSessionOptions -Protocol S3 -S3Bucket backup -RootPath /backup } | Should -Throw '*not both*'
        { New-ScpSessionOptions -Protocol S3 -UserName key -S3CredentialsFromEnvironment } | Should -Throw '*not both*'
    }
    It 'parses session URLs without overwriting their protocol or TLS settings' {
        $options = New-ScpSessionOptions -SessionUrl 'ftpes://alice@example.org:2121/'
        $options.Protocol.ToString() | Should -Be Ftp
        $options.FtpSecure.ToString() | Should -Be Explicit
        $options.UserName | Should -Be alice
        $options.PortNumber | Should -Be 2121
        $options = New-ScpSessionOptions -SessionUrl 'https://example.org/dav/'
        $options.Protocol.ToString() | Should -Be Webdav
        $options.Secure | Should -BeTrue
    }
    It 'supports explicit trust-on-first-use while retaining strict checks by default' {
        (New-ScpSessionOptions -Protocol Sftp -SshHostKeyPolicy AcceptNew).SshHostKeyPolicy.ToString() | Should -Be AcceptNew
        { New-ScpSessionOptions -Protocol Sftp } | Should -Throw '*SshHostKeyFingerprint*'
        { New-ScpSessionOptions -Protocol Sftp -NoSshKeyCheck -SshHostKeyPolicy Check } | Should -Throw '*conflicts*'
    }
    It 'builds equivalent permission objects from supported representations' {
        (New-ScpItemPermission -Octal 644).Numeric | Should -Be 420
        (New-ScpItemPermission -Numeric 420).Octal | Should -Be '644'
        (New-ScpItemPermission -Text 'rw-r--r--').Octal | Should -Be '644'
        (New-ScpItemPermission -UserRead -UserWrite -GroupRead -OtherRead).Octal | Should -Be '644'
        { New-ScpItemPermission -Octal 889 } | Should -Throw
    }
    It 'builds predictable resume settings and applies permission objects' {
        $resume=New-ScpTransferResumeSupport -Threshold 512
        $resume.State.ToString() | Should -Be Smart
        $resume.Threshold | Should -Be 512
        { New-ScpTransferResumeSupport -State Off -Threshold 512 } | Should -Throw '*Smart*'
        $permission=New-ScpItemPermission -Octal 640
        $options=New-ScpTransferOptions -ResumeSupport $resume -FilePermissions $permission
        $options.ResumeSupport.Threshold | Should -Be 512
        $options.FilePermissions.Octal | Should -Be '640'
        { New-ScpTransferOptions -Permissions 644 -FilePermissions $permission } | Should -Throw '*not both*'
    }
    It 'escapes a literal wildcard path for file-mask use' {
        '/data/[1]*.txt' | ConvertTo-ScpEscapedString | Should -Be '/data/[[]1][*].txt'
    }
}
Describe 'Session creation and registration' {
    InModuleScope PowerScp {
        BeforeEach {
            $script:ScpSessions=@{}
            $fake = [pscustomobject]@{ Opened=$false; Disposed=$false; XmlLogPath=''; XmlLogPreserve=$false; Options=$null }
            $fake | Add-Member ScriptMethod Open { param($options) $this.Options=$options; $this.Opened=$true }
            $fake | Add-Member ScriptMethod Close { $this.Opened=$false }
            $fake | Add-Member ScriptMethod Dispose { $this.Disposed=$true; $this.Opened=$false }
            Mock New-ScpSessionObject { $fake }
        }
        AfterEach { $script:ScpSessions=@{} }
        It 'uses piped options and registers the opened session by name' {
            $options=New-ScpSessionOptions -Protocol Ftp -RemoteHost example.org -UserName alice
            $opened=$options | New-ScpSession -Name archive -XmlLogPath session.xml -XmlLogPreserve
            $opened.Opened | Should -BeTrue
            [object]::ReferenceEquals($fake.Options,$options) | Should -BeTrue
            [object]::ReferenceEquals((Get-ScpSession -Name archive),$opened) | Should -BeTrue
            $fake.ScpSessionName | Should -Be archive
            $fake.RemoteHost | Should -Be example.org
            $fake.XmlLogPath | Should -Be session.xml
            $fake.XmlLogPreserve | Should -BeTrue
            { $options | New-ScpSession -Name archive } | Should -Throw '*already exists*'
        }
        It 'never constructs or opens a connection during WhatIf' {
            New-ScpSession -Protocol S3 -S3CredentialsFromEnvironment -WhatIf
            Should -Invoke New-ScpSessionObject -Times 0
            @(Get-ScpSession).Count | Should -Be 0
        }
    }
}
Describe 'Remote administration operations' {
    BeforeAll {
        $root=Split-Path $PSScriptRoot -Parent
        . (Join-Path $PSScriptRoot 'Helpers/New-PowerScpTestAdapter.ps1')
        $adapter = New-PowerScpTestAdapter -SourceRoot $root -Destination (Join-Path $TestDrive 'PowerScpFeatureHarness') -Name 'PowerScpFeatureHarness'
        Import-Module $adapter -Force
        function New-FeatureSession {
            $fake=[pscustomobject]@{ Opened=$true; Calls=[collections.generic.list[object]]::new(); Files=@{}; Bytes=$null; TempPath=$null; Fail=$false; Stream=$null }
            $fake | Add-Member ScriptMethod FileExists { param($path) $this.Calls.Add(@('Exists',$path)); return $this.Files.ContainsKey($path) }
            $fake | Add-Member ScriptMethod GetFileInfo {
                param($path)
                if ($this.Files.ContainsKey($path)) { return $this.Files[$path] }
                return [pscustomobject]@{ FullName=$path; Name=[WinSCP.RemotePath]::GetFileName($path); IsDirectory=$false }
            }
            $fake | Add-Member ScriptMethod MoveFile { param($source,$target) $this.Calls.Add(@('Move',$source,$target)) }
            $fake | Add-Member ScriptMethod DuplicateFile { param($source,$target) $this.Calls.Add(@('Copy',$source,$target)) }
            $fake | Add-Member ScriptMethod RemoveFile { param($path) $this.Calls.Add(@('Remove',$path)) }
            $fake | Add-Member ScriptMethod PutFiles {
                param($local,$remote,$remove,$options)
                $this.Calls.Add(@('Put',$local,$remote,$remove,$options))
                $this.TempPath=$local
                $this.Bytes=[IO.File]::ReadAllBytes($local)
                $result=[pscustomobject]@{ Fail=$this.Fail }
                $result | Add-Member ScriptMethod Check { if ($this.Fail) { throw 'Transfer failed' } }
                return $result
            }
            $fake | Add-Member ScriptMethod GetFiles {
                param($remote,$local,$remove,$options)
                $this.Calls.Add(@('Get',$remote,$local,$remove,$options))
                $result=[pscustomobject]@{}
                $result | Add-Member ScriptMethod Check {}
                return $result
            }
            $fake | Add-Member ScriptMethod GetFile {
                param($path,$options) $this.Stream=[IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes("one`ntwo`n")); return $this.Stream
            }
            $fake | Add-Member ScriptMethod CompareDirectories {
                param($mode,$local,$remote,$remove,$mirror,$criteria,$options)
                $this.Calls.Add(@('Compare',$mode,$local,$remote,$remove,$mirror,$criteria))
                return [pscustomobject]@{ Action='UploadNew' }
            }
            $fake | Add-Member ScriptMethod EnumerateRemoteFiles { param($path,$filter,$options) return @($this.Files.Values) }
            $fake | Add-Member ScriptMethod Close { $this.Opened=$false }
            $fake | Add-Member ScriptMethod Dispose { $this.Opened=$false }
            return $fake
        }
    }
    AfterAll { Remove-Module PowerScpFeatureHarness }
    BeforeEach { $fake=New-FeatureSession }
    It 'blocks rename traversal and handles parent paths as remote paths' {
        { Rename-ScpItem -Session $fake -RemotePath '/data/old.txt' -NewName '../new.txt' } | Should -Throw '*single filename*'
        Rename-ScpItem -Session $fake -RemotePath '/data/old.txt' -NewName new.txt
        $call=@($fake.Calls | Where-Object { $_[0] -eq 'Move' })[0]
        $call[2] | Should -Be '/data/new.txt'
    }
    It 'requires Force for replacement and never deletes a destination directory' {
        $fake.Files['/dest.txt']=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false}
        { Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' } | Should -Throw '*already exists*'
        Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force
        @($fake.Calls | Where-Object { $_[0] -eq 'Remove' }).Count | Should -Be 1
        $fake.Files['/dir']=[pscustomobject]@{FullName='/dir';Name='dir';IsDirectory=$true}
        $fake.Files['/dir/source.txt']=[pscustomobject]@{FullName='/dir/source.txt';Name='source.txt';IsDirectory=$true}
        { Move-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dir' -Force } | Should -Throw '*directory*'
    }
    It 'refuses to overwrite the source itself' {
        $fake.Files['/source.txt']=[pscustomobject]@{FullName='/source.txt';Name='source.txt';IsDirectory=$false}
        { Move-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/source.txt' -Force } | Should -Throw '*same item*'
        @($fake.Calls | Where-Object { $_[0] -eq 'Remove' }).Count | Should -Be 0
    }
    It 'creates empty files and removes temporary files on success and failure' {
        New-ScpItem -Session $fake -RemotePath '/empty.txt' | Out-Null
        $fake.Bytes.Length | Should -Be 0
        Test-Path -LiteralPath $fake.TempPath | Should -BeFalse
        $fake.Fail=$true
        { New-ScpItem -Session $fake -RemotePath '/config.txt' -Value 'settings' } | Should -Throw '*Transfer failed*'
        Test-Path -LiteralPath $fake.TempPath | Should -BeFalse
    }
    It 'writes exact UTF-8 content and rejects append settings for replacement' {
        Set-ScpContent -Session $fake -RemotePath '/config.txt' -Value "hello`nworld" | Out-Null
        [Text.Encoding]::UTF8.GetString($fake.Bytes) | Should -Be "hello`nworld"
        Test-Path -LiteralPath $fake.TempPath | Should -BeFalse
        { Set-ScpContent -Session $fake -RemotePath '/config.txt' -Value text -TransferOptions (New-ScpTransferOptions -OverWriteMode Append) } | Should -Throw '*Overwrite*'
    }
    It 'reads lines or raw text and disposes the download stream' {
        @(Get-ScpContent -Session $fake -RemotePath '/config.txt') | Should -Be @('one','two')
        $fake.Stream.CanRead | Should -BeFalse
        Get-ScpContent -Session $fake -RemotePath '/config.txt' -Raw | Should -Be "one`ntwo`n"
        $fake.Stream.CanRead | Should -BeFalse
    }
    It 'compares directories without uploading or deleting' {
        $diff=Compare-ScpDirectory -Session $fake -LocalPath $TestDrive -RemotePath '/root' -Remove
        $diff.Action | Should -Be UploadNew
        $fake.Calls.Count | Should -Be 1
        $fake.Calls[0][0] | Should -Be Compare
        $fake.Calls[0][4] | Should -BeTrue
    }
    It 'does not write, replace, rename or close anything during WhatIf' {
        New-ScpItem -Session $fake -RemotePath '/file.txt' -WhatIf
        Set-ScpContent -Session $fake -RemotePath '/file.txt' -Value text -WhatIf
        Rename-ScpItem -Session $fake -RemotePath '/old.txt' -NewName new.txt -WhatIf
        Close-ScpSession -Session $fake -WhatIf
        $fake.Calls.Count | Should -Be 0
        $fake.Opened | Should -BeTrue
    }
    It 'selects directories and returns names without file objects' {
        $fake.Files['/root/dir']=[pscustomobject]@{FullName='/root/dir';Name='dir';IsDirectory=$true}
        $fake.Files['/root/file']=[pscustomobject]@{FullName='/root/file';Name='file';IsDirectory=$false}
        @(Get-ScpChildItem -Session $fake -RemotePath /root -DirectoriesOnly -Name) | Should -Be @('dir')
    }
    It 'downloads a literal file under a different local name' {
        Receive-ScpItem -Session $fake -RemotePath '/report[1].txt' -LocalPath $TestDrive -LiteralPath -DestinationFileName 'saved.txt' | Out-Null
        $fake.Calls[0][1] | Should -Be '/report[[]1].txt'
        $fake.Calls[0][2] | Should -Be (Join-Path $TestDrive saved.txt)
        { Receive-ScpItem -Session $fake -RemotePath '/*.txt' -LocalPath $TestDrive -DestinationFileName saved.txt } | Should -Throw '*literal*'
    }
    It 'refuses content writes to directory destinations' {
        { Set-ScpContent -Session $fake -RemotePath '/dir/' -Value text } | Should -Throw '*file path*'
        $fake.Files['/dir']=[pscustomobject]@{FullName='/dir';Name='dir';IsDirectory=$true}
        { Set-ScpContent -Session $fake -RemotePath '/dir' -Value text } | Should -Throw '*directory*'
        @($fake.Calls | Where-Object { $_[0] -eq 'Put' }).Count | Should -Be 0
    }

    It 'closes reusable sessions and unregisters them only on disposal' {
        & (Get-Module PowerScpFeatureHarness) { param($session) $script:ScpSessions['archive']=$session } $fake
        Close-ScpSession -Session $fake
        $fake.Opened | Should -BeFalse
        @(Get-ScpSession -Name archive).Count | Should -Be 1
        @(Get-ScpSession -OpenedOnly).Count | Should -Be 0
        Remove-ScpSession -Session $fake | Out-Null
        { Get-ScpSession -Name archive } | Should -Throw '*No session*'
    }

    It 'rejects rename to an existing directory without moving the source' {
        $fake.Files['/data/archive']=[pscustomobject]@{FullName='/data/archive';Name='archive';IsDirectory=$true}
        { Rename-ScpItem -Session $fake -RemotePath '/data/report.txt' -NewName archive -Force } | Should -Throw '*directory*'
        @($fake.Calls | Where-Object { $_[0] -in @('Move','Remove') }).Count | Should -Be 0
    }
    It 'requires binary mode for exact content writes' {
        foreach ($mode in @('Ascii','Automatic')) {
            { Set-ScpContent -Session $fake -RemotePath '/text.txt' -Value "one`ntwo" -TransferOptions (New-ScpTransferOptions -TransferMode $mode) } | Should -Throw '*Binary*'
            { New-ScpItem -Session $fake -RemotePath '/text.txt' -Value text -TransferOptions (New-ScpTransferOptions -TransferMode $mode) } | Should -Throw '*Binary*'
        }
        @($fake.Calls | Where-Object { $_[0] -eq 'Put' }).Count | Should -Be 0
    }
    It 'rejects directory sources and invalid Windows download names' {
        $fake.Files['/dir']=[pscustomobject]@{FullName='/dir';Name='dir';IsDirectory=$true}
        { Receive-ScpItem -Session $fake -RemotePath '/dir' -LocalPath $TestDrive -LiteralPath -DestinationFileName saved.txt } | Should -Throw '*remote file*'
        foreach ($name in @('bad*.txt','bad?.txt','file:stream','CON.txt','trailing.','trailing ','bad|name')) {
            { Receive-ScpItem -Session $fake -RemotePath '/file' -LocalPath $TestDrive -LiteralPath -DestinationFileName $name } | Should -Throw '*Windows filename*'
        }
        @($fake.Calls | Where-Object { $_[0] -eq 'Get' }).Count | Should -Be 0
    }
    It 'restores the original destination when replacement fails' {
        $fake.Files['/dest.txt']=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false}
        $fake | Add-Member ScriptMethod MoveFile {
            param($source,$target)
            $this.Calls.Add(@('Move',$source,$target))
            $this.Files[$target]=$this.Files[$source]
            $this.Files.Remove($source)
        } -Force
        $fake | Add-Member ScriptMethod DuplicateFile { param($source,$target) throw 'Copy failed' } -Force
        { Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force } | Should -Throw '*Copy failed*'
        $fake.Files.ContainsKey('/dest.txt') | Should -BeTrue
        @($fake.Files.Keys | Where-Object { $_ -like '*powerscp-backup*' }).Count | Should -Be 0
        @($fake.Calls | Where-Object { $_[0] -eq 'Remove' }).Count | Should -Be 0
    }
    It 'retains the backup and partial target if restoration is unsafe' {
        $fake.Files['/dest.txt']=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false}
        $fake | Add-Member ScriptMethod MoveFile {
            param($source,$target)
            $this.Files[$target]=$this.Files[$source]; $this.Files.Remove($source)
        } -Force
        $fake | Add-Member ScriptMethod DuplicateFile {
            param($source,$target)
            $this.Files[$target]=[pscustomobject]@{FullName=$target;IsDirectory=$false}
            throw 'Partial copy failed'
        } -Force
        { Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force } | Should -Throw '*recover it manually*'
        $fake.Files.ContainsKey('/dest.txt') | Should -BeTrue
        @($fake.Files.Keys | Where-Object { $_ -like '*powerscp-backup*' }).Count | Should -Be 1
    }
    It 'rejects directory-over-file replacement before preserving or deleting the target' {
        $fake.Files['/source']=[pscustomobject]@{FullName='/source';Name='source';IsDirectory=$true}
        $fake.Files['/dest']=[pscustomobject]@{FullName='/dest';Name='dest';IsDirectory=$false}
        { Move-ScpItem -Session $fake -RemotePath '/source' -Destination '/dest' -Force } | Should -Throw '*file with a directory*'
        @($fake.Calls | Where-Object { $_[0] -in @('Move','Remove') }).Count | Should -Be 0
    }
    It 'disposes tracked sessions when the module is removed' {
        & (Get-Module PowerScpFeatureHarness) { param($session) $script:ScpSessions['tracked']=$session } $fake
        Remove-Module PowerScpFeatureHarness
        $fake.Opened | Should -BeFalse
        Import-Module $adapter -Force
    }

    It 'removes the backup only after successful replacement' {
        $original=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false;Content='old'}
        $replacement=[pscustomobject]@{FullName='/source.txt';Name='source.txt';IsDirectory=$false;Content='new'}
        $fake.Files['/dest.txt']=$original
        $fake.Files['/source.txt']=$replacement
        $fake | Add-Member ScriptMethod MoveFile {
            param($source,$target)
            $this.Calls.Add(@('Move',$source,$target)); $this.Files[$target]=$this.Files[$source]; $this.Files.Remove($source)
        } -Force
        $fake | Add-Member ScriptMethod DuplicateFile {
            param($source,$target)
            $this.Calls.Add(@('Copy',$source,$target)); $this.Files[$target]=$this.Files[$source]
        } -Force
        $fake | Add-Member ScriptMethod RemoveFile {
            param($path) $this.Calls.Add(@('Remove',$path)); $this.Files.Remove($path)
        } -Force
        Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force
        $fake.Files['/dest.txt'].Content | Should -Be new
        @($fake.Files.Keys | Where-Object { $_ -like '*powerscp-backup*' }).Count | Should -Be 0
        @($fake.Calls | Where-Object { $_[0] -in @('Move','Copy','Remove') } | ForEach-Object { $_[0] }) | Should -Be @('Move','Copy','Remove')
    }
    It 'does not attempt replacement when the original cannot be backed up' {
        $fake.Files['/dest.txt']=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false}
        $fake | Add-Member ScriptMethod MoveFile { param($source,$target) throw 'Backup denied' } -Force
        { Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force } | Should -Throw '*Backup denied*'
        $fake.Files.ContainsKey('/dest.txt') | Should -BeTrue
        @($fake.Calls | Where-Object { $_[0] -in @('Copy','Remove') }).Count | Should -Be 0
    }
    It 'reports retained originals when successful replacement cannot clean its backup' {
        $fake.Files['/dest.txt']=[pscustomobject]@{FullName='/dest.txt';Name='dest.txt';IsDirectory=$false}
        $fake | Add-Member ScriptMethod RemoveFile { param($path) throw 'Cleanup denied' } -Force
        $warnings=@()
        Copy-ScpItem -Session $fake -RemotePath '/source.txt' -Destination '/dest.txt' -Force -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings.Count | Should -Be 1
        $warnings[0].ToString() | Should -Match 'Replacement succeeded.*powerscp-backup-'
    }

}
