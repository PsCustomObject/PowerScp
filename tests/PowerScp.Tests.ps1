BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'PowerScp.psd1') -Force -ErrorAction Stop }
BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $root 'PowerScp.psd1') -Force -ErrorAction Stop
}
Describe 'Public module contract' {
    It 'imports the manifest and exports only public commands' {
        $manifest = Test-ModuleManifest (Join-Path $root 'PowerScp.psd1') -ErrorAction Stop
        $manifest.Version | Should -Be '1.2.0'
        @(Get-Command -Module PowerScp).Count | Should -Be 31
        Get-Command Assert-ScpSession -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'applies all transfer settings simultaneously' {
        $options = New-ScpTransferOptions -Permissions '0755' -SpeedLimit 1024 -FileMask '*.txt' -OverWriteMode Resume -PreserveTimeStamp $false -TransferMode Text
        $options.FilePermissions.Octal | Should -Be '755'
        $options.SpeedLimit | Should -Be 1024
        $options.FileMask | Should -Be '*.txt'
        $options.OverwriteMode.ToString() | Should -Be 'Resume'
        $options.PreserveTimestamp | Should -BeFalse
        $options.TransferMode.ToString() | Should -Be 'Ascii'
    }
    It 'rejects invalid octal permissions and negative speeds' {
        { New-ScpTransferOptions -Permissions 789 } | Should -Throw
        { New-ScpTransferOptions -SpeedLimit -1 } | Should -Throw
    }
    It 'binds and validates a piped session in process' {
        $session = New-Object WinSCP.Session
        try {
            $session | Test-ScpSession | Should -BeFalse
            { $session | Test-ScpPath -RemotePath '/' } | Should -Throw '*not in an open state*'
        } finally { $session.Dispose() }
    }
    It 'normalizes each piped remote path' {
        @('a\b','c\d') | Format-StringPath | Should -Be @('a/b','c/d')
    }
}
Describe 'Connection options' {
    InModuleScope PowerScp {
        It 'preserves protocol, credentials, port defaults and timeout' {
            $cred = [pscredential]::new('alice',(ConvertTo-SecureString 'secret' -AsPlainText -Force))
            $options = New-ScpSessionOptions -RemoteHost example.org -Credentials $cred -Protocol Sftp -SshHostKeyFingerprint @(('a'*43),('b'*43)) -ConnectionTimeOut ([timespan]::FromSeconds(30))
            $options.Protocol.ToString() | Should -Be 'Sftp'
            $options.PortNumber | Should -Be 0
            $options.UserName | Should -Be 'alice'
            $options.SecurePassword.Length | Should -Be 6
            $options.Timeout.TotalSeconds | Should -Be 30
            $options.SshHostKeyFingerprint | Should -Be (('a'*43)+';'+('b'*43))
        }
        It 'honors explicit false security switches' {
            { New-ScpSessionOptions -Protocol Sftp -NoSshKeyCheck:$false } | Should -Throw '*fingerprint*'
            $options = New-ScpSessionOptions -Protocol Sftp -SshHostKeyFingerprint ('a'*43) -NoSshKeyCheck:$false -NoTlsCheck:$false
            $options.GiveUpSecurityAndAcceptAnySshHostKey | Should -BeFalse
            $options.GiveUpSecurityAndAcceptAnyTlsHostCertificate | Should -BeFalse
        }
        It 'sets WebDAV root and TLS options and rejects invalid protocol combinations' {
            $options = New-ScpSessionOptions -Protocol Webdav -WebDavSecure -WebDavRoot '/dav' -TlsHostCertificateFingerprint ((@('aa')*32)-join ':')
            $options.RootPath | Should -Be '/dav'
            $options.WebdavSecure | Should -BeTrue
            $options.TlsHostCertificateFingerprint | Should -Be ((@('aa')*32)-join ':')
            { New-ScpSessionOptions -Protocol S3 -WebDavSecure } | Should -Throw '*WebDAV*'
        }
        It 'allows unencrypted private keys without a passphrase' {
            $keyPath = Join-Path $TestDrive 'key.ppk'
            Set-Content $keyPath 'test key'
            $options = New-ScpSessionOptions -Protocol Sftp -SshHostKeyFingerprint ('a'*43) -SshKeyPath $keyPath
            $options.SshPrivateKeyPath | Should -Be $keyPath
        }
        It 'disposes a failed connection and allows key-only authentication' {
            $fake = [pscustomobject]@{ Disposed=$false; XmlLogPreserve=$false }
            $fake | Add-Member ScriptMethod Open { param($options) throw 'Open failed' }
            $fake | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
            Mock New-ScpSessionObject { $fake }
            { New-ScpSession -RemoteHost example.org -UserName alice -Protocol Sftp -SshHostKeyFingerprint ('a'*43) } | Should -Throw '*Open failed*'
            $fake.Disposed | Should -BeTrue
        }
        It 'applies FTP connection options' {
            $options = New-ScpSessionOptions -RemoteHost example.org -Protocol Ftp -ServerPort 2121 -FtpMode Active -FtpSecure Explicit
            $options.FtpMode.ToString() | Should -Be Active
            $options.FtpSecure.ToString() | Should -Be Explicit
            $options.PortNumber | Should -Be 2121
        }
        It 'uses the requested fingerprint scan settings and disposes its session' {
            $fake = [pscustomobject]@{ Disposed=$false; Scanned=$null }
            $fake | Add-Member ScriptMethod ScanFingerprint { param($options,$algorithm) $this.Scanned=$options; return $algorithm }
            $fake | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
            Mock New-ScpSessionObject { $fake }
            Get-HostFingerPrint -RemoteHost example.org -UserName alice -Password secret -PortNumber 2222 -Protocol Sftp | Should -Be 'SHA-256'
            $fake.Scanned.Password | Should -Be secret
            $fake.Scanned.PortNumber | Should -Be 2222
            $fake.Scanned.Protocol.ToString() | Should -Be Sftp
            $fake.Disposed | Should -BeTrue
        }
    }
}
# WinSCP.Session is sealed and its methods are not virtual. This temporary adapter
# removes only Session type annotations so test doubles can exercise the unchanged
# function bodies. Public type binding is covered above with the real assembly.
Describe 'Transfer and enumeration regressions' {
    BeforeAll {
        $source = Get-Content (Join-Path $root 'PowerScp.psm1') -Raw
        $source = $source.Substring($source.IndexOf('function Assert-ScpPlatform'))
        $source = $source.Replace('[WinSCP.Session]','[object]')
        $adapter = Join-Path $TestDrive 'PowerScpHarness.psm1'
        Set-Content $adapter $source -Encoding utf8
        Import-Module $adapter -Force
        function New-FakeSession {
            $fake = [pscustomobject]@{ Opened=$true; Calls=[collections.generic.list[object]]::new(); Items=@(); Exists=$true; Fail=$false }
            $fake | Add-Member ScriptMethod FileExists { param($path) $this.Calls.Add(@('Exists',$path)); return $this.Exists }
            $fake | Add-Member ScriptMethod GetFileInfo { param($path) return [pscustomobject]@{IsDirectory=$true;FullName=$path;Name='dir'} }
            $fake | Add-Member ScriptMethod CreateDirectory { param($path) $this.Calls.Add(@('Create',$path)) }
            $fake | Add-Member ScriptMethod PutFiles {
                param($local,$remote,$remove,$options)
                $this.Calls.Add(@('Put',$local,$remote,$remove,$options))
                $result=[pscustomobject]@{Fail=$this.Fail;Checked=$false}
                $result | Add-Member ScriptMethod Check { $this.Checked=$true; if($this.Fail){throw 'Transfer failed'} }
                return $result
            }
            $fake | Add-Member ScriptMethod GetFiles {
                param($remote,$local,$remove,$options)
                return $this.PutFiles($local,$remote,$remove,$options)
            }
            $fake | Add-Member ScriptMethod RemoveFiles {
                param($path) $this.Calls.Add(@('Remove',$path)); return $this.PutFiles('',$path,$false,$null)
            }
            $fake | Add-Member ScriptMethod MoveFile { param($source,$destination) $this.Calls.Add(@('Move',$source,$destination)) }
            $fake | Add-Member ScriptMethod DuplicateFile { param($source,$destination) $this.Calls.Add(@('Copy',$source,$destination)) }
            $fake | Add-Member ScriptMethod ExecuteCommand { param($command) return $this.PutFiles('',$command,$false,$null) }
            $fake | Add-Member ScriptMethod SynchronizeDirectories {
                param($mode,$local,$remote,$remove,$mirror,$criteria,$options)
                $this.Calls.Add(@('Sync',$mode,$local,$remote,$remove,$mirror,$criteria,$options))
                return $this.PutFiles($local,$remote,$remove,$options)
            }
            $fake | Add-Member ScriptMethod CalculateFileChecksum { param($algorithm,$path) $this.Calls.Add(@('Hash',$algorithm,$path)); return 'abc123' }
            $fake | Add-Member ScriptMethod EnumerateRemoteFiles { param($path,$filter,$options) $this.Calls.Add(@('List',$path,$filter,$options)); return $this.Items }
            return $fake
        }
    }
    AfterAll { Remove-Module PowerScpHarness }
    BeforeEach {
        $fake=New-FakeSession
        $local=Join-Path $TestDrive 'source[1].txt'
        Set-Content -LiteralPath $local 'contents'
    }
    It 'uploads without TransferFilesOnly and never interprets overwrite mode as removal' {
        $result=Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -OverWriteMode Resume
        $call=@($fake.Calls | Where-Object { $_[0] -eq 'Put' })[0]
        $call[1] | Should -Be ($local.Replace('[','[[]'))
        $call[2] | Should -Be '/upload/'
        $call[3] | Should -BeFalse
        $call[4].OverwriteMode.ToString() | Should -Be Resume
        $result.Checked | Should -BeTrue
    }
    It 'performs no remote reads or writes under WhatIf, even when the directory is missing' {
        $fake.Exists=$false
        Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/missing/' -WhatIf
        $fake.Calls.Count | Should -Be 0
        New-ScpDirectory -Session $fake -RemotePath '/missing' -WhatIf
        @($fake.Calls | Where-Object { $_[0] -eq 'Create' }).Count | Should -Be 0
    }
    It 'checks transfer failures and propagates ErrorAction Stop' {
        $fake.Fail=$true
        { Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -ErrorAction Stop } | Should -Throw '*Transfer failed*'
    }
    It 'uploads the single file when TransferFilesOnly is specified' {
        Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -TransferFilesOnly | Out-Null
        @($fake.Calls | Where-Object { $_[0] -eq 'Put' }).Count | Should -Be 1
    }
    It 'rejects flattened duplicate names before a remote mutation' {
        $folder=Join-Path $TestDrive 'tree'
        New-Item -ItemType Directory -Path (Join-Path $folder a),(Join-Path $folder b) -Force | Out-Null
        Set-Content (Join-Path $folder 'a/same.txt') 'a'
        Set-Content (Join-Path $folder 'b/same.txt') 'b'
        { Send-ScpItem -Session $fake -LocalPath $folder -RemotePath '/upload' -TransferFilesOnly } | Should -Throw '*duplicate*'
        $fake.Calls.Count | Should -Be 0
    }
    It 'uses the supplied checksum path and algorithm' {
        Get-ScpItemCheckSum -Session $fake -ItemName 'dir\file.txt' -HashAlgorithm sha-256 | Should -Be abc123
        $fake.Calls[0][2] | Should -Be 'dir/file.txt'
    }
    It 'retains recursion with FilesOnly and enforces Depth' {
        $fake.Items=@(
            [pscustomobject]@{FullName='/root/a.txt';IsDirectory=$false},
            [pscustomobject]@{FullName='/root/child/b.txt';IsDirectory=$false},
            [pscustomobject]@{FullName='/root/child/deeper/c.txt';IsDirectory=$false},
            [pscustomobject]@{FullName='/root/child';IsDirectory=$true}
        )
        @(Get-ScpChildItem -Session $fake -RemotePath '/root' -Recurse -Depth 1 -FilesOnly).Count | Should -Be 2
        $fake.Calls[0][3].ToString() | Should -Be AllDirectories
    }
    It 'downloads without removing sources and checks results' {
        $result=Receive-ScpItem -Session $fake -RemotePath '/remote/*.txt' -LocalPath $TestDrive
        $fake.Calls[0][3] | Should -BeFalse
        $result.Checked | Should -BeTrue
    }
    It 'escapes literal deletion paths and checks removal failures' {
        $fake.Fail=$true
        { Remove-ScpItem -Session $fake -RemotePath '/data/[1].txt' -Confirm:$false -ErrorAction Stop } | Should -Throw '*Transfer failed*'
        $fake.Calls[0][1] | Should -Be '/data/[[]1].txt'
    }
    It 'honors WhatIf across every remote mutation wrapper' {
        Receive-ScpItem -Session $fake -RemotePath '/file' -LocalPath $TestDrive -WhatIf
        Remove-ScpItem -Session $fake -RemotePath '/file' -WhatIf
        Move-ScpItem -Session $fake -RemotePath '/file' -Destination '/new' -WhatIf
        Copy-ScpItem -Session $fake -RemotePath '/file' -Destination '/new' -WhatIf
        Invoke-ScpCommand -Session $fake -Command 'echo hello' -WhatIf
        Sync-ScpDirectory -Session $fake -LocalPath $TestDrive -RemotePath '/root' -WhatIf
        $fake.Calls.Count | Should -Be 0
    }
    It 'passes synchronization settings and checks results' {
        $result=Sync-ScpDirectory -Session $fake -LocalPath $TestDrive -RemotePath '/root' -Mode Local -Remove -Mirror
        $fake.Calls[0][1].ToString() | Should -Be Local
        $fake.Calls[0][4] | Should -BeTrue
        $fake.Calls[0][5] | Should -BeTrue
        $result.Checked | Should -BeTrue
        { Sync-ScpDirectory -Session $fake -LocalPath $TestDrive -RemotePath '/root' -Mode Both -Remove } | Should -Throw '*Mode Both*'
    }
    It 'checks remote command failures' {
        $fake.Fail=$true
        { Invoke-ScpCommand -Session $fake -Command 'bad command' } | Should -Throw '*Transfer failed*'
    }
    It 'uses caller-provided transfer options unchanged' {
        $options=New-ScpTransferOptions -SpeedLimit 10
        Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -TransferOptions $options | Out-Null
        $call=@($fake.Calls | Where-Object { $_[0] -eq 'Put' })[0]
        [object]::ReferenceEquals($call[4],$options) | Should -BeTrue
    }

    It 'removes files by mask only when explicitly requested' {
        Remove-ScpItem -Session $fake -RemotePath '/data/*.tmp' -UseFileMask -Confirm:$false | Out-Null
        $fake.Calls[0][1] | Should -Be '/data/*.tmp'
    }
    It 'uploads with an explicit destination filename and source removal' {
        Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -DestinationFileName 'renamed.txt' -Remove | Out-Null
        $call=@($fake.Calls | Where-Object { $_[0] -eq 'Put' })[0]
        $call[2] | Should -Be '/upload/renamed.txt'
        $call[3] | Should -BeTrue
        { Send-ScpItem -Session $fake -LocalPath $local -RemotePath '/upload' -DestinationFileName '../bad.txt' } | Should -Throw '*single filename*'
    }
    It 'executes multiple commands and checks each result' {
        @(Invoke-ScpCommand -Session $fake -Command @('first','second')).Count | Should -Be 2
    }

}

