# Load moule's function
$paramGetChildItem = @{
	Path = "$PSScriptRoot\Public\*.ps1", "$PSScriptRoot\Support\*.ps1"
	Exclude = '*.tests.ps1', '*profile.ps1'
	ErrorAction = 'SilentlyContinue'
}

Get-ChildItem @paramGetChildItem |
ForEach-Object { . $_.FullName }

# Load assembly
Add-Type -Path "$PSScriptRoot\lib\WinSCPnet.dll"