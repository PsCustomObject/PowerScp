function Start-WinScpConsole
{
<#
	.SYNOPSIS
		Will open WinSCP Console
	
	.DESCRIPTION
		Function will invoke WinSCP console and will wait till the window is closed before terminating execution.
	
	.EXAMPLE
		PS C:\> Start-WinScpConsole
#>
	
	[OutputType([void])]
	param ()
	
	# Define WinSCP exe path
	[string]$exePath = "$PSScriptRoot\..\bin\WinSCP.exe"
	
	# Define exe arguments
	[string]$scpArgs = '/Console'
	
	# Launch WinSCP console
	$paramStartProcess = @{
		FilePath	 = $exePath
		ArgumentList = $scpArgs
		Wait		 = $true
	}
	
	Start-Process @paramStartProcess
}