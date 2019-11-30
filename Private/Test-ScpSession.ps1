function Test-ScpSession
{
<#
	.SYNOPSIS
		Test if a WinSCP.Session object is in oppen state.
	
	.DESCRIPTION
		Helper function to test test if a WinSCP.Session object is in open state.
	
	.PARAMETER Session
		A WinSCP.Session object for which status should be checked.
	
	.EXAMPLE
		PS C:\> Test-ScpSession -Session $value1
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[Alias('SCpSession', 'WinScpSession')]
		[WinSCP.Session]
		$Session
	)
	
	if ($Session.Opened)
	{
		Write-Verbose -Message 'Session is open'
		
		return $true
	}
	else
	{
		Write-Verbose -Message 'Session is not in open state'
		
		return $false
	}
}