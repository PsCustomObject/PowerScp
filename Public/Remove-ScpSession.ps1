function Remove-ScpSession
{
<#
	.SYNOPSIS
		Will close an SCP Session
	
	.DESCRIPTION
		Will close an SCP Session using dispoe() method. A disposed sesison cannot be re-used or re-opened.
	
	.PARAMETER Session
		A WinSCP.Session object.
	
	.EXAMPLE
				PS C:\> Close-ScpSession -Session $value1
	
	.NOTES
		Additional information about the function.
#>
	
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[WinSCP.Session]$Session
	)
	
	begin
	{
		# Get arguments from pipeline
		$sessionValueFromPipeLine = $PSBoundParameters.ContainsKey('Session')
	}
	process
	{
		try
		{
			$Session.Dispose()
			
			return $true
		}
		catch
		{
			return $false
		}
	}
}
