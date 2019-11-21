function Close-ScpSession
{
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
