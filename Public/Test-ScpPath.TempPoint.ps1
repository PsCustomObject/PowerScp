function Test-ScpPath
{
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[ValidateScript({
				if ($_.Opened)
				{
					return $true
				}
				else
				{
					throw 'Session must be in Open State - Aborting'
				}
			})]
		[WinSCP.Session]$Session,
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$RemotePath
	)
	
	begin
	{
		# Get arguments from pipeline
		$sessionValueFromPipeLine = $PSBoundParameters.ContainsKey('Session')
	}
	
	process
	{
		foreach ($item in (Format-StringPath -Path $($RemotePath)))
		{
			try
			{
				# Check if remote file exists
				$Session.FileExists($item)
			}
			catch
			{
				# Get last error message
				[string]$reportedException = $Error[0].Exception.Message
				
				Write-Error -Message $reportedException #TODO: Revise this maybe write a warning and have full output?
			}
		}
	}
}
