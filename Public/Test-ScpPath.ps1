function Test-ScpPath
{
<#
	.SYNOPSIS
		Checks if path on a remote WinSCP Session exists.
	
	.DESCRIPTION
		Checks if path on a remote WinSCP Session exists.
	
	.PARAMETER Session
		A valid WinSCP.Session object. Requires connection to be in open state.
	
	.PARAMETER RemotePath
		A string representing path on the remote host.
	
	.EXAMPLE
		PS C:\> Test-ScpPath -Session $value1 -RemotePath $value2
#>
	
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[WinSCP.Session]
		$Session,
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$RemotePath
	)
	
	begin
	{
		# Check session state
		if (Test-ScpSession -Session $Session)
		{
			Write-Verbose -Message 'Session is in open state we can continue'
		}
		else
		{
			throw 'The WinSCP Session is not in an open state'
		}
	}
	
	process
	{
		# Sanitize input path
		$RemotePath = Format-StringPath -Path $RemotePath
		
		try
		{
			$Session.FileExists($RemotePath)
		}
		catch
		{
			if ($PSBoundParameters.ContainsKey('Verbose'))
			{
				# Save exception message
				[string]$reportedException = $_.Exception.Message
				
				Write-Error -Message $reportedException
			}
			
			return $false
		}
	}
}