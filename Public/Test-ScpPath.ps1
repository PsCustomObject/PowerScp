function Test-ScpPath
{
<#
	.SYNOPSIS
		Check if path exists
	
	.DESCRIPTION
		Will check if path on a remote WinSCP Session exists.
	
	.PARAMETER Session
		A valid WinSCP.Session object. Requires connection to be in open state.
	
	.PARAMETER RemotePath
		A string representing path on the remote host.
	
	.PARAMETER Debug
		When used will display full error, if any, output instead of exception message only.
	
	.EXAMPLE
		PS C:\> Test-ScpPath -Session $value1 -RemotePath $value2
#>
	
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
		[string[]]$RemotePath,
		[switch]$Debug
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
				
				if ($PSBoundParameters.ContainsKey('Debug'))
				{
					Write-Error -Message $_
				}
				else
				{
					# Save exception message
					[string]$reportedException = $_.Exception.Message
					
					Write-Error -Message $reportedException
				}
			}
		}
	}
}
