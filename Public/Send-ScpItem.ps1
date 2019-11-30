function Send-ScpItem
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string[]]$LocalPath,
		[Parameter(Mandatory = $true)]
		[string]$RemotePath,
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
		# Validate local paths
		foreach ($path in $LocalPath)
		{
			
			
			if (!(Test-Path $path))
			{
				Write-Warning -Message "Cannot find path $path because it does not exist"
				
				continue
			}
			else
			{
				if ($RemotePath.EndsWith('/') -eq $false)
				{
					# Check if path is a directory
					[bool]$isDirectory = Get-Sc
				}
			}
		}
	}
}
