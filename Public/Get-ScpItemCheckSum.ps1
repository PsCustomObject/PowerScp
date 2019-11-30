function Get-ScpItemCheckSum
{
<#
	.SYNOPSIS
		Function will get checksum of an item on remote host.
	
	.DESCRIPTION
		Function will get checksum of an item on remote host to which an SCP session has been established.
	
	.PARAMETER Session
		A WinSCP.Session object containing information about the remote host. Session must be in open state.
	
	.PARAMETER HashAlgorithm
		Specifies the algorithm to use when calculating item checksum.
	
	.PARAMETER ItemName
		A string representing the name of the item for which checksum should be calculated.
	
	.EXAMPLE
		PS C:\> Get-ScpItemCheckSum -Session $value1
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[WinSCP.Session]
		$Session,
		[SupportsWildcards()]
		[ValidateSet('md2', 'md5', 'sha-1', 'sha-224', 'sha-256', 'sha-384', 'sha-512', 'shake128', 'shake256', IgnoreCase = $true)]
		[string]
		$HashAlgorithm = 'md5',
		$ItemName
	)
	
	begin
	{
		# Check a session is open
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
		# Format path for SCP session
		[string]$path = Format-StringPath -Path $path
		
		# Validate path is valid
		if (!(Test-ScpPath -RemotePath $path -Session $Session))
		{
			Write-Error -Message "Cannot find path: $path because it does not exist"
			
			return $null
		}
		
		try
		{
			# Get matching items
			$Session.EnumerateRemoteFiles($path, $Filter, $enumOptions) #TODO: This requires full path and should be revised
			
			# Return item checksum
			return ($Session.CalculateFileChecksum($HashAlgorithm, $path))
		}
		catch
		{
			# Save exception message
			[string]$reportedException = $_.Exception.Message
			
			Write-Error -Message $reportedException
			
			return $null
		}
	}
}s