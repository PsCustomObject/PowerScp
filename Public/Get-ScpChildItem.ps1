function Get-ScpChildItem
{
<#
	.SYNOPSIS
		Function will return items on a remote server.
	
	.DESCRIPTION
		Function will return items on a remote session where an SCP Session has been established.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.PARAMETER RemotePath
		A string representing a folder on the remote server. If path does not exist script will return a $null value and print an error.
	
	.PARAMETER Filter
		Windows wildcard to filter files, if not spcecified will default to $null returning all files. If a filename is specified only that item will be returned.
	
	.PARAMETER Recurse
		When specified it will cause function to recurse in any subfolder in the remote path
	
	.PARAMETER Depth
		Paramter can only be used when the -Recurse parameter is also specified and is used to limite the number of levels, folder, function will recurse in.
		
		If -Recurse is used and -Depth is not specified it will default to 0 meaning no recursion limit will be applied.
	
	.PARAMETER FilesOnly
		When specified it will list/return files only omitting any matching directory.
	
	.EXAMPLE
		PS C:\> Get-ScpChildItem -Session $scpSession -FilesOnly
	
	.OUTPUTS
		WinSCP.RemoteFileInfo, System.Null
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding(DefaultParameterSetName = 'Recurse')]
	[OutputType([array], ParameterSetName = 'Recurse')]
	[OutputType([array], ParameterSetName = 'NoRecurse')]
	[OutputType([WinSCP.RemoteFileInfo])]
	param
	(
		[Parameter(ParameterSetName = 'NoRecurse',
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[Parameter(ParameterSetName = 'Recurse')]
		[SupportsWildcards()]
		[WinSCP.Session]
		$Session,
		[Parameter(ParameterSetName = 'NoRecurse',
				   Mandatory = $true)]
		[Parameter(ParameterSetName = 'Recurse')]
		[ValidateNotNullOrEmpty()]
		[string[]]
		$RemotePath,
		[Parameter(ParameterSetName = 'NoRecurse')]
		[Parameter(ParameterSetName = 'Recurse')]
		[ValidateNotNullOrEmpty()]
		[string]
		$Filter = $null,
		[Parameter(ParameterSetName = 'Recurse')]
		[switch]
		$Recurse,
		[Parameter(ParameterSetName = 'Recurse')]
		[int]
		$Depth = 0,
		[Parameter(ParameterSetName = 'Recurse')]
		[Parameter(ParameterSetName = 'NoRecurse')]
		[switch]
		$FilesOnly
	)
	
	begin
	{
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
		switch ($PsCmdlet.ParameterSetName)
		{
			'Recurse'
			{
				# Recurse into subfolders
				[WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::AllDirectories -bor [WinSCP.EnumerationOptions]::MatchDirectories
			}
			'NoRecurse'
			{
				# Enumerate matching directories without recursing
				[WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None -bor [WinSCP.EnumerationOptions]::MatchDirectories
			}
		}
		
		foreach ($path in $RemotePath)
		{
			# Format path for SCP session
			[string]$path = Format-StringPath -Path $path
			
			# Validate path exists
			if (!(Test-ScpPath -RemotePath $path -Session $Session))
			{
				Write-Error -Message "Cannot find path: $path because it does not exist"
				
				continue
			}
			
			switch ($PSBoundParameters)
			{
				'FilesOnly'
				{
					# Enumerate files only
					[WinSCP.EnumerationOptions]$enumOptions = [WinSCP.EnumerationOptions]::None
				}
			}
			
			try
			{
				# Get matching items
				$Session.EnumerateRemoteFiles($path, $Filter, $enumOptions)
			}
			catch
			{
				# Save exception message
				[string]$reportedException = $_.Exception.Message
				
				Write-Error -Message $reportedException
				
				return $null
			}
		}
	}
}