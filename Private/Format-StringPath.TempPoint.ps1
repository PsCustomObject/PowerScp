function Format-StringPath
{
	[OutputType([String])]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]]$Path
	)
	
	Process
	{
		foreach ($item in $Path)
		{
			# Sanitize input
			if ($item.Contains('\'))
			{
				$item = $item.Replace('\', '/')
			}
			
			$item
		}
	}
}