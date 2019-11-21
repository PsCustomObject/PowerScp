function Format-StringPath
{
<#
	.SYNOPSIS
		Will format string in SCP format.
	
	.DESCRIPTION
		Will format string in SCP format replacing backslashes to slashes.
	
	.PARAMETER Path
		A string representing the path(s) to format.
	
	.EXAMPLE
		PS C:\> Format-StringPath -Path $value1
#>
	
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