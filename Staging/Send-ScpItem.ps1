function Send-ScpItem
{
<#
    .SYNOPSIS
        A brief description of the Send-ScpItem function.
    
    .DESCRIPTION
        A detailed description of the Send-ScpItem function.
    
    .PARAMETER LocalPath
        A description of the LocalPath parameter.
    
    .PARAMETER RemotePath
        A description of the RemotePath parameter.
    
    .PARAMETER Session
        A description of the Session parameter.
    
    .PARAMETER OverWriteMode
        Specifies behavior when overwriting files on remote destination. 
        
        Note that not all options apply to all protocols.
    
    .PARAMETER SpeedLimit
        A description of the SpeedLimit parameter.
    
    .EXAMPLE
        PS C:\> Send-ScpItem -LocalPath 'value1' -RemotePath 'value2' -Session $Session
    
    .NOTES
        Additional information about the function.
#>
    
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $LocalPath,
        [Parameter(Mandatory = $true)]
        [string]
        $RemotePath,
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [WinSCP.Session]
        $Session,
        [ValidateSet('Overwrite', 'Resume', 'Append', IgnoreCase = $true)]
        [string]
        $OverWriteMode = 'Overwrite',
        [int]
        $SpeedLimit
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
                    [bool]$isDirectory = Get-ScpChildItem -RemotePath $RemotePath
                    
                    #TODO: If not dir we should skip or overwrite?
                    #TODO: If dir but missing trailing / we should add it
                    #TODO: If dir does not exist we should create it
                }
            }
        }
    }
}