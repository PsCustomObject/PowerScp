function Remove-ScpItem
{
    <#
        .SYNOPSIS
            A brief description of the Remove-ScpItem function.
        
        .DESCRIPTION
            A detailed description of the Remove-ScpItem function.
        
        .PARAMETER RemotePath
            A string representing a folder on the remote server. If path does not exist script will return a $null value and print an error.
        
        .PARAMETER Session
            A WinSCP.Session object containing information about the remote host. 
        
            Session must be in open state or an exception will be thrown.
        
        .EXAMPLE
            PS C:\> Remove-ScpItem -RemotePath 'value1' -Session $Session
    #>
    
    [CmdletBinding(ConfirmImpact = 'High',
                   SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,
        [Parameter(Mandatory = $true)]
        [WinSCP.Session]
        $Session
    )
    
    begin
    {
        # Check session status
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
        foreach ($item in $RemotePath)
        {
            # Format path for SCP session
            [string]$item = Format-StringPath -Path $item
            
            # Validate path exists
            if (!(Test-ScpPath -RemotePath $item -Session $Session))
            {
                Write-Warning -Message "Cannot process $item because it does not exist"
                
                continue
            }
            
            if ($PSCmdlet.ShouldProcess($item))
            {
                try
                {
                    # Remove item
                    [void]($Session.RemoveFiles($item))
                }
                catch
                {
                    # Save exception message
                    [string]$reportedException = $_.Exception.Message
                    
                    Write-Error -Message $reportedException
                }
            }
        }
    }
}