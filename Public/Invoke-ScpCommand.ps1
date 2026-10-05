function Invoke-ScpCommand
{
    <#
        .SYNOPSIS
            Execute a command on a server supporting shell commands.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([WinSCP.CommandExecutionResult])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Command
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($item in $Command)
        {
            if ($PSCmdlet.ShouldProcess($item, 'Execute remote command'))
            {
                $result = $Session.ExecuteCommand($item)

                $result.Check()
                $result
            }
        }
    }
}
