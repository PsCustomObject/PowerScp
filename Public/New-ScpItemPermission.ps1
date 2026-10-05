function New-ScpItemPermission
{
    <#
        .SYNOPSIS
            Create Unix permissions from octal, numeric or symbolic notation, or individual flags.

        .PARAMETER Numeric
            Decimal bitmask, for example 420 for octal 644.
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding(DefaultParameterSetName = 'Octal')]
    [OutputType([WinSCP.FilePermissions])]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'Octal')]
        [ValidatePattern('^[0-7]{3,4}$')]
        [string]
        $Octal,

        [Parameter(Mandatory, ParameterSetName = 'Numeric')]
        [ValidateRange(0, 4095)]
        [int]
        $Numeric,

        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Text,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $UserRead,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $UserWrite,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $UserExecute,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $GroupRead,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $GroupWrite,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $GroupExecute,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $OtherRead,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $OtherWrite,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $OtherExecute,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $SetUid,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $SetGid,

        [Parameter(ParameterSetName = 'Flags')]
        [switch]
        $Sticky
    )

    $permissions = New-Object WinSCP.FilePermissions

    if ($PSCmdlet.ParameterSetName -eq 'Flags')
    {
        $permissions.Numeric = 0

        foreach ($key in $PSBoundParameters.Keys)
        {
            if ($key -in @('UserRead', 'UserWrite', 'UserExecute', 'GroupRead', 'GroupWrite', 'GroupExecute', 'OtherRead', 'OtherWrite', 'OtherExecute', 'SetUid', 'SetGid', 'Sticky'))
            {
                $permissions.$key = [bool]$PSBoundParameters[$key]
            }
        }
    }
    else
    {
        # Parameter set names mirror the WinSCP permission properties (Octal, Numeric and Text).
        $permissions.($PSCmdlet.ParameterSetName) = $PSBoundParameters[$PSCmdlet.ParameterSetName]
    }

    $permissions
}
