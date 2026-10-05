function New-ScpTransferResumeSupport
{
    <#
        .SYNOPSIS
            Configure automatic resume and uploads through temporary filenames.

        .PARAMETER Threshold
            Minimum size in KB. Threshold selects Smart mode; combine it only with State Smart.
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding()]
    [OutputType([WinSCP.TransferResumeSupport])]
    param
    (
        [WinSCP.TransferResumeSupportState]
        $State = 'Default',

        [ValidateRange(0, 2147483647)]
        [int]
        $Threshold
    )

    if ($PSBoundParameters.ContainsKey('Threshold') -and $PSBoundParameters.ContainsKey('State') -and $State -ne 'Smart')
    {
        throw 'Threshold can only be combined with State Smart.'
    }

    $resume = New-Object WinSCP.TransferResumeSupport

    $resume.State = $State

    if ($PSBoundParameters.ContainsKey('Threshold'))
    {
        $resume.Threshold = $Threshold
    }

    $resume
}
