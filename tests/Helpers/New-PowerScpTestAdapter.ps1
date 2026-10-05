function New-PowerScpTestAdapter
{
    param
    (
        [string] $SourceRoot,
        [string] $Destination,
        [string] $Name
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    # Keep the real loader and assemblies; only relax the sealed session type for fakes.
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'lib') -Destination $Destination -Recurse

    foreach ($folder in @('Private', 'Public'))
    {
        $target = Join-Path $Destination $folder
        New-Item -ItemType Directory -Path $target -Force | Out-Null

        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $SourceRoot $folder) -Filter '*.ps1' -File)
        {
            $source = Get-Content -LiteralPath $file.FullName -Raw
            $source = $source.Replace('[WinSCP.Session]', '[object]')
            Set-Content -LiteralPath (Join-Path $target $file.Name) -Value $source -Encoding UTF8
        }
    }

    $adapter = Join-Path $Destination "$Name.psm1"
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'PowerScp.psm1') -Destination $adapter

    return $adapter
}
