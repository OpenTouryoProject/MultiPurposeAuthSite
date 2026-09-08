<#
.SYNOPSIS
    net10.0 版と net48 版の両方をビルドし、結果をまとめて表示する。

.DESCRIPTION
    既存の 10_MultiPurposeAuthSite*.bat は、ビルド ツールの選択・NuGet の復元・
    node_modules の再取得までを含む「一式」のバッチで、対話的に pause する。

    このスクリプトは、それとは別に「今のワーキング ツリーがビルドを通るか」だけを
    非対話で確かめるためのもの。ひとつでも失敗したら終了コードを 1 にする。

    ErrorLines / WarningLines は、出力から重複を除いた「行数」であり、
    MSBuild が最後に出す件数とは一致しない（MSB3277 のように 1 件で
    何行も出る警告があるため）。増減を見る目安として使う。

.PARAMETER Configuration
    Debug（既定）または Release。

.PARAMETER Target
    all（既定） / core（net10.0 のみ） / netfx（net48 のみ） / tests（テスト プロジェクトのみ）。

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Target core
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',

    [ValidateSet('all', 'core', 'netfx', 'tests')]
    [string] $Target = 'all'
)

$ErrorActionPreference = 'Stop'

$programs = Split-Path -Parent $PSScriptRoot
$results = @()

# ---------------------------------------------------------------------------
# net48 のビルドに使う MSBuild を探す
# ---------------------------------------------------------------------------
function Find-MSBuild {
    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) { return $path }
    }

    return $null
}

# ---------------------------------------------------------------------------
# ビルド結果を数える
# ---------------------------------------------------------------------------
function Invoke-Build {
    param(
        [string] $Name,
        [scriptblock] $Command
    )

    Write-Host ''
    Write-Host "=== $Name ===" -ForegroundColor Cyan

    $output = & $Command 2>&1
    $exitCode = $LASTEXITCODE

    $errors = @($output | Select-String -Pattern '\berror [A-Z]+[0-9]+' | Select-Object -ExpandProperty Line -Unique)
    $warnings = @($output | Select-String -Pattern '\bwarning [A-Z]+[0-9]+' | Select-Object -ExpandProperty Line -Unique)

    if ($exitCode -ne 0) {
        # 失敗したときだけ、原因が分かるように出力を見せる。
        $errors | Select-Object -First 20 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }

    $script:results += [pscustomobject]@{
        Name     = $Name
        ExitCode = $exitCode
        ErrorLines   = $errors.Count
        WarningLines = $warnings.Count
    }
}

# ---------------------------------------------------------------------------
# net10.0（dotnet build）
# ---------------------------------------------------------------------------
if ($Target -in @('all', 'core')) {
    $sln = Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln'

    Invoke-Build -Name 'net10.0 (MultiPurposeAuthSiteCore)' -Command {
        dotnet build $sln -c $Configuration -v:m -nologo
    }
}

# ---------------------------------------------------------------------------
# net48（MSBuild）
#
# CommonLibrary の NetFxLibrary.csproj と NetCoreLibrary.csproj は
# obj\ を共有するため、直前に net10.0 をビルドしていると
# project.assets.json が上書きされている。先に Restore を回す。
# ---------------------------------------------------------------------------
if ($Target -in @('all', 'netfx')) {
    $msbuild = Find-MSBuild

    if ($null -eq $msbuild) {
        Write-Host ''
        Write-Host '=== net48 (MultiPurposeAuthSite) ===' -ForegroundColor Cyan
        Write-Host 'MSBuild が見つかりません。Visual Studio が必要です。スキップします。' -ForegroundColor Yellow
    }
    else {
        $sln = Join-Path $programs 'MultiPurposeAuthSite\MultiPurposeAuthSite.sln'

        Invoke-Build -Name 'net48 (MultiPurposeAuthSite)' -Command {
            & $msbuild $sln -t:Restore -v:q -nologo
            & $msbuild $sln -p:Configuration=$Configuration -v:m -nologo
        }
    }
}

# ---------------------------------------------------------------------------
# E2E テスト
# ---------------------------------------------------------------------------
if ($Target -in @('all', 'tests')) {
    $csproj = Join-Path $PSScriptRoot 'E2ETests\E2ETests.csproj'

    Invoke-Build -Name 'E2ETests' -Command {
        dotnet build $csproj -c $Configuration -v:m -nologo
    }
}

# ---------------------------------------------------------------------------
# まとめ
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '=== まとめ ===' -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failed = @($results | Where-Object { $_.ExitCode -ne 0 })

if ($failed.Count -gt 0) {
    Write-Host ("失敗: " + ($failed.Name -join ', ')) -ForegroundColor Red
    exit 1
}

Write-Host 'すべてビルドできました。' -ForegroundColor Green
exit 0
