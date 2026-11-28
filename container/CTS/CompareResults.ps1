<#
.SYNOPSIS
    適合性テストの結果（out\<プラン>-result.json）を、モジュールごとの基準（ResultBaseline.csv）と比べる（#439）。

.DESCRIPTION
    **今の正しい形でも、FAILED・時間切れが残るモジュールがある**（自動では回せないもの、RFC 10070 で落ちるのが正しいものなど。
    container/CTS/README.md・root/14_TESTING.md 5 節）。そのため、RunTestPlan.ps1 の終了コード（FAILED が 1 つでもあれば 1）では
    合否を決められない。**モジュールごとに「今の正しい結果」を基準に持ち、それと違うものだけを差として出す。**

    ＜比べる単位＞
      プラン（out\ のファイルの名前。-ResponseType を添えたものを含む）・モジュール・バリアント（JSON の全項目を名前順に並べたもの）。
      **同じモジュールが、バリアント（response_type など）ごとに並ぶ**（Implicit・Hybrid）ので、バリアントまで含める。
      結果は RunTestPlan.ps1 の Result（PASSED・FAILED・WARNING・REVIEW・SKIPPED・TIMEOUT（状態））。

    ＜差の種類＞
      変わった : 基準と結果が違う（**良くなった方向も差とする**。基準の更新を促すため）
      増えた   : 基準に無いモジュール（Conformance Suite の版を上げた、プランを足した など）
      無い     : 基準に在るのに、結果に無いモジュール（比べたプランの分だけ）

    ＜比べるプラン＞
      -Plan を省くと、out\ の結果のうち、**基準に載っているプラン**をすべて比べる（手元の out\ に残る試しの結果を拾わない）。
      **基準に載っていないプランを -Plan で渡すと、そのモジュールはすべて「増えた」になる。**

    ＜基準を更新する＞
      -Update を付けると、比べたプランの基準の行を、結果で置き換える（ほかのプランの行は残す）。**差を人が確かめてから使う。**

    **自動操作のぶれ**（サインインのボタンを押しても送られず、FAILED になる。#350。主な原因は #440 で直した）も、差として出る。
    回し直すのは呼ぶ側（RunTestPlan.ps1 -Module。CI のワークフロー）で、このスクリプトは比べるだけ。

    ＜終了コード＞
      0 : 差が無い（-Update なら、基準を書いた）
      1 : 差がある
      2 : 前提の誤り（結果・基準が読めない など）

.PARAMETER Plan
    比べるプラン（out\ のファイルの名前から -result.json を除いたもの。例：oidcc-basic、oidcc-dynamic-code-id_token）。
.PARAMETER ResultDir
    結果の置き場所（既定は out\）。
.PARAMETER Baseline
    基準のファイル（既定は ResultBaseline.csv）。
.PARAMETER Update
    比べたプランの基準の行を、結果で置き換える。
.PARAMETER SummaryPath
    差の表（Markdown）を書き足すファイル（GitHub Actions の $GITHUB_STEP_SUMMARY など）。
.PARAMETER DiffPath
    差の一覧（JSON。プラン・モジュール・バリアント・基準・結果）を書くファイル（回し直すモジュールを選ぶのに使う）。

.EXAMPLE
    .\CompareResults.ps1

.EXAMPLE
    .\CompareResults.ps1 -Plan oidcc-basic, oidcc-config -SummaryPath $env:GITHUB_STEP_SUMMARY

.EXAMPLE
    .\CompareResults.ps1 -Plan oidcc-basic -Update

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/27  玄人 幸道         新規（#439）
     2026/11/28  玄人 幸道         差に、落ちた判定の名前（結果の JSON の Failures）を添えるようにした（#439）
     2026/11/28  玄人 幸道         自動操作のぶれの説明を、#440 で分かった原因に合わせた（#440）
#>
[CmdletBinding()]
param(
    [string[]] $Plan,
    [string] $ResultDir,
    [string] $Baseline,
    [switch] $Update,
    [string] $SummaryPath,
    [string] $DiffPath
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。11_CODING.md 5 節）。区切りは / で書く
$here = Split-Path -Parent $PSCommandPath
if (-not $ResultDir) { $ResultDir = Join-Path $here 'out' }
if (-not $Baseline) { $Baseline = Join-Path $here 'ResultBaseline.csv' }

function Sort-Ordinal([object[]]$Rows)
{
    # **並べ替えは序数（ordinal）で行う**。Sort-Object は文化圏の比べ方で、5.1（.NET Framework）と 7（.NET）で
    #   「-」の扱いが違い、基準のファイルの行の順が変わる（差分が無駄に出る）
    if ($Rows.Count -eq 0) { return @() }
    [string[]]$keys = @($Rows | ForEach-Object { $_.Plan + "`t" + $_.Module + "`t" + $_.Variant })
    [object[]]$items = @($Rows)
    [Array]::Sort($keys, $items, [StringComparer]::Ordinal)
    return $items
}

function Get-VariantKey($Variant)
{
    # **バリアントの全項目を、名前順に「名前=値」で並べる**（JSON の項目の順は、Conformance Suite の版で変わりうる）
    if ($null -eq $Variant) { return '' }
    $pairs = @($Variant.PSObject.Properties | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })
    return ($pairs -join ';')
}

#region 基準を読む

$baseRows = @()
if (Test-Path -LiteralPath $Baseline)
{
    $baseRows = @(Import-Csv -LiteralPath $Baseline -Encoding UTF8)
}
elseif (-not $Update)
{
    Write-Host ('基準がありません : {0}（作るなら -Update）' -f $Baseline) -ForegroundColor Red
    exit 2
}

$basePlans = @($baseRows | ForEach-Object { $_.Plan } | Sort-Object -Unique)

#endregion

#region 結果を読む

if (-not $Plan)
{
    $Plan = @(Get-ChildItem -LiteralPath $ResultDir -Filter '*-result.json' -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Name -replace '-result\.json$', '' } | Where-Object { $basePlans -contains $_ } | Sort-Object)
    if ($Plan.Count -eq 0)
    {
        Write-Host ('基準に載っているプランの結果がありません : {0}' -f $ResultDir) -ForegroundColor Red
        exit 2
    }
}

$resultRows = New-Object Collections.ArrayList
foreach ($name in $Plan)
{
    $path = Join-Path $ResultDir ('{0}-result.json' -f $name)
    if (-not (Test-Path -LiteralPath $path))
    {
        Write-Host ('結果がありません : {0}' -f $path) -ForegroundColor Red
        exit 2
    }

    $json = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    $seen = @{}
    foreach ($m in @($json.modules))
    {
        $variant = Get-VariantKey $m.Variant
        # **同じモジュール・同じバリアントが 2 度並ぶなら、2 つ目以降に番号を添える**（並びの順で対応させる）
        $k = $m.Module + '|' + $variant
        $seen[$k] = 1 + [int]$seen[$k]
        $module = if ($seen[$k] -gt 1) { '{0}#{1}' -f $m.Module, $seen[$k] } else { [string]$m.Module }
        # Failures（落ちた判定の名前。RunTestPlan.ps1 が書く）は、比べない。差の一覧に添えるだけ
        $failures = if ($m.PSObject.Properties['Failures']) { (@($m.Failures) -join ',') } else { '' }
        [void]$resultRows.Add([pscustomobject]@{ Plan = $name; Module = $module; Variant = $variant; Result = [string]$m.Result; Failures = $failures })
    }
}

#endregion

#region 基準を更新する

if ($Update)
{
    $kept = @($baseRows | Where-Object { $Plan -notcontains $_.Plan })
    $rows = Sort-Ordinal (@($kept) + @($resultRows))
    # **改行は CRLF・BOM 付きの UTF-8**（Export-Csv は 5.1 と 7 で既定の符号化が違うので、自分で書く）
    $lines = @('"Plan","Module","Variant","Result"') + @($rows | ForEach-Object {
        ('"{0}","{1}","{2}","{3}"' -f $_.Plan.Replace('"', '""'), $_.Module.Replace('"', '""'), $_.Variant.Replace('"', '""'), $_.Result.Replace('"', '""')) })
    [IO.File]::WriteAllText($Baseline, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $true))
    Write-Host ('基準を書きました : {0}（プラン {1} 件、{2} 行）' -f $Baseline, $Plan.Count, @($resultRows).Count)
    exit 0
}

#endregion

#region 比べる

$baseMap = @{}
foreach ($r in $baseRows | Where-Object { $Plan -contains $_.Plan }) { $baseMap[$r.Plan + '|' + $r.Module + '|' + $r.Variant] = $r.Result }
$resultMap = @{}
foreach ($r in $resultRows) { $resultMap[$r.Plan + '|' + $r.Module + '|' + $r.Variant] = $r }

$diffs = New-Object Collections.ArrayList
foreach ($r in $resultRows)
{
    $k = $r.Plan + '|' + $r.Module + '|' + $r.Variant
    if (-not $baseMap.ContainsKey($k))
    {
        [void]$diffs.Add([pscustomobject]@{ Kind = '増えた'; Plan = $r.Plan; Module = $r.Module; Variant = $r.Variant; Expected = ''; Actual = $r.Result; Failures = $r.Failures })
    }
    elseif ($baseMap[$k] -ne $r.Result)
    {
        [void]$diffs.Add([pscustomobject]@{ Kind = '変わった'; Plan = $r.Plan; Module = $r.Module; Variant = $r.Variant; Expected = $baseMap[$k]; Actual = $r.Result; Failures = $r.Failures })
    }
}
foreach ($k in $baseMap.Keys)
{
    if (-not $resultMap.ContainsKey($k))
    {
        $parts = $k.Split('|')
        [void]$diffs.Add([pscustomobject]@{ Kind = '無い'; Plan = $parts[0]; Module = $parts[1]; Variant = ($parts[2..($parts.Count - 1)] -join '|'); Expected = $baseMap[$k]; Actual = ''; Failures = '' })
    }
}
$diffs = @(Sort-Ordinal @($diffs))

#endregion

#region 出す

Write-Host ''
Write-Host '================ 基準との比較 ================'
foreach ($name in $Plan)
{
    $n = @($resultRows | Where-Object { $_.Plan -eq $name }).Count
    $d = @($diffs | Where-Object { $_.Plan -eq $name }).Count
    Write-Host ('  {0,-62} モジュール {1,3}  差 {2}' -f $name, $n, $d)
}
foreach ($d in $diffs)
{
    $why = if ($d.Failures) { '（落ちた判定 : {0}）' -f $d.Failures } else { '' }
    Write-Host ('  [{0}] {1} / {2}（{3}）: {4} → {5}{6}' -f $d.Kind, $d.Plan, $d.Module, $d.Variant, $d.Expected, $d.Actual, $why) -ForegroundColor Yellow
}
Write-Host $(if ($diffs.Count -eq 0) { '  差はありません。' } else { ('  差 {0} 件' -f $diffs.Count) })

if ($SummaryPath)
{
    $md = New-Object Collections.ArrayList
    [void]$md.Add('### 適合性テスト：基準との比較')
    [void]$md.Add('')
    [void]$md.Add('| プラン | モジュール | 差 |')
    [void]$md.Add('|---|---:|---:|')
    foreach ($name in $Plan)
    {
        [void]$md.Add(('| {0} | {1} | {2} |' -f $name, @($resultRows | Where-Object { $_.Plan -eq $name }).Count, @($diffs | Where-Object { $_.Plan -eq $name }).Count))
    }
    if ($diffs.Count -gt 0)
    {
        [void]$md.Add('')
        [void]$md.Add('| 種類 | プラン | モジュール | バリアント | 基準 | 結果 | 落ちた判定 |')
        [void]$md.Add('|---|---|---|---|---|---|---|')
        foreach ($d in $diffs) { [void]$md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f $d.Kind, $d.Plan, $d.Module, $d.Variant, $d.Expected, $d.Actual, $d.Failures)) }
    }
    [void]$md.Add('')
    [IO.File]::AppendAllText($SummaryPath, (($md -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}

if ($DiffPath)
{
    [IO.File]::WriteAllText($DiffPath, (ConvertTo-Json -InputObject @($diffs) -Depth 3), (New-Object Text.UTF8Encoding $false))
}

if ($diffs.Count -gt 0) { exit 1 }
exit 0

#endregion
