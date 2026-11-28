<#
.SYNOPSIS
    適合性テストのプランを順に回し、基準と比べ、違ったモジュールだけを回し直して、REVIEW も基準と比べる（#439）。

.DESCRIPTION
    **CI（.github/workflows/conformance.yml）の群のジョブが呼ぶ本体**である。手元でも、同じように回せる。
    2_DockerComposeUp.ps1 で Conformance Suite と OP を起動してから呼ぶ。

    1. **プランを 1 つずつ回す**（RunTestPlan.ps1。終了コードの 1（FAILED がある）は、ここでは見ない。基準と比べて決める）
    2. **基準（ResultBaseline.csv）と比べる**（CompareResults.ps1）
    3. **差が出たモジュールだけを回し直す**（RunTestPlan.ps1 -Module。-Retry 回まで）。
       **自動操作のぶれ**（サインインの要求が OP に届かず INTERRUPTED になる。#350）を、回し直しで拾う。
       **基準に無いモジュール（増えた）は回し直さない**（ぶれではない）
    4. **最後の比較の結果を、差の表として出す**（-SummaryPath）。
       **残った差が少なく（-FlakyLimit 件以下）、すべて自動操作のぶれ（WebRunner）なら、落とさずに警告に留める**
    5. **REVIEW の材料を、基準（ReviewBaseline.csv）と比べる**（ExtractReview.ps1。#417）。
       **報告書から取り出すので、ランナーの上で回す**（報告書は CI の成果物には残さない。秘密を含む）

    ＜プランの書き方＞
      out\ のファイルの名前と同じ（RunTestPlan.ps1 の -Plan に、code 以外の -ResponseType なら「-」で添えたもの）。
      例：oidcc-basic、oidcc-dynamic-code-id_token、oidcc-rp-initiated-logout-dynamic-id_token-token

    ＜終了コード＞
      0 : 基準と同じ（REVIEW も同じ）。残った差が自動操作のぶれだけで、警告に留めたときも 0
      1 : 基準と違う（回し直しても残った）、または REVIEW の材料の形が変わった
      2 : 前提の誤り（Conformance Suite に届かない、プランの名前の誤り など）

.PARAMETER Plan
    回すプラン（上の書き方。カンマ区切りの 1 つの文字列も受ける）。
.PARAMETER Retry
    差が出たモジュールを回し直す回数の上限（既定は 8）。
    **CI のランナーでは、自動操作のぶれ（WebRunner の「unexpected url for task: Verify Complete」）が手元より多い**（#439 の試行で、
    Implicit・Hybrid の 1 回目に 2〜3 割。回し直したモジュールの半分ほどがまた落ちる）ので、5 回でも 1 件ずつ残ることがあった。
    **本当の回帰は、何回回し直しても落ちる**ので、回数を増やしても落とす基準は緩まない。
.PARAMETER FlakyLimit
    回し直しても残った差が、この件数以下で、すべて自動操作のぶれ（基準が PASSED・WARNING、結果が FAILED、落ちた判定が WebRunner とそのモジュールだけ）なら、
    落とさずに警告に留める（既定は 3。0 にすると、ぶれでも落とす）。
.PARAMETER SummaryPath
    差の表（Markdown）を書き足すファイル（GitHub Actions の $GITHUB_STEP_SUMMARY など）。
.PARAMETER NoReview
    REVIEW の材料を比べない。

.EXAMPLE
    .\RunPlans.ps1 -Plan oidcc-basic, oidcc-config

.EXAMPLE
    pwsh ./RunPlans.ps1 -Plan 'oidcc-dynamic,oidcc-dynamic-code-id_token' -SummaryPath $env:GITHUB_STEP_SUMMARY

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/27  玄人 幸道         新規（#439）
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Plan,
    [int] $Retry = 8,
    [int] $FlakyLimit = 3,
    [string] $SummaryPath,
    [switch] $NoReview
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。11_CODING.md 5 節）。区切りは / で書く
$here = Split-Path -Parent $PSCommandPath
$runTestPlan = Join-Path $here 'RunTestPlan.ps1'
$compare = Join-Path $here 'CompareResults.ps1'
$outDir = Join-Path $here 'out'

# **カンマ区切りの 1 つの文字列も受ける**（powershell -File・GitHub Actions の matrix から渡すとき）
$Plan = @($Plan | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

#region プランの名前を、RunTestPlan.ps1 の -Plan と -ResponseType に分ける

# **RunTestPlan.ps1 の -Plan に書ける名前は、その ValidateSet が一次情報**（ここに写さない）
$known = @((Get-Command $runTestPlan).Parameters['Plan'].Attributes |
    Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })

function Split-PlanName([string]$Name)
{
    # **長い名前から当てる**（oidcc-rp-initiated-logout-dynamic は oidcc-rp-initiated-logout より先に当てる）。
    #   残りは response_type（「-」を空白に戻す。id_token の「_」はそのまま）
    foreach ($k in @($known | Sort-Object { $_.Length } -Descending))
    {
        if ($Name -eq $k) { return @{ Plan = $k; ResponseType = 'code' } }
        if ($Name.StartsWith($k + '-'))
        {
            return @{ Plan = $k; ResponseType = $Name.Substring($k.Length + 1).Replace('-', ' ') }
        }
    }
    return $null
}

$specs = @()
foreach ($name in $Plan)
{
    $s = Split-PlanName $name
    if (-not $s)
    {
        Write-Host ('プランの名前が分かりません : {0}' -f $name) -ForegroundColor Red
        exit 2
    }
    $specs += , @{ Name = $name; Plan = $s.Plan; ResponseType = $s.ResponseType }
}

#endregion

function Invoke-Plan($Spec, [string[]]$Modules)
{
    $a = @{ Plan = $Spec.Plan }
    if ($Spec.ResponseType -ne 'code') { $a.ResponseType = $Spec.ResponseType }
    if ($Modules) { $a.Module = $Modules }
    # **出力は画面へ流す**（関数の戻り値に混ぜない）
    & $runTestPlan @a | Out-Host
    return $LASTEXITCODE
}

#region 1. 回す

$started = Get-Date
foreach ($s in $specs)
{
    Write-Host ''
    Write-Host ('======== {0} ========' -f $s.Name) -ForegroundColor Cyan
    $t = Get-Date
    $code = Invoke-Plan $s $null
    Write-Host ('  （{0:N1} 分。終了コード {1}）' -f ((Get-Date) - $t).TotalMinutes, $code)
    if ($code -eq 2)
    {
        Write-Host ('前提の誤りで回せませんでした : {0}' -f $s.Name) -ForegroundColor Red
        exit 2
    }
}

#endregion

#region 2・3. 比べて、違ったモジュールだけを回し直す

$diffPath = Join-Path $outDir 'diff.json'
for ($attempt = 1; $attempt -le $Retry; $attempt++)
{
    & $compare -Plan $Plan -DiffPath $diffPath
    $code = $LASTEXITCODE
    if ($code -eq 0) { break }
    if ($code -ne 1) { exit 2 }

    $diffs = @([IO.File]::ReadAllText($diffPath) | ConvertFrom-Json | Where-Object { $_.Kind -ne '増えた' })
    if ($diffs.Count -eq 0) { break }

    Write-Host ''
    Write-Host ('======== 回し直し {0}/{1}（{2} 件）========' -f $attempt, $Retry, $diffs.Count) -ForegroundColor Cyan
    foreach ($s in $specs)
    {
        # **モジュールの名前の「#2」など（同じモジュール・同じバリアントの 2 つ目）は落とす**（名前で回すと、すべて回る）
        $mods = @($diffs | Where-Object { $_.Plan -eq $s.Name } | ForEach-Object { ([string]$_.Module) -replace '#\d+$', '' } | Sort-Object -Unique)
        if ($mods.Count -eq 0) { continue }
        $c = Invoke-Plan $s $mods
        if ($c -eq 2) { exit 2 }
    }
}

#endregion

#region 4. 最後の比較

$a = @{ Plan = $Plan; DiffPath = $diffPath }
if ($SummaryPath) { $a.SummaryPath = $SummaryPath }
& $compare @a
$resultCode = $LASTEXITCODE
if ($resultCode -eq 2) { exit 2 }

# **回し直しても残った差が、自動操作のぶれだけなら、落とさずに警告に留める**（#439 で決めた）。条件はすべて満たすこと：
#   - 残った差が -FlakyLimit 件以下
#   - すべて「変わった」で、基準が PASSED・WARNING、結果が FAILED
#   - 落ちた判定（Failures）が WebRunner を含み、ほかはそのモジュール自身（モジュールの失敗の印）だけ
#   **CI のランナーでは、2 回サインインするモジュール（max-age-10000 など）の WebRunner の「Verify Complete」が手元より多く、
#   回し直しを 8 回しても 1 件ほど残る**（#439 の試行。原因は別に追う）。
#   **特定の画面だけが壊れた回帰も、同じ形で警告になりうる**ので、警告（GitHub の注釈とジョブのまとめ）を読む
if ($resultCode -eq 1)
{
    $left = @([IO.File]::ReadAllText($diffPath) | ConvertFrom-Json)
    $flaky = @(foreach ($d in $left)
    {
        $mod = ([string]$d.Module) -replace '#\d+$', ''
        $srcs = @(([string]$d.Failures) -split ',' | Where-Object { $_ })
        $others = @($srcs | Where-Object { ($_ -ne 'WebRunner') -and ($_ -ne $mod) })
        if (($d.Kind -eq '変わった') -and (@('PASSED', 'WARNING') -contains $d.Expected) -and ($d.Actual -eq 'FAILED') -and
            ($srcs -contains 'WebRunner') -and ($others.Count -eq 0)) { $d }
    })
    if (($left.Count -le $FlakyLimit) -and ($flaky.Count -eq $left.Count))
    {
        foreach ($d in $left)
        {
            # GitHub Actions の注釈（手元では、そのまま 1 行出るだけ）。run: の外なので ASCII に限らないが、注釈は英語にしておく
            Write-Host ('::warning::Conformance: only the browser automation (WebRunner) failed after {0} retries: {1} / {2} ({3})' -f $Retry, $d.Plan, $d.Module, $d.Variant)
        }
        if ($SummaryPath)
        {
            $line = '**残った差 {0} 件は、自動操作のぶれ（WebRunner）だけなので、落とさずに警告に留めた**（回し直し {1} 回の後。同じモジュールが続けて残るなら、回帰を疑う）。' -f $left.Count, $Retry
            [IO.File]::AppendAllText($SummaryPath, ($line + "`n`n"), (New-Object Text.UTF8Encoding $false))
        }
        Write-Host ('残った差 {0} 件は、自動操作のぶれ（WebRunner）だけなので、警告に留めます。' -f $left.Count) -ForegroundColor Yellow
        $resultCode = 0
    }
}

#endregion

#region 5. REVIEW

$reviewCode = 0
if (-not $NoReview)
{
    Write-Host ''
    Write-Host '======== REVIEW の材料と基準の比較 ========' -ForegroundColor Cyan
    & (Join-Path $here 'ExtractReview.ps1') -Plan $Plan
    $reviewCode = $LASTEXITCODE
    if ($reviewCode -eq 2) { exit 2 }
    if ($SummaryPath)
    {
        $line = if ($reviewCode -eq 0) { 'REVIEW の材料：基準と同じ。' } else { 'REVIEW の材料：**基準と違うものがある**（ジョブのログの ExtractReview.ps1 の出力。合否を付け直す）。' }
        [IO.File]::AppendAllText($SummaryPath, ($line + "`n`n"), (New-Object Text.UTF8Encoding $false))
    }
}

#endregion

Write-Host ''
Write-Host ('所要時間 : {0:N1} 分' -f ((Get-Date) - $started).TotalMinutes)
if (($resultCode -ne 0) -or ($reviewCode -ne 0)) { exit 1 }
exit 0
