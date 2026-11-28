<#
.SYNOPSIS
    適合性テストのプランを順に回し、基準と比べ、違ったモジュールだけを回し直して、REVIEW も基準と比べる（#439）。

.DESCRIPTION
    **CI（.github/workflows/conformance.yml）の群のジョブが呼ぶ本体**である。手元でも、同じように回せる。
    2_DockerComposeUp.ps1 で Conformance Suite と OP を起動してから呼ぶ。

    1. **プランを 1 つずつ回す**（RunTestPlan.ps1。終了コードの 1（FAILED がある）は、ここでは見ない。基準と比べて決める）
    2. **基準（ResultBaseline.csv）と比べる**（CompareResults.ps1）
    3. **差が出たモジュールだけを回し直す**（RunTestPlan.ps1 -Module。-Retry 回まで）。
       **まれな自動操作のぶれ**（ランナーの一時的な遅れなど）を、回し直しで拾う。
       **基準に無いモジュール（増えた）は回し直さない**（ぶれではない）
    4. **最後の比較の結果を、差の表として出す**（-SummaryPath）。**回し直しても残った差は落とす**
    5. **REVIEW の材料を、基準（ReviewBaseline.csv）と比べる**（ExtractReview.ps1。#417）。
       **報告書から取り出すので、ランナーの上で回す**（報告書は CI の成果物には残さない。秘密を含む）

    ＜プランの書き方＞
      out\ のファイルの名前と同じ（RunTestPlan.ps1 の -Plan に、code 以外の -ResponseType なら「-」で添えたもの）。
      例：oidcc-basic、oidcc-dynamic-code-id_token、oidcc-rp-initiated-logout-dynamic-id_token-token

    ＜終了コード＞
      0 : 基準と同じ（REVIEW も同じ）
      1 : 基準と違う（回し直しても残った）、または REVIEW の材料の形が変わった
      2 : 前提の誤り（Conformance Suite に届かない、プランの名前の誤り など）

.PARAMETER Plan
    回すプラン（上の書き方。カンマ区切りの 1 つの文字列も受ける）。
.PARAMETER Retry
    差が出たモジュールを回し直す回数の上限（既定は 2）。
    **#439 では 8 回にし、残ったぶれを警告に留めていた。** CI で、WebRunner の「unexpected url for task: Verify Complete」が
    OIDC の群の 1 回目に 1〜2 割出ていたため。**原因は OP のサインインの画面だった**（ボタンのハンドラを jQuery の ready の後に付けていたので、
    自動操作のブラウザが速く押すと送られなかった。#440）。**直した後は、全プランの 1 回目の差が 0 件になった**ので、2 回に戻し、警告に留める規則を外した。
    **本当の回帰は、何回回し直しても落ちる。**
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
     2026/11/28  玄人 幸道         回し直しの既定を 2 回にし、残ったぶれを警告に留める規則（-FlakyLimit）を外した（#440）
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Plan,
    [int] $Retry = 2,
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

# **回し直しても残った差は、落とす**（#439 では、自動操作のぶれだけなら警告に留めていた。原因を直したので外した。#440）

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
