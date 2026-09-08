<#
.SYNOPSIS
    E2E テストを実行し、結果を集約して合否を判定する。

.DESCRIPTION
    OpenTouryo リポジトリの root/programs/2_RunAllTests.ps1 に倣ったもの。

    ＜構造＞
      実行そのものは root\programs\Tests\test.ps1 に委ねる。
      「どう起動して、どう流すか」の正はあちらに置き、本スクリプトは
      呼び出しと集計だけを担う（1_BuildAll.ps1 がバッチに対して行うのと同じ形）。

    ＜なぜ TRX を読むのか＞
      コンソールの集計行（"テストの合計数: ..." など）は**ロケールで変わる**。
      TRX（XML）の outcome 属性は Passed / Failed / NotExecuted で固定なので、
      こちらを読む。

    ＜Skip を失敗にしない＞
      テストは net10.0 版と net48 版の両方に同じものを流し、
      **起動していない側は Skip する**（Tests\README.md）。
      net48 版は IIS Express での手動起動が前提なので、
      Skip が多いことは異常ではない。

      ただし **1 件も実行されなかった場合は NG** とする。
      サイトを起動し忘れたまま「失敗 0 件」を緑と読むのが、いちばん危ない。

    ＜前提＞
      ・ビルド済みであること（1_BuildAll.ps1、または Visual Studio）
      ・-Launch を付けない場合は、サイトを起動しておくこと

.PARAMETER Launch
    net10.0 版を起動してからテストする（test.ps1 に渡す）。

.PARAMETER Url
    -Launch のときに待ち受ける URL（test.ps1 に渡す）。

.PARAMETER Filter
    dotnet test の --filter に渡す式（test.ps1 に渡す）。

.PARAMETER Configuration
    Debug（既定）または Release。

.PARAMETER OutputDir
    TRX と実行ログの保存先。既定は %TEMP%\MpasTestResults。

.EXAMPLE
    .\2_RunAllTests.ps1 -Launch

.EXAMPLE
    .\2_RunAllTests.ps1 -Filter "FullyQualifiedName~RequestObjectTests"

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/08  玄人 幸道         新規作成（OpenTouryo の 2_RunAllTests.ps1 に倣う）
#>
[CmdletBinding()]
param(
    [switch]$Launch,
    [string]$Url = 'https://localhost:44300',
    [string]$Filter,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$OutputDir = (Join-Path $env:TEMP "MpasTestResults")
)

# 本スクリプトは root に置き、その配下の programs\Tests を対象とする。
$progRoot = Join-Path $PSScriptRoot "programs"
$testPs1  = Join-Path $progRoot "Tests\test.ps1"

New-Item -ItemType Directory -Force $OutputDir | Out-Null

# サマリの整形。Format-Table は 5.1 で全角の桁を数えないため、自前で揃える。
. (Join-Path $PSScriptRoot "SummaryTable.ps1")

if (-not (Test-Path $testPs1))
{
    Write-Host ("  実行スクリプトが見つかりません : {0}" -f $testPs1) -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------
# 実行
# ------------------------------------------------------------------
$trx = Join-Path $OutputDir "E2ETests.trx"
$log = Join-Path $OutputDir "E2ETests.log"

# 前回の結果が残っていると、失敗しても「前回の緑」を読んでしまう。
Remove-Item $trx -EA SilentlyContinue

$splat = @{
    Configuration = $Configuration
    TrxPath       = $trx
}
if ($Launch) { $splat.Launch = $true }
if ($Url)    { $splat.Url    = $Url }
if ($Filter) { $splat.Filter = $Filter }

Write-Host "=== E2ETests ===" -ForegroundColor Cyan
if (-not $Launch)
{
    Write-Host "  -Launch が無いので、サイトは起動しません（起動済みであること）。"
}

$sw = [Diagnostics.Stopwatch]::StartNew()

# **画面にも出しつつ、ログにも残す。** 長いので、失敗時に読み返せるようにする。
& $testPs1 @splat *>&1 | Tee-Object -FilePath $log
$testExit = $LASTEXITCODE

$sw.Stop()

# ------------------------------------------------------------------
# TRX の解析
# ------------------------------------------------------------------
# outcome は Passed / Failed / NotExecuted（＝ Skip）で、ロケールによらない。
function Get-TrxResults([string]$path)
{
    if (-not (Test-Path $path))
    {
        return $null
    }

    [xml]$doc = Get-Content $path -Raw

    $rows = @()

    foreach ($r in $doc.TestRun.Results.UnitTestResult)
    {
        $rows += [pscustomobject]@{
            名前   = $r.testName
            結果   = $r.outcome
            メッセージ = if ($r.Output -and $r.Output.ErrorInfo) { $r.Output.ErrorInfo.Message } else { "" }
        }
    }

    return $rows
}

$rows = Get-TrxResults $trx

if ($null -eq $rows)
{
    Write-Host ""
    Write-Host ("  TRX が出力されていません : {0}" -f $trx) -ForegroundColor Red
    Write-Host  "  テストの起動そのものに失敗しています。上のログを確認してください。"
    Write-Host ""
    Write-Host ("  ログ : {0}" -f $log)
    exit 1
}

$passed  = @($rows | Where-Object { $_.結果 -eq "Passed" })
$failed  = @($rows | Where-Object { $_.結果 -eq "Failed" })
$skipped = @($rows | Where-Object { $_.結果 -eq "NotExecuted" })

# ------------------------------------------------------------------
# サマリ
# ------------------------------------------------------------------
Write-Host ""
Write-Host "================ サマリ ================"
Write-Host ""

$summary = @(
    [pscustomobject]@{
        対象 = "E2ETests"
        結果 = if ($failed.Count -eq 0 -and $passed.Count -gt 0) { "OK" } else { "NG" }
        成功 = $passed.Count
        失敗 = $failed.Count
        Skip = $skipped.Count
        秒   = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
)

Write-SummaryTable $summary

# --- Skip の内訳 ---
#
# **Skip は 2 種類ある。** 混ぜて数えると、どちらも見えなくなる。
#   ・対象のサイトが起動していない  … 環境の話
#   ・未修正と分かっている項目      … 仕様の話（Tests\README.md「未修正の項目」）
if ($skipped.Count -gt 0)
{
    Write-Host ""
    Write-Host ("  Skip {0} 件の内訳" -f $skipped.Count)

    # テスト名の (targetKey: "netfx") で、起動していない対象の分を切り分ける。
    $byTarget = $skipped | Group-Object {
        $m = [regex]::Match($_.名前, 'targetKey:\s*"([^"]+)"')
        if ($m.Success) { $m.Groups[1].Value } else { "(対象なし)" }
    } | Sort-Object Count -Descending

    foreach ($g in $byTarget)
    {
        Write-Host ("      {0,4}  {1}" -f $g.Count, $g.Name)
    }

    Write-Host ""
    Write-Host "  対象ごとの Skip は、そのサイトが起動していないだけのことが多い。"
    Write-Host "  (対象なし) は、未修正として Skip 指定しているもの（Tests\README.md）。"
}

# --- 失敗の一覧 ---
if ($failed.Count -gt 0)
{
    Write-Host ""
    Write-Host "================ 失敗したテスト ================" -ForegroundColor Red

    foreach ($f in ($failed | Select-Object -First 30))
    {
        Write-Host ("  " + $f.名前)

        $msg = ($f.メッセージ -replace '\s+', ' ').Trim()
        if ($msg -ne "")
        {
            if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + " …" }
            Write-Host ("      " + $msg) -ForegroundColor DarkGray
        }
    }

    if ($failed.Count -gt 30)
    {
        Write-Host ("  ... 他 {0} 件（詳細はログを参照）" -f ($failed.Count - 30))
    }
}

Write-Host ""
Write-Host ("  所要時間 : {0:N1} 分" -f $sw.Elapsed.TotalMinutes)
Write-Host ("  TRX      : {0}" -f $trx)
Write-Host ("  ログ     : {0}" -f $log)
Write-Host ""

# ------------------------------------------------------------------
# 合否
# ------------------------------------------------------------------
# **1 件も実行されなかったら NG。**
#   サイトを起動し忘れると全件 Skip になり、「失敗 0 件」で緑に見えてしまう。
if ($passed.Count -eq 0)
{
    Write-Host "  1 件も実行されていません。サイトが起動しているか確認してください。" -ForegroundColor Red
    Write-Host "  （-Launch を付けると net10.0 版を起動してから流します）"
    exit 1
}

if ($failed.Count -eq 0)
{
    Write-Host "  全テスト OK" -ForegroundColor Green
    exit 0
}

Write-Host ("  {0} 件が失敗" -f $failed.Count) -ForegroundColor Red
exit 1
