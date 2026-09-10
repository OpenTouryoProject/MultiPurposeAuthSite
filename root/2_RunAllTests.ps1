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

.PARAMETER UpdateTestCases
    テストケースの原本（programs\Tests\TESTCASES.md）を作り直して終わる。

    原本は「テストが何を・何を根拠に確かめるのか」を書いたもので、
    実行のたびに変わらない。**テストを変えたときだけ**作り直す。

.PARAMETER OutputDir
    TRX と実行ログの保存先。
    既定は root\programs\Tests\E2ETests\Result（.gitignore 済み）。

    サイトの起動ログ（MpasSite.*.log）も、ここへ出すよう test.ps1 に渡す。

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
    [switch]$UpdateTestCases,
    [string]$Url = 'https://localhost:44300',
    [string]$Filter,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$OutputDir
)

# ------------------------------------------------------------------
# パスの既定値は、param() ではなく本体で決める
# ------------------------------------------------------------------
# **$PSScriptRoot を param() の既定値で使わない。**
# [CmdletBinding()] を付けたスクリプトを Windows PowerShell 5.1 で
# -File 起動すると、既定値を評価する時点では $PSScriptRoot が空で、
#   Join-Path : Cannot bind argument to parameter 'Path' because it is an empty string.
# になる（[CmdletBinding()] が無ければ入る。PowerShell 7 では両方とも入る）。
#
# 0_RunAll.ps1 から & で呼ぶ分には呼び出し元の値が見えるため表面化せず、
# **単体で -File 起動したときだけ落ちる。**
# ------------------------------------------------------------------

if (-not $OutputDir)
{
    $OutputDir = Join-Path $PSScriptRoot "programs\Tests\E2ETests\Result"
}

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
    LogDir        = $OutputDir
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
        # 標準出力（TestReport が書いた「観点・根拠・検証・観測」）も拾う。
        # **報告書の本体はこれである。**
        $stdout = ""
        if ($r.Output -and $r.Output.StdOut) { $stdout = [string]$r.Output.StdOut }

        # 並び順に使う識別子。TestReport が "[TC-1.1] ..." の形で出す。
        #
        #   TC-n.n        基本テストケース（input.md 由来）
        #   SM-n          疎通（スモーク）
        #   RT-<Issue>.n  個別 Issue の回帰
        $tc = ""
        $m = [regex]::Match($stdout, '\[([A-Z]{2}-[0-9]+(?:\.[0-9]+)?)\]')
        if ($m.Success) { $tc = $m.Groups[1].Value }

        $rows += [pscustomobject]@{
            名前   = $r.testName
            結果   = $r.outcome
            メッセージ = if ($r.Output -and $r.Output.ErrorInfo) { $r.Output.ErrorInfo.Message } else { "" }
            TC     = $tc
            出力   = $stdout
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

# ------------------------------------------------------------------
# 記録の分解
# ------------------------------------------------------------------
# TestReport が書いた記録には、2 種類のものが混ざっている。
#
#   説明 : 観点・根拠・手順・検証項目・観測項目
#          **実行しても変わらない。** テストケースの原本に置く
#   実測 : 期待・実測・判定・結果
#          **毎回変わる。** 実行結果の報告に置く
#
# **毎回同じ説明を刷り直さない。** 説明は TESTCASES.md にあり、
# 報告は「その回に何が起きたか」だけを持つ。

# 1 テスト分の記録を、構造に分解する。
function ConvertTo-Record
{
    param([string]$Text)

    $rec = [pscustomobject]@{
        タイトル = ""
        観点     = ""
        根拠     = ""
        手順     = New-Object System.Collections.Generic.List[string]
        補足     = New-Object System.Collections.Generic.List[string]
        検証     = New-Object System.Collections.Generic.List[string]
        観測     = New-Object System.Collections.Generic.List[object]
    }

    $lastObserve = $null

    foreach ($line in ($Text -split "`r?`n"))
    {
        if ($line -match '^\s*\[[A-Z]{2}-[0-9.]+\]\s*(.+)$')
        {
            $rec.タイトル = $Matches[1].Trim()
            continue
        }
        if ($line -match '^\s*観点\s*:\s*(.+)$') { $rec.観点 = $Matches[1].Trim(); continue }
        if ($line -match '^\s*根拠\s*:\s*(.+)$') { $rec.根拠 = $Matches[1].Trim(); continue }
        if ($line -match '^\s*手順\s*:\s*(.+)$')
        {
            # "(1) ..." の番号は落とす。Markdown の番号付き一覧と二重になる。
            $null = $rec.手順.Add(($Matches[1].Trim() -replace '^\([0-9]+\)\s*', ''))
            continue
        }
        if ($line -match '^\s*補足\s*:\s*(.+)$') { $null = $rec.補足.Add($Matches[1].Trim()); continue }

        if ($line -match '^\s*検証[0-9]+\s*:\s*(.+)$')
        {
            $null = $rec.検証.Add($Matches[1].Trim())
            $lastObserve = $null
            continue
        }

        if ($line -match '^\s*観測[0-9]+\s*:\s*(.+)$')
        {
            $lastObserve = [pscustomobject]@{ 名前 = $Matches[1].Trim(); 注記 = "" }
            $null = $rec.観測.Add($lastObserve)
            continue
        }

        if ($line -match '^\s*注記\s*=\s*(.+)$' -and $null -ne $lastObserve)
        {
            $lastObserve.注記 = $Matches[1].Trim()
            continue
        }
    }

    return $rec
}

# 実測の行だけを残す（報告用）。
function Get-MeasuredLines
{
    param([string]$Text)

    $keep = New-Object System.Collections.Generic.List[string]

    foreach ($line in ($Text -split "`r?`n"))
    {
        # 「対象」も残す。**どちらのアプリを測ったのかは、その回の事実である。**
        # net48版と net10.0版は同じURLで構成されているため、
        # ここが記録に無いと、後から取り違えを見抜けない（実際に取り違えた）。
        if ($line -match '^\s*対象\s*:' -or
            $line -match '^\s*(検証|観測)[0-9]+\s*:' -or
            $line -match '^\s*(期待|実測|判定)\s*=' -or
            $line -match '^\s*結果\s*:')
        {
            $null = $keep.Add($line.TrimEnd())
        }
    }

    return ($keep -join [Environment]::NewLine)
}

# ------------------------------------------------------------------
# 報告書（E2ETests.report.md）
# ------------------------------------------------------------------
# **テストの妥当性を、実行した人以外が評価できるようにする。**
#   テスト名と OK / NG だけでは、期待値の根拠も、実際に何が起きたかも分からない。
#   TestReport が各テストに書かせた内容を、TC 番号順に 1 枚へまとめる。
$reportPath = Join-Path $OutputDir "E2ETests.report.md"

$md = New-Object System.Text.StringBuilder
$null = $md.AppendLine("# E2E テスト結果")
$null = $md.AppendLine()
$null = $md.AppendLine("| | |")
$null = $md.AppendLine("|---|---|")
$null = $md.AppendLine(("| 実行日時 | {0} |" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")))
# **「叩いた先」は 1 つに決まらない。**
# net48版と net10.0版を同時に測ると URL が 2 つになる（-Url で片方をずらす）。
# ここに -Url の値だけを書くと、もう一方を測った事実が消える。
# TargetTestBase が各テストに書かせた「対象 … / 応答 …」から、
# 実際に応答したアプリを拾う。
# **「応答」を含む行だけに限ること。** TestReport の Target()（クライアント名や
# redirect_uri を書くもの）も「対象」で始まるため、条件を緩めると全部拾う。
$measuredApps = New-Object System.Collections.Generic.List[string]

foreach ($row in $rows)
{
    foreach ($line in ($row.出力 -split "`r?`n"))
    {
        if ($line -match '^\s*対象\s*:\s*(.+?応答\s*:.+?)\s*$')
        {
            $app = $Matches[1]
            if (-not $measuredApps.Contains($app)) { $null = $measuredApps.Add($app) }
        }
    }
}

if ($measuredApps.Count -eq 0)
{
    # 1 件も測れていない（全て Skip など）。起動を指示した URL を書く。
    $null = $md.AppendLine(("| 叩いた先 | {0} |" -f $Url))
}
else
{
    $null = $md.AppendLine(("| 叩いた先 | {0} |" -f ($measuredApps -join "<br>")))
}
$null = $md.AppendLine(("| 構成 | {0} |" -f $Configuration))
$null = $md.AppendLine(("| 成功 / 失敗 / Skip | {0} / {1} / {2} |" -f `
    $passed.Count, $failed.Count, $skipped.Count))
$null = $md.AppendLine()

$null = $md.AppendLine("## この報告の読み方")
$null = $md.AppendLine()
$null = $md.AppendLine("**この文書は「その回に何が起きたか」だけを持つ。**")
$null = $md.AppendLine("各テストが何を・何を根拠に確かめるのかは、実行しても変わらないので")
$null = $md.AppendLine("[テストケースの原本](../../TESTCASES.md)に置いてある。")
$null = $md.AppendLine("**妥当性を評価するときは、原本と併せて読むこと。**")
$null = $md.AppendLine()
$null = $md.AppendLine("- **検証** … **合否を判定した項目。** 1 つでも外れればテストは失敗する")
$null = $md.AppendLine("- **観測** … **判定していない項目。** 仕様が幅を持つもの、現状を記録するもの")
$null = $md.AppendLine()
$null = $md.AppendLine("**「検証」と「観測」は別物である。** 観測は合否に影響しない。")
$null = $md.AppendLine("観測に「望ましくない」と書かれていても、テストは成功する。")
$null = $md.AppendLine()
$null = $md.AppendLine("Skip は失敗ではない。起動していない対象と、未修正と分かっている項目の 2 種類がある。")
$null = $md.AppendLine()

# --- 一覧 ---
$null = $md.AppendLine("## 一覧")
$null = $md.AppendLine()
$null = $md.AppendLine("| ID | テスト | 対象 | 結果 |")
$null = $md.AppendLine("|---|---|---|---|")

# 識別子を持つものを先、持たないものを後ろに。
# 群の順は TC（基本）→ SM（疎通）→ RT（回帰）。群の中は番号順。
function Get-IdRank
{
    param([string]$Id)

    if (-not $Id) { return 9 }

    switch ($Id.Substring(0, 2))
    {
        "TC"    { return 0 }
        "SM"    { return 1 }
        "RT"    { return 2 }
        default { return 8 }
    }
}

function Get-IdPart
{
    param([string]$Id, [int]$Index)

    if (-not $Id) { return 0 }

    $m = [regex]::Match($Id, '^[A-Z]{2}-([0-9]+)(?:\.([0-9]+))?$')
    if (-not $m.Success) { return 0 }

    $v = $m.Groups[$Index + 1].Value
    if (-not $v) { return 0 }

    return [int]$v
}

$ordered = @($rows | Sort-Object `
    @{ Expression = { Get-IdRank $_.TC } }, `
    @{ Expression = { Get-IdPart $_.TC 0 } }, `
    @{ Expression = { Get-IdPart $_.TC 1 } }, `
    名前)

foreach ($row in $ordered)
{
    # テスト名から、対象（core / netfx）と短い名前を取り出す。
    $target = ""
    $mt = [regex]::Match($row.名前, 'targetKey:\s*"([^"]+)"')
    if ($mt.Success) { $target = $mt.Groups[1].Value }

    $short = ($row.名前 -replace '^.*\.', '') -replace '\(targetKey.*$', ''

    $verdict = switch ($row.結果)
    {
        "Passed"      { "OK" }
        "Failed"      { "**NG**" }
        "NotExecuted" { "Skip" }
        default       { $row.結果 }
    }

    $null = $md.AppendLine(("| {0} | {1} | {2} | {3} |" -f `
        ($row.TC -replace '^$', '-'), $short, ($target -replace '^$', '-'), $verdict))
}

$null = $md.AppendLine()

# --- 詳細 ---
$null = $md.AppendLine("## 詳細")
$null = $md.AppendLine()

foreach ($row in $ordered)
{
    if ($row.結果 -eq "NotExecuted")
    {
        continue
    }

    $target = ""
    $mt = [regex]::Match($row.名前, 'targetKey:\s*"([^"]+)"')
    if ($mt.Success) { $target = $mt.Groups[1].Value }

    $short = ($row.名前 -replace '^.*\.', '') -replace '\(targetKey.*$', ''

    $null = $md.AppendLine(("### {0} {1}（対象: {2}）" -f `
        ($row.TC -replace '^$', '-'), $short, ($target -replace '^$', '-')))
    $null = $md.AppendLine()

    # **実測だけを載せる。** 観点・根拠・手順は TESTCASES.md にある。
    $measured = if ($row.出力) { Get-MeasuredLines $row.出力 } else { "" }

    if ($measured)
    {
        $null = $md.AppendLine('```')
        $null = $md.AppendLine($measured)
        $null = $md.AppendLine('```')
    }
    else
    {
        $null = $md.AppendLine("（このテストは記録を出していない）")
    }

    if ($row.結果 -eq "Failed")
    {
        $null = $md.AppendLine()
        $null = $md.AppendLine("**失敗の理由**")
        $null = $md.AppendLine()
        $null = $md.AppendLine('```')
        $null = $md.AppendLine(($row.メッセージ -replace '\s+$', ''))
        $null = $md.AppendLine('```')
    }

    $null = $md.AppendLine()
}

# UTF-8（BOM 無し）で書く。読み手が別のツールでも開けるように。
[System.IO.File]::WriteAllText($reportPath, $md.ToString(), (New-Object Text.UTF8Encoding $false))
# ------------------------------------------------------------------
# テストケースの原本（programs\Tests\TESTCASES.md）
# ------------------------------------------------------------------
# -UpdateTestCases のときだけ作り直す。
# **実行のたびに書き換えない。** 中身は実行結果に依らないので、
# 毎回書き換えると、コミットの差分が意味の無いものになる。
if ($UpdateTestCases)
{
    $casesPath = Join-Path $PSScriptRoot "programs\Tests\TESTCASES.md"

    $tc = New-Object System.Text.StringBuilder
    $null = $tc.AppendLine("# テストケース一覧（原本）")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine('`root/programs/Tests/E2ETests/Tests/` のテストが、')
    $null = $tc.AppendLine("**何を・何を根拠に確かめるのか**を並べたもの。")
    $null = $tc.AppendLine('実行結果は含まない（そちらは `Result/E2ETests.report.md`）。')
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("> **この文書は生成物である。** テストを変えたら作り直すこと。")
    $null = $tc.AppendLine(">")
    $null = $tc.AppendLine('> ```powershell')
    $null = $tc.AppendLine("> cd root")
    $null = $tc.AppendLine("> .\2_RunAllTests.ps1 -Launch -UpdateTestCases")
    $null = $tc.AppendLine('> ```')
    $null = $tc.AppendLine(">")
    $null = $tc.AppendLine('> 元になるのは、各テストが `TestReport` に書かせた内容である。')
    $null = $tc.AppendLine("> **テスト コードが一次情報**であり、この文書はその写しにすぎない。")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("## 読み方")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("- **観点** … 何が満たされていれば良いのか")
    $null = $tc.AppendLine("- **根拠** … その期待値がどの仕様に基づくのか（RFC / OIDC の該当箇所）")
    $null = $tc.AppendLine("- **手順** … 何を送るか")
    $null = $tc.AppendLine("- **検証** … **合否を判定する項目。** 1 つでも外れればテストは失敗する")
    $null = $tc.AppendLine("- **観測** … **判定しない項目。** 仕様が幅を持つもの、現状を記録するもの")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("**「検証」と「観測」は別物である。**")
    $null = $tc.AppendLine("観測に「望ましくない」と書かれていても、テストは成功する。")
    $null = $tc.AppendLine("仕様が幅を持つ項目を合否に混ぜると、「通った」の意味が薄まるため。")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("テストはアプリを **HTTP で外から叩く**（ブラックボックス）。")
    $null = $tc.AppendLine("JWT のデコードと署名検証は、実装側のコードを使わず独立に行っている。")
    $null = $tc.AppendLine("同じテストを net10.0 版と net48 版の両方に流す。")
    $null = $tc.AppendLine()
    $null = $tc.AppendLine("---")
    $null = $tc.AppendLine()

    # 識別子ごとに 1 件だけ載せる（同じテストが対象ごとに 2 回出るため）。
    $seen = @{}
    $count = 0
    $group = ""

    foreach ($row in $ordered)
    {
        if (-not $row.TC -or -not $row.出力) { continue }
        if ($seen.ContainsKey($row.TC)) { continue }

        $seen[$row.TC] = $true
        $count++

        # 群が変わったら見出しを入れる。
        $thisGroup = $row.TC.Substring(0, 2)

        if ($thisGroup -ne $group)
        {
            $group = $thisGroup

            $heading = switch ($group)
            {
                "TC"    { "TC. 基本テストケース" }
                "SM"    { "SM. 疎通（テスト基盤そのものの確認）" }
                "RT"    { "RT. 個別 Issue の回帰" }
                default { $group }
            }

            $null = $tc.AppendLine("# " + $heading)
            $null = $tc.AppendLine()
        }

        $rec = ConvertTo-Record $row.出力

        $null = $tc.AppendLine(("## {0} {1}" -f $row.TC, $rec.タイトル))
        $null = $tc.AppendLine()
        $null = $tc.AppendLine("| | |")
        $null = $tc.AppendLine("|---|---|")
        $null = $tc.AppendLine(("| 観点 | {0} |" -f ($rec.観点 -replace '\|', '\|')))
        $null = $tc.AppendLine(("| 根拠 | {0} |" -f ($rec.根拠 -replace '\|', '\|')))

        $short = ($row.名前 -replace '^.*\.', '') -replace '\(targetKey.*$', ''
        $null = $tc.AppendLine(('| テスト | `{0}` |' -f $short))

        $null = $tc.AppendLine()

        if ($rec.手順.Count -gt 0)
        {
            $null = $tc.AppendLine("**手順**")
            $null = $tc.AppendLine()
            foreach ($s in $rec.手順) { $null = $tc.AppendLine("1. " + $s) }
            $null = $tc.AppendLine()
        }

        if ($rec.検証.Count -gt 0)
        {
            $null = $tc.AppendLine("**検証（合否を判定する）**")
            $null = $tc.AppendLine()
            foreach ($v in $rec.検証) { $null = $tc.AppendLine("- " + $v) }
            $null = $tc.AppendLine()
        }

        if ($rec.観測.Count -gt 0)
        {
            $null = $tc.AppendLine("**観測（判定しない）**")
            $null = $tc.AppendLine()
            foreach ($o in $rec.観測)
            {
                $null = $tc.AppendLine("- " + $o.名前)
                if ($o.注記) { $null = $tc.AppendLine("  - " + $o.注記) }
            }
            $null = $tc.AppendLine()
        }

        if ($rec.補足.Count -gt 0)
        {
            $null = $tc.AppendLine("**補足**")
            $null = $tc.AppendLine()
            foreach ($n in $rec.補足) { $null = $tc.AppendLine("- " + $n) }
            $null = $tc.AppendLine()
        }
    }


    # --- Skip 中のテストケース ---
    #
    # **実行されないので、上の一覧には現れない。**
    # だが未修正の欠陥を記した重要な項目なので、Skip の理由から別枠で載せる。
    # 起動していない対象による Skip は、テストケースの話ではないので除く。
    $held = @{}

    foreach ($row in $rows)
    {
        if ($row.結果 -ne "NotExecuted") { continue }
        if (-not $row.メッセージ) { continue }
        # **肯定条件で絞る。**
        # 起動していない対象による Skip は、テストケースの話ではない。
        # 除外条件（「起動してください」を含まない）で書くと、
        # 到達性の判定を変えたときに取りこぼす（実際に取りこぼした）。
        # 未修正項目の Skip 理由は「未修正」で始める約束にしてある。
        if ($row.メッセージ -notmatch '^未修正') { continue }

        $name = ($row.名前 -replace '^.*\.', '') -replace '\(targetKey.*$', ''

        if (-not $held.ContainsKey($name))
        {
            $held[$name] = ($row.メッセージ -replace '\s+', ' ').Trim()
        }
    }

    if ($held.Count -gt 0)
    {
        $null = $tc.AppendLine("# 保留中のテストケース（Skip）")
        $null = $tc.AppendLine()
        $null = $tc.AppendLine("**未修正だと分かっている項目は、期待する動作を書いたうえで Skip にしている。**")
        $null = $tc.AppendLine("消さずに残すのは、直したときに Skip を外すだけで検証できるようにするため。")
        $null = $tc.AppendLine()
        $null = $tc.AppendLine("**実行されないため、上の一覧には現れない。**")
        $null = $tc.AppendLine("観点・根拠・手順はテスト コードにある。")
        $null = $tc.AppendLine()
        $null = $tc.AppendLine("| テスト | Skip の理由（Issue 番号・実測日・実測結果） |")
        $null = $tc.AppendLine("|---|---|")

        foreach ($name in ($held.Keys | Sort-Object))
        {
            $null = $tc.AppendLine(('| `{0}` | {1} |' -f $name, ($held[$name] -replace '\|', '\|')))
        }

        $null = $tc.AppendLine()
    }

    [System.IO.File]::WriteAllText($casesPath, $tc.ToString(), (New-Object Text.UTF8Encoding $false))

    Write-Host ""
    Write-Host ("  テストケースの原本を作り直しました（{0} 件）。" -f $count) -ForegroundColor Green
    Write-Host ("  {0}" -f $casesPath)
}

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
Write-Host ("  報告書   : {0}" -f $reportPath)
Write-Host ("  原本     : {0}" -f (Join-Path $PSScriptRoot "programs\Tests\TESTCASES.md"))
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
