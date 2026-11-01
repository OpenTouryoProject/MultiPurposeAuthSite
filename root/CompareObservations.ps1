<#
.SYNOPSIS
    E2E の観測（TestReport.Observe）の値を、前回の実行と比べて差分を報告する（#315。QUALITY.md 2 節）。

.DESCRIPTION
    観測は判定しないので、値が変わってもテストは落ちない。
    「変わったことに気付くために残す」役割を果たすには、前回との比較が要る。

    **判定はしない。** 差分を表示するだけで、終了コードは合否に関わらない。

    ＜基準はコミットしない＞
      観測の値には、配備ごとの値（client_id・kid）や、サインイン中の利用者の名前を含む画面の文面が入る。
      公開のリポジトリに置けないので、前回の値は Result（.gitignore 済み）に置く。
      ストアごとに値が違いうるので、ストアごとにファイルを分ける。

    ＜一部だけ回したとき＞
      今回実行したテストだけを比べ、基準のうち、そのテストの分だけを置き換える（他は残す）。

    ＜揺れの正規化＞
      実行のたびに変わる値（ランダムな値・ミリ秒・画面のバイト数）は、比べる前に置き換える。

.PARAMETER Trx
    E2E の TRX。
.PARAMETER Baseline
    前回の値のファイル。無ければ作るだけで、比べない。
.PARAMETER ReportPath
    差分を追記する報告書（省略可）。

.OUTPUTS
    終了コードは常に 0（TRX を読めないときだけ 2）。

.EXAMPLE
    .\CompareObservations.ps1 -Trx programs\Tests\E2ETests\Result\E2ETests.trx -Baseline programs\Tests\E2ETests\Result\E2ETests.observations.mem.txt

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/01  玄人 幸道         新規作成（#315）
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Trx,
    [Parameter(Mandatory = $true)][string]$Baseline,
    [string]$ReportPath
)

$ErrorActionPreference = "Stop"

# 実行のたびに変わる値を置き換える
function Get-NormalizedValue([string]$Value)
{
    $v = $Value
    $v = [regex]::Replace($v, '\b\d+ ミリ秒', '<時間> ミリ秒')
    # 画面の大きさ（トークンの長さで揺れる）
    $v = [regex]::Replace($v, '\b\d+ bytes\b', '<大きさ> bytes')
    # kid・client_id・CSRF のトークンなど（32 文字以上の、ランダムに見える並び）
    $v = [regex]::Replace($v, '[A-Za-z0-9_-]{32,}', '<値>')
    return $v
}

try
{
    if (-not (Test-Path -LiteralPath $Trx))
    {
        Write-Host ("  TRX がありません : {0}" -f $Trx) -ForegroundColor Red
        exit 2
    }

    # --- 今回の値 --------------------------------------------------------
    #   キーは「識別子 / 対象 / 何を見たか / 同じテストの中での順番」。
    [xml]$doc = Get-Content -LiteralPath $Trx -Raw -Encoding UTF8
    $current = [ordered]@{}
    $ran = @{}

    foreach ($r in $doc.TestRun.Results.UnitTestResult)
    {
        if (-not ($r.Output -and $r.Output.StdOut)) { continue }
        $out = [string]$r.Output.StdOut

        $idMatch = [regex]::Match($out, '\[([A-Z0-9]{2}-C?[0-9.]+)\]')
        if (-not $idMatch.Success) { continue }
        $id = $idMatch.Groups[1].Value

        $targetMatch = [regex]::Match([string]$r.testName, 'targetKey:\s*"([^"]+)"')
        $target = $(if ($targetMatch.Success) { $targetMatch.Groups[1].Value } else { "-" })
        $ran["$id/$target"] = $true

        $seen = @{}
        foreach ($m in [regex]::Matches($out, '観測\d+ : (.*?)\r?\n\s*実測 = (.*?)\r?\n'))
        {
            $what = $m.Groups[1].Value.Trim()
            $n = 1 + [int]$seen[$what]
            $seen[$what] = $n
            $current["$id`t$target`t$what`t$n"] = Get-NormalizedValue $m.Groups[2].Value.Trim()
        }
    }

    # --- 前回の値 --------------------------------------------------------
    $previous = [ordered]@{}
    $hasBaseline = Test-Path -LiteralPath $Baseline
    if ($hasBaseline)
    {
        foreach ($l in (Get-Content -LiteralPath $Baseline -Encoding UTF8))
        {
            $f = $l -split "`t", 5
            if ($f.Count -eq 5) { $previous[($f[0..3] -join "`t")] = $f[4] }
        }
    }

    # --- 比べる（今回実行したテストの分だけ） ------------------------------
    $changes = New-Object Collections.ArrayList
    if ($hasBaseline)
    {
        foreach ($k in $current.Keys)
        {
            if (-not $previous.Contains($k)) { [void]$changes.Add(@($k, "（無し）", $current[$k])) }
            elseif ($previous[$k] -cne $current[$k]) { [void]$changes.Add(@($k, $previous[$k], $current[$k])) }
        }
        foreach ($k in $previous.Keys)
        {
            $f = $k -split "`t"
            if ($ran.ContainsKey($f[0] + "/" + $f[1]) -and -not $current.Contains($k))
            {
                [void]$changes.Add(@($k, $previous[$k], "（無し）"))
            }
        }
    }

    # --- 基準を更新する（今回実行しなかったテストの分は残す） -----------------
    $merged = New-Object Collections.ArrayList
    foreach ($k in $previous.Keys)
    {
        $f = $k -split "`t"
        if (-not $ran.ContainsKey($f[0] + "/" + $f[1])) { [void]$merged.Add($k + "`t" + $previous[$k]) }
    }
    foreach ($k in $current.Keys) { [void]$merged.Add($k + "`t" + $current[$k]) }
    $sorted = @($merged | Sort-Object)
    [IO.File]::WriteAllLines($Baseline, [string[]]$sorted, (New-Object Text.UTF8Encoding $false))

    # --- 報告 ------------------------------------------------------------
    Write-Host ""
    if (-not $hasBaseline)
    {
        Write-Host ("  観測の値 {0} 件を基準として記録しました（次回から比べます）" -f $current.Count)
        exit 0
    }
    if ($changes.Count -eq 0)
    {
        Write-Host ("  観測の変化はありません（{0} 件を比較）" -f $current.Count)
    }
    else
    {
        Write-Host ("  観測の変化 {0} 件（判定はしません。テストの合否には関わりません）" -f $changes.Count) -ForegroundColor Yellow
    }

    $lines = New-Object Collections.ArrayList
    foreach ($c in $changes)
    {
        $f = $c[0] -split "`t"
        [void]$lines.Add(("{0}（{1}） {2}" -f $f[0], $f[1], $f[2]))
        [void]$lines.Add("    前回 = " + $c[1])
        [void]$lines.Add("    今回 = " + $c[2])
    }
    foreach ($l in $lines) { Write-Host ("    " + $l) }

    if ($ReportPath -and (Test-Path -LiteralPath $ReportPath))
    {
        $sb = New-Object Text.StringBuilder
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("## 観測の変化（前回の実行との差）")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine(("**判定はしない。** {0} 件（{1} 件を比較。実行のたびに変わる値は置き換えてある）。" -f $changes.Count, $current.Count))
        [void]$sb.AppendLine()
        if ($lines.Count -gt 0)
        {
            [void]$sb.AppendLine('```')
            foreach ($l in $lines) { [void]$sb.AppendLine($l) }
            [void]$sb.AppendLine('```')
        }
        [IO.File]::AppendAllText($ReportPath, $sb.ToString(), (New-Object Text.UTF8Encoding $false))
    }
    exit 0
}
catch
{
    # **失敗しても、テストの合否に影響させない。**
    Write-Host ("  観測の比較に失敗しました : {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    exit 2
}
