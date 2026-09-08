<#
.SYNOPSIS
    ビルドと E2E テストを順に実行し、結果をまとめる。

.DESCRIPTION
    OpenTouryo リポジトリの root/programs/0_RunAll.ps1 に倣ったもの。

    1_BuildAll.ps1 → 2_RunAllTests.ps1 の順に実行する。
    **順序は固定。** テストは動いているサイトを叩くため、ビルドが前提になる。

    ※ ダブル クリック起動でもカレント ディレクトリに依存しないよう $PSScriptRoot を使う。

.PARAMETER Launch
    2_RunAllTests.ps1 に渡す。net10.0 版を起動してからテストする。

    **既定で付ける。** 通しで回すときにサイトの起動を人に任せると、
    起動し忘れが「全件 Skip」になり、合否として読めなくなる。
    既に起動しているサイトを使いたいときは -Launch:$false を渡す。

.PARAMETER Url
    -Launch のときに待ち受ける URL。

.PARAMETER Configuration
    Debug（既定）または Release。

.PARAMETER SkipClean
    1_BuildAll.ps1 に渡す。クリーン処理を省略する。

.PARAMETER IgnoreErrors
    1_BuildAll.ps1 に渡す。既知のエラーとして合否判定から外す正規表現。

.EXAMPLE
    .\0_RunAll.ps1

.EXAMPLE
    .\0_RunAll.ps1 -Launch:$false

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/08  玄人 幸道         新規作成（OpenTouryo の 0_RunAll.ps1 に倣う）
#>
[CmdletBinding()]
param(
    [switch]$Launch = $true,
    [string]$Url = 'https://localhost:44300',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$SkipClean,
    [string[]]$IgnoreErrors = @()
)

# まとめの整形。Format-Table は 5.1 で全角の桁を数えないため、自前で揃える。
. (Join-Path $PSScriptRoot "SummaryTable.ps1")

# UseXxx = $true のものにだけ、その引数を渡す。
$scripts = @(
    @{ Name = "1_BuildAll.ps1";    UseBuild = $true;  UseTest = $false }
    @{ Name = "2_RunAllTests.ps1"; UseBuild = $false; UseTest = $true }
)

$results = @()

foreach ($s in $scripts)
{
    $path = Join-Path $PSScriptRoot $s.Name

    if (-not (Test-Path $path))
    {
        Write-Host ("  スクリプトが見つかりません : {0}" -f $s.Name) -ForegroundColor Red
        $results += [pscustomobject]@{ スクリプト = $s.Name; 終了コード = "無し"; 秒 = "-" }
        continue
    }

    $splat = @{ Configuration = $Configuration }

    if ($s.UseBuild)
    {
        if ($SkipClean)    { $splat.SkipClean    = $true }
        if ($IgnoreErrors) { $splat.IgnoreErrors = $IgnoreErrors }
    }

    if ($s.UseTest)
    {
        $splat.Launch = $Launch
        $splat.Url    = $Url
    }

    # **実行時間を測る。** 通しは長い。合計だけ見ても、どこを短くすればよいかが分からない。
    $sw = [Diagnostics.Stopwatch]::StartNew()

    # **引数の食い違いは、ここで捕まえる。**
    #   束縛に失敗すると $LASTEXITCODE が更新されないため、
    #   何もせずに素通りしたのに「終了コードが空」で NG になり、
    #   原因が分からないまま止まる。
    try
    {
        & $path @splat
        $code = $LASTEXITCODE
    }
    catch
    {
        Write-Host ("  {0} の実行に失敗しました : {1}" -f $s.Name, $_.Exception.Message) -ForegroundColor Red
        $code = "実行不可"
    }

    if ($null -eq $code) { $code = "不明" }

    $sw.Stop()

    $results += [pscustomobject]@{
        スクリプト = $s.Name
        終了コード = $code
        秒         = ("{0:N1}" -f $sw.Elapsed.TotalSeconds)
    }

    # **ビルドが NG なら、そこで止める。**
    #   建っていないものを叩いても、テストの失敗はビルドの失敗の写しにしかならない。
    if ($s.Name -eq "1_BuildAll.ps1" -and $code -ne 0)
    {
        Write-Host ""
        Write-Host "ビルドが NG のため、テストは実行しません。" -ForegroundColor Yellow
        break
    }
}

# --- 結果のまとめ ---
Write-Host ""
Write-Host "================ 全体のまとめ ================"
Write-Host ""
Write-SummaryTable $results
Write-Host ""

# **合計も出す。** 1 本ずつの秒を足す手間を省く。
$totalSec = ($results | Where-Object { $_.秒 -ne "-" } |
             ForEach-Object { [double]$_.秒 } | Measure-Object -Sum).Sum
Write-Host ("  合計 : {0:N1} 秒（{1:N1} 分）" -f $totalSec, ($totalSec / 60))
Write-Host ""

$ng = @($results | Where-Object { $_.終了コード -ne 0 })

if ($ng.Count -eq 0)
{
    Write-Host "すべて OK です。" -ForegroundColor Green
}
else
{
    Write-Host ("{0} 本が 0 以外で終了しました。上のログを確認してください。" -f $ng.Count) -ForegroundColor Yellow
}

# --- 画面を残すための処理 ---
Read-Host "`nEnterキーを押すとウィンドウを閉じます"
