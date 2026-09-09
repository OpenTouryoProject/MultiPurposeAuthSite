<#
.SYNOPSIS
    全ビルド（root\programs\0_ExecAllBat.bat 相当）を実行し、エラー・警告を集約して合否を判定する。

.DESCRIPTION
    OpenTouryo リポジトリの root/programs/1_BuildAll.ps1 に倣ったもの。

    既存のビルド バッチをそのまま呼び出し、出力を解析して結果を集約する。
    「何をビルドするか」の正はバッチ側（root\programs\*.bat）に残し、
    本スクリプトは実行と判定のみを担う。

    ＜なぜラッパーが必要か＞
      ・各バッチは MSBuild の終了コードを伝播しない（%ERRORLEVEL% を見ていない）
      ・各バッチの末尾に pause があり、対話入力を待つ
      ・-v:d（詳細）で出力が膨大なため、目視での確認が難しい
    このため、stdin を与えて実行し、出力から error / warning を抽出して判定する。

    ＜文字化けについて＞
      判定に使うのは「: error CS1002:」のようなコード部分だけで、ここは ASCII である。
      MSBuild の日本語のメッセージがコード ページの食い違いで化けても、
      **合否は変わらない**（"ビルドに成功しました" のような文言では判定しない）。

    ＜クリーンと nuget.exe＞
      1_DeleteDir.bat は packages フォルダも消す。
      net48 版は packages.config を使うため、復元には nuget.exe が要る
      （MSBuild の -t:Restore は packages.config を扱えない）。

      nuget.exe は root\programs に置いてある（OpenTouryo と同じ）。
      **万一それが失われている作業ツリーでは、クリーンを見送る。**
      消してしまうと、そこから復元できなくなるため。

.PARAMETER Only
    ステップ名の部分一致で対象を絞る（例: -Only "net48"）。動作確認用。

.PARAMETER List
    -Only に指定できるステップ名を一覧表示して終わる。**ここが一次情報。**

.PARAMETER SkipClean
    クリーン処理（1_DeleteDir / 2_DeleteFile）を省略する。
    ※ 前回のビルド成果物が残っていると、ビルドが通ったように見えることがある。

.PARAMETER WarnDetail
    警告の内訳（種類ごとの件数と代表例）を出す。

.PARAMETER Configuration
    Debug（既定）または Release。

    z_Common.bat は BUILD_CONFIG が設定済みならそれを尊重するので、
    環境変数として渡すことで、バッチ側の構成を切り替えられる。

.PARAMETER OutputDir
    各ステップの出力ログの保存先。
    既定は root\programs\Tests\E2ETests\Result（.gitignore 済み）。

    ビルドとテストのログを 1 か所に集める。散らばっていると、
    失敗したときに「どれを見るのか」から始めることになる。

.PARAMETER IgnoreErrors
    「既知のエラー」として合否判定から除外する正規表現。複数指定できる。
    除外したものは黙って消さず、件数と内容をサマリに別枠で出す。

.EXAMPLE
    .\1_BuildAll.ps1

.EXAMPLE
    .\1_BuildAll.ps1 -Only "net10" -SkipClean

.EXAMPLE
    .\1_BuildAll.ps1 -WarnDetail

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/08  玄人 幸道         新規作成（OpenTouryo の 1_BuildAll.ps1 に倣う）
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$Only,
    [switch]$List,
    [switch]$SkipClean,
    [switch]$WarnDetail,
    [string]$OutputDir = (Join-Path $PSScriptRoot "programs\Tests\E2ETests\Result"),
    [string[]]$IgnoreErrors = @()
)

# 本スクリプトは root に置き、その配下の programs を対象とする。
# ビルド バッチは相対パスでソリューションを参照しているため、
# ステップごとに programs へ移動して呼ぶ。
$progRoot = Join-Path $PSScriptRoot "programs"

New-Item -ItemType Directory -Force $OutputDir | Out-Null

# サマリの整形。Format-Table は 5.1 で全角の桁を数えないため、自前で揃える。
. (Join-Path $PSScriptRoot "SummaryTable.ps1")

# ------------------------------------------------------------------
# ビルド ステップの定義（0_ExecAllBat.bat と同じ順序・同じ内容）
# ------------------------------------------------------------------
# Name  : 表示名（ログのファイル名にもなる）
# Bat   : 呼び出すバッチ
# Clean : $true のものは -SkipClean で省略される
$steps = @(
    @{ Name = "Clean (dir)";     Bat = "1_DeleteDir.bat";                 Clean = $true }
    @{ Name = "Clean (file)";    Bat = "2_DeleteFile.bat";                Clean = $true }
    @{ Name = "net48";           Bat = "10_MultiPurposeAuthSite.bat" }
    @{ Name = "net10.0";         Bat = "10_MultiPurposeAuthSiteCore.bat" }
)

# ------------------------------------------------------------------
# nuget.exe の有無
# ------------------------------------------------------------------
# 無い場合はクリーンを見送る（packages を消すと net48 が復元できなくなる）。
# **黙って飛ばさない。** サマリに「見送り」として残す。
#
# 通常は root\programs\nuget.exe が見つかるので、この分岐には入らない。
function Find-NuGet
{
    $local = Join-Path $progRoot "nuget.exe"
    if (Test-Path $local) { return $local }

    $cmd = Get-Command "nuget.exe" -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    return $null
}

$nuget = Find-NuGet
$skipCleanForNuGet = $false

if ($null -eq $nuget)
{
    $skipCleanForNuGet = $true

    Write-Host ""
    Write-Host "【警告】nuget.exe が見つかりません。クリーンを見送ります。" -ForegroundColor Yellow
    Write-Host "        1_DeleteDir.bat は packages を消しますが、net48 版は"
    Write-Host "        packages.config を使うため、nuget.exe が無いと復元できません。"
    Write-Host "        本来は root\programs\nuget.exe にあります。復元してください。"
    Write-Host ""
}

# ------------------------------------------------------------------
# 出力の解析
# ------------------------------------------------------------------
# MSBuild のエラー・警告行は「: error CS1002:」のような形式で、
# コード部分はロケールによらないため、これを抽出する。
# （"ビルドに成功しました" 等のサマリ文言は日本語環境で変わるため使わない）
#
# ※ コードを伴わない「: error :」形式もある。このため省略可能として扱う。
function Get-Diagnostics([string[]]$lines)
{
    $errors   = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines)
    {
        if ($line -match ':\s*error(\s+[A-Za-z]+\d+)?\s*:')
        {
            $errors.Add($line.Trim())
        }
        elseif ($line -match ':\s*warning(\s+[A-Za-z]+\d+)?\s*:')
        {
            $warnings.Add($line.Trim())
        }
        elseif ($line -match '^\s*\[ERROR\]')
        {
            # z_Common.bat が MSBuild 未検出時に出力する独自のエラー
            $errors.Add($line.Trim())
        }
    }

    # 同一の指摘が複数プロジェクトから重複して出るため、一意化する。
    return [pscustomobject]@{
        Errors   = @($errors   | Select-Object -Unique)
        Warnings = @($warnings | Select-Object -Unique)
    }
}

# -IgnoreErrors に指定された正規表現のいずれかに一致するか。
# 一致したものは合否判定から外すが、握り潰しにならないよう別枠で一覧する。
function Test-KnownError([string]$line)
{
    foreach ($pattern in $IgnoreErrors)
    {
        if ($line -match $pattern)
        {
            return $true
        }
    }
    return $false
}

# ------------------------------------------------------------------
# 実行
# ------------------------------------------------------------------

# **-Only に何を指定できるかは、ここが一次情報である。**
#   文書に書き写すと二重管理になり、対象が増減したときに古くなる。
if ($List)
{
    Write-Host "=== -Only に指定できる名前（部分一致）===" -ForegroundColor Cyan
    foreach ($x in $steps) { Write-Host ("  {0,-14} {1}" -f $x.Name, $x.Bat) }
    Write-Host ("  ---- {0} 件 ----" -f $steps.Count)
    exit 0
}

# **-Only が空振りしたら止める。**
#   1 件も選ばれないまま進むと「全ステップ OK」と表示され、
#   **打ち間違いが緑になる。** 何も建てていないのに成功に見えるのが最も悪い。
if ($Only)
{
    $matched = @($steps | Where-Object { ($_.Name -like "*$Only*") -or ($_.Bat -like "*$Only*") })

    if ($matched.Count -eq 0)
    {
        Write-Host ("  **-Only '$Only' に一致するステップがありません。**") -ForegroundColor Red
        Write-Host ("  -List で一覧を出せます。") -ForegroundColor Yellow
        exit 1
    }

    Write-Host ("  -Only '$Only' : {0} ステップに絞りました" -f $matched.Count) -ForegroundColor Yellow
}

# バッチ側の構成を切り替える。
# z_Common.bat は「if not defined BUILD_CONFIG set BUILD_CONFIG=Debug」なので、
# ここで入れておけば、そちらが尊重する。
$savedConfig = $env:BUILD_CONFIG
$env:BUILD_CONFIG = $Configuration

Write-Host ("構成 : {0}" -f $Configuration) -ForegroundColor Cyan

$results = @()
$allErrors = New-Object System.Collections.Generic.List[string]
$allKnown  = New-Object System.Collections.Generic.List[string]
$total = [Diagnostics.Stopwatch]::StartNew()

foreach ($s in $steps)
{
    if ($Only -and ($s.Name -notlike "*$Only*") -and ($s.Bat -notlike "*$Only*"))
    {
        continue
    }

    if ($s.Clean -and ($SkipClean -or $skipCleanForNuGet))
    {
        $why = if ($SkipClean) { "-SkipClean" } else { "nuget.exe 無し" }

        Write-Host ("=== {0} ===" -f $s.Name) -ForegroundColor Cyan
        Write-Host ("  見送り : {0}" -f $why)

        $results += [pscustomobject]@{
            ステップ = $s.Name; 結果 = "見送り"
            エラー = 0; 既知 = 0; 警告 = 0; 秒 = 0
        }
        continue
    }

    $bat = Join-Path $progRoot $s.Bat

    if (-not (Test-Path $bat))
    {
        Write-Host ("  [{0}] バッチが見つかりません : {1}" -f $s.Name, $s.Bat) -ForegroundColor Red
        $results += [pscustomobject]@{
            ステップ = $s.Name; 結果 = "バッチ無し"
            エラー = "-"; 既知 = "-"; 警告 = "-"; 秒 = "-"
        }
        continue
    }

    Write-Host ("=== {0} ===" -f $s.Name) -ForegroundColor Cyan

    $safe = ($s.Name -replace '[^A-Za-z0-9]', '_')
    $log  = Join-Path $OutputDir "$safe.log"
    $sw   = [Diagnostics.Stopwatch]::StartNew()

    # 各バッチは末尾に pause を持つため、stdin を与えて実行する
    # （0_ExecAllBat.bat の "echo | call ..." と同じ方式）。
    #
    # **バッチは自分のフォルダから呼ぶ。** 相対パスで参照を解決しているため、
    # 呼び出し元のカレントが違うと、ソリューションを見つけられない。
    Push-Location $progRoot
    cmd /c "echo. | call `"$bat`"" *>&1 | Out-File $log -Encoding UTF8
    Pop-Location
    $sw.Stop()

    $diag = Get-Diagnostics (Get-Content $log -EA SilentlyContinue)

    # 既知のエラーを判定対象から外す。件数はサマリに残すため、捨てずに分けて持つ。
    $stepErrors = New-Object System.Collections.Generic.List[string]
    $stepKnown  = New-Object System.Collections.Generic.List[string]

    foreach ($e in $diag.Errors)
    {
        if (Test-KnownError $e)
        {
            $stepKnown.Add($e)
            $allKnown.Add(("[{0}] {1}" -f $s.Name, $e))
        }
        else
        {
            $stepErrors.Add($e)
            $allErrors.Add(("[{0}] {1}" -f $s.Name, $e))
        }
    }

    $verdict = if ($stepErrors.Count -eq 0) { "OK" } else { "NG" }
    $color   = if ($verdict -eq "OK") { "Green" } else { "Red" }
    $knownNote = if ($stepKnown.Count -gt 0) { " / 既知 {0}" -f $stepKnown.Count } else { "" }

    Write-Host ("  {0}  エラー {1} / 警告 {2}{3}  ({4:N1} 秒)" -f `
        $verdict, $stepErrors.Count, $diag.Warnings.Count, $knownNote, $sw.Elapsed.TotalSeconds) -ForegroundColor $color

    $results += [pscustomobject]@{
        ステップ = $s.Name
        結果     = $verdict
        エラー   = $stepErrors.Count
        既知     = $stepKnown.Count
        警告     = $diag.Warnings.Count
        警告詳細 = $diag.Warnings
        秒       = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

$total.Stop()

# 呼び出し元の環境を汚さないよう、戻す。
if ($null -eq $savedConfig)
{
    Remove-Item Env:\BUILD_CONFIG -EA SilentlyContinue
}
else
{
    $env:BUILD_CONFIG = $savedConfig
}

# ------------------------------------------------------------------
# サマリ
# ------------------------------------------------------------------
Write-Host ""
Write-Host "================ サマリ ================"
Write-Host ""
# **警告詳細は列にしない。** 表が壊れるので、集計にだけ使う。
Write-SummaryTable ($results | Select-Object * -ExcludeProperty 警告詳細)

# --- 警告の内訳 ---
#
# **件数だけでは何を直せばよいか分からない。** 種類ごとにまとめる。
# 既定では出さない。毎回出ると本題（エラー）が埋もれるため。
if ($WarnDetail)
{
    $withWarn = @($results | Where-Object { $_.警告詳細 -and $_.警告詳細.Count -gt 0 })

    if ($withWarn.Count -eq 0)
    {
        Write-Host ""
        Write-Host "  警告はありません。"
    }
    else
    {
        Write-Host ""
        Write-Host "================ 警告の内訳 ================"

        foreach ($r in ($withWarn | Sort-Object { -$_.警告詳細.Count }))
        {
            Write-Host ""
            Write-Host ("  {0}（{1} 件）" -f $r.ステップ, $r.警告詳細.Count)

            # 「: warning XXnnnn :」から種類を取り出す。取れないものは (種類不明) にまとめる。
            $byCode = $r.警告詳細 | ForEach-Object {
                $m = [regex]::Match($_, ':\s*warning\s+([A-Za-z]+\d+)\s*:')
                if ($m.Success) { $m.Groups[1].Value } else { "(種類不明)" }
            } | Group-Object | Sort-Object Count -Descending

            foreach ($g in $byCode)
            {
                # 代表を 1 つ出す。**同じ種類でも中身が違うことがある**ので、目印になる。
                $sample = @($r.警告詳細 | Where-Object { $_ -match [regex]::Escape($g.Name) })[0]
                if ($null -eq $sample) { $sample = "" }
                $sample = ($sample -replace '\s+', ' ')
                if ($sample.Length -gt 96) { $sample = $sample.Substring(0, 96) + " …" }

                Write-Host ("      {0,4}  {1,-12} {2}" -f $g.Count, $g.Name, $sample)
            }
        }

        Write-Host ""
        Write-Host "  **同じ種類は、たいてい 1 か所の対処でまとめて消える。**"
        Write-Host "  MSB3277 は版の混在（OpenTouryo アセンブリと NuGet の食い違い）。"
    }
}

Write-Host ""
Write-Host ("  所要時間 : {0:N1} 分" -f $total.Elapsed.TotalMinutes)
Write-Host ("  ログ     : {0}" -f $OutputDir)

if ($allErrors.Count -gt 0)
{
    Write-Host ""
    Write-Host "================ エラー一覧 ================" -ForegroundColor Red
    $allErrors | Select-Object -First 30 | ForEach-Object { Write-Host ("  " + $_) }
    if ($allErrors.Count -gt 30)
    {
        Write-Host ("  ... 他 {0} 件（詳細はログを参照）" -f ($allErrors.Count - 30))
    }
}

# 除外したものは必ず表示する。黙って消すと、-IgnoreErrors が広すぎたときに気付けない。
if ($allKnown.Count -gt 0)
{
    Write-Host ""
    Write-Host "======== 既知として除外したエラー ========" -ForegroundColor Yellow
    Write-Host ("  除外条件 : {0}" -f ($IgnoreErrors -join " , "))
    $allKnown | Select-Object -First 30 | ForEach-Object { Write-Host ("  " + $_) }
    if ($allKnown.Count -gt 30)
    {
        Write-Host ("  ... 他 {0} 件（詳細はログを参照）" -f ($allKnown.Count - 30))
    }
}

# 「見送り」は飛ばした印であって失敗ではないので、NG に数えない。
$ng = @($results | Where-Object { $_.結果 -ne "OK" -and $_.結果 -ne "見送り" })

Write-Host ""
if ($ng.Count -eq 0)
{
    Write-Host "  全ステップ OK" -ForegroundColor Green
    exit 0
}
else
{
    Write-Host ("  {0} ステップが NG" -f $ng.Count) -ForegroundColor Red
    exit 1
}
