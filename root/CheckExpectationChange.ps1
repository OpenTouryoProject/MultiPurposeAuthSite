<#
.SYNOPSIS
    期待値の変更（QUALITY.md 3 節）を検出し、トレーラー Expectation-Change が付いているかを確かめる（#315）。

.DESCRIPTION
    commit-msg フック（.githooks/commit-msg）と、PR の CI が使う検出器。
    **何を期待値の変更と呼ぶかは、ここが実装である。** 定義は QUALITY.md 3 節。

    ＜テスト＞
      root/programs/Tests/**/*.cs の差分で、ファイルごとに次を数える（将来の単体テストのプロジェクトも、ここに入る）。
        テストの削除   … [Fact]・[Theory]・[InlineData] などの行が、足した数より多く消えた
        Skip の追加    … Skip.If(・Skip.IfNot(・Skip =・SkipException( の行が、消した数より多く足された
        検証の削除     … .Verify(・.VerifyEqual( の行が、足した数より多く消えた（観測への移動を含む）
                         UnitTests の下では、Assert.・[Basis( の行も同じように数える（#324）
      消えた行と足した行を差し引くので、書き直し（引数を変えるなど）は数えない。
      // で始まる行は数えない（コメント アウトは「消えた」と数える）。

      さらに、コミット全体で**根拠の変更**を見る。
        Report(id, title, viewpoint, basis) の id ごとに basis を比べ、変わった・消えたものを数える。
        ファイルをまたいで移しただけなら数えない。
      **アサーションの緩和は見ない**（機械的に判定できない）。レビューの観点で拾う（QUALITY.md 4 節）。

    ＜仕組み自体＞
      この検出の仕組みのファイル（.githooks/・.claude/settings.json・.claude/hooks/・本スクリプト・
      .github/workflows/expectation-change.yml・TestReport.cs）の**変更・削除・名前の変更**も、期待値の変更と同じに扱う。
      仕組みを緩めれば、期待値をいくら変えても通るようになるため。**追加は数えない**（導入は緩めることではない）。

    ＜トレーラー＞
      コミット メッセージに「Expectation-Change: <理由>」の行があれば、人が承認したものとする。
      # で始まる行と、git commit -v の切り取り線から後は見ない。

    ＜TESTCASES.md の作り直し＞
      -Range と -CheckTestCases を併せて指定すると、期待値の変更の代わりに、
      「テストの内容を変えたのに TESTCASES.md が変わっていない」を見る。
      TESTCASES.md は生成物で、作り直しには E2E の実行が要るので、**CI では検出だけ行う。**
      テストの内容は TestReport に渡す文面（Report・Step・Note・Target・Verify・VerifyEqual・Observe）と
      テスト メソッドの名前で比べる（条件式だけの変更は、原本に現れないので数えない）。
      通しの既定から外れるテストは原本に載らないので、範囲のコミットに
      「TestCases-Unchanged: <理由>」があれば通す。

.PARAMETER Staged
    ステージした差分（HEAD との差）を見る。commit-msg フックが使う。
    **マージの途中（MERGE_HEAD がある）なら見ない。** 取り込む側のコミットで確かめ済みのため。
.PARAMETER MessageFile
    -Staged のときの、コミット メッセージのファイル（commit-msg フックの第 1 引数）。
.PARAMETER Commit
    コミットと、その最初の親との差を見る。メッセージはそのコミットのもの。
    **マージ コミットは見ない**（-Staged と同じ理由）。
.PARAMETER Range
    <base>..<head> の範囲の、マージでないコミットを 1 つずつ -Commit で見る。PR の CI が使う。
    **本スクリプトがまだ無いコミット（導入より前）は見ない。** 規約が無かった時点のコミットだからである。
.PARAMETER CheckTestCases
    -Range と併せて、TESTCASES.md の作り直しの漏れを見る。

.OUTPUTS
    終了コード 0 = 期待値の変更が無い、またはトレーラーがある
               1 = トレーラーの無い期待値の変更がある（-CheckTestCases では、作り直しの漏れがある）
               2 = 実行できない（引数の誤り・git の失敗）

.EXAMPLE
    .\CheckExpectationChange.ps1 -Commit HEAD

.EXAMPLE
    .\CheckExpectationChange.ps1 -Staged -MessageFile ..\.git\COMMIT_EDITMSG

.EXAMPLE
    .\CheckExpectationChange.ps1 -Range develop..HEAD

.EXAMPLE
    .\CheckExpectationChange.ps1 -Range develop..HEAD -CheckTestCases

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/01  玄人 幸道         新規作成（#315。OpenTouryo #640 の検出器を、E2E のテスト向けに書き直した）
#>
[CmdletBinding()]
param(
    [switch]$Staged,
    [string]$MessageFile,
    [string]$Commit,
    [string]$Range,
    [switch]$CheckTestCases
)

$ErrorActionPreference = "Stop"

# 対象のパス（git のパス。区切りは /）
$testPattern      = '^root/programs/Tests/.+\.cs$'
$testCasesSource  = '^root/programs/Tests/E2ETests/Tests/.+\.cs$'
$testCasesFile    = 'root/programs/Tests/TESTCASES.md'
$selfPath         = 'root/CheckExpectationChange.ps1'
$guardPattern     = '^(\.githooks/|\.claude/settings\.json$|\.claude/hooks/|root/CheckExpectationChange\.ps1$|\.github/workflows/expectation-change\.yml$|root/programs/Tests/E2ETests/Infrastructure/TestReport\.cs$)'

# 数える行。属性の並び（[Test, Ignore("...")]）にも当たるよう、[ か , の直後を見る。
$testAttrPattern = '[\[,]\s*(Fact|Theory|SkippableFact|SkippableTheory|InlineData|MemberData|ClassData|Test|TestCase|TestCaseSource)\s*[\],(]'
$skipPattern     = '\bSkip\s*\.\s*(If|IfNot)\s*\(|[\[,(]\s*Skip\s*=|\bSkipException\s*\(|[\[,]\s*(Ignore|Explicit)\s*[\],(]'
$verifyPattern   = '\.\s*(Verify|VerifyEqual)\s*\('
# 単体テストの検証は Assert と [Basis]。**E2E の Assert は前提の確認なので、数えない**（#324）
$unitTestPattern   = '^root/programs/Tests/UnitTests/'
$unitVerifyPattern = '\bAssert\s*\.|\[\s*Basis\s*\('

# 空の木（親の無いコミットの比較元）
$emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# ------------------------------------------------------------------
# git の呼び出し
# ------------------------------------------------------------------
#   **コンソールのコード ページに触れずに、UTF-8 で受け取る。** フックはコンソールを人と共有しており、
#   [Console]::OutputEncoding を変えると、人の画面の表示まで変わる。
#   カレントは変えない。フックでは git が GIT_INDEX_FILE 等を相対パスで渡すことがある。
function Invoke-Git([string[]]$Arguments)
{
    $quoted = foreach ($a in $Arguments)
    {
        if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
    }

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = "git"
    $psi.Arguments = "-c core.quotepath=false " + ($quoted -join " ")
    $psi.WorkingDirectory = (Get-Location).ProviderPath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = New-Object Text.UTF8Encoding $false

    $p = [Diagnostics.Process]::Start($psi)
    # 標準エラーは別に読む（両方を順に読むと、バッファが詰まって止まることがある）
    $errTask = $p.StandardError.ReadToEndAsync()
    $text = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()

    $lines = @()
    if ($text) { $lines = @($text -split "`n" | ForEach-Object { $_.TrimEnd("`r") }) }
    if ($lines.Count -gt 0 -and $lines[-1] -eq "") { $lines = $lines[0..($lines.Count - 2)] }

    return [pscustomobject]@{ ExitCode = $p.ExitCode; Lines = $lines; Text = $text; Error = $errTask.Result }
}

# 失敗したら止める版
function Invoke-GitChecked([string[]]$Arguments)
{
    $r = Invoke-Git $Arguments
    if ($r.ExitCode -ne 0) { throw ("git {0} が失敗しました : {1}" -f ($Arguments -join " "), $r.Error.Trim()) }
    return $r
}

# 表示。**出力がパイプなら、UTF-8 のバイトを直接書く。**
#   フックを mintty・TortoiseGit・CI から動かすと、出力はパイプになる。5.1 はパイプへ、
#   コンソールのコード ページ（日本語の Windows では 932）で書き出すため、受け取る側（UTF-8）で化ける。
$script:rawOut = $null
function Write-Msg([string]$Text = "", [ConsoleColor]$ForegroundColor)
{
    if (-not [Console]::IsOutputRedirected)
    {
        if ($PSBoundParameters.ContainsKey("ForegroundColor")) { Write-Host $Text -ForegroundColor $ForegroundColor } else { Write-Host $Text }
        return
    }
    if (-not $script:rawOut) { $script:rawOut = [Console]::OpenStandardOutput() }
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($Text + "`n")
    $script:rawOut.Write($bytes, 0, $bytes.Length)
    $script:rawOut.Flush()
}

# ------------------------------------------------------------------
# メッセージのトレーラー
# ------------------------------------------------------------------
function Get-Trailer([string[]]$Lines, [string]$Name)
{
    $found = @()
    foreach ($l in $Lines)
    {
        if ($l -match '^# -+ >8 -+') { break }   # git commit -v の切り取り線
        if ($l.StartsWith("#")) { continue }
        if ($l -match ('^' + $Name + ':\s*(\S.*)$')) { $found += $Matches[1].Trim() }
    }
    return , $found
}

# ------------------------------------------------------------------
# C# の呼び出しの引数を読む
# ------------------------------------------------------------------
#   行の差分では、複数行にまたがる引数（根拠は別の行に書く）を比べられないので、引数の単位で読む。
#   文字列の外の空白を除いて返す（折り返しを変えただけなら、同じになる）。
function Get-CallArguments([string]$Text, [int]$Start)
{
    $args2 = New-Object Collections.ArrayList
    $sb = New-Object Text.StringBuilder
    $depth = 0
    $i = $Start
    while ($i -lt $Text.Length)
    {
        $c = $Text[$i]
        $next = $(if ($i + 1 -lt $Text.Length) { $Text[$i + 1] } else { [char]0 })

        # コメント
        if ($c -eq '/' -and $next -eq '/')
        {
            $e = $Text.IndexOf("`n", $i)
            if ($e -lt 0) { break }
            $i = $e + 1
            continue
        }
        if ($c -eq '/' -and $next -eq '*')
        {
            $e = $Text.IndexOf("*/", $i + 2)
            if ($e -lt 0) { break }
            $i = $e + 2
            continue
        }

        # 文字列（@"..." は "" で引用符を表す。それ以外は \ でエスケープする）
        if ($c -eq '"')
        {
            $verbatim = ($i -gt 0 -and ($Text[$i - 1] -eq '@' -or ($i -gt 1 -and $Text[$i - 2] -eq '@' -and $Text[$i - 1] -eq '$')))
            [void]$sb.Append($c)
            $i++
            while ($i -lt $Text.Length)
            {
                $d = $Text[$i]
                [void]$sb.Append($d)
                $i++
                if ($verbatim)
                {
                    if ($d -eq '"')
                    {
                        if ($i -lt $Text.Length -and $Text[$i] -eq '"') { [void]$sb.Append('"'); $i++; continue }
                        break
                    }
                }
                else
                {
                    if ($d -eq '\' -and $i -lt $Text.Length) { [void]$sb.Append($Text[$i]); $i++; continue }
                    if ($d -eq '"') { break }
                }
            }
            continue
        }

        # 文字リテラル（'"' や '(' で数え違えないように）
        if ($c -eq "'")
        {
            $e = $i + 1
            if ($e -lt $Text.Length -and $Text[$e] -eq '\') { $e++ }
            $e = $Text.IndexOf("'", $e + 1)
            if ($e -lt 0) { break }
            [void]$sb.Append($Text.Substring($i, $e - $i + 1))
            $i = $e + 1
            continue
        }

        if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $depth++ }
        elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}')
        {
            if ($depth -eq 0)
            {
                [void]$args2.Add($sb.ToString())
                return , $args2.ToArray()
            }
            $depth--
        }
        elseif ($c -eq ',' -and $depth -eq 0)
        {
            [void]$args2.Add($sb.ToString())
            [void]$sb.Clear()
            $i++
            continue
        }

        if (-not [char]::IsWhiteSpace($c)) { [void]$sb.Append($c) }
        $i++
    }
    return , $args2.ToArray()
}

# Report(id, title, viewpoint, basis) を集める（id → basis）
function Add-Basis([string]$Text, [hashtable]$Map)
{
    if (-not $Text) { return }
    foreach ($m in [regex]::Matches($Text, '(?<![\w])Report\s*\('))
    {
        $a = Get-CallArguments $Text ($m.Index + $m.Length)
        if ($a.Count -ge 4) { $Map[$a[0]] = $a[3] }
    }
}

# TESTCASES.md に現れる内容を、出てくる順に並べる
function Get-TestCaseItems([string]$Text)
{
    if (-not $Text) { return , @() }
    $items = New-Object Collections.ArrayList
    $pattern = '(?<![\w])Report\s*\(|\.\s*(?<one>Step|Note|Target|Verify|VerifyEqual|Observe)\s*\(|public\s+(?:async\s+)?(?:Task|void)\s+(?<name>\w+)\s*\('
    foreach ($m in [regex]::Matches($Text, $pattern))
    {
        if ($m.Groups["name"].Success) { [void]$items.Add("test:" + $m.Groups["name"].Value); continue }
        $a = Get-CallArguments $Text ($m.Index + $m.Length)
        if ($a.Count -eq 0) { continue }
        if ($m.Groups["one"].Success)
        {
            [void]$items.Add($m.Groups["one"].Value + ":" + $a[0])
        }
        else
        {
            [void]$items.Add("Report:" + ($a -join "|"))
        }
    }
    return , $items.ToArray()
}

# あるコミット（または索引）のファイルの中身。無ければ空文字。
function Get-Blob([string]$Spec)
{
    $r = Invoke-Git @("show", $Spec)
    if ($r.ExitCode -ne 0) { return "" }
    return $r.Text
}

# ------------------------------------------------------------------
# 本体
# ------------------------------------------------------------------
try
{
    if (@(@($Staged.IsPresent, [bool]$Commit, [bool]$Range) | Where-Object { $_ }).Count -ne 1)
    {
        Write-Msg "  -Staged・-Commit・-Range のどれか 1 つを指定してください。" -ForegroundColor Red
        exit 2
    }
    if ($CheckTestCases -and -not $Range)
    {
        Write-Msg "  -CheckTestCases は -Range と併せて指定してください。" -ForegroundColor Red
        exit 2
    }

    # --- TESTCASES.md の作り直しの漏れ ---------------------------------
    if ($CheckTestCases)
    {
        if ($Range -notmatch '^(.+)\.\.(.+)$')
        {
            Write-Msg "  -Range は <base>..<head> の形で指定してください。" -ForegroundColor Red
            exit 2
        }
        $head = $Matches[2]
        $base = (Invoke-GitChecked @("merge-base", $Matches[1], $head)).Lines[0]

        $names = (Invoke-GitChecked @("diff", "--name-only", $base, $head, "--", ":(top)root/programs/Tests/")).Lines
        if ($names -contains $testCasesFile)
        {
            Write-Msg "  TESTCASES.md は作り直されています。"
            exit 0
        }

        $changed = @()
        foreach ($n in $names)
        {
            if ($n -notmatch $testCasesSource) { continue }
            $old = Get-TestCaseItems (Get-Blob "${base}:$n")
            $new = Get-TestCaseItems (Get-Blob "${head}:$n")
            if (($old -join "`n") -cne ($new -join "`n")) { $changed += $n }
        }
        if ($changed.Count -eq 0)
        {
            Write-Msg "  テストの内容の変更はありません。"
            exit 0
        }

        $messages = (Invoke-GitChecked @("log", "--format=%B", "$base..$head")).Lines
        $reasons = Get-Trailer $messages "TestCases-Unchanged"
        if ($reasons.Count -gt 0)
        {
            Write-Msg ("  テストの内容の変更 {0} 件。トレーラーで承認済み : {1}" -f $changed.Count, ($reasons -join " / "))
            exit 0
        }

        Write-Msg ""
        Write-Msg "  **テストの内容を変えたのに、TESTCASES.md が作り直されていません**" -ForegroundColor Red
        foreach ($x in $changed) { Write-Msg ("    " + $x) -ForegroundColor Yellow }
        Write-Msg ""
        Write-Msg "  root で .\2_RunAllTests.ps1 -Launch -UpdateTestCases を回してください。"
        Write-Msg "  原本に現れない変更（通しの既定から外れるテストなど）なら、トレーラーに理由を書いてください。"
        Write-Msg "    TestCases-Unchanged: <理由>"
        Write-Msg ""
        exit 1
    }

    # --- 範囲は、コミットごとに自分自身を -Commit で呼ぶ -----------------
    if ($Range)
    {
        $commits = @((Invoke-GitChecked @("rev-list", "--no-merges", "--reverse", $Range)).Lines)
        Write-Msg ("  {0} の {1} 件のコミットを見ます" -f $Range, $commits.Count)
        $worst = 0
        $skipped = 0
        foreach ($c in $commits)
        {
            # **導入より前のコミットは見ない。** 規約が無かった時点のコミットに、トレーラーは求められない。
            if ((Invoke-Git @("cat-file", "-e", "${c}:$selfPath")).ExitCode -ne 0) { $skipped++; continue }
            & $PSCommandPath -Commit $c
            if ($LASTEXITCODE -gt $worst) { $worst = $LASTEXITCODE }
        }
        if ($skipped -gt 0) { Write-Msg ("  導入より前のコミット {0} 件は見ていません" -f $skipped) }
        if ($worst -eq 1)
        {
            Write-Msg "  既にあるコミットは、メッセージを書き直す（git rebase -i で reword）。push 済みなら force push になるので、人が判断する。"
        }
        exit $worst
    }

    # --- 比較の両端と、メッセージ ---------------------------------------
    if ($Staged)
    {
        if (-not $MessageFile -or -not (Test-Path $MessageFile))
        {
            Write-Msg ("  -MessageFile が見つかりません : {0}" -f $MessageFile) -ForegroundColor Red
            exit 2
        }
        if ((Invoke-Git @("rev-parse", "-q", "--verify", "MERGE_HEAD")).ExitCode -eq 0) { exit 0 }

        $base = "HEAD"
        if ((Invoke-Git @("rev-parse", "-q", "--verify", "HEAD")).ExitCode -ne 0) { $base = $emptyTree }
        $diffEnds = @("--cached", $base)
        $newSpec  = { param($path) ":$path" }
        $message  = @(Get-Content -LiteralPath $MessageFile -Encoding UTF8)
        $label    = "ステージした変更"
    }
    else
    {
        $sha = (Invoke-GitChecked @("rev-parse", "--verify", "$Commit^{commit}")).Lines[0]
        $parents = @((Invoke-GitChecked @("rev-list", "--parents", "-n", "1", $sha)).Lines[0] -split ' ' | Select-Object -Skip 1)
        if ($parents.Count -gt 1) { exit 0 }

        $base = $(if ($parents.Count -eq 1) { $parents[0] } else { $emptyTree })
        $diffEnds = @($base, $sha)
        $newSpec  = { param($path) "${sha}:$path" }
        $message  = @((Invoke-GitChecked @("log", "-1", "--format=%B", $sha)).Lines)
        $label    = "コミット " + $sha.Substring(0, 8)
    }

    $findings = @()

    # --- 仕組み自体 ------------------------------------------------------
    $oldBasis = @{}
    $newBasis = @{}
    foreach ($n in (Invoke-GitChecked (@("diff", "-M", "--name-status") + $diffEnds + @("--", ":(top)"))).Lines)
    {
        $f = $n -split "`t"
        $status = $f[0].Substring(0, 1)
        $oldPath = $f[1]
        $newPath = $f[$f.Count - 1]

        if ($status -ne "A" -and $oldPath -match $guardPattern)
        {
            $findings += ("仕組みの変更   : {0}" -f $(if ($oldPath -eq $newPath) { $oldPath } else { "$oldPath → $newPath" }))
        }

        # 根拠は、コミット全体で比べる（ファイルをまたいで移しただけなら数えない）
        if ($status -ne "A" -and $oldPath -match $testPattern -and $base -ne $emptyTree) { Add-Basis (Get-Blob "${base}:$oldPath") $oldBasis }
        if ($status -ne "D" -and $newPath -match $testPattern) { Add-Basis (Get-Blob (& $newSpec $newPath)) $newBasis }
    }

    foreach ($id in ($oldBasis.Keys | Sort-Object))
    {
        if (-not $newBasis.ContainsKey($id)) { $findings += ("根拠の削除     : {0}" -f $id); continue }
        if ($oldBasis[$id] -cne $newBasis[$id]) { $findings += ("根拠の変更     : {0}" -f $id) }
    }

    # --- テスト ----------------------------------------------------------
    #   1 回の diff を「diff --git」の行でファイルに分け、消えた行・足した行を数える。
    #   パスはリポジトリのルートからにする（:(top)）。カレントは変えない。
    $diff = (Invoke-GitChecked (@("diff", "-M", "-U0", "--no-color") + $diffEnds + @("--", ":(top)root/programs/Tests/"))).Lines
    $file = $null
    $count = @{}
    foreach ($l in $diff)
    {
        if ($l -match '^diff --git a/.+ b/(.+)$')
        {
            $file = $Matches[1]
            if ($file -notmatch $testPattern) { $file = $null; continue }
            $count[$file] = @{ TestDel = 0; TestAdd = 0; SkipDel = 0; SkipAdd = 0; VerifyDel = 0; VerifyAdd = 0 }
            continue
        }
        if (-not $file) { continue }
        if ($l.StartsWith("+++") -or $l.StartsWith("---")) { continue }
        if (-not ($l.StartsWith("+") -or $l.StartsWith("-"))) { continue }

        $body = $l.Substring(1)
        if ($body.TrimStart().StartsWith("//")) { continue }
        $del = $l.StartsWith("-")
        if ($body -match $testAttrPattern) { if ($del) { $count[$file].TestDel++ } else { $count[$file].TestAdd++ } }
        if ($body -match $skipPattern)     { if ($del) { $count[$file].SkipDel++ } else { $count[$file].SkipAdd++ } }
        if (($body -match $verifyPattern) -or (($file -match $unitTestPattern) -and ($body -match $unitVerifyPattern)))
        {
            if ($del) { $count[$file].VerifyDel++ } else { $count[$file].VerifyAdd++ }
        }
    }
    foreach ($k in ($count.Keys | Sort-Object))
    {
        $c = $count[$k]
        if ($c.TestDel -gt $c.TestAdd)     { $findings += ("テストの削除   : {0}（{1} 件）" -f $k, ($c.TestDel - $c.TestAdd)) }
        if ($c.SkipAdd -gt $c.SkipDel)     { $findings += ("Skip の追加    : {0}（{1} 件）" -f $k, ($c.SkipAdd - $c.SkipDel)) }
        if ($c.VerifyDel -gt $c.VerifyAdd) { $findings += ("検証の削除     : {0}（{1} 件）" -f $k, ($c.VerifyDel - $c.VerifyAdd)) }
    }

    # --- 判定 -----------------------------------------------------------
    if ($findings.Count -eq 0) { exit 0 }

    $trailers = Get-Trailer $message "Expectation-Change"
    if ($trailers.Count -gt 0)
    {
        Write-Msg ("  期待値の変更 {0} 件（{1}）。トレーラーで承認済み : {2}" -f $findings.Count, $label, ($trailers -join " / "))
        exit 0
    }

    Write-Msg ""
    Write-Msg ("  **トレーラーの無い期待値の変更があります**（{0}。QUALITY.md 3 節）" -f $label) -ForegroundColor Red
    foreach ($x in $findings) { Write-Msg ("    " + $x) -ForegroundColor Yellow }
    Write-Msg ""
    Write-Msg "  差分を確かめたうえで、コミット メッセージの末尾に理由を書いてください。"
    Write-Msg "    Expectation-Change: <何が・なぜ変わったか（仕様の該当箇所・Issue 番号）>"
    Write-Msg ""
    exit 1
}
catch
{
    Write-Msg ("  期待値の変更を確かめられませんでした : {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 2
}
