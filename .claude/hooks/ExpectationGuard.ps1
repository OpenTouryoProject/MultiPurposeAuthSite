<#
.SYNOPSIS
    期待値の変更（QUALITY.md 3 節）になりうる編集を、人の確認付きにする（#315 の段 1）。

.DESCRIPTION
    Claude Code の PreToolUse フック（.claude/settings.json）から呼ばれる。
    ツールの入力（JSON）を標準入力で受け取り、該当すれば「ask」を返す。該当しなければ何も出さない。

    ＜確認付きにするもの＞
      Edit・Write・MultiEdit
        - TESTCASES.md（生成物）を手で編集するもの
        - root/programs/Tests/**/*.cs の編集で、テストの属性の行が減るもの、Skip の行が増えるもの、
          .Verify(・.VerifyEqual( の行が減るもの
      Bash・PowerShell
        - TESTCASES.md を指していて、書き込む操作（リダイレクト・Set-Content・cp・sed -i など）を含むもの
          （**推測である。** 漏れは段 2・段 3 が塞ぐ。2_RunAllTests.ps1 -UpdateTestCases は、パスを書かないので対象にしない）

    数え方は CheckExpectationChange.ps1 と同じ（// で始まる行は数えない）。
    **根拠（Report の第 4 引数）の変更は、ここでは見ない。** 編集の断片からは判定できないので、段 2・段 3 に任せる。
    **このフックは止めない。** 人に見せるだけで、許可すれば編集は進む。承認の記録は段 2・段 3 のトレーラーである。

    **失敗したら何もしない**（エージェントの作業を止めない）。

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/01  玄人 幸道         新規作成（#315 段 1。OpenTouryo #640 と同じ作り）
#>

$testCasesPattern = '/root/programs/Tests/TESTCASES\.md$'
$testPattern      = '/root/programs/Tests/.+\.cs$'
$testAttrPattern  = '[\[,]\s*(Fact|Theory|SkippableFact|SkippableTheory|InlineData|MemberData|ClassData|Test|TestCase|TestCaseSource)\s*[\],(]'
$skipPattern      = '\bSkip\s*\.\s*(If|IfNot)\s*\(|[\[,(]\s*Skip\s*=|\bSkipException\s*\(|[\[,]\s*(Ignore|Explicit)\s*[\],(]'
$verifyPattern    = '\.\s*(Verify|VerifyEqual)\s*\('

# コマンドで原本を書き換えそうな操作（2>$null・*>&1 のような、捨てるだけのリダイレクトは除く）
$fileInCommand  = 'TESTCASES\.md'
$writeInCommand = '(?<![0-9*])>(?!\s*(\$null|/dev/null|&))|\b(Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|Remove-Item|Rename-Item|WriteAll(Text|Bytes|Lines))\b|(^|[\s;|&(])(cp|mv|rm|copy|move|del|tee)\s|\bsed\s+(-\w*\s+)*-i'

# 行を数える（// で始まる行は数えない）
function Get-LineCount([string]$Text, [string]$Pattern)
{
    if (-not $Text) { return 0 }
    $n = 0
    foreach ($l in ($Text -split "`n"))
    {
        if ($l.TrimStart().StartsWith("//")) { continue }
        if ($l -match $Pattern) { $n++ }
    }
    return $n
}

# ask を返す。**コンソールのコード ページに触れずに、UTF-8 で書く。**
function Write-Ask([string]$Reason)
{
    $json = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "ask"
            permissionDecisionReason = $Reason + "（QUALITY.md 3 節。コミットにはトレーラー Expectation-Change: <理由> が要る）"
        }
    } | ConvertTo-Json -Compress -Depth 4
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
}

try
{
    $reader = New-Object IO.StreamReader([Console]::OpenStandardInput(), (New-Object Text.UTF8Encoding $false))
    $hook = $reader.ReadToEnd() | ConvertFrom-Json
    $tool = "$($hook.tool_name)"
    $in   = $hook.tool_input

    if ($tool -in @("Bash", "PowerShell"))
    {
        $cmd = "$($in.command)"
        if ($cmd -match $fileInCommand -and $cmd -match $writeInCommand)
        {
            Write-Ask "TESTCASES.md（生成物）を書き換える可能性のあるコマンドです"
        }
        exit 0
    }

    if ($tool -notin @("Edit", "Write", "MultiEdit")) { exit 0 }

    $path = ("$($in.file_path)" -replace '\\', '/')
    if ($path -match $testCasesPattern)
    {
        Write-Ask "TESTCASES.md（生成物）を手で編集します"
        exit 0
    }
    if ($path -notmatch $testPattern) { exit 0 }

    # 編集の前後の文字列。Write は既存のファイルと、新しい内容を比べる。
    $before = @(); $after = @()
    switch ($tool)
    {
        "Edit"      { $before += "$($in.old_string)"; $after += "$($in.new_string)" }
        "MultiEdit" { foreach ($e in @($in.edits)) { $before += "$($e.old_string)"; $after += "$($e.new_string)" } }
        "Write"
        {
            if (Test-Path -LiteralPath $in.file_path) { $before += [IO.File]::ReadAllText($in.file_path) }
            $after += "$($in.content)"
        }
    }
    $b = $before -join "`n"; $a = $after -join "`n"

    $reasons = @()
    $testDel = (Get-LineCount $b $testAttrPattern) - (Get-LineCount $a $testAttrPattern)
    $skipAdd = (Get-LineCount $a $skipPattern) - (Get-LineCount $b $skipPattern)
    $verDel  = (Get-LineCount $b $verifyPattern) - (Get-LineCount $a $verifyPattern)
    if ($testDel -gt 0) { $reasons += ("テストの属性が {0} 件減ります" -f $testDel) }
    if ($skipAdd -gt 0) { $reasons += ("Skip が {0} 件増えます" -f $skipAdd) }
    if ($verDel -gt 0)  { $reasons += ("検証が {0} 件減ります" -f $verDel) }

    if ($reasons.Count -gt 0)
    {
        Write-Ask ("テストを変えます（{0}） : {1}" -f ($reasons -join "、"), [IO.Path]::GetFileName($path))
    }
    exit 0
}
catch
{
    # 失敗しても止めない。理由だけ標準エラーへ出す（Claude Code はブロックしない）
    [Console]::Error.WriteLine("ExpectationGuard.ps1: " + $_.Exception.Message)
    exit 1
}
