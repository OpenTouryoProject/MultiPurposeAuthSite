# expectation-guard-source: OpenTouryoCodingAgentAssets@ade897953a72 src/quality/ExpectationGuard/ExpectationGuard.ps1 sha256:85dcee11730b097bff3f05dcab17a919571a610c64dc2e5aadc7e602ef404ffa
<#
.SYNOPSIS
    期待値の変更になりうる編集を、人の確認付きにする（段 1。Claude Code の PreToolUse フック）。

.DESCRIPTION
    .claude/settings.json の PreToolUse から呼ばれる。判定は本体（CheckExpectationChange.ps1 -PreToolUse）が、
    規則のファイル（rules.common.psd1・rules.psd1）を読んで行う。ここは本体を呼ぶだけ。
    **このフックは止めない。** 人に見せるだけで、許可すれば編集は進む。承認の記録は段 2・段 3 のトレーラーである。
    **失敗したら何もしない**（エージェントの作業を止めない）。

.NOTES
    原本：OpenTouryoCodingAgentAssets の src/quality/ExpectationGuard/（OpenTouryoCodingAgentAssets#3）。
    本体のパス（root/CheckExpectationChange.ps1）は install.ps1 -IncludeQualityGuard が埋める。
#>

try
{
    $root = $env:CLAUDE_PROJECT_DIR
    if (-not $root) { $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    & (Join-Path $root "root/CheckExpectationChange.ps1") -PreToolUse
    exit $LASTEXITCODE
}
catch
{
    [Console]::Error.WriteLine("ExpectationGuard.ps1: " + $_.Exception.Message)
    exit 1
}
