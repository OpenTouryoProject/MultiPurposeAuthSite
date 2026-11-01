<#
.SYNOPSIS
    TESTCASES.md の根拠を、種類ごとに数える（#315。QUALITY.md 6 節・7 節）。

.DESCRIPTION
    TestReport の basis は必須の引数なので、有無を数えるとほぼ 100% になり、意味が無い。
    そこで、次の 3 種類の割合を、テストの群（SM・TC・EX・RT など）ごとに数える。

      外部の仕様       … RFC・OIDC・SAML など、リポジトリの外の文書を指すもの
      Issue            … 外部の仕様を指さず、Issue の番号だけを指すもの
      リポジトリの前提 … どちらも指さないもの

    **外部の仕様と Issue の両方を挙げる根拠は、外部の仕様に数える。**
    「節あり」は、外部の仕様のうち節番号まで書いたもの。

    E2E はサイトを外から叩くので、テストと名前空間は 1 対 1 に対応しない。
    そのため、品質マップの名前空間ではなく、テストの群で数える。

    **判定はしない。** 根拠の内容が正しいかは見ない（原典で確かめるのは人とレビューの役目）。

.PARAMETER Path
    TESTCASES.md のパス。省略時は programs\Tests\TESTCASES.md。

.EXAMPLE
    .\CountBasis.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/01  玄人 幸道         新規作成（#315）
#>
[CmdletBinding()]
param(
    [string]$Path
)

$ErrorActionPreference = "Stop"

if (-not $Path)
{
    $Path = Join-Path $PSScriptRoot "programs\Tests\TESTCASES.md"
}

# 外部の仕様の名前。**大文字と小文字を区別する**（fido2-net-lib のようなライブラリ名を、FIDO の仕様に数えない）。
$externalPattern = 'RFC ?\d|OIDC|OpenID|FAPI|SAML|OAuth|CIBA|RP-Initiated|Back-?Channel|Front-?Channel|WebAuthn|FIDO|NIST|OWASP|JARM|W3C|OASIS'

$groups = [ordered]@{}
$group = ""

foreach ($line in (Get-Content -LiteralPath $Path -Encoding UTF8))
{
    if ($line -match '^## ([A-Z0-9]{2})-') { $group = $Matches[1]; continue }
    if ($line -notmatch '^\| 根拠 \| (.*) \|$') { continue }
    $basis = $Matches[1]

    if (-not $groups.Contains($group))
    {
        $groups[$group] = [pscustomobject]@{ 群 = $group; 計 = 0; 外部 = 0; 節あり = 0; Issue = 0; 前提 = 0 }
    }
    $g = $groups[$group]
    $g.計++

    if ($basis -cmatch $externalPattern)
    {
        $g.外部++
        # SAML の根拠は § を付けずに「Bindings 3.4」と書く。版（1.0・2.0）は節に数えない。
        if ($basis -match '§' -or ($basis -replace '\b\d+\.0\b', '') -match '\b\d+\.\d+') { $g.節あり++ }
    }
    elseif ($basis -match '#\d+') { $g.Issue++ }
    else { $g.前提++ }
}

$rows = @($groups.Values)
$total = [pscustomobject]@{
    群     = "計"
    計     = ($rows | Measure-Object 計 -Sum).Sum
    外部   = ($rows | Measure-Object 外部 -Sum).Sum
    節あり = ($rows | Measure-Object 節あり -Sum).Sum
    Issue  = ($rows | Measure-Object Issue -Sum).Sum
    前提   = ($rows | Measure-Object 前提 -Sum).Sum
}

function Format-Rate([int]$Value, [int]$All)
{
    if ($All -eq 0) { return "0" }
    return ("{0}（{1:N0}%）" -f $Value, (100.0 * $Value / $All))
}

"| 群 | テスト | 外部の仕様 | うち節あり | Issue | リポジトリの前提 |"
"|---|---:|---:|---:|---:|---:|"
foreach ($r in ($rows + $total))
{
    "| {0} | {1} | {2} | {3} | {4} | {5} |" -f $r.群, $r.計,
        (Format-Rate $r.外部 $r.計), (Format-Rate $r.節あり $r.外部),
        (Format-Rate $r.Issue $r.計), (Format-Rate $r.前提 $r.計)
}
