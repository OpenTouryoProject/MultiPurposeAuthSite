<#
.SYNOPSIS
    E2E のカバレッジを、品質マップ（QUALITY.md 1 節）の名前空間の単位で集計する（#315）。

.DESCRIPTION
    2_RunAllTests.ps1 -Launch -Coverage が書き出す cobertura を読み、
    net10.0 版・net48 版・両版の和（どちらかで 1 回でも通った行）を、名前空間ごとに出す。
    あわせて、リスク「高」の名前空間で、**どちらの版でも 1 行も通らなかったメソッド**を一覧にする。

    **カバレッジは判定に使わない。** どこを書き足すかを選ぶための指針である。

    ＜Util.Test は合計から外す＞
      製品の経路に無い（E2E の足場である）ので、数えると合計が実力より良く見える。別の行に出す。

    ＜数えないもの＞
      .cs 以外（Razor の生成コード）と、リソースの生成コード（*.Designer.cs）。

.PARAMETER CoverageDir
    cobertura のあるフォルダ。省略時は programs\Tests\E2ETests\Result\coverage。
.PARAMETER Update
    programs\Tests\COVERAGE.md の表を置き換える。無ければ画面に出すだけ。
    **全件成功した通しの結果にだけ使う。**

.EXAMPLE
    .\CoverageReport.ps1

.EXAMPLE
    .\CoverageReport.ps1 -Update

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/01  玄人 幸道         新規作成（#315）
#>
[CmdletBinding()]
param(
    [string]$CoverageDir,
    [switch]$Update
)

$ErrorActionPreference = "Stop"

if (-not $CoverageDir)
{
    $CoverageDir = Join-Path $PSScriptRoot "programs\Tests\E2ETests\Result\coverage"
}

# 品質マップの行。Pattern はパス（区切りは /）に当てる。**上から順に見て、最初に当たった行に数える。**
$map = @(
    @{ Name = "TokenProviders";              Risk = "高";       High = $true;  Pattern = '/CommonLibrary/TokenProviders/' }
    @{ Name = "Extensions.Sts";              Risk = "高";       High = $true;  Pattern = '/CommonLibrary/Extensions/Sts/' }
    @{ Name = "SamlProviders";               Risk = "高";       High = $true;  Pattern = '/CommonLibrary/SamlProviders/' }
    @{ Name = "Controllers";                 Risk = "高";       High = $true;  Pattern = '/Controllers/' }
    @{ Name = "Extensions.FIDO";             Risk = "高";       High = $true;  Pattern = '/CommonLibrary/Extensions/FIDO/' }
    @{ Name = "Util.Sts・Util.IdP";          Risk = "中〜高";   High = $false; Pattern = '/CommonLibrary/Util/(Sts|IdP)/' }
    @{ Name = "Password";                    Risk = "中〜高";   High = $false; Pattern = '/CommonLibrary/Password/' }
    @{ Name = "Data";                        Risk = "中〜高";   High = $false; Pattern = '/CommonLibrary/Data/' }
    @{ Name = "Manager・Co";                 Risk = "中";       High = $false; Pattern = '/CommonLibrary/(Manager|Co)/' }
    @{ Name = "Network・Notifications・Entity・ViewModels・Log"; Risk = "中〜低"; High = $false; Pattern = '/CommonLibrary/(Network|Notifications|Entity|ViewModels|Log)/' }
    @{ Name = "その他（表に無いもの）";      Risk = "中〜低";   High = $false; Pattern = '.' }
)
$testPattern = '/CommonLibrary/Util/Test/'

# cobertura の 1 ファイルを読む。行 → 通ったか、メソッド → 行 を返す。
function Read-Cobertura([string]$Path)
{
    $lines = @{}     # "file|line" → 通ったか
    $methods = @{}   # "file|method" → 行のキーの一覧

    [xml]$doc = [IO.File]::ReadAllText($Path)
    foreach ($class in $doc.SelectNodes("//class"))
    {
        $file = ([string]$class.filename) -replace '\\', '/'
        if ($file -notmatch '\.cs$' -or $file -match '\.Designer\.cs$') { continue }

        # 非同期メソッドは状態機械のクラスになる（Foo/<Bar>d__3 の MoveNext）ので、元の名前へ戻す。
        $cls = [string]$class.name
        foreach ($method in $class.SelectNodes("methods/method"))
        {
            #   ラムダはクロージャのクラス（Foo/<>c__DisplayClass5_0 の <Bar>b__1）になるので、同じく元の名前へ戻す。
            #   **元のメソッドと同じ行の集まりとして数える**（本体が通っていれば、ラムダだけを未到達と数えない）。
            $name = [string]$method.name
            $m = [regex]::Match($cls, '<(\w+)>')
            if (-not $m.Success) { $m = [regex]::Match($name, '^<(\w+)>') }
            if ($m.Success) { $name = $m.Groups[1].Value }
            $short = (($cls -replace '[/+.]<.*$', '') -split '\.')[-1] + "." + $name

            $mkey = "$file|$short"
            if (-not $methods.ContainsKey($mkey)) { $methods[$mkey] = New-Object Collections.ArrayList }

            foreach ($line in $method.SelectNodes("lines/line"))
            {
                $key = "$file|" + $line.number
                $hit = ([int64]$line.hits) -gt 0
                if ($lines.ContainsKey($key)) { $lines[$key] = $lines[$key] -or $hit } else { $lines[$key] = $hit }
                [void]$methods[$mkey].Add($key)
            }
        }
    }
    return @{ Lines = $lines; Methods = $methods }
}

# パスを品質マップの行へ（Util.Test は別に扱うので $null）
function Get-MapRow([string]$File)
{
    if ($File -match $testPattern) { return $null }
    foreach ($r in $map) { if ($File -match $r.Pattern) { return $r } }
}

# 名前空間ごとの [通った行, 全体] を数える
function Get-Counts([hashtable]$Lines)
{
    $c = @{}
    foreach ($k in $Lines.Keys)
    {
        $file = ($k -split '\|')[0]
        $name = $(if ($file -match $testPattern) { "Util.Test" } else { (Get-MapRow $file).Name })
        if (-not $c.ContainsKey($name)) { $c[$name] = @(0, 0) }
        $c[$name][1]++
        if ($Lines[$k]) { $c[$name][0]++ }
    }
    return $c
}

function Format-Rate([object]$Pair)
{
    if (-not $Pair -or $Pair[1] -eq 0) { return "—" }
    return ("{0:N1}%（{1:N0} / {2:N0}）" -f (100.0 * $Pair[0] / $Pair[1]), $Pair[0], $Pair[1])
}

$corePath = Join-Path $CoverageDir "core.cobertura.xml"
$fxPath   = Join-Path $CoverageDir "netfx.cobertura.xml"
foreach ($p in $corePath, $fxPath)
{
    if (-not (Test-Path -LiteralPath $p))
    {
        Write-Host ("  cobertura がありません : {0}（2_RunAllTests.ps1 -Launch -Coverage で作る）" -f $p) -ForegroundColor Red
        exit 2
    }
}

$core = Read-Cobertura $corePath
$fx   = Read-Cobertura $fxPath

# 両版の和。ソリューションのルートより上のパスは揃っているので、そのまま突き合わせる。
$union = @{}
foreach ($src in $core.Lines, $fx.Lines)
{
    foreach ($k in $src.Keys)
    {
        if ($union.ContainsKey($k)) { $union[$k] = $union[$k] -or $src[$k] } else { $union[$k] = $src[$k] }
    }
}

$cCore  = Get-Counts $core.Lines
$cFx    = Get-Counts $fx.Lines
$cUnion = Get-Counts $union

$out = New-Object Collections.ArrayList
[void]$out.Add("| 名前空間 | リスク | net10.0 版 | net48 版 | 両版の和 |")
[void]$out.Add("|---|---|---:|---:|---:|")
$total = @{ Core = @(0, 0); Fx = @(0, 0); Union = @(0, 0) }
foreach ($r in $map)
{
    $n = $r.Name
    if (-not $cUnion.ContainsKey($n)) { continue }
    [void]$out.Add(("| {0} | {1} | {2} | {3} | {4} |" -f $n, $r.Risk, (Format-Rate $cCore[$n]), (Format-Rate $cFx[$n]), (Format-Rate $cUnion[$n])))
    foreach ($pair in @(@("Core", $cCore[$n]), @("Fx", $cFx[$n]), @("Union", $cUnion[$n])))
    {
        if ($pair[1])
        {
            $total[$pair[0]][0] += $pair[1][0]
            $total[$pair[0]][1] += $pair[1][1]
        }
    }
}
[void]$out.Add(("| **計（`Util.Test` を除く）** | | {0} | {1} | {2} |" -f (Format-Rate $total.Core), (Format-Rate $total.Fx), (Format-Rate $total.Union)))
[void]$out.Add(("| `Util.Test`（足場） | 低 | {0} | {1} | {2} |" -f (Format-Rate $cCore["Util.Test"]), (Format-Rate $cFx["Util.Test"]), (Format-Rate $cUnion["Util.Test"])))

# --- リスク「高」で、どちらの版でも通らなかったメソッド -------------------
$uncovered = @{}
foreach ($src in $core.Methods, $fx.Methods)
{
    foreach ($k in $src.Keys)
    {
        $file, $method = $k -split '\|', 2
        $row = Get-MapRow $file
        if (-not $row -or -not $row.High) { continue }
        $keys = @($src[$k] | Select-Object -Unique)
        if ($keys.Count -eq 0) { continue }
        if (@($keys | Where-Object { $union[$_] }).Count -gt 0) { $uncovered[$k] = $null; continue }
        if (-not $uncovered.ContainsKey($k) -or ($null -ne $uncovered[$k] -and $keys.Count -gt $uncovered[$k]))
        {
            $uncovered[$k] = $keys.Count
        }
    }
}

[void]$out.Add("")
[void]$out.Add("### リスク「高」で、どちらの版でも 1 行も通らなかったメソッド")
[void]$out.Add("")
foreach ($r in ($map | Where-Object { $_.High }))
{
    # 行の多い順。**5.1 と 7 で並びが変わらないよう、序数で比べる**（Sort-Object はカルチャに依る）。
    [string[]]$sortKeys = @($uncovered.Keys | Where-Object { $null -ne $uncovered[$_] -and ($_ -split '\|')[0] -match $r.Pattern } |
        ForEach-Object { "{0:D8}`t{1}" -f (99999999 - $uncovered[$_]), $_ })
    [Array]::Sort($sortKeys, [StringComparer]::Ordinal)
    $rows = @($sortKeys | ForEach-Object { ($_ -split "`t", 2)[1] })
    $sum = 0
    foreach ($k in $rows) { $sum += $uncovered[$k] }
    [void]$out.Add(("#### {0}（{1} 個・{2} 行）" -f $r.Name, $rows.Count, $sum))
    [void]$out.Add("")
    if ($rows.Count -gt 0)
    {
        [void]$out.Add("| メソッド | 行 | ファイル |")
        [void]$out.Add("|---|---:|---|")
        foreach ($k in $rows)
        {
            $file, $method = $k -split '\|', 2
            $rel = ($file -replace '^.*/root/programs/', '')
            [void]$out.Add(("| ``{0}`` | {1} | ``{2}`` |" -f $method, $uncovered[$k], $rel))
        }
        [void]$out.Add("")
    }
}

if (-not $Update)
{
    $out | ForEach-Object { $_ }
    exit 0
}

$doc = Join-Path $PSScriptRoot "programs\Tests\COVERAGE.md"
$text = [IO.File]::ReadAllText($doc)
$pattern = '(?s)(<!-- COVERAGE:BEGIN -->).*(<!-- COVERAGE:END -->)'
if ($text -notmatch $pattern) { throw "COVERAGE.md に COVERAGE:BEGIN / END がありません" }
$body = "<!-- COVERAGE:BEGIN -->`r`n`r`n" + ($out -join "`r`n") + "`r`n`r`n<!-- COVERAGE:END -->"
$text = [regex]::Replace($text, $pattern, { param($m) $body })
[IO.File]::WriteAllText($doc, $text, (New-Object Text.UTF8Encoding $true))
Write-Host ("  更新しました : {0}" -f $doc)
