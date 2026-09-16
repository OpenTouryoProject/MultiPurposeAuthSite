<#
.SYNOPSIS
    3 つの RDB の DDL が、互いにミラーになっているかを確かめる。

.DESCRIPTION
    files/resource/MultiPurposeAuthSite/Sql/{sqlserver,oracle,pstgrs}/ の
    Create_UserStore.sql と Select_UserStore.sql を突き合わせる。

    ＜なぜ要るか＞
      DBMS ごとに別のファイルで同じ構造を保っているため、**片方だけ直る**ことが起きる。
      実際に #206 では、oracle だけ 6 年以上更新されず、その間に追加された
      DeviceAuthZData と CibaData が入っていなかった。
      SQL は実行しないと分からない部分もあるが、**定義の食い違いは読めば分かる。**

    ＜何を見るか＞
      Create_UserStore.sql … CREATE TABLE のテーブル名と、その列名
      Select_UserStore.sql … SELECT * FROM の対象テーブル名

      **両方を見る。** 片方だけ見る作りにすると、もう片方の差を見落とす
      （Select 側は CREATE TABLE を持たないので、同じ判定では数えられない）。

    ＜比較のしかた＞
      方言の差は無視する。括り文字（[] ""）を外し、大小文字を揃えて比べる。
      列の型は比べない（nvarchar(max) と NVARCHAR2(2000) のように、対応はするが同一ではない）。
      **型まで揃えたいかは、人が決めること。** ここでは「在る / 無い」だけを見る。

.PARAMETER Detail
    差が無いテーブルも含めて、すべて表示する。

.EXAMPLE
    .\CompareDdl.ps1

.EXAMPLE
    .\CompareDdl.ps1 -Detail

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/13  玄人 幸道         新規作成（#206）
#>
[CmdletBinding()]
param(
    [switch]$Detail
)

$dbms = @('sqlserver', 'oracle', 'pstgrs')

# 本スクリプトは root に置き、その配下の Sql を対象とする。
$sqlRoot = Join-Path $PSScriptRoot "files\resource\MultiPurposeAuthSite\Sql"

# ------------------------------------------------------------------
# 正規化
# ------------------------------------------------------------------
# 括り文字を外し、小文字に揃える。
#   [CibaData] / "CibaData" / cibadata → cibadata
function Get-Normalized([string]$name)
{
    return $name.Trim().Trim('[', ']', '"').ToLower()
}

# ------------------------------------------------------------------
# Create_UserStore.sql を読む
# ------------------------------------------------------------------
# 戻り値 : @{ テーブル名 = @(列名...) }
#
# **制約・索引の行を列として数えない。** CONSTRAINT / PRIMARY / FOREIGN などで始まる行は飛ばす。
function Read-CreateScript([string]$path)
{
    $tables = [ordered]@{}
    $current = $null

    foreach ($line in (Get-Content -LiteralPath $path))
    {
        if ($line -match '^\s*CREATE\s+TABLE\s+(?<name>[\[\"]?[A-Za-z0-9_]+[\]\"]?)')
        {
            $current = Get-Normalized $Matches['name']
            $tables[$current] = New-Object System.Collections.Generic.List[string]
            continue
        }

        if ($null -eq $current) { continue }

        # テーブル定義の終わり
        if ($line -match '^\s*\)') { $current = $null; continue }

        # 列ではない行
        if ($line -match '^\s*(CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK|WITH|ON|--|/\*|CREATE|ALTER|GO|SET)\b') { continue }

        if ($line -match '^\s*(?<name>[\[\"]?[A-Za-z0-9_]+[\]\"]?)\s+[A-Za-z\[\"]')
        {
            $tables[$current].Add((Get-Normalized $Matches['name']))
        }
    }

    return $tables
}

# ------------------------------------------------------------------
# Select_UserStore.sql を読む
# ------------------------------------------------------------------
# 戻り値 : @(テーブル名...)
function Read-SelectScript([string]$path)
{
    $names = New-Object System.Collections.Generic.List[string]

    foreach ($line in (Get-Content -LiteralPath $path))
    {
        foreach ($m in [regex]::Matches($line, 'FROM\s+(?<name>[\[\"]?[A-Za-z0-9_]+[\]\"]?)'))
        {
            $names.Add((Get-Normalized $m.Groups['name'].Value))
        }
    }

    return $names
}

# ------------------------------------------------------------------
# 突き合わせ
# ------------------------------------------------------------------
$ng = 0

Write-Host ""
Write-Host "================ Create_UserStore.sql ================" -ForegroundColor Cyan

$created = @{}
foreach ($d in $dbms)
{
    $path = Join-Path $sqlRoot "$d\Create_UserStore.sql"

    if (-not (Test-Path $path))
    {
        Write-Host ("  [NG] ファイルがありません : {0}" -f $path) -ForegroundColor Red
        $ng++
        continue
    }

    $created[$d] = Read-CreateScript $path
    Write-Host ("  {0,-10} テーブル {1,2} 件" -f $d, $created[$d].Count)
}

if ($created.Count -eq $dbms.Count)
{
    # --- テーブルの有無 ---
    $allTables = @($created.Values | ForEach-Object { $_.Keys } | Sort-Object -Unique)

    Write-Host ""
    Write-Host ("  {0,-32} {1,-10} {2,-8} {3}" -f 'テーブル', 'sqlserver', 'oracle', 'pstgrs')

    foreach ($t in $allTables)
    {
        $marks = @($dbms | ForEach-Object { if ($created[$_].Contains($t)) { 'あり' } else { '**無し**' } })

        if ($marks -contains '**無し**')
        {
            $ng++
            Write-Host ("  {0,-32} {1,-10} {2,-8} {3}" -f $t, $marks[0], $marks[1], $marks[2]) -ForegroundColor Red
        }
        elseif ($Detail)
        {
            Write-Host ("  {0,-32} {1,-10} {2,-8} {3}" -f $t, $marks[0], $marks[1], $marks[2])
        }
    }

    # --- 列の有無（3 つとも在るテーブルだけ）---
    Write-Host ""
    Write-Host "  【列の差】"

    $colDiff = 0
    foreach ($t in $allTables)
    {
        if (@($dbms | Where-Object { -not $created[$_].Contains($t) }).Count -gt 0) { continue }

        $allCols = @($dbms | ForEach-Object { $created[$_][$t] } | Sort-Object -Unique)

        foreach ($c in $allCols)
        {
            $marks = @($dbms | ForEach-Object { if ($created[$_][$t] -contains $c) { 'あり' } else { '**無し**' } })

            if ($marks -contains '**無し**')
            {
                $colDiff++
                $ng++
                Write-Host ("  {0}.{1,-24} {2,-10} {3,-8} {4}" -f $t, $c, $marks[0], $marks[1], $marks[2]) -ForegroundColor Red
            }
        }
    }

    if ($colDiff -eq 0) { Write-Host "  差なし" -ForegroundColor Green }
}

Write-Host ""
Write-Host "================ Select_UserStore.sql ================" -ForegroundColor Cyan

$selected = @{}
foreach ($d in $dbms)
{
    $path = Join-Path $sqlRoot "$d\Select_UserStore.sql"

    if (-not (Test-Path $path))
    {
        Write-Host ("  [NG] ファイルがありません : {0}" -f $path) -ForegroundColor Red
        $ng++
        continue
    }

    $selected[$d] = Read-SelectScript $path
    Write-Host ("  {0,-10} SELECT 対象 {1,2} 件" -f $d, $selected[$d].Count)
}

if ($selected.Count -eq $dbms.Count)
{
    $allTables = @($selected.Values | ForEach-Object { $_ } | Sort-Object -Unique)

    Write-Host ""
    $selDiff = 0
    foreach ($t in $allTables)
    {
        $marks = @($dbms | ForEach-Object { if ($selected[$_] -contains $t) { 'あり' } else { '**無し**' } })

        if ($marks -contains '**無し**')
        {
            $selDiff++
            $ng++
            Write-Host ("  {0,-32} {1,-10} {2,-8} {3}" -f $t, $marks[0], $marks[1], $marks[2]) -ForegroundColor Red
        }
        elseif ($Detail)
        {
            Write-Host ("  {0,-32} {1,-10} {2,-8} {3}" -f $t, $marks[0], $marks[1], $marks[2])
        }
    }

    if ($selDiff -eq 0) { Write-Host "  差なし" -ForegroundColor Green }
}

# ------------------------------------------------------------------
# まとめ
# ------------------------------------------------------------------
Write-Host ""

if ($ng -eq 0)
{
    Write-Host "ミラーになっています（定義の食い違いはありません）。" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ※ **SQL が実行できるかは、これでは分かりません。**" -ForegroundColor Yellow
    Write-Host "     実機で流せるのは、テストで UserStoreType を切り替えられるようになってから。"
    exit 0
}
else
{
    Write-Host ("{0} 件の食い違いがあります。上の赤い行を直してください。" -f $ng) -ForegroundColor Red
    exit 1
}
