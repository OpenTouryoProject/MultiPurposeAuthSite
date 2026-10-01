<#
.SYNOPSIS
    repo の DDL を、各コンテナの初期化ディレクトリへ流し込む。

.DESCRIPTION
    ＜なぜ要るか＞
      E2E 用の UserStore は**作り直せること**に価値がある（#250 の段階 1）。
      **DDL の原本は repo にしか置かない**（root/files/resource/.../Sql/{sqlserver,oracle,pstgrs}）。
      ここへコピーしたものは**生成物**で、.gitignore 済みである。

      **コピーを忘れると、古いスキーマのまま起動する。**
      #245 の段階 3 で踏んだ「古い DB に列が無い」（FamilyId / UsedDate）は、それが原因だった。
      **1_DockerComposeUp.bat が、起動の前に必ずこれを呼ぶ。**

    ＜改行コード＞
      **LF に直す。** コンテナの中で shell / sqlplus が読むため、CRLF だと動かないものがある。

    ＜Oracle だけ 1 行足す＞
      gvenzl のイメージは、初期化スクリプトを **CDB のルートで SYS として**実行する。
      **CDB に SCOTT は居ない**ので、ALTER SESSION SET CURRENT_SCHEMA では
      ORA-01435（user does not exist）になる（実測）。
      **先頭で SCOTT として PDB に繋ぎ直す**
      （SCOTT は docker-compose.yml の APP_USER が作る）。

    ＜非対話＞
      **pause を入れない**（#250 の段階 1 で外した）。自動で回せるようにするため。

.EXAMPLE
    .\0_CopyInitSql.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/30  玄人 幸道         非対話にし、Oracle を追加した（#250 の段階 1）
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath
$sqlRoot = Join-Path $here '..\root\files\resource\MultiPurposeAuthSite\Sql'

# 方言 → コピー先（コンテナの初期化ディレクトリ）
$targets = @(
    @{ Dialect = 'pstgrs';    Dir = 'postgres\init';  Prefix = $null },
    @{ Dialect = 'sqlserver'; Dir = 'sqlserver\init'; Prefix = $null },

    # **Oracle は CDB のルートで SYS として実行される**ので、
    #   **SCOTT で PDB に繋ぎ直す 1 行を足す**（#250 の段階 1 で実測して直した）。
    #   ALTER SESSION SET CURRENT_SCHEMA = SCOTT では
    #   **ORA-01435: user does not exist** になる（CDB に SCOTT は居ない）。
    @{ Dialect = 'oracle';    Dir = 'oracle\init';
       Prefix = 'CONNECT SCOTT/tiger@localhost/FREEPDB1' }
)

foreach ($t in $targets)
{
    $src = Join-Path $sqlRoot ($t.Dialect + '\Create_UserStore.sql')
    $dstDir = Join-Path $here $t.Dir
    $dst = Join-Path $dstDir '1_Create_UserStore.sql'

    if (-not (Test-Path $src))
    {
        throw ("DDL が見つかりません : " + $src)
    }

    New-Item -ItemType Directory -Force $dstDir | Out-Null

    # 既定のエンコードは 5.1 が ANSI、7 が UTF-8 なので明示する（CODING.md 5 節）
    $text = Get-Content -Path $src -Raw -Encoding UTF8

    if ($t.Prefix)
    {
        $text = $t.Prefix + "`n" + $text
    }

    # **LF に直す。** CRLF が混ざっていても 1 度 LF に寄せる
    $text = $text -replace "`r`n", "`n"

    # **BOM を付けない**（sqlcmd / psql / sqlplus が先頭の BOM を読み間違えることがある）
    [System.IO.File]::WriteAllText($dst, $text, (New-Object System.Text.UTF8Encoding $false))

    Write-Output ("  {0,-10} -> {1}" -f $t.Dialect, $t.Dir)
}

Write-Output ""
Write-Output "  DDL を流し込みました（生成物なので .gitignore 済み）。"
