<#
.SYNOPSIS
    適合性テスト（Conformance Suite）と、その相手の OP を止めて消す（#350 / #439）。

.DESCRIPTION
    **停止の手順の本体**である（#439。..\Stub\ と同じ形。#401）。**Windows の 3_DockerComposeDown.bat も、これを呼ぶだけ。**
    **Linux（GitHub Actions の ubuntu-latest など）では pwsh で呼ぶ。**

    **docker compose --env-file ..\E2E\.env [--env-file .env.cts] down**
    （.env.cts は 2_DockerComposeUp.ps1 が呼ぶ Prepare.ps1 が作る。無ければ付けない）

    **結果（out\）・MongoDB のデータ（mongo\）・証明書と鍵（certs\）・ログ（logs\）は、ホストに残る。**

    ＜終了コード＞
      0 : 止めた
      1 : docker compose が失敗した

.EXAMPLE
    .\3_DockerComposeDown.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/27  玄人 幸道         新規。3_DockerComposeDown.bat の手順を移し、Linux の pwsh でも呼べるようにした（#439）
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。11_CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath

$envArgs = @()
foreach ($f in (Join-Path $here '../E2E/.env'), (Join-Path $here '.env.cts'))
{
    if (Test-Path -LiteralPath $f -PathType Leaf) { $envArgs += @('--env-file', $f) }
}

Push-Location $here

try
{
    & docker compose @envArgs down

    if ($LASTEXITCODE -ne 0)
    {
        Write-Output ""
        Write-Output "  停止に失敗しました。"
        exit 1
    }
}
finally
{
    Pop-Location
}

exit 0
