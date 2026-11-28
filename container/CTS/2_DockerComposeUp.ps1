<#
.SYNOPSIS
    適合性テスト（Conformance Suite。版を固定）と、その相手の OP（MPAS の net10.0 版・mem）を起動する（#350 / #439）。

.DESCRIPTION
    **起動の手順の本体**である（#439。..\Stub\ と同じ形。#401）。**Windows の 2_DockerComposeUp.bat も、これを呼ぶだけ**（手順を二重に持たない）。
    **Linux（GitHub Actions の ubuntu-latest など）では pwsh で呼ぶ。**

    1. **..\E2E\.env が在ることを確かめる**（..\E2E\1_PublishIdP.ps1 が作る。OP の証明書のパスワード）
    2. **publish の成果物がソースより古ければ警告する**（..\Common\CheckPublishFreshness.ps1。起動は止めない）
    3. **Prepare.ps1 で、nginx の証明書・compose に渡す値（.env.cts）・MTLS のフック・FAPI の鍵と証明書を用意する**
    4. **docker compose --env-file ..\E2E\.env --env-file .env.cts up -d --build**
       **--build が要る**（publish の成果物を OP のイメージに入れる。#294）

    **Conformance Suite の起動には 1〜2 分かかる。** このスクリプトは待たない（RunTestPlan.ps1 が、届かなければそう言って止まる）。
    **Conformance Suite と MongoDB はメモリを使う。** 要らないコンテナ（..\E2E\・..\Store\）は止めておく。

    ＜ホストのリソース＞
      **OP は C:\root\files\resource を /resource として読む。** 場所は環境変数 E2E_RESOURCE_DIR で替えられる（docker-compose.yml。..\E2E\ と同じ）。

    ＜終了コード＞
      0 : 起動した
      1 : ..\E2E\.env が無い、Prepare.ps1 が失敗した、docker compose が失敗した

.EXAMPLE
    .\2_DockerComposeUp.ps1

.EXAMPLE
    pwsh ./2_DockerComposeUp.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/27  玄人 幸道         新規。2_DockerComposeUp.bat の手順を移し、Linux の pwsh でも呼べるようにした（#439）
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。11_CODING.md 5 節）。
# **区切りは / で書く**（Linux の pwsh は \ を区切りにしない。Windows は / も受ける）
$here = Split-Path -Parent $PSCommandPath
$e2eEnv = Join-Path $here '../E2E/.env'

if (-not (Test-Path -LiteralPath $e2eEnv -PathType Leaf))
{
    Write-Output ""
    Write-Output "  ..\E2E\.env がありません。先に ..\E2E\1_PublishIdP.ps1 を動かしてください。"
    exit 1
}

Push-Location $here

try
{
    & (Join-Path $here '../Common/CheckPublishFreshness.ps1') -PublishDir (Join-Path $here '../E2E/app/publish')

    # **nginx の証明書（localhost.emobix.co.uk。OP だけが信頼する）と、compose に渡す値（.env.cts）など**（#350）
    & (Join-Path $here 'Prepare.ps1')
    if ($LASTEXITCODE -ne 0)
    {
        Write-Output ""
        Write-Output "  用意（Prepare.ps1）に失敗しました。"
        exit 1
    }

    & docker compose --env-file $e2eEnv --env-file (Join-Path $here '.env.cts') up -d --build

    if ($LASTEXITCODE -ne 0)
    {
        Write-Output ""
        Write-Output "  起動に失敗しました。"
        exit 1
    }

    Write-Output ""
    Write-Output "  Conformance Suite と、その相手の OP を起動しました。"
    Write-Output "    Conformance Suite : https://localhost.emobix.co.uk:8443/"
    Write-Output "    OP（issuer）      : https://mpas-cts.localhost:44311"
    Write-Output "    Discovery         : https://mpas-cts.localhost:44311/.well-known/openid-configuration"
    Write-Output ""
    Write-Output "  Conformance Suite の起動には 1〜2 分かかります。プランと設定は config\ と README.md。"
    Write-Output "  止めて消す : 3_DockerComposeDown.ps1（Windows なら 3_DockerComposeDown.bat）"
}
finally
{
    Pop-Location
}

exit 0
