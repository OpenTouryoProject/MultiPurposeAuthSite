<#
.SYNOPSIS
    MPAS スタブを起動する（#294 / #340 / #401）。

.DESCRIPTION
    **起動の手順の本体**である（#401）。**Windows の 2_DockerComposeUp.bat も、これを呼ぶだけ**（手順を二重に持たない）。
    **Linux（GitHub Actions の ubuntu-latest など）では pwsh で呼ぶ**（README.md 1 節）。

    1. **publish の成果物がソースより古ければ警告する**（..\Common\CheckPublishFreshness.ps1。起動は止めない。#340）
    2. **docker compose [--env-file <パラメタのファイル>] up -d --build**
       **--build が要る**（..\E2E\ と同じ。無いと、publish の成果物がイメージに入らない）

    **用意（publish と証明書）は 1_PublishStub.ps1**（最初と、MPAS を更新したとき）。

    ＜終了コード＞
      0 : 起動した
      1 : パラメタのファイルが無い、docker compose が失敗した

.PARAMETER EnvFile
    パラメタのファイル（.env.sample を写したもの。README.md 2 節）。**相対パスは、呼んだ場所から見たもの。**
    省略すると、docker-compose.yml の既定値で起動する。

.EXAMPLE
    .\2_DockerComposeUp.ps1 my-stub.env

.EXAMPLE
    pwsh ./2_DockerComposeUp.ps1 ./my-stub.env

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/18  玄人 幸道         新規。2_DockerComposeUp.bat の手順を移し、Linux の pwsh でも呼べるようにした（#401）
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $EnvFile
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）。
# **区切りは / で書く**（Linux の pwsh は \ を区切りにしない。Windows は / も受ける。#401）
$here = Split-Path -Parent $PSCommandPath

$envArgs = @()

if (-not [string]::IsNullOrEmpty($EnvFile))
{
    # **呼んだ場所から見た相対パスを、絶対パスにする**（下で $here に移るため。.bat の %~f1 と同じ）
    $envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path (Get-Location).Path $EnvFile }
    $envPath = [System.IO.Path]::GetFullPath($envPath)

    if (-not (Test-Path -LiteralPath $envPath -PathType Leaf))
    {
        Write-Output "  パラメタのファイルがありません : $envPath"
        exit 1
    }

    $envArgs = @('--env-file', $envPath)
}

Push-Location $here

try
{
    & (Join-Path $here '../Common/CheckPublishFreshness.ps1') -PublishDir (Join-Path $here 'app/publish')

    & docker compose @envArgs up -d --build

    if ($LASTEXITCODE -ne 0)
    {
        Write-Output ""
        Write-Output "  起動に失敗しました。"
        exit 1
    }

    Write-Output ""
    Write-Output "  MPAS のスタブを起動しました（確認 : /.well-known/openid-configuration が 200 を返すこと）。"
    Write-Output "  状態を戻す : docker compose $($envArgs -join ' ') restart"
    Write-Output "  止めて消す : 3_DockerComposeDown.ps1（Windows なら 3_DockerComposeDown.bat）[パラメタのファイル]"
}
finally
{
    Pop-Location
}

exit 0
