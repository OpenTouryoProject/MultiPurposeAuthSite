<#
.SYNOPSIS
    MPAS スタブを止めて消す（#340 / #401）。

.DESCRIPTION
    **停止の手順の本体**である（#401）。**Windows の 3_DockerComposeDown.bat も、これを呼ぶだけ**（手順を二重に持たない）。
    **Linux（GitHub Actions の ubuntu-latest など）では pwsh で呼ぶ**（README.md 1 節）。

    **docker compose [--env-file <パラメタのファイル>] down**
    **2_DockerComposeUp.ps1 と同じファイルを渡す**（compose のプロジェクト名は mpas-stub に固定なので、省いても消える）。
    **状態は残らない**（UserStoreType=mem）。DataProtection の鍵（keys）とログ（logs）はホストに残る。

    ＜終了コード＞
      0 : 止めた
      1 : パラメタのファイルが無い、docker compose が失敗した

.PARAMETER EnvFile
    パラメタのファイル（2_DockerComposeUp.ps1 に渡したもの）。**相対パスは、呼んだ場所から見たもの。**

.EXAMPLE
    .\3_DockerComposeDown.ps1 my-stub.env

.EXAMPLE
    pwsh ./3_DockerComposeDown.ps1 ./my-stub.env

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/18  玄人 幸道         新規。3_DockerComposeDown.bat の手順を移し、Linux の pwsh でも呼べるようにした（#401）
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $EnvFile
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
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
