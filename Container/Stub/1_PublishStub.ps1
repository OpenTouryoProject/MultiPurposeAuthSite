<#
.SYNOPSIS
    MPAS スタブのコンテナに要るものを用意する（#294）。

.DESCRIPTION
    ＜何を用意するか＞
      1. **アプリの publish 成果物**（app\publish）
         **appsettings.json は、雛形（_appsettings.json）に差し替える。**
         **開発者の手元の appsettings.json（秘密を含む）を、イメージに入れないため。**
      2. **HTTPS の証明書**（cert\aspnetapp.pfx）と、そのパスワード（cert\cert.env）
      3. **log4net の構成**（..\Common\LogConf.xml を写す。二重に持たない）

    ＜証明書は、ホストの開発用証明書を書き出す＞
      **..\E2E\0_PublishIdP.ps1 と同じ。** ホストで既に信頼されているので、ブラウザが警告を出さない。
      **パスワードは自動生成し、cert.env に書く**（compose が env_file として読む）。
      **自分の証明書を使うなら、.env の STUB_CERT_DIR / STUB_CERT_ENV_FILE で差し替える**（README.md）。

    ＜publish は Debug のまま＞
      **テストのスタブ**なので、Release にする理由が無い（..\E2E\ と同じ）。

.PARAMETER NewCertificate
    証明書を作り直す（期限切れなど）。

.EXAMPLE
    .\1_PublishStub.ps1

.EXAMPLE
    .\1_PublishStub.ps1 -NewCertificate

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/10/30  玄人 幸道         新規（#294）
     2026/10/31  玄人 幸道         stub\ から Container\Stub\ へ移した（#318）
#>
[CmdletBinding()]
param(
    [switch] $NewCertificate
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath
$coreDir = Join-Path $here '..\..\root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore'
$proj = Join-Path $coreDir 'MultiPurposeAuthSiteCore.csproj'
$template = Join-Path $coreDir '_appsettings.json'
$logConf = Join-Path $here '..\Common\LogConf.xml'
$pub = Join-Path $here 'app\publish'
$art = Join-Path $here 'app\artifacts'
$certDir = Join-Path $here 'cert'
$pfx = Join-Path $certDir 'aspnetapp.pfx'
$certEnv = Join-Path $certDir 'cert.env'

# ---------------------------------------------------------------- 証明書
New-Item -ItemType Directory -Force $certDir | Out-Null

if ($NewCertificate -or -not (Test-Path $pfx) -or -not (Test-Path $certEnv))
{
    # **パスワードを自動生成する**（保存はするが、人が覚える必要は無い）
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = [Convert]::ToBase64String($bytes).Replace('+', 'a').Replace('/', 'b').Replace('=', '')

    Remove-Item $pfx -Force -ErrorAction SilentlyContinue

    # **ホストの開発用証明書を書き出す**（既に信頼されているので、ブラウザが警告を出さない）
    dotnet dev-certs https -ep $pfx -p $password | Out-Null

    if (-not (Test-Path $pfx))
    {
        throw "開発用証明書を書き出せませんでした。`dotnet dev-certs https --trust` を先に実行してください。"
    }

    # **compose が env_file として読む**（コンテナの環境変数になる）
    [System.IO.File]::WriteAllText(
        $certEnv, "Kestrel__Certificates__Default__Password=$password`n", (New-Object System.Text.UTF8Encoding $false))

    Write-Output "  証明書を書き出しました : cert\aspnetapp.pfx（パスワードは cert\cert.env）"
}
else
{
    Write-Output "  証明書は既にあります : cert\aspnetapp.pfx（作り直すなら -NewCertificate）"
}

# ---------------------------------------------------------------- publish
Write-Output "  publish しています ..."

Remove-Item -Recurse -Force $pub -ErrorAction SilentlyContinue

# **中間出力を Visual Studio と共用しない**（--artifacts-path。..\E2E\0_PublishIdP.ps1 と同じ理由）。
dotnet publish $proj -c Debug -o $pub --artifacts-path $art --nologo -v quiet

if ($LASTEXITCODE -ne 0)
{
    throw "publish に失敗しました。"
}

# **appsettings.json を雛形に差し替える**（手元の設定・秘密をイメージに入れない）。
#   **appsettings.Development.json も外す**（スタブは環境名 Stub で動き、読まない）。
Copy-Item $template (Join-Path $pub 'appsettings.json') -Force
Remove-Item (Join-Path $pub 'appsettings.Development.json') -Force -ErrorAction SilentlyContinue

# **log4net の構成**（Dockerfile が写す）
Copy-Item $logConf (Join-Path $here 'app\LogConf.xml') -Force

# **鍵とログの置き場**（compose がマウントする）
New-Item -ItemType Directory -Force (Join-Path $here 'keys'), (Join-Path $here 'logs') | Out-Null

Write-Output "  publish しました : app\publish（appsettings.json は雛形）"
Write-Output ""
Write-Output "  起動 : docker compose --env-file <パラメタのファイル> up -d --build"
Write-Output "         （Container\Stub\ で実行する。パラメタのファイルは .env.sample を写して作る）"
