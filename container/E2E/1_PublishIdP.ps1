<#
.SYNOPSIS
    IdP コンテナに要るものを用意する（#250 の段階 2）。

    **成果物は 1 つで、上流も下流も同じイメージを使う**（#281）。
    役の違いは docker-compose.yml の設定だけであるので、ここでは分けない。
    （#318 で 3_PublishUpstream.ps1 から改名した。上流だけのものではないため）
    （#340 で 0_PublishIdP.ps1 から改名した。起動（2_DockerComposeUp.bat）と分け、..\Stub\ と同じ番号にした）

.DESCRIPTION
    ＜何を用意するか＞
      1. **アプリの publish 成果物**（app\publish）
         **appsettings.json は、雛形（_appsettings.json）に差し替える**（#340。..\Stub\1_PublishStub.ps1 と同じ）。
         **開発者の手元の appsettings.json（秘密を含む）を、イメージに入れないため。**
         手元のものは、**起動時にマウントする**（docker-compose.yml）。
         **appsettings.Development.json は残す**（E2E は環境名 Development で動く。リポジトリに在るもので、秘密は無い）。
      2. **HTTPS の証明書**（cert\aspnetapp.pfx）と、そのパスワード（.env）
      3. **log4net の構成**（..\Common\LogConf.xml を app\ に写す。Stub と共用する。#318）

    ＜証明書は、ホストの開発用証明書を書き出す＞
      **毎回作り直すと、ブラウザが毎回「信頼されていない」と言う。**
      **ホストの `dotnet dev-certs` の証明書は既に信頼されている**ので、それを書き出して使う。
      **自己テスト（ブラウザで叩く）が警告なしで通る。**

      **パスワードは自動生成し、.env に保存する。**
      pfx とパスワードは対なので、**pfx を残すならパスワードも残す**。
      **人が覚える必要は無い**（このスクリプトが作り、compose が読む）。

      **どちらも .gitignore 済み。** pfx の中身は**ホストの開発用証明書の秘密鍵**である。

    ＜publish は Debug のまま＞
      **E2E と自己テストのための上流**なので、Release にする理由が無い。
      ビルド済みの成果物とも揃う。

.EXAMPLE
    .\1_PublishIdP.ps1

.EXAMPLE
    # 証明書を作り直す（期限切れなど）
    .\1_PublishIdP.ps1 -NewCertificate

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/30  玄人 幸道         新規（#250 の段階 2）
     2026/10/31  玄人 幸道         store\ から Container\E2E\ へ移し、改名した（#318）
     2026/11/07  玄人 幸道         0_PublishIdP.ps1 から改名し、appsettings.json を雛形に差し替えるようにした（#340）
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
$pub = Join-Path $here 'app\publish'
$art = Join-Path $here 'app\artifacts'
$logConf = Join-Path $here '..\Common\LogConf.xml'
$certDir = Join-Path $here 'cert'
$pfx = Join-Path $certDir 'aspnetapp.pfx'
$envFile = Join-Path $here '.env'

# ---------------------------------------------------------------- 証明書

New-Item -ItemType Directory -Force $certDir | Out-Null

if ($NewCertificate -or -not (Test-Path $pfx) -or -not (Test-Path $envFile))
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

    # **compose が読む**（${CERT_PASSWORD}）
    [System.IO.File]::WriteAllText(
        $envFile, "CERT_PASSWORD=$password`n", (New-Object System.Text.UTF8Encoding $false))

    Write-Output "  証明書を書き出しました : cert\aspnetapp.pfx（パスワードは .env）"
}
else
{
    Write-Output "  証明書は既にあります : cert\aspnetapp.pfx（作り直すなら -NewCertificate）"
}

# ---------------------------------------------------------------- publish

Write-Output "  publish しています ..."

Remove-Item -Recurse -Force $pub -ErrorAction SilentlyContinue

# **中間出力を Visual Studio と共用しない**（--artifacts-path）。
#   **既定では、プロジェクトの `obj\Debug\net10.0` を VS と取り合う。**
#   `dotnet publish` は そこに publish 用の成果物
#   （`staticwebassets.publish.json` / `swae.publish.ex.cache` など）を書くため、
#   **VS のデバッグ実行が壊れる**（Web ツールが不整合な状態を読む）。
#
#   **実際に踏んだ**（#250 の段階 4）。VS が次のエラーで起動しなくなった。
#     An element with the same key but a different value already exists.
#     Key: 'Microsoft.WebTools.ProjectSystem.WebServer.IISExpressWebServer'
dotnet publish $proj -c Debug -o $pub --artifacts-path $art --nologo -v quiet

if ($LASTEXITCODE -ne 0)
{
    throw "publish に失敗しました。"
}

# **appsettings.json を雛形に差し替える**（手元の設定・秘密をイメージに入れない。#340）。
#   **手元の appsettings.json は、起動時にマウントする**（docker-compose.yml。イメージの中の雛形を覆う）。
#   **appsettings.Development.json は外さない**（E2E は環境名 Development で動き、これを読む。..\Stub\ は外す）。
Copy-Item $template (Join-Path $pub 'appsettings.json') -Force

# **log4net の構成**（Dockerfile が写す。原本は ..\Common\ に 1 つだけ置く。#318）
Copy-Item $logConf (Join-Path $here 'app\LogConf.xml') -Force

Write-Output "  publish しました : app\publish（appsettings.json は雛形）"
Write-Output ""
Write-Output "  上流コンテナは https://localhost:44301 で待ち受けます（PathBase 無し）。"
Write-Output "  下流コンテナ（docker compose up -d downstream）は https://localhost:44303 です。"
Write-Output ""
Write-Output "  起動 : .\2_DockerComposeUp.bat"
