<#
.SYNOPSIS
    ハイブリッド IdP の**上流側**コンテナに要るものを用意する（#250 の段階 2）。

.DESCRIPTION
    ＜何を用意するか＞
      1. **アプリの publish 成果物**（store\app\publish）
      2. **HTTPS の証明書**（store\cert\aspnetapp.pfx）と、そのパスワード（store\.env）

    ＜証明書は、ホストの開発用証明書を書き出す＞
      **毎回作り直すと、ブラウザが毎回「信頼されていない」と言う。**
      **ホストの `dotnet dev-certs` の証明書は既に信頼されている**ので、それを書き出して使う。
      **自己テスト（ブラウザで叩く）が警告なしで通る。**

      **パスワードは自動生成し、store\.env に保存する。**
      pfx とパスワードは対なので、**pfx を残すならパスワードも残す**。
      **人が覚える必要は無い**（このスクリプトが作り、compose が読む）。

      **どちらも .gitignore 済み。** pfx の中身は**ホストの開発用証明書の秘密鍵**である。

    ＜publish は Debug のまま＞
      **E2E と自己テストのための上流**なので、Release にする理由が無い。
      ビルド済みの成果物とも揃う。

.EXAMPLE
    .\3_PublishUpstream.ps1

.EXAMPLE
    # 証明書を作り直す（期限切れなど）
    .\3_PublishUpstream.ps1 -NewCertificate

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/30  玄人 幸道         新規（#250 の段階 2）
#>
[CmdletBinding()]
param(
    [switch] $NewCertificate
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath
$proj = Join-Path $here '..\root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.csproj'
$pub = Join-Path $here 'app\publish'
$art = Join-Path $here 'app\artifacts'
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

Write-Output "  publish しました : app\publish"
Write-Output ""
Write-Output "  上流コンテナは https://localhost:44301 で待ち受けます（PathBase 無し）。"
