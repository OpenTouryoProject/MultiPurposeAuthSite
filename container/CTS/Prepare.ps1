<#
.SYNOPSIS
    適合性テストの環境を用意する（nginx の証明書と、compose に渡す値。#350 の段階 3）。

.DESCRIPTION
    2_DockerComposeUp.bat が、起動の前に呼ぶ。**作った物はどれも Git の管理外**である。

    ＜1. nginx の証明書（certs\nginx.crt・certs\nginx.key）＞
      **OP から Conformance Suite へ、サーバ間で TLS の要求を送るプランがある**（Back-Channel Logout の logout_token の POST）。
      原本の nginx の証明書は CN=localhost の自己署名なので、**OP は名前の不一致と信頼の無さで、正しく断る**
      （HttpRequestException。OP の検証を緩める設定は無いし、作らない）。
      そこで、**localhost.emobix.co.uk の名前を持つ証明書を作り、nginx に差し替え、OP のコンテナだけがそれを信頼する**
      （docker-compose.yml の nginx のマウントと、op の SSL_CERT_FILE）。
      **既に在れば作らない**（作り直すなら certs\ を消す）。
      **Conformance Suite の nginx のイメージ（版を固定したもの）の openssl を使う**（手元に openssl を要らなくした）。

    ＜2. compose に渡す値（.env.cts）＞
      **動的登録（DCR）の管理クライアントの所有者（owner）は、利用者名で書く**（#307 の段階 5-b）。
      **テスト利用者の名前は、手元の appsettings.json の TestUserSuffix で変わる**ので、compose に直書きできない。
      ここで RunTestPlan.ps1 と同じ規則（tanaka ＋ TestUserSuffix）で決めて、CTS_REGISTRATION_OWNER に書く。
      **毎回書き直す**（appsettings.json を変えたときに追従する）。

    **終了コード**：0（用意できた）／1（用意できなかった）

.EXAMPLE
    .\Prepare.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/10  玄人 幸道         新規（#350）
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath

#region 1. nginx の証明書

$certDir = Join-Path $here 'certs'
$crt = Join-Path $certDir 'nginx.crt'
$key = Join-Path $certDir 'nginx.key'

if ((Test-Path -LiteralPath $crt) -and (Test-Path -LiteralPath $key))
{
    Write-Host ('nginx の証明書は在ります : {0}' -f $crt)
}
else
{
    New-Item -ItemType Directory -Force -Path $certDir | Out-Null

    # **docker-compose.yml の nginx と同じイメージ・同じ版**（release-v5.3.4）
    $image = 'registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4'

    # **SAN に localhost.emobix.co.uk を入れる**（OP は SAN で名前を照合する）。localhost も入れる（手元のブラウザ用）
    $opensslArgs = @(
        'run', '--rm', '--entrypoint', 'openssl',
        '-v', ($certDir + ':/out'),
        $image,
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '825',
        '-keyout', '/out/nginx.key', '-out', '/out/nginx.crt',
        '-subj', '/CN=localhost.emobix.co.uk',
        '-addext', 'subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost',
        '-addext', 'extendedKeyUsage=serverAuth'
    )

    & docker @opensslArgs
    if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath $crt) -or -not (Test-Path -LiteralPath $key))
    {
        Write-Host 'nginx の証明書を作れませんでした（docker が動いているか、イメージを取得できるかを確かめてください）。' -ForegroundColor Red
        exit 1
    }

    Write-Host ('nginx の証明書を作りました : {0}' -f $crt)
}

#endregion

#region 2. compose に渡す値

$appsettings = Join-Path $here '..\..\root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\appsettings.json'
if (-not (Test-Path -LiteralPath $appsettings))
{
    Write-Host ('手元の appsettings.json がありません : {0}' -f $appsettings) -ForegroundColor Red
    exit 1
}

# **appsettings.json はコメントを含みうる**ので、ConvertFrom-Json（5.1 はコメントを読めない）ではなく、値を正規表現で引く（RunTestPlan.ps1 と同じ）
$settingsText = [IO.File]::ReadAllText($appsettings)
$m = [regex]::Match($settingsText, '"TestUserSuffix"\s*:\s*"((?:[^"\\]|\\.)*)"')
$suffix = if ($m.Success) { [regex]::Unescape($m.Groups[1].Value) } else { '' }

# テスト利用者（**OP の種データが作る一般の利用者**。E2E の TestEnv.TestUserName と同じ名前）
$owner = 'tanaka' + $suffix

# **改行は LF、BOM 無し**（compose の env ファイル）
$envPath = Join-Path $here '.env.cts'
[IO.File]::WriteAllText($envPath, ('CTS_REGISTRATION_OWNER=' + $owner + "`n"), (New-Object Text.UTF8Encoding $false))
Write-Host ('compose に渡す値を書きました : {0}' -f $envPath)

#endregion

exit 0
