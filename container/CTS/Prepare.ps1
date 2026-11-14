<#
.SYNOPSIS
    適合性テストの環境を用意する（nginx の証明書、compose に渡す値、MTLS のフック、FAPI の鍵・証明書。#350 の段階 3・4）。

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
      FAPI のクライアントの公開鍵（4.）も、ここに書く（CTS_FAPI_CLIENT1_JWK・CTS_FAPI_CLIENT2_JWK）。

    ＜3. MTLS のテスト専用のフック（hooks\）＞
      OP の Kestrel に、クライアント証明書を求めさせる（E2E・スタブと同じ MtlsTestHook。段階 4 の FAPI）。

    ＜4. FAPI のクライアントの鍵と、MTLS のクライアント証明書（certs\）＞
      クライアント 2 つ分（client・client2）の EC P-256 の鍵（JWK）と、自己署名のクライアント証明書。
      **秘密鍵は RunTestPlan.ps1 が Conformance Suite の設定に埋め、公開鍵と Subject は OP の登録に渡す。**

    **終了コード**：0（用意できた）／1（用意できなかった）

.EXAMPLE
    .\Prepare.ps1

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/10  玄人 幸道         新規（#350）
     2026/11/11  玄人 幸道         MTLS のフックと、FAPI のクライアントの鍵・証明書を作るようにした（#350 の段階 4）
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

#region 3. MTLS のテスト専用のフック（hooks\MtlsTestHook.dll）

# **E2E・スタブと同じフック**（root\programs\Tests\MtlsTestHook。DOTNET_STARTUP_HOOKS で読ませる）。
#   **アプリのコードは変えず、Kestrel にクライアント証明書を求めさせる**（要求するだけで、必須にはしない）。
#   **発行元を問わずに受け付ける**ので、テスト専用。ASPNETCORE_ENVIRONMENT が Development でなければ何もしない。
#   **在れば作らない**（作り直すなら hooks\ を消す）。
$hookDir = Join-Path $here 'hooks'
if (Test-Path -LiteralPath (Join-Path $hookDir 'MtlsTestHook.dll'))
{
    Write-Host ('MTLS のフックは在ります : {0}' -f $hookDir)
}
else
{
    New-Item -ItemType Directory -Force -Path $hookDir | Out-Null
    $hookArt = Join-Path $here 'hooks-build'

    & dotnet build (Join-Path $here '..\..\root\programs\Tests\MtlsTestHook\MtlsTestHook.csproj') `
        -c Debug -o $hookDir --artifacts-path $hookArt --nologo -v quiet | Out-Null

    if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath (Join-Path $hookDir 'MtlsTestHook.dll')))
    {
        Write-Host 'MTLS のフックを作れませんでした（dotnet の SDK が要る）。' -ForegroundColor Red
        exit 1
    }

    Write-Host ('MTLS のフックを作りました : {0}' -f $hookDir)
}

#endregion

#region 4. FAPI のクライアントの鍵と、MTLS のクライアント証明書

# **FAPI のプランは、クライアントを 2 つ使う**（client・client2）。
#   - 鍵（private_key_jwt・DPoP・Request Object の署名）：**EC P-256（ES256）**。
#     OP の Discovery の token_endpoint_auth_signing_alg_values_supported は RS256・ES256 で、FAPI 2.0 は RS256 を認めない
#     **秘密鍵は Conformance Suite の設定に、公開鍵は OP の登録（jwk_ecdsa_publickey）に渡す**
#   - クライアント証明書（tls_client_auth・証明書に縛ったトークン）：**自己署名の RSA**。OP は Subject（tls_client_auth_subject_dn）で照合する
#   **在れば作らない**（作り直すなら certs\ を消す）。

function ConvertTo-Base64Url([byte[]]$Bytes)
{
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$fapiPublicJwks = @{}
foreach ($n in 1, 2)
{
    $jwkPath = Join-Path $certDir ('fapi-client{0}.jwk.json' -f $n)

    if (-not (Test-Path -LiteralPath $jwkPath))
    {
        $ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $ep = $ec.ExportParameters($true)
        $x = ConvertTo-Base64Url $ep.Q.X
        $y = ConvertTo-Base64Url $ep.Q.Y
        $d = ConvertTo-Base64Url $ep.D

        # **kid は RFC 7638 の拇印**（必須の項目を辞書順に並べた JSON の SHA-256）
        $thumbInput = '{"crv":"P-256","kty":"EC","x":"' + $x + '","y":"' + $y + '"}'
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $kid = ConvertTo-Base64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($thumbInput)))

        $private = '{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"' + $kid + '","x":"' + $x + '","y":"' + $y + '","d":"' + $d + '"}'
        [IO.File]::WriteAllText($jwkPath, $private, (New-Object Text.UTF8Encoding $false))
        Write-Host ('FAPI のクライアントの鍵を作りました : {0}' -f $jwkPath)
    }

    # **公開鍵は、秘密鍵から d を除いて作る**（OP の jwk_ecdsa_publickey は、JWK の JSON を base64url にしたもの）
    $jwk = Get-Content -LiteralPath $jwkPath -Raw | ConvertFrom-Json
    $public = '{"kty":"EC","alg":"ES256","crv":"P-256","x":"' + $jwk.x + '","y":"' + $jwk.y + '","kid":"' + $jwk.kid + '"}'
    $fapiPublicJwks[$n] = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($public))

    $mtlsCrt = Join-Path $certDir ('mtls-client{0}.crt' -f $n)
    $mtlsKey = Join-Path $certDir ('mtls-client{0}.key' -f $n)
    if (-not ((Test-Path -LiteralPath $mtlsCrt) -and (Test-Path -LiteralPath $mtlsKey)))
    {
        # **Subject は docker-compose.yml の tls_client_auth_subject_dn と同じにする**
        $mtlsArgs = @(
            'run', '--rm', '--entrypoint', 'openssl',
            '-v', ($certDir + ':/out'),
            'registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4',
            'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '825',
            '-keyout', ('/out/mtls-client{0}.key' -f $n), '-out', ('/out/mtls-client{0}.crt' -f $n),
            '-subj', ('/CN=CTS FAPI Client {0}' -f $n),
            '-addext', 'extendedKeyUsage=clientAuth'
        )
        & docker @mtlsArgs
        if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath $mtlsCrt))
        {
            Write-Host 'MTLS のクライアント証明書を作れませんでした。' -ForegroundColor Red
            exit 1
        }
        Write-Host ('MTLS のクライアント証明書を作りました : {0}' -f $mtlsCrt)
    }
}

#endregion

#region 2. compose に渡す値（最後に書く。3・4 の値も入れる）

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
$envText = 'CTS_REGISTRATION_OWNER=' + $owner + "`n" +
    'CTS_FAPI_CLIENT1_JWK=' + $fapiPublicJwks[1] + "`n" +
    'CTS_FAPI_CLIENT2_JWK=' + $fapiPublicJwks[2] + "`n"
[IO.File]::WriteAllText($envPath, $envText, (New-Object Text.UTF8Encoding $false))
Write-Host ('compose に渡す値を書きました : {0}' -f $envPath)

#endregion

exit 0
