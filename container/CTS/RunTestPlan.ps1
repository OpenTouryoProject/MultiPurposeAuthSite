<#
.SYNOPSIS
    適合性テスト（Conformance Suite）のプランを、REST の API で回す（#350）。
.DESCRIPTION
    ＜前提＞
      2_DockerComposeUp.bat で、Conformance Suite と相手の OP を起動しておくこと。
      Conformance Suite は dev の構成（SPRING_PROFILES_ACTIVE=dev）なので、API は認証なしで呼べる。

    ＜何をするか＞
      1. config\<プラン>.json（雛形）の差し込み口（@TEST_USER@・@TEST_PASSWORD@）を、
         **手元の appsettings.json のテスト利用者で埋めて**、out\<プラン>.json に書く（out\ は Git の管理外）。
         **テスト利用者のパスワードは秘密なので、雛形には書かない。**
      2. プランを作り（POST api/plan）、モジュールを 1 つずつ起動し（POST api/runner）、終わるまで待つ（GET api/info/{id}）。
         **ブラウザの操作（サインイン・同意）は、Conformance Suite の server が雛形の "browser" で自動で行う。**
      3. 結果を表で出し、out\ に JSON と、Conformance Suite の報告書（exporthtml の zip）を書く。

    ＜Python の run-test-plan.py を使わない理由＞
      原本の scripts\run-test-plan.py と同じ API を呼ぶだけなので、Python と追加のパッケージ（httpx・pyparsing）を要らなくした。
      **プランの選び方・バリアントは、このスクリプトの表で固定する**（下の $plans）。

    ＜終了コード＞
      0 : すべてのモジュールが終わり、FAILED・INTERRUPTED・時間切れが無い
      1 : どれかが FAILED・INTERRUPTED・時間切れ
      2 : 前提の誤り（Conformance Suite に届かない、設定が読めない など）
.PARAMETER Plan
    回すプラン（下の ValidateSet。表は $plans）。
    **設定の雛形は、プランごとに持たない**こともある（$plans の Config。Implicit・Hybrid・form_post は oidcc-basic の雛形を使う）。
.PARAMETER ResponseType
    response_type をプランのバリアントで指定するプランの、response_type（既定は code）。
    **code 以外を選べるのは、$plans で ResponseTypeAxis = $true のプランだけ**（oidcc-dynamic と、ログアウトの 3 プランの動的登録版。#426）。
    code 以外なら、out\ のファイルの名前に response_type を添える（例：out\oidcc-dynamic-code-id_token-report.zip）。
.PARAMETER ModuleTimeoutSec
    1 つのモジュールを待つ上限（秒）。ブラウザの自動操作が合わないと WAITING のまま止まるので、上限で打ち切る。
.EXAMPLE
    .\RunTestPlan.ps1 -Plan oidcc-basic
.EXAMPLE
    .\RunTestPlan.ps1 -Plan oidcc-dynamic -ResponseType 'code id_token'
.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/10  玄人 幸道         新規（#350）
     2026/11/10  玄人 幸道         段階 3 のプラン（Implicit・Hybrid・form_post・ログアウト・動的登録）を足した。雛形をプランの間で共有できるようにした（#350）
     2026/11/11  玄人 幸道         段階 4 のプラン（FAPI）を足した。クライアントの鍵とクライアント証明書を埋める（#350）
     2026/11/11  玄人 幸道         段階 4 のプラン（FAPI 2.0 Message Signing・FAPI 1.0 Advanced・FAPI-CIBA）と、CIBA の端末役（承認の自動化）を足した（#350）
     2026/11/17  玄人 幸道         FAPI 2.0 Message Signing のクライアントを、署名した Request Object を必須にした登録（17・18）に分けた（#385）
     2026/11/21  玄人 幸道         FAPI 2.0 SP の、認証と縛りの交差・plain_oauth・client_credentials のプランと、scope の置き換えを足した（#416）
     2026/11/21  玄人 幸道         FAPI 1.0 Advanced・FAPI-CIBA・FAPI 2.0 MS の mTLS と、MS の要求と応答の残りの組のプランを足した（#416）
     2026/11/24  玄人 幸道         client_credentials のプランのクライアント（23・24）を fapi2 の登録にした説明に直した（#424）
     2026/11/25  玄人 幸道         OIDC の 9 プランを動的登録したクライアントで回す版（-dynamic）と、oidcc-test-plan の mtls（code と form_post）を足した（#426）
     2026/11/25  玄人 幸道         oidcc-dynamic とログアウトの 3 プランの動的登録版を、code 以外の response_type で回す指定（-ResponseType）を足した（#426）
#>
[CmdletBinding()]
param(
    [ValidateSet('oidcc-basic', 'oidcc-config',
        'oidcc-implicit', 'oidcc-hybrid',
        'oidcc-formpost-basic', 'oidcc-formpost-implicit', 'oidcc-formpost-hybrid',
        'oidcc-rp-initiated-logout', 'oidcc-frontchannel-rp-initiated-logout', 'oidcc-backchannel-rp-initiated-logout',
        'oidcc-basic-dynamic', 'oidcc-implicit-dynamic', 'oidcc-hybrid-dynamic',
        'oidcc-formpost-basic-dynamic', 'oidcc-formpost-implicit-dynamic', 'oidcc-formpost-hybrid-dynamic',
        'oidcc-rp-initiated-logout-dynamic', 'oidcc-frontchannel-rp-initiated-logout-dynamic', 'oidcc-backchannel-rp-initiated-logout-dynamic',
        'oidcc-mtls', 'oidcc-mtls-formpost',
        'oidcc-dynamic',
        'fapi2-sp-private-key-jwt-dpop', 'fapi2-sp-mtls',
        'fapi2-sp-private-key-jwt-mtls', 'fapi2-sp-mtls-dpop',
        'fapi2-sp-plain-oauth', 'fapi2-sp-client-credentials',
        'fapi2-ms-private-key-jwt-dpop',
        'fapi2-ms-mtls', 'fapi2-ms-signed-plain-response', 'fapi2-ms-unsigned-jarm',
        'fapi1-adv-private-key-jwt-par', 'fapi1-adv-mtls-par',
        'fapi-ciba-private-key-jwt-poll', 'fapi-ciba-mtls-poll')]
    [string]$Plan = 'oidcc-basic',

    [ValidateSet('code', 'id_token', 'id_token token', 'code id_token', 'code token', 'code id_token token')]
    [string]$ResponseType = 'code',

    [int]$ModuleTimeoutSec = 180
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$base = 'https://localhost.emobix.co.uk:8443/'
$appsettings = Join-Path $here '..\..\root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\appsettings.json'
$outDir = Join-Path $here 'out'

# プランの名前・バリアント・設定の雛形（Conformance Suite の api/plan/available で確かめた値）
#   **Implicit・Hybrid は、プランの中で response_type ごとにモジュールを作る**（バリアントで指定しない）。
#   **form_post は、プランの名前で決まる**（各モジュールのバリアントが response_mode=form_post）。
#   **ログアウトと oidcc-dynamic のプランは、response_type をプランのバリアントで指定する**（既定は code。
#   ResponseTypeAxis = $true のプランだけ、-ResponseType で code 以外にできる。#426）。
$static = '{"server_metadata":"discovery","client_registration":"static_client"}'
$staticCode = '{"client_registration":"static_client","response_type":"code"}'
$dynamic = '{"server_metadata":"discovery","client_registration":"dynamic_client"}'
$dynamicCode = '{"client_registration":"dynamic_client","response_type":"code"}'
# 動的登録の管理クライアント（initial access token を取る。docker-compose.yml と同じ。**適合性テスト専用の値**）
$registrationClientId = 'c75c11e0000000000000000000000007'
$registrationClientSecret = 'cts-client7-secret-for-conformance-test-only'
function Get-OidccTestVariant([string]$ClientAuthType, [string]$ResponseMode)
{
    # **oidcc-test-plan は、軸をすべてバリアントで指定する**（certification のプランは、プランの名前で軸が決まる）。
    #   **server_metadata の軸は無い**（Discovery を使う。api/plan/available で確かめた）
    return ('{{"client_registration":"static_client","client_auth_type":"{0}","response_type":"code","response_mode":"{1}"}}' -f $ClientAuthType, $ResponseMode)
}
$plans = @{
    'oidcc-basic'             = @{ Name = 'oidcc-basic-certification-test-plan';             Variant = $static; Config = 'oidcc-basic' }
    'oidcc-config'            = @{ Name = 'oidcc-config-certification-test-plan';            Variant = $null;   Config = 'oidcc-config' }
    'oidcc-implicit'          = @{ Name = 'oidcc-implicit-certification-test-plan';          Variant = $static; Config = 'oidcc-basic' }
    'oidcc-hybrid'            = @{ Name = 'oidcc-hybrid-certification-test-plan';            Variant = $static; Config = 'oidcc-basic' }
    'oidcc-formpost-basic'    = @{ Name = 'oidcc-formpost-basic-certification-test-plan';    Variant = $static; Config = 'oidcc-basic' }
    'oidcc-formpost-implicit' = @{ Name = 'oidcc-formpost-implicit-certification-test-plan'; Variant = $static; Config = 'oidcc-basic' }
    'oidcc-formpost-hybrid'   = @{ Name = 'oidcc-formpost-hybrid-certification-test-plan';   Variant = $static; Config = 'oidcc-basic' }
    # **ログアウトは、プランごとにクライアントを分ける**（登録したログアウトの口が、別のプランの検査に混ざらないように）。
    #   値は docker-compose.yml の OP の環境変数と同じ（**適合性テスト専用の値**）。雛形の @CLIENT_ID@・@CLIENT_SECRET@ を埋める
    'oidcc-rp-initiated-logout'              = @{ Name = 'oidcc-rp-initiated-logout-certification-test-plan';              Variant = $staticCode; Config = 'oidcc-logout'
                                                  ClientId = 'c75c11e0000000000000000000000004'; ClientSecret = 'cts-client4-secret-for-conformance-test-only' }
    'oidcc-frontchannel-rp-initiated-logout' = @{ Name = 'oidcc-frontchannel-rp-initiated-logout-certification-test-plan'; Variant = $staticCode; Config = 'oidcc-logout'
                                                  ClientId = 'c75c11e0000000000000000000000005'; ClientSecret = 'cts-client5-secret-for-conformance-test-only' }
    'oidcc-backchannel-rp-initiated-logout'  = @{ Name = 'oidcc-backchannel-rp-initiated-logout-certification-test-plan';  Variant = $staticCode; Config = 'oidcc-logout'
                                                  ClientId = 'c75c11e0000000000000000000000006'; ClientSecret = 'cts-client6-secret-for-conformance-test-only' }
    # **上の 9 プランを、動的登録したクライアントで回す版**（#426。Dynamic = $true）。
    #   **雛形は静的な版と同じ**で、client・client2・client_secret_post の中身を initial access token に置き換える（下の「設定を作る」）。
    #   Conformance Suite がモジュールごとにクライアントを登録する（ログアウトの口も登録の要求に載る。#426 で MPAS が受けるようにした）
    'oidcc-basic-dynamic'             = @{ Name = 'oidcc-basic-certification-test-plan';             Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-implicit-dynamic'          = @{ Name = 'oidcc-implicit-certification-test-plan';          Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-hybrid-dynamic'            = @{ Name = 'oidcc-hybrid-certification-test-plan';            Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-formpost-basic-dynamic'    = @{ Name = 'oidcc-formpost-basic-certification-test-plan';    Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-formpost-implicit-dynamic' = @{ Name = 'oidcc-formpost-implicit-certification-test-plan'; Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-formpost-hybrid-dynamic'   = @{ Name = 'oidcc-formpost-hybrid-certification-test-plan';   Variant = $dynamic; Config = 'oidcc-basic'; Dynamic = $true
                                           RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-rp-initiated-logout-dynamic'              = @{ Name = 'oidcc-rp-initiated-logout-certification-test-plan';              Variant = $dynamicCode; Config = 'oidcc-logout'; Dynamic = $true; ResponseTypeAxis = $true
                                                          RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-frontchannel-rp-initiated-logout-dynamic' = @{ Name = 'oidcc-frontchannel-rp-initiated-logout-certification-test-plan'; Variant = $dynamicCode; Config = 'oidcc-logout'; Dynamic = $true; ResponseTypeAxis = $true
                                                          RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    'oidcc-backchannel-rp-initiated-logout-dynamic'  = @{ Name = 'oidcc-backchannel-rp-initiated-logout-certification-test-plan';  Variant = $dynamicCode; Config = 'oidcc-logout'; Dynamic = $true; ResponseTypeAxis = $true
                                                          RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    # **oidcc-test-plan の、certification のプランに無いクライアント認証**（#426。静的な登録。雛形は oidcc-basic で、client・client2 を置き換える）。
    #   mtls（tls_client_auth）：31・32（**クライアント証明書は FAPI と同じ**。Prepare.ps1 が certs\ に作る。設定の mtls・mtls2 に埋める）
    #   **none（公開クライアント）は足さない**：Conformance Suite は none で PKCE を送らず、MPAS は公開クライアントに PKCE を求める（RFC 9700 §2.1.1。README の「足さないもの」）
    'oidcc-mtls'         = @{ Name = 'oidcc-test-plan'; Variant = (Get-OidccTestVariant 'mtls' 'default');   Config = 'oidcc-basic'; ClientAuth = 'mtls'
                               ClientId = 'c75c11e000000000000000000000001f'; Client2Id = 'c75c11e0000000000000000000000020' }
    'oidcc-mtls-formpost' = @{ Name = 'oidcc-test-plan'; Variant = (Get-OidccTestVariant 'mtls' 'form_post'); Config = 'oidcc-basic'; ClientAuth = 'mtls'
                               ClientId = 'c75c11e000000000000000000000001f'; Client2Id = 'c75c11e0000000000000000000000020' }
    # **動的登録は、initial access token を回す直前に取って埋める**（MPAS は、それの無い登録を受けない。#307）。
    #   管理クライアントの値は docker-compose.yml と同じ（**適合性テスト専用の値**）。雛形の @INITIAL_ACCESS_TOKEN@ を埋める
    'oidcc-dynamic' = @{ Name = 'oidcc-dynamic-certification-test-plan'; Variant = '{"response_type":"code"}'; Config = 'oidcc-dynamic'; ResponseTypeAxis = $true
                         RegistrationClientId = $registrationClientId; RegistrationClientSecret = $registrationClientSecret }
    # **FAPI は、クライアントを 2 つ使う**（client・client2）。**鍵とクライアント証明書は Prepare.ps1 が certs\ に作り、ここで埋める**（Fapi = $true）。
    #   バリアントは代表の組み合わせだけ（plain_fapi・openid_connect・simple・grant_management=disabled）
    #   **モジュールを待つ上限を長くする**（ModuleTimeoutSec。PAR の request_uri の期限（OP は 300 秒）が切れるのを待つモジュールがある）
    'fapi2-sp-private-key-jwt-dpop' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop"}'
        ClientId = 'c75c11e0000000000000000000000008'; Client2Id = 'c75c11e0000000000000000000000009' }
    'fapi2-sp-mtls' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"mtls","sender_constrain":"mtls"}'
        ClientId = 'c75c11e000000000000000000000000a'; Client2Id = 'c75c11e000000000000000000000000b' }
    # **FAPI 2.0 SP の、上の 2 つで回していない組**（#416）
    #   認証と縛りの交差：private_key_jwt ＋ mTLS（19・20）、mTLS ＋ DPoP（21・22）
    'fapi2-sp-private-key-jwt-mtls' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"mtls"}'
        ClientId = 'c75c11e0000000000000000000000013'; Client2Id = 'c75c11e0000000000000000000000014' }
    'fapi2-sp-mtls-dpop' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"mtls","sender_constrain":"dpop"}'
        ClientId = 'c75c11e0000000000000000000000015'; Client2Id = 'c75c11e0000000000000000000000016' }
    #   OIDC を使わない FAPI 2.0（openid=plain_oauth）：8・9 を使う。**scope に openid を入れると、Conformance Suite が始める前に落とす**ので、Scope で置き換える
    #   **資源は /TestResource**（openid を求めない。/userinfo は openid の無いトークンを 403 で断る。#425）
    'fapi2-sp-plain-oauth' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420; Scope = 'email'; ResourcePath = '/TestResource'
        Variant = '{"fapi_profile":"plain_fapi","openid":"plain_oauth","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop"}'
        ClientId = 'c75c11e0000000000000000000000008'; Client2Id = 'c75c11e0000000000000000000000009' }
    #   client_credentials（fapi_profile=fapi_client_credentials_grant）：23・24（**client_mode は fapi2**。#416 では normal だった。#424。docker-compose.yml の説明）。
    #   **openid は、このプロファイルには当たらない**（Conformance Suite が画面で隠す）が、**API では値が要る**（無いと「requires a value for variant 'openid'」）。
    #   **plain_oauth にする**（openid_connect にすると、出ない id_token の acr を確かめに行き、環境の誤りとして止まる。2026-11-21）。scope は openid を外す
    'fapi2-sp-client-credentials' = @{ Name = 'fapi2-security-profile-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420; Scope = 'email'; ResourcePath = '/TestResource'
        Variant = '{"fapi_profile":"fapi_client_credentials_grant","openid":"plain_oauth","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop"}'
        ClientId = 'c75c11e0000000000000000000000017'; Client2Id = 'c75c11e0000000000000000000000018' }
    # **FAPI 2.0 Message Signing**：SP の private_key_jwt＋DPoP に、署名した Request Object（signed_non_repudiation）と JARM を足したもの
    #   **クライアントは SP と分ける**（17・18。署名した Request Object を必須にした登録。SP のプランは署名の無い PAR を送るので、8・9 には立てられない。#385）
    'fapi2-ms-private-key-jwt-dpop' = @{ Name = 'fapi2-message-signing-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"signed_non_repudiation","fapi_response_mode":"jarm"}'
        ClientId = 'c75c11e0000000000000000000000011'; Client2Id = 'c75c11e0000000000000000000000012' }
    #   **Message Signing の、上で回していない組**（#416 の段 2）
    #   mTLS ＋ mTLS（29・30）
    'fapi2-ms-mtls' = @{ Name = 'fapi2-message-signing-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"mtls","sender_constrain":"mtls","fapi_request_method":"signed_non_repudiation","fapi_response_mode":"jarm"}'
        ClientId = 'c75c11e000000000000000000000001d'; Client2Id = 'c75c11e000000000000000000000001e' }
    #   署名した要求 ＋ 通常の応答（JARM 無し）：17・18（署名した Request Object の必須はそのままでよい）
    'fapi2-ms-signed-plain-response' = @{ Name = 'fapi2-message-signing-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"signed_non_repudiation","fapi_response_mode":"plain_response"}'
        ClientId = 'c75c11e0000000000000000000000011'; Client2Id = 'c75c11e0000000000000000000000012' }
    #   署名の無い要求 ＋ JARM：8・9（**17・18 は署名した Request Object を必須にしているので使えない**。8・9 は JARM の alg も登録してある）
    'fapi2-ms-unsigned-jarm' = @{ Name = 'fapi2-message-signing-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","openid":"openid_connect","authorization_request_type":"simple","grant_management":"disabled","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","fapi_response_mode":"jarm"}'
        ClientId = 'c75c11e0000000000000000000000008'; Client2Id = 'c75c11e0000000000000000000000009' }
    # **FAPI 1.0 Advanced**：private_key_jwt・PAR（pushed）・JARM（#370）
    #   **plain_response（Hybrid の code id_token）にしない。** MPAS は fapi1 の登録に Hybrid を許さない（FA-1.4）ので、
    #   FAPI 1.0 Advanced §5.2.2 の 2 の「code ＋ JARM」の側で回す（#350 で plain_response にしていたのは誤り。#370 で見つけた）
    'fapi1-adv-private-key-jwt-par' = @{ Name = 'fapi1-advanced-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm"}'
        ClientId = 'c75c11e000000000000000000000000c'; Client2Id = 'c75c11e000000000000000000000000d' }
    #   mTLS のクライアント認証（25・26。#416 の段 2）
    'fapi1-adv-mtls-par' = @{ Name = 'fapi1-advanced-final-test-plan'; Config = 'fapi2'; Fapi = $true; ModuleTimeoutSec = 420
        Variant = '{"fapi_profile":"plain_fapi","client_auth_type":"mtls","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm"}'
        ClientId = 'c75c11e0000000000000000000000019'; Client2Id = 'c75c11e000000000000000000000001a' }
    # **FAPI-CIBA**：poll・private_key_jwt・静的な登録。**利用者の承認は、このスクリプトが認証デバイスの代わりに送る**（Ciba = $true。下の「CIBA の端末役」）
    'fapi-ciba-private-key-jwt-poll' = @{ Name = 'fapi-ciba-id1-test-plan'; Config = 'fapi-ciba'; Fapi = $true; ModuleTimeoutSec = 420; Ciba = $true
        Variant = '{"client_registration":"static_client","ciba_mode":"poll","client_auth_type":"private_key_jwt","fapi_ciba_profile":"plain_fapi"}'
        ClientId = 'c75c11e000000000000000000000000f'; Client2Id = 'c75c11e0000000000000000000000010'
        DeviceClientId = 'c75c11e000000000000000000000000e'; DeviceClientSecret = 'cts-client14-secret-for-conformance-test-only' }
    #   mTLS のクライアント認証（27・28。#416 の段 2）。端末役は上と同じ
    'fapi-ciba-mtls-poll' = @{ Name = 'fapi-ciba-id1-test-plan'; Config = 'fapi-ciba'; Fapi = $true; ModuleTimeoutSec = 420; Ciba = $true
        Variant = '{"client_registration":"static_client","ciba_mode":"poll","client_auth_type":"mtls","fapi_ciba_profile":"plain_fapi"}'
        ClientId = 'c75c11e000000000000000000000001b'; Client2Id = 'c75c11e000000000000000000000001c'
        DeviceClientId = 'c75c11e000000000000000000000000e'; DeviceClientSecret = 'cts-client14-secret-for-conformance-test-only' }
}

# **OP のトークン エンドポイント（手元の PC から）**。issuer の mpas-cts.localhost は、PowerShell の名前解決では引けないことがあるので、localhost で叩く
$opTokenEndpoint = 'https://localhost:44311/token'
$p = $plans[$Plan]

# **response_type を code 以外にする**（#426。ResponseTypeAxis = $true のプランだけ）。
#   プランのバリアントの "response_type":"code" を置き換え、out\ のファイルの名前に添える（code の版と並べて残す）
$outName = $Plan
if ($ResponseType -ne 'code')
{
    if (-not $p.ResponseTypeAxis)
    {
        Write-Host ('-ResponseType で code 以外を選べるのは、次のプランだけです : {0}' -f ((@($plans.Keys | Where-Object { $plans[$_].ResponseTypeAxis }) | Sort-Object) -join ', ')) -ForegroundColor Red
        exit 2
    }
    if (-not $p.Variant.Contains('"response_type":"code"')) { throw ('The variant has no response_type to replace: ' + $Plan) }
    $p = $p.Clone()
    $p.Variant = $p.Variant.Replace('"response_type":"code"', ('"response_type":"{0}"' -f $ResponseType))
    $outName = $Plan + '-' + $ResponseType.Replace(' ', '-')
}

# **プランが長い上限を求めるなら、それに従う**（-ModuleTimeoutSec を明示したときは、それを使う）
if ($p.ModuleTimeoutSec -and -not $PSBoundParameters.ContainsKey('ModuleTimeoutSec'))
{
    $ModuleTimeoutSec = $p.ModuleTimeoutSec
}

#region HTTP（自己署名の証明書。5.1 と 7 で API を分ける。root\11_CODING.md 5 節）

if ($PSVersionTable.PSVersion.Major -lt 6)
{
    if (-not ('MpasCtsTls' -as [type]))
    {
        # **スクリプト ブロックではなく、コンパイルしたデリゲートを使う**（root\11_CODING.md 5 節）
        Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class MpasCtsTls
{
    public static void TrustAll()
    {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            { return true; };
    }
}
"@
    }
    [MpasCtsTls]::TrustAll()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

function Invoke-Cts([string]$Method, [string]$PathAndQuery, [string]$Body, [string]$OutFile)
{
    $url = $base + $PathAndQuery

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $args1 = @{ Method = $Method; Uri = $url; SkipCertificateCheck = $true; TimeoutSec = 60 }
        # **本文の無い POST にも Content-Type を付ける**（7 はフォームの型を付け、api/runner が 415 で断る）
        if ($Method -eq 'POST') { $args1.ContentType = 'application/json' }
        if ($Body) { $args1.Body = [Text.Encoding]::UTF8.GetBytes($Body) }
        if ($OutFile) { Invoke-WebRequest @args1 -OutFile $OutFile; return $null }
        $res = Invoke-WebRequest @args1
        return [string]$res.Content
    }

    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.Timeout = 60000
    if ($Body)
    {
        $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($Body)
        $req.ContentType = 'application/json'
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
    }
    elseif ($Method -eq 'POST')
    {
        $req.ContentLength = 0
    }

    $res = $req.GetResponse()
    try
    {
        $stream = $res.GetResponseStream()
        if ($OutFile)
        {
            $fs = [IO.File]::Create($OutFile)
            try { $stream.CopyTo($fs) } finally { $fs.Close() }
            return $null
        }
        $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding $false))
        return $reader.ReadToEnd()
    }
    finally
    {
        $res.Close()
    }
}

function Get-InitialAccessToken([string]$ClientId, [string]$ClientSecret)
{
    # **client_credentials で、scope=client_registration のアクセス トークンを取る**（client_secret_basic）
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        [Uri]::EscapeDataString($ClientId) + ':' + [Uri]::EscapeDataString($ClientSecret)))
    $body = 'grant_type=client_credentials&scope=client_registration'

    # **先にサインインの画面を 1 回開く。** OP の種データ（テスト利用者）は、AccountController への最初の要求で作られる。
    #   **動的登録のプランは、サインインより先に登録を叩く**ので、OP を起動し直した直後だと所有者（owner）の利用者が居らず、
    #   登録が 403（access_denied : The owner of this registration cannot be determined.）で断られる。
    $loginPage = $opTokenEndpoint.Replace('/token', '/Account/Login')

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        [void](Invoke-WebRequest -Method GET -Uri $loginPage -SkipCertificateCheck -TimeoutSec 60)
        $res = Invoke-WebRequest -Method POST -Uri $opTokenEndpoint -SkipCertificateCheck -TimeoutSec 60 `
            -Headers @{ Authorization = 'Basic ' + $basic } -ContentType 'application/x-www-form-urlencoded' -Body $body
        $json = [string]$res.Content
    }
    else
    {
        $warm = [System.Net.HttpWebRequest]::Create($loginPage)
        $warm.Timeout = 60000
        $warm.GetResponse().Close()

        $req = [System.Net.HttpWebRequest]::Create($opTokenEndpoint)
        $req.Method = 'POST'
        $req.Timeout = 60000
        $req.Headers['Authorization'] = 'Basic ' + $basic
        $req.ContentType = 'application/x-www-form-urlencoded'
        $bytes = [Text.Encoding]::ASCII.GetBytes($body)
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
        $res = $req.GetResponse()
        try { $json = (New-Object IO.StreamReader($res.GetResponseStream())).ReadToEnd() } finally { $res.Close() }
    }

    $token = ($json | ConvertFrom-Json).access_token
    if ([string]::IsNullOrEmpty($token)) { throw ('initial access token が返りませんでした : ' + $json) }
    return [string]$token
}

function Invoke-OpForm([string]$Path, [string]$Body, [string]$Authorization)
{
    # **OP の口をフォーム形式で叩き、状態コードと本文を返す**（手元の PC から。自己署名の証明書）
    $uri = $opTokenEndpoint.Replace('/token', $Path)

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $headers = @{}
        if ($Authorization) { $headers['Authorization'] = $Authorization }
        $res = Invoke-WebRequest -Method POST -Uri $uri -SkipCertificateCheck -TimeoutSec 60 -SkipHttpErrorCheck `
            -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $Body
        return [pscustomobject]@{ Status = [int]$res.StatusCode; Content = [string]$res.Content }
    }

    $req = [System.Net.HttpWebRequest]::Create($uri)
    $req.Method = 'POST'
    $req.Timeout = 60000
    if ($Authorization) { $req.Headers['Authorization'] = $Authorization }
    $req.ContentType = 'application/x-www-form-urlencoded'
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $req.ContentLength = $bytes.Length
    $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
    try { $res = $req.GetResponse() } catch [System.Net.WebException] { $res = $_.Exception.Response; if (-not $res) { throw } }
    try
    {
        $content = (New-Object IO.StreamReader($res.GetResponseStream())).ReadToEnd()
        return [pscustomobject]@{ Status = [int]$res.StatusCode; Content = $content }
    }
    finally { $res.Close() }
}

#endregion

#region 前提

try
{
    [void](Invoke-Cts 'GET' 'api/currentuser' $null $null)
}
catch
{
    Write-Host ('Conformance Suite（{0}）に届きません。2_DockerComposeUp.bat で起動してください（起動には 1〜2 分かかる）。' -f $base) -ForegroundColor Red
    Write-Host ('  理由 : {0}' -f $_.Exception.Message)
    exit 2
}

if (-not (Test-Path -LiteralPath $appsettings))
{
    Write-Host ('手元の appsettings.json がありません : {0}' -f $appsettings) -ForegroundColor Red
    exit 2
}

# **appsettings.json はコメントを含みうる**ので、ConvertFrom-Json（5.1 はコメントを読めない）ではなく、値を正規表現で引く
$settingsText = [IO.File]::ReadAllText($appsettings)
function Get-SettingValue([string]$Name)
{
    $m = [regex]::Match($settingsText, '"' + [regex]::Escape($Name) + '"\s*:\s*"((?:[^"\\]|\\.)*)"')
    if ($m.Success) { return [regex]::Unescape($m.Groups[1].Value) }
    return $null
}

$password = Get-SettingValue 'TestUserPWD'
$suffix = Get-SettingValue 'TestUserSuffix'
if ([string]::IsNullOrEmpty($password))
{
    Write-Host '手元の appsettings.json に TestUserPWD がありません（テスト利用者を作れない）。' -ForegroundColor Red
    exit 2
}

# テスト利用者（**OP の種データが作る一般の利用者**。E2E の TestEnv.TestUserName と同じ名前）
$user = 'tanaka' + [string]$suffix

#endregion

#region 設定を作る

$template = Join-Path $here ('config\{0}.json' -f $p.Config)
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$configPath = Join-Path $outDir ('{0}.json' -f $outName)

function ConvertTo-JsonString([string]$Value)
{
    # JSON の文字列の中身として埋める（引用符・バックスラッシュ・制御文字を逃がす）
    return (ConvertTo-Json $Value).Trim('"')
}

$config = [IO.File]::ReadAllText($template)
$config = $config.Replace('@TEST_USER@', (ConvertTo-JsonString $user))
$config = $config.Replace('@TEST_PASSWORD@', (ConvertTo-JsonString $password))
if ($p.Scope)
{
    # **雛形の scope を置き換える**（openid=plain_oauth は、scope に openid があると Conformance Suite が始める前に落とす。#416）
    $config = $config.Replace('"scope": "openid email"', ('"scope": "{0}"' -f (ConvertTo-JsonString $p.Scope)))
}
if ($p.ResourcePath)
{
    # **雛形の資源（/userinfo）を置き換える**（openid の無いトークンで呼ぶプランは /TestResource。#425）
    if (-not $config.Contains('"resourceUrl": "https://mpas-cts.localhost:44311/userinfo"'))
    {
        throw ('The template has no resourceUrl to replace: ' + $template)
    }
    $config = $config.Replace('"resourceUrl": "https://mpas-cts.localhost:44311/userinfo"', ('"resourceUrl": "https://mpas-cts.localhost:44311{0}"' -f (ConvertTo-JsonString $p.ResourcePath)))
}
function Set-ConfigBlock([string]$Text, [string]$Name, [string]$Json, [string]$After)
{
    # **雛形の "Name": { ... }（入れ子の無いオブジェクト）を、Json に置き換える**（After があれば、その後ろに並べる）。
    #   "client" は "client2"・"client_secret_post" に当たらない（名前の後ろの引用符まで照合する）。
    #   **見つからなければ $null を返す**（ログアウトの雛形には client2 が無い）。2 つ以上あれば、雛形の誤りとして止める
    $ms = [regex]::Matches($Text, '"' + [regex]::Escape($Name) + '"\s*:\s*\{[^{}]*\}')
    if ($ms.Count -eq 0) { return $null }
    if ($ms.Count -gt 1) { throw ('The template has more than one "{0}" block: {1}' -f $Name, $template) }
    $replacement = '"{0}": {1}' -f $Name, $Json
    if ($After) { $replacement += ',' + $After }
    return $Text.Substring(0, $ms[0].Index) + $replacement + $Text.Substring($ms[0].Index + $ms[0].Length)
}

function Get-MtlsBlock([int]$N)
{
    # **クライアント証明書と秘密鍵（PEM）を、設定の mtls・mtls2 の形にする**（Prepare.ps1 が certs\ に作る。Git の管理外）
    $crtPath = Join-Path $here ('certs\mtls-client{0}.crt' -f $N)
    $keyPath = Join-Path $here ('certs\mtls-client{0}.key' -f $N)
    foreach ($f in $crtPath, $keyPath)
    {
        if (-not (Test-Path -LiteralPath $f))
        {
            Write-Host ('クライアント証明書がありません（2_DockerComposeUp.bat が呼ぶ Prepare.ps1 で作る） : {0}' -f $f) -ForegroundColor Red
            exit 2
        }
    }
    return ('{{"cert": "{0}", "key": "{1}"}}' -f (ConvertTo-JsonString ([IO.File]::ReadAllText($crtPath))), (ConvertTo-JsonString ([IO.File]::ReadAllText($keyPath))))
}

if ($p.Dynamic)
{
    # **動的登録の版**（#426）：静的なクライアントの中身を、initial access token に置き換える（下の RegistrationClientId で埋める）
    $iatBlock = '{"initial_access_token": "@INITIAL_ACCESS_TOKEN@"}'
    $replaced = Set-ConfigBlock $config 'client' $iatBlock
    if (-not $replaced) { throw ('The template has no "client" block: ' + $template) }
    $config = $replaced
    foreach ($name in 'client2', 'client_secret_post')
    {
        $replaced = Set-ConfigBlock $config $name $iatBlock
        if ($replaced) { $config = $replaced }
    }
}
if ($p.ClientAuth)
{
    # **oidcc-test-plan の mtls**（#426）：client・client2 を、秘密の無いクライアントに置き換え、証明書（mtls・mtls2）を並べる
    $after = $null
    if ($p.ClientAuth -eq 'mtls')
    {
        $after = ' "mtls": ' + (Get-MtlsBlock 1) + ', "mtls2": ' + (Get-MtlsBlock 2)
    }
    foreach ($pair in @(@('client', $p.ClientId, $null), @('client2', $p.Client2Id, $after)))
    {
        $replaced = Set-ConfigBlock $config $pair[0] ('{{"client_id": "{0}"}}' -f (ConvertTo-JsonString $pair[1])) $pair[2]
        if (-not $replaced) { throw ('The template has no "{0}" block: {1}' -f $pair[0], $template) }
        $config = $replaced
    }
}
elseif ($p.ClientId)
{
    $config = $config.Replace('@CLIENT_ID@', (ConvertTo-JsonString $p.ClientId))
    $config = $config.Replace('@CLIENT_SECRET@', (ConvertTo-JsonString $p.ClientSecret))
}
if ($p.Fapi)
{
    # **FAPI のクライアントの秘密鍵とクライアント証明書**（Prepare.ps1 が certs\ に作る。Git の管理外）
    $certDir = Join-Path $here 'certs'
    $config = $config.Replace('@CLIENT2_ID@', (ConvertTo-JsonString $p.Client2Id))

    foreach ($n in 1, 2)
    {
        $suffixName = if ($n -eq 1) { '' } else { '2' }
        $jwkPath = Join-Path $certDir ('fapi-client{0}.jwk.json' -f $n)
        $crtPath = Join-Path $certDir ('mtls-client{0}.crt' -f $n)
        $keyPath = Join-Path $certDir ('mtls-client{0}.key' -f $n)
        foreach ($f in $jwkPath, $crtPath, $keyPath)
        {
            if (-not (Test-Path -LiteralPath $f))
            {
                Write-Host ('FAPI の鍵・証明書がありません（2_DockerComposeUp.bat が呼ぶ Prepare.ps1 で作る） : {0}' -f $f) -ForegroundColor Red
                exit 2
            }
        }

        # **jwks は JSON のオブジェクトで埋める**（雛形では引用符ごと差し込み口にしてある）
        $jwks = '{"keys":[' + [IO.File]::ReadAllText($jwkPath).Trim() + ']}'
        $config = $config.Replace(('"@CLIENT{0}_JWKS@"' -f $suffixName), $jwks)
        $config = $config.Replace(('@MTLS{0}_CERT@' -f $suffixName), (ConvertTo-JsonString ([IO.File]::ReadAllText($crtPath))))
        $config = $config.Replace(('@MTLS{0}_KEY@' -f $suffixName), (ConvertTo-JsonString ([IO.File]::ReadAllText($keyPath))))
    }
}
if ($p.RegistrationClientId)
{
    try
    {
        $iat = Get-InitialAccessToken $p.RegistrationClientId $p.RegistrationClientSecret
    }
    catch
    {
        Write-Host ('initial access token を取れませんでした（OP の DCR と管理クライアントの設定を確かめてください） : {0}' -f $_.Exception.Message) -ForegroundColor Red
        exit 2
    }
    $config = $config.Replace('@INITIAL_ACCESS_TOKEN@', (ConvertTo-JsonString $iat))
}
[IO.File]::WriteAllText($configPath, $config, (New-Object Text.UTF8Encoding $false))

#endregion

#region CIBA の端末役（Ciba = $true のプランだけ）

# **CIBA は、利用者が認証デバイスで「許可」を押すまでトークンが出ない。** Conformance Suite はそれを待ち続ける。
#   そこで、このスクリプトが認証デバイスの代わりをする（E2E の CibaTests と同じ流れ）：
#   1. 端末役のクライアント（AuthenticationDeviceClientIds に挙げたもの）で、テスト利用者のトークンを ROPC で取る
#   2. POST /SetDeviceToken で端末を登録する（**プッシュの宛先**。値は何でもよい）
#   3. モジュールを待つ間に、OP の送信箱（.\fcm\。FcmOutboxDirectory）を見て、新しいプッシュの auth_req_id に POST /ciba_result（許可）を返す
#   **全部「許可」する**ので、利用者の拒否を求めるモジュールは落ちる（自動では回せない）。
$fcmDir = Join-Path $here 'fcm'
$cibaToken = $null
$cibaSeen = @{}

if ($p.Ciba)
{
    $basicDevice = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        [Uri]::EscapeDataString($p.DeviceClientId) + ':' + [Uri]::EscapeDataString($p.DeviceClientSecret)))

    # **先にサインインの画面を 1 回開く**（OP の種データの利用者は、AccountController への最初の要求で作られる）
    if ($PSVersionTable.PSVersion.Major -ge 6) { [void](Invoke-WebRequest -Uri $opTokenEndpoint.Replace('/token', '/Account/Login') -SkipCertificateCheck -TimeoutSec 60) }
    else { ([System.Net.HttpWebRequest]::Create($opTokenEndpoint.Replace('/token', '/Account/Login'))).GetResponse().Close() }

    $ropc = Invoke-OpForm '/token' ('grant_type=password&scope=openid&username=' + [Uri]::EscapeDataString($user) + '&password=' + [Uri]::EscapeDataString($password)) $basicDevice
    $cibaToken = ($ropc.Content | ConvertFrom-Json).access_token
    if ([string]::IsNullOrEmpty($cibaToken))
    {
        Write-Host ('CIBA の端末役のトークンを取れませんでした（{0}）。' -f $ropc.Status) -ForegroundColor Red
        exit 2
    }

    $set = Invoke-OpForm '/SetDeviceToken' 'device_token=cts-authentication-device' ('Bearer ' + $cibaToken)
    if ($set.Status -ne 200)
    {
        Write-Host ('CIBA の端末を登録できませんでした（/SetDeviceToken : {0} {1}）。' -f $set.Status, $set.Content) -ForegroundColor Red
        exit 2
    }

    # **前の実行の送信箱は、数えない**（ファイルの名前を覚えておく）
    New-Item -ItemType Directory -Force -Path $fcmDir | Out-Null
    Get-ChildItem -LiteralPath $fcmDir -Filter '*.json' | ForEach-Object { $cibaSeen[$_.Name] = $true }
}

function Approve-CibaPush
{
    # **送信箱の新しいプッシュに、許可を返す**（auth_req_id は data の中）
    #   **届いてから 8 秒置いてから返す。** Conformance Suite は、最初の問い合わせ（ポーリング）に
    #   authorization_pending が返ることを確かめる（CIBA Core §11）。すぐに許可すると、最初からトークンが返り、その検査が落ちる。
    #   問い合わせの間隔（interval）は 5 秒なので、1 回は「まだ」を返せる
    foreach ($file in @(Get-ChildItem -LiteralPath $fcmDir -Filter '*.json'))
    {
        if ($cibaSeen.ContainsKey($file.Name)) { continue }
        if (((Get-Date) - $file.LastWriteTime).TotalSeconds -lt 8) { continue }
        $cibaSeen[$file.Name] = $true

        try { $push = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json } catch { continue }
        $authReqId = [string]$push.data.auth_req_id
        if ([string]::IsNullOrEmpty($authReqId)) { continue }

        $r = Invoke-OpForm '/ciba_result' ('auth_req_id=' + [Uri]::EscapeDataString($authReqId) + '&result=true') ('Bearer ' + $cibaToken)
        Write-Host ('    （CIBA の許可を返した : {0}）' -f $r.Status) -ForegroundColor DarkGray
    }
}

#endregion

#region プランを作り、モジュールを回す

$query = 'api/plan?planName=' + [Uri]::EscapeDataString($p.Name)
if ($p.Variant) { $query += '&variant=' + [Uri]::EscapeDataString($p.Variant) }

$created = (Invoke-Cts 'POST' $query $config $null) | ConvertFrom-Json
$planId = $created.id

Write-Host ('プラン : {0}（{1}）' -f $p.Name, $planId) -ForegroundColor Cyan
Write-Host ('  {0}plan-detail.html?plan={1}' -f $base, $planId)

$results = New-Object Collections.ArrayList

foreach ($m in @($created.modules))
{
    $runQuery = 'api/runner?test=' + [Uri]::EscapeDataString($m.testModule) + '&plan=' + [Uri]::EscapeDataString($planId)
    if ($m.variant)
    {
        $runQuery += '&variant=' + [Uri]::EscapeDataString(($m.variant | ConvertTo-Json -Compress))
    }

    $run = (Invoke-Cts 'POST' $runQuery $null $null) | ConvertFrom-Json
    $testId = $run.id

    # **待ち時間は回数ではなく実時間で測る**（root\11_CODING.md 5 節）
    $deadline = (Get-Date).AddSeconds($ModuleTimeoutSec)
    $info = $null
    do
    {
        Start-Sleep -Seconds 2
        if ($p.Ciba) { Approve-CibaPush }
        $info = (Invoke-Cts 'GET' ('api/info/' + $testId) $null $null) | ConvertFrom-Json
    }
    while (($info.status -ne 'FINISHED') -and ($info.status -ne 'INTERRUPTED') -and ((Get-Date) -lt $deadline))

    $status = [string]$info.status
    $result = [string]$info.result
    if (($status -ne 'FINISHED') -and ($status -ne 'INTERRUPTED'))
    {
        $result = 'TIMEOUT（' + $status + '）'
    }

    # **同じモジュールが response_type ごとに並ぶ**（Implicit・Hybrid）ので、区別できるように添える
    $label = $m.testModule
    $rt = [string]$info.variant.response_type
    $rm = [string]$info.variant.response_mode
    if ($rt) { $label += ' [' + $rt + $(if ($rm -and ($rm -ne 'default')) { ' / ' + $rm } else { '' }) + ']' }

    [void]$results.Add([pscustomobject]@{ Module = $m.testModule; Variant = $info.variant; Status = $status; Result = $result; Id = $testId })
    Write-Host ('  {0,-12} {1}' -f $result, $label)
}

#endregion

#region 結果

$resultPath = Join-Path $outDir ('{0}-result.json' -f $outName)
[IO.File]::WriteAllText($resultPath, (@{ plan = $p.Name; planId = $planId; modules = $results } | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))

$zip = Join-Path $outDir ('{0}-report.zip' -f $outName)
try
{
    # **URL は api/plan/exporthtml/{id}**（release-v5.3.4 で確かめた。api/plan/{id}/exporthtml は 404）
    [void](Invoke-Cts 'GET' ('api/plan/exporthtml/' + $planId) $null $zip)
}
catch
{
    Write-Host ('報告書（exporthtml）を書き出せませんでした : {0}' -f $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host ''
Write-Host '================ 結果 ================'
$results | Group-Object Result | Sort-Object Name | ForEach-Object { Write-Host ('  {0,-20} {1}' -f $_.Name, $_.Count) }
Write-Host ('  結果の JSON : {0}' -f $resultPath)
Write-Host ('  報告書      : {0}' -f $zip)

$bad = @($results | Where-Object { ($_.Result -eq 'FAILED') -or ($_.Status -eq 'INTERRUPTED') -or ($_.Result -like 'TIMEOUT*') })
if ($bad.Count -gt 0) { exit 1 }
exit 0

#endregion
