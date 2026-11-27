# 適合性テスト（Conformance Suite）— `container\CTS\`（#350）

**OpenID Foundation の Conformance Suite（適合性テスト）を手元で起動し、MPAS（net10.0 版）を相手に回す**（`ANALYSIS-IdP.md` の **D-14**）。
**外部の基準を、最終的な正とする**（`QUALITY.md` 2 節）。E2E は、このリポジトリが書いたテストなので、書いた側と同じ読み違いを共有しうる。

- 原本：https://gitlab.com/openid/conformance-suite（ビルド済みのイメージ。`docker-compose-prebuilt.yml` を元にした）
- **版は固定する**（`release-v5.3.4`）。上げるときは、`docker-compose.yml` の server と nginx のタグを、同じ版に手で上げる
- **認定（certification）を取るためのものではない。** 手元で回して、不適合を見つけて直すためのもの
- **いつ回すか・結果の仕分け**は `QUALITY.md` 2 節と `root/14_TESTING.md` 5 節「適合性テスト」（リリースの前に全プラン、適合性テストで見つかった不適合を直すときにそのプラン）

## 手順

```powershell
cd container\E2E
.\1_PublishIdP.ps1          # OP の発行物と証明書（E2E と共用。MPAS を直したら、先にこれ）

cd ..\CTS
.\2_DockerComposeUp.bat     # Conformance Suite と OP を起動する（Conformance Suite の起動には 1〜2 分かかる。先に Prepare.ps1 を呼ぶ）
.\RunTestPlan.ps1 -Plan oidcc-basic    # プランを回す（下の表）
.\ExtractReview.ps1         # REVIEW の判定と材料を、報告書から取り出す（下の「REVIEW の見方」。コンテナは要らない）
.\3_DockerComposeDown.bat   # 止める
```

| `-Plan` | Conformance Suite のプラン | 設定の雛形 |
|---|---|---|
| `oidcc-basic`・`oidcc-config` | `oidcc-basic-certification-test-plan`・`oidcc-config-certification-test-plan` | `oidcc-basic.json`・`oidcc-config.json` |
| `oidcc-implicit`・`oidcc-hybrid` | `oidcc-implicit-…`・`oidcc-hybrid-…`（**response_type ごとにモジュールが並ぶ**） | `oidcc-basic.json` |
| `oidcc-formpost-basic`・`-implicit`・`-hybrid` | `oidcc-formpost-*-certification-test-plan`（`response_mode=form_post`） | `oidcc-basic.json` |
| `oidcc-rp-initiated-logout`・`oidcc-frontchannel-rp-initiated-logout`・`oidcc-backchannel-rp-initiated-logout` | 同じ名前の `…-certification-test-plan`（`response_type=code`） | `oidcc-logout.json`（**クライアントはプランごとに別**） |
| 上の 9 つの名前に `-dynamic` を付けたもの（`oidcc-basic-dynamic` など） | 同じプランを `client_registration=dynamic_client` で（**Conformance Suite がモジュールごとにクライアントを動的登録する**。ログアウトの口も登録の要求に載る。#426）。**ログアウトの 3 つの動的登録版は、`-ResponseType` で `code` 以外の 5 つも**（下の注） | 静的な版と同じ雛形（**`client`・`client2`・`client_secret_post` の中身を、`RunTestPlan.ps1` が initial access token に置き換える**） |
| `oidcc-mtls`・`oidcc-mtls-formpost` | `oidcc-test-plan`（`client_auth_type=mtls`（`tls_client_auth`）・`response_type=code`。後者は `response_mode=form_post`。#426） | `oidcc-basic.json`（**クライアントは 31・32**に置き換え、クライアント証明書（FAPI と同じ）を `mtls`・`mtls2` に埋める） |
| `oidcc-dynamic` | `oidcc-dynamic-certification-test-plan`（`response_type=code`。**`-ResponseType` で `code` 以外の 5 つも**。下の注） | `oidcc-dynamic.json` |
| `fapi2-sp-private-key-jwt-dpop`・`fapi2-sp-mtls` | `fapi2-security-profile-final-test-plan`（`plain_fapi`・`openid_connect`・`simple`・`grant_management=disabled`。前者は `private_key_jwt`＋DPoP、後者は MTLS＋MTLS） | `fapi2.json`（**クライアントは 2 つずつ**。鍵とクライアント証明書を埋める） |
| `fapi2-sp-private-key-jwt-mtls`・`fapi2-sp-mtls-dpop` | 同上（**認証と縛りの交差**。前者は `private_key_jwt`＋MTLS、後者は MTLS＋DPoP。#416） | `fapi2.json`（クライアントは 19・20、21・22） |
| `fapi2-sp-plain-oauth` | 同上の `private_key_jwt`＋DPoP を、`openid=plain_oauth`（OIDC を使わない OAuth）で。#416 | `fapi2.json`（クライアントは 8・9。**`scope` を `email` に置き換える**：Conformance Suite は、`scope` に `openid` があると始める前に落とす。**資源は `/TestResource` に置き換える**（`ResourcePath`。#425）） |
| `fapi2-sp-client-credentials` | 同上の `fapi_profile=fapi_client_credentials_grant`（`openid=plain_oauth`・`private_key_jwt`＋DPoP。ブラウザを使わない）。#416 | `fapi2.json`（クライアントは 23・24。**`client_mode=fapi2`**（#424。#416 では normal）。下の「登録と、テスト利用者」。`scope` は `email`、**資源は `/TestResource`**（#425）。**`openid=openid_connect` にすると、出ていない id_token の `acr` を確かめに行って止まる**） |
| `fapi2-ms-private-key-jwt-dpop` | `fapi2-message-signing-final-test-plan`（上の `private_key_jwt`＋DPoP に、署名した Request Object・JARM） | `fapi2.json`（**クライアントは SP と分ける**：17・18。署名した Request Object を必須にした登録。#385） |
| `fapi2-ms-mtls` | 同上の MTLS＋MTLS（#416） | `fapi2.json`（クライアントは 29・30） |
| `fapi2-ms-signed-plain-response`・`fapi2-ms-unsigned-jarm` | 同上の `private_key_jwt`＋DPoP で、**署名と JARM を片方だけ使う**組（前者は署名した Request Object＋通常の応答、後者は署名の無い要求＋JARM。#416） | `fapi2.json`（前者は 17・18、**後者は 8・9**：17・18 は署名した Request Object を必須にしている） |
| `fapi1-adv-private-key-jwt-par` | `fapi1-advanced-final-test-plan`（`plain_fapi`・`private_key_jwt`・`pushed`・`jarm`。**`plain_response`（Hybrid）ではない**：MPAS は fapi1 の登録に Hybrid を許さない（FA-1.4）。#370） | `fapi2.json`（クライアントは `client_mode=fapi1`） |
| `fapi1-adv-mtls-par` | 同上の MTLS のクライアント認証（#416） | `fapi2.json`（クライアントは 25・26） |
| `fapi-ciba-private-key-jwt-poll` | `fapi-ciba-id1-test-plan`（`plain_fapi`・poll・`private_key_jwt`・静的な登録） | `fapi-ciba.json`（**利用者の承認は、`RunTestPlan.ps1` が認証デバイスの代わりに送る**。下の「CIBA の承認」） |
| `fapi-ciba-mtls-poll` | 同上の MTLS のクライアント認証（#416） | `fapi-ciba.json`（クライアントは 27・28。端末役は同じ） |

- **FAPI のバリアントは、MPAS が対応する方式を確かめる組だけ**にしてある（軸を全部掛け合わせると数十通り）。#350 の段階 4 で代表の組を決め、**#416 で、認証と縛りの交差・mTLS のクライアント認証・`plain_oauth`・client_credentials・Message Signing の要求と応答の残りの組を足した**
- **`-ResponseType`**（#426）：`response_type` をプランのバリアントで指定するプランのうち、**`oidcc-dynamic` と、ログアウトの 3 つの動的登録版**だけ、`code` 以外（`id_token`・`id_token token`・`code id_token`・`code token`・`code id_token token`）でも回す。
  例：`.\RunTestPlan.ps1 -Plan oidcc-dynamic -ResponseType 'code id_token'`。`out\` のファイルの名前に添える（`oidcc-dynamic-code-id_token-report.zip`。`ExtractReview.ps1 -Plan` にもこの名前を渡す）。
  **ほかのプランには付けない**（Implicit・Hybrid のプランは、プランの中で `response_type` ごとにモジュールが並ぶ。ログアウトの静的な版は、下の「足さないもの」）
- **リリースの前には、上の表のすべてのプランを回す**（#416 で足したものも含める。`QUALITY.md` 2 節）。認証と縛りの組み合わせのような回帰（#423）は、代表の組だけでは拾えないため。**`-ResponseType` の付くプランは、6 つの `response_type` をすべて回す**（#426）
- **足さないもの**（MPAS が持たない方式・対象にしていないもの。#416）

  | プラン・バリアント | 理由 |
  |---|---|
  | FAPI-CIBA `ciba_mode=ping` | **MPAS が ping を持たない**（poll だけを広告。FAPI-CIBA は ping を任意とする）。push は Conformance Suite に無い |
  | `client_auth_type=client_secret_jwt`（`oidcc-test-plan`） | MPAS が持たない |
  | `client_auth_type=none`（`oidcc-test-plan`。公開クライアント） | **Conformance Suite は PKCE を送らず**（PKCE を確かめる 1 モジュールだけが送る）、**MPAS は公開クライアントの認可コードを PKCE が無ければ引き換えない**（RFC 9700 §2.1.1 は公開クライアントに PKCE を求める。#294 の C-40。`13_CONFIGURATION.md`「PKCE だけで認可コードを引き換えられる登録」）。#426 で回すと、トークン エンドポイントへ進むモジュールが `invalid_client` で FAILED 27・PASSED 4 だった（PKCE を送る `oidcc-ensure-request-with-valid-pkce-succeeds` は通る） |
  | ログアウトの 3 プランの静的な版の、`code` 以外の `response_type` | **動的登録版で回す**（#426 で決めた）。ログアウトの振る舞いは登録の種類で変わらず、静的と動的の差は `code` の組で見ている（どちらも同じ結果）。静的な版で回すには、ログアウトのクライアント（4・5・6）に `redirect_uri_token` を足す必要がある |
  | FAPI 1.0 Advanced `fapi_auth_request_method=by_value` | `request_parameter_supported=false`（`request` で値を直に渡す形を持たない） |
  | FAPI 1.0 Advanced `fapi_response_mode=plain_response` | fapi1 の登録に Hybrid を許さない（FA-1.4。JARM の側で回している） |
  | `authorization_request_type=rar`・`grant_management=enabled` | RAR・Grant Management を持たない |
  | `oidcc-session-management-certification-test-plan` | Session Management は見送りと決めた |
  | `oidcc-3rdparty-init-login-certification-test-plan` | 3rd party initiated login を持たない |
  | `fapi_profile` の地域のプロファイル（`openbanking_*`・`consumerdataright_au`・`connectid_au`・`cbuae`・`ksa` など）、`*-brazil-dcr-*` | 地域のエコシステムの追加の規定で、MPAS は対象にしていない |
  | `fapi2-*-id1`・`-id2`（旧版） | final の版で回している |
  | eKYC・OID4VP・OID4VCI・SSF・AuthZEN・OpenID Federation | MPAS が持たない機能 |
  | RP を相手にするプラン（`oidcc-client-*`・`fapi*-client-test-plan`） | MPAS の ID 連携（RP の役）を確かめられるが、Conformance Suite を OP にして MPAS からサインインさせる仕掛けが要る（別に検討する） |

| | URL |
|---|---|
| Conformance Suite（画面） | https://localhost.emobix.co.uk:8443/ （結果の一覧・各モジュールのログ） |
| OP（issuer） | https://mpas-cts.localhost:44311 |
| Discovery | https://mpas-cts.localhost:44311/.well-known/openid-configuration |

- **メモリを使う**（Java の server・MongoDB・nginx・OP）。**要らないコンテナ（`..\E2E\`・`..\Store\`）は止めておく**
- **server は、MongoDB が応答してから起動する**（`healthcheck`）。`mongo\` は Windows のフォルダなので、MongoDB が開くのに 1 分ほどかかることがあり、server は 30 秒で諦めて終了していた
- **hosts の編集は要らない。** `localhost.emobix.co.uk` は公開の DNS が 127.0.0.1 を返し、`mpas-cts.localhost` は Edge・Chrome が 127.0.0.1 に向ける（RFC 6761）
- OP の証明書は localhost 向けの開発用のもの（E2E と共用）なので、**ブラウザで OP を開くと、名前の不一致の警告が出る**（進んでよい）

## 仕組み

### 名前とポート

**issuer は、ブラウザと Conformance Suite の両方から、同じ URL で届くこと**が要る（OIDC Discovery 1.0 §4.3。Discovery を取った URL と `iss` が一致すること）。

| 名前 | ブラウザ（手元の PC） | Conformance Suite（コンテナ） |
|---|---|---|
| `localhost.emobix.co.uk`（Conformance Suite） | 公開の DNS が 127.0.0.1 を返す | nginx のネットワークの別名 |
| `mpas-cts.localhost`（OP） | Edge・Chrome が `*.localhost` を 127.0.0.1 に向ける | op のネットワークの別名（Java の名前解決で、OP のコンテナに届くことを確かめた） |

- **E2E の upstream（`https://localhost:44301`）は使えない** — Conformance Suite のコンテナから見ると、`localhost` は自分自身を指す
- **ポートは、中と外で同じにする**（44311）。違うと、issuer の URL がどちらかで届かない
- **`IssuerId` を、Discovery の URL と同じ値にしてある**（雛形の `IssuerId` は論理名で、URL と違う。そのままだと Discovery の検査で落ちる）
- `curl` は `*.localhost` を自分で 127.0.0.1 に向ける（DNS に問わない）ので、**コンテナの中から `curl` で確かめるときは `--resolve` を付ける**

### nginx の証明書（`Prepare.ps1`）

**OP から Conformance Suite へ、サーバ間で TLS の要求を送るプランがある**（Back-Channel Logout の `logout_token` の POST）。
原本の nginx の証明書は `CN=localhost` の自己署名なので、**OP は名前の不一致と信頼の無さで、正しく断る**（`HttpRequestException`。OP の検証は緩めない）。

- `Prepare.ps1` が、**`localhost.emobix.co.uk` を SAN に持つ自己署名の証明書を `certs\` に作る**（無いときだけ。Conformance Suite の nginx のイメージの `openssl` を使う）
- nginx は、それを原本の証明書の場所にマウントして使う。**OP のコンテナだけが、`SSL_CERT_FILE` でそれを信頼する**（.NET は Linux で OpenSSL の信頼の起点を使う）
- 作り直すなら `certs\` を消す。手元のブラウザで Conformance Suite を開くと、自己署名の警告が出るのは前と同じ

### OP の TLS の暗号スイート（`tls\openssl.cnf`）

**OP（Kestrel が TLS を終端）の TLS 1.2 の暗号スイートを、BCP 195 が勧めるもの（ECDHE と AES-GCM の 4 つ）に絞ってある**（#369。FAPI 2.0 Security Profile §5.2.2）。
**アプリのコードは変えていない。** .NET は Linux で、OpenSSL の設定に従う。`docker-compose.yml` の `OPENSSL_CONF` で、`tls\openssl.cnf`（Git の管理下）を読ませる。

- **絞らないと、FAPI 2.0 の `happy-flow`・`ensure-holder-of-key-required` が FAILED になる**（`RequireOnlyBCP195RecommendedCiphersForTLS12`。CBC のスイートで繋がる）
- **ほかのプランは変わらない**（Conformance Suite は GCM を話す）。OP が外へ出す TLS（Back-Channel Logout の POST）にも効く
- 配備で絞る方法（Linux・Windows・リバース プロキシ）は [`13_CONFIGURATION.md`](../../root/13_CONFIGURATION.md)「TLS の暗号スイートを絞る」

### FAPI の鍵・クライアント証明書と、MTLS（`Prepare.ps1`）

| 作る物 | 置き場所 | 使い道 |
|---|---|---|
| **EC P-256 の鍵**（2 つ。`client`・`client2`） | `certs\fapi-client{1,2}.jwk.json`（秘密鍵の JWK） | `private_key_jwt`・DPoP の署名。**秘密鍵は `RunTestPlan.ps1` が設定の `client.jwks` に埋め、公開鍵は `.env.cts` 経由で OP の登録（`jwk_ecdsa_publickey`）に渡す** |
| **クライアント証明書**（2 つ。自己署名の RSA） | `certs\mtls-client{1,2}.crt`・`.key` | `tls_client_auth` と、証明書に縛ったトークン。**Subject（`CN=CTS FAPI Client 1`・`2`）を OP の登録（`tls_client_auth_subject_dn`）に書く** |
| **MTLS のテスト専用のフック** | `hooks\MtlsTestHook.dll` | **OP の Kestrel に、クライアント証明書を求めさせる**（E2E・スタブと同じ。`DOTNET_STARTUP_HOOKS`。**要求するだけで必須にはしない**ので、ほかのプランは変わらない。**発行元を問わずに受け付ける**ので、テスト専用） |

- **鍵は ES256 にしてある。** OP の Discovery の `token_endpoint_auth_signing_alg_values_supported` は RS256・PS256・ES256 で（#395）、FAPI 2.0 は RS256 を認めない（OP も FAPI の登録の RS256 を断る）
- **ES256 で署名した Request Object は、登録の `jwk_ecdsa_publickey` で検証する**（#370。以前は RS256 だけで、FAPI 2.0 Message Signing・FAPI 1.0 Advanced は、大半のモジュールが PAR の所で止まっていた）
- **JARM の署名は、登録の `authorization_signed_response_alg=ES256`**（#370。FAPI 2.0 の 8・9 と、FAPI 1.0 Advanced の 12・13。登録が無いと RS256 で、FAPI の検査で落ちる）

### CIBA の承認（`RunTestPlan.ps1` の端末役）

**CIBA は、利用者が認証デバイスで「許可」を押すまでトークンが出ない。** Conformance Suite はそれを待ち続けるので、`RunTestPlan.ps1` が認証デバイスの代わりをする（E2E の `CibaTests` と同じ流れ）。

1. **端末役のクライアント**（14 番目。CTS 専用。`AuthenticationDeviceClientIds` に挙げる）で、テスト利用者のトークンを ROPC で取る
2. `POST /SetDeviceToken` で端末を登録する（プッシュの宛先）
3. モジュールを待つ間に、OP の**送信箱**（`.\fcm\`。`FcmOutboxDirectory`。`IsDebug` のときだけ働くテスト用の設定）を見て、新しいプッシュの `auth_req_id` に `POST /ciba_result`（許可）を返す

- **届いてから 8 秒置いてから許可する。** Conformance Suite は、最初の問い合わせに `authorization_pending` が返ることを確かめる（すぐに許可すると、その検査が落ちる）
- **全部「許可」する**ので、利用者の拒否を求めるモジュール（`fapi-ciba-id1-user-rejects-authentication`）は自動では回せない
- `/SetDeviceToken`・`/ciba_result` は `AuthenticationDeviceClientIds` のクライアントのトークンだけを受ける。**この環境では、同梱の認証デバイスの登録は使わない**
- どれも**在れば作らない**（作り直すなら `certs\`・`hooks\` を消す）。秘密鍵を含むので、**共有しない**

### 登録と、テスト利用者

| | 置き場所 |
|---|---|
| クライアント（`client`・`client2`。`client_secret_basic`） | `docker-compose.yml` の OP の環境変数（**適合性テスト専用の値**。E2E の `docker-compose.yml` と同じ扱い） |
| クライアント（`client_secret_post`。`oidcc-server-client-secret-post` が使う） | 同上（3 つ目。設定の `"client_secret_post"`。静的な登録では、認証の方式ごとにクライアントを分けて渡す作り） |
| クライアント（ログアウト。4〜6 つ目） | 同上。**プランごとに分ける**（RP-Initiated・Front-Channel・Back-Channel。登録したログアウトの口が、別のプランの検査に混ざらないように）。`RunTestPlan.ps1` が雛形の `@CLIENT_ID@`・`@CLIENT_SECRET@` を埋める |
| 動的登録（DCR）の管理クライアント（7 つ目） | 同上。**`scope=client_registration` と `owner`（作った登録の所有者。利用者名）を登録する**（#307）。`owner` が無いと、登録は 403（`access_denied`）で断られる。**名前は `Prepare.ps1` が `.env.cts` に書く**（テスト利用者の名前は手元の `appsettings.json` で変わる） |
| initial access token | **MPAS は、それの無い登録を受けない。** `RunTestPlan.ps1 -Plan oidcc-dynamic`（と `-dynamic` の付くプラン。#426）が、回す直前に管理クライアントで `client_credentials` のトークンを取り、雛形の `@INITIAL_ACCESS_TOKEN@`（設定の `client.initial_access_token`）を埋める。期限はプラン 1 つ分より長くしてある（`DcrAccessTokenExpireTimeSpanFromSeconds=3600`。既定は 300 秒） |
| FAPI 2.0 のクライアント（8〜11 つ目。`client_mode=fapi2`） | 同上。8・9 は `private_key_jwt`（＋ DPoP）、10・11 は `tls_client_auth`（＋ 証明書に縛ったトークン）。**次を登録する**：`id_token_signed_response_alg=ES256`（**登録が無いと RS256 になり、FAPI 2.0 の検査で全部止まる**。#355）、**FAPI の要件の強制**（`require_pushed_authorization_requests`・`require_pkce`・`dpop_bound_access_tokens` か `tls_client_certificate_bound_access_tokens`。#346。**どれも既定は false で、立てないと PAR・PKCE の無い要求が通る**） |
| FAPI 2.0 Message Signing のクライアント（17・18 番目。`client_mode=fapi2`） | 同上。8・9 と同じ形に、**署名した Request Object の必須（`require_signed_request_object`）を足したもの**（#385）。**8・9 は Security Profile のプランと共用なので立てられない**（Security Profile は署名の無い PAR を送る） |
| FAPI 2.0 の、認証と縛りの交差のクライアント（19〜22 番目。`client_mode=fapi2`） | 同上（#416）。19・20 は `private_key_jwt`＋証明書に縛ったトークン（`tls_client_certificate_bound_access_tokens`。証明書は設定の `mtls`・`mtls2`）、21・22 は `tls_client_auth`＋DPoP に縛ったトークン（`dpop_bound_access_tokens`）。**ほかの項目は 8〜11 と同じ** |
| FAPI 2.0 の client_credentials のクライアント（23・24 番目。**`client_mode=fapi2`**） | 同上（#416）。`private_key_jwt`＋DPoP の必須（`dpop_bound_access_tokens`）。**#424 で、fapi2 の登録にも `private_key_jwt`・mTLS の client_credentials を開けた**（`ClientModePolicy`。FAPI 2.0 Security Profile §5.3.2.1 の NOTE 2）。**#416 では、MPAS が client_credentials を normal の登録にしか許さなかったので、normal の登録と #346 の項目で回していた** |
| mTLS のクライアント認証のクライアント（25〜30 番目） | 同上（#416）。**同じプランの `private_key_jwt` の登録から、認証だけを `tls_client_auth`（Subject は `CN=CTS FAPI Client 1`・`2`）に入れ替えたもの**：25・26 は FAPI 1.0 Advanced（12・13 の形）、27・28 は FAPI-CIBA（15・16 の形）、29・30 は FAPI 2.0 Message Signing（17・18 の形で、縛りも証明書）。**公開鍵（`jwk_ecdsa_publickey`）は残す**（Request Object・CIBA の認証要求の署名に使う） |
| FAPI 1.0 Advanced のクライアント（12・13 番目。`client_mode=fapi1`） | 同上。`private_key_jwt`・`id_token_signed_response_alg=ES256`。鍵は FAPI 2.0 と同じ。**FAPI 1.0 Advanced の要件の強制**（`require_signed_request_object`・`require_pkce`・`tls_client_certificate_bound_access_tokens`。§5.2.2 の 1・18・5。#385）。**証明書に縛ったトークンには、設定の `mtls`・`mtls2` のクライアント証明書を使う** |
| CIBA のクライアント（15・16 番目。`client_mode=fapi_ciba`）と端末役（14 番目） | 同上。CIBA の認証要求の署名は ES256 固定なので、公開鍵は `jwk_ecdsa_publickey`。**証明書に縛ったトークンを必須にする**（`tls_client_certificate_bound_access_tokens`。FAPI-CIBA ID1 §5.2.2 が求める FAPI 1.0 Advanced §5.2.2 の 5。#385）。端末役は秘密だけを持ち、`AuthenticationDeviceClientIds` に挙げる |
| 認可コードの期限 | **60 秒にしてある**（`OAuth2AuthorizationCodeExpireTimeSpanFromSeconds`。FAPI 2.0 は 60 秒以下。雛形の既定は 600 秒。**サーバ全体に効く**） |
| 折り返し先 | `https://localhost.emobix.co.uk:8443/test/a/mpas-cts/callback`（`alias` は設定の `"alias"` と同じ。Implicit・Hybrid の `redirect_uri_token` も同じ） |
| ログアウトの口 | 折り返し先の `/callback` を `/post_logout_redirect`・`/frontchannel_logout`・`/backchannel_logout` に替えたもの（Conformance Suite が決めた口） |
| テスト利用者 | OP の種データが作る一般の利用者（`tanaka` ＋ `TestUserSuffix`）。**パスワードは手元の `appsettings.json` の `TestUserPWD`** |

### 設定（`config\*.json`）と、ブラウザの自動操作

**サインインと同意は、Conformance Suite の server がブラウザを自動で操作して行う**（設定の `"browser"`。原本の試験用の設定と同じ書き方）。

| 画面 | 操作 |
|---|---|
| サインイン（`/Account/Login`） | `Email`・`Password` の欄を埋め、`normal_signin` を押す |
| 同意（`/authorize`） | `submit.Grant` を押す（**同意を記録した後は出ない**ので、任意の手順にしてある） |
| 折り返し（`/test/*/callback`） | Conformance Suite の完了の印（`submission_complete`）を待つ |

- **テスト利用者の名前とパスワードは、雛形では差し込み口**（`@TEST_USER@`・`@TEST_PASSWORD@`）である。
  `RunTestPlan.ps1` が手元の `appsettings.json` から埋めて、**`out\<プラン>.json` に書く**（`out\` は Git の管理外）
- 画面から回すときは、`out\<プラン>.json` を貼る
- **Conformance Suite のログ（`mongo\`）と報告書の zip（`out\`）には、ブラウザの自動操作で入力したテスト利用者のパスワードが平文で残る**（`Entering text` の記録）。どちらも Git の管理外だが、**ログや報告書を、そのまま Issue などに貼らない**
- **まれに、サインインのボタンを押しても画面が変わらず、そのモジュールが FAILED になる**（`Unexpected URL for non-optional task`。段階 3 の通しで 3 回、#416 で 3 回、#422 で 1 回、#421 の全プランで 4 回、#429 の FAPI 2.0 の 10 プランで 1 回、#426 の全 56 の組で 4 回と、OIDC の 42 の組の回し直しで 7 回）。**どれも、サインインの要求（`POST /Account/Login`）が OP に届いていない**（OP の ACCESS ログで確かめた。Conformance Suite のブラウザ（HtmlUnit）の側で、ボタンのスクリプトが動かなかった）。回し直すと通るので、**同じモジュールだけで続けて落ちるかを見てから**、不適合として扱う

**画面の写し（REVIEW）を求めるモジュールは、モジュールごとの `"override"` で、そのときの画面を写しの代わりにする**（原本の CI の設定 `.gitlab-ci/local-provider-oidcc-conformance-config.json` と同じ書き方）。
`wait` のコマンドの末尾に `update-image-placeholder`（無くてもよいなら `-optional`）を付けると、待った画面で写しの欄が埋まる。
**埋まらないと、モジュールは `WAITING` のまま止まり、`RunTestPlan.ps1` が時間切れにする**（次のモジュールが同じ `alias` を取るので、打ち切られる）。

| モジュール | 待つ画面（文言） |
|---|---|
| `oidcc-prompt-login`・`oidcc-max-age-1` | 2 回目の認可のサインイン（`Use a local account to sign in.`） |
| `oidcc-ensure-registered-redirect-uri` | 登録の無い `redirect_uri` のエラー画面（`Invalid redirect_uri`） |
| ログアウトの異常系（`oidcc-rp-initiated-logout-bad-*`・`-modified-id-token-hint`・`-no-id-token-hint`・`-query-added-*`） | **誤りを示した確認の画面**（`Do you want to sign out of this site`。**押さない**。OP は RP へ戻さない。RP-Initiated Logout 1.0 §4・§6） |
| ログアウトの戻り先が無い形（`-no-params`・`-no-post-logout-redirect-uri`・`-only-state`） | 確認の画面で「Yes」（`allow`）を押し、サインアウトした後のホーム（`Sign-up`） |
| 動的登録の `-logo-uri`・`-policy-uri`・`-tos-uri` | サインインの画面 |
| 動的登録の `redirect_uri` の誤り（`-ensure-redirect-uri-in-authorization-request`・`-query-mismatch`・`-query-added`） | エラー画面（`An error occurred while processing your request`） |
| FAPI 2.0・FAPI 1.0 Advanced の `par-attempt-to-use-request_uri-for-different-client` | エラー画面（`The client_id does not match the request object`） |
| FAPI 2.0・FAPI 1.0 Advanced の `par-attempt-reuse-request_uri`・`par-attempt-to-use-expired-request_uri` | 使用済み・期限切れの `request_uri` のエラー画面（`The request_uri is unknown, expired, or already used.`。#368）。**reuse は 1 回目を通常どおり進め、2 回目でこの画面を待つ**（callback を待つ手順の `match` は、Conformance Suite のホストから書く。認可の URL が `redirect_uri` に callback の URL を載せるため） |

- **FAPI 1.0 Advanced の上書きは、FAPI 2.0 と同じ中身**（#385。以前は FAPI 2.0 のモジュール名だけにあり、FAPI 1.0 Advanced は既定の自動操作のまま `Unable to locate element` で落ちていた）
- **REVIEW は、写しで合否を付ける項目である。** 自動では、待った画面が出たことまでしか確かめていない。**合否は、エージェントが `ExtractReview.ps1` の材料から付け、人がその表を承認する**（下の「REVIEW の見方」。#417）
- **ログアウトの確認の画面**：MPAS は、`id_token_hint` が無い・一致しない・要求に誤りがあるとき、確認の画面を出す（RP-Initiated Logout 1.0 §2 の MUST）。雛形では「Yes」を任意の手順で押す
- **自動では回せないモジュール**（FAPI 2.0・`oidcc-dynamic`・`oidcc-mtls`。FAILED・TIMEOUT になるが、OP の不適合ではない）
  - `oidcc-server-rotate-keys`（`oidcc-dynamic`（どの `response_type` も）・`oidcc-mtls`・`oidcc-mtls-formpost`。#426）：**OP の署名の鍵を、人が入れ替える操作が要る**（`TellUserToRotateOpKeys`。入れ替えてから「Start」を押すのを待つ）。
    自動の実行では待つ間に時間切れになり、TIMEOUT（INTERRUPTED）になる（#414。手で回すかは決めていない）
  - `…-user-rejects-authentication`：利用者が同意を断る操作が要る。**MPAS は同意を記録した後は同意の画面を出さず、サインインの画面には取り消しのボタンが無い**。
    **E2E の `RT-413.2` で補う**（PAR で預けた要求を同意の画面で拒否すると `access_denied`。#413。クライアントは `TestClient`）
  - `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`：**1 回目のサインインの画面では何もせず、2 回目で入る**操作が要る。自動操作は、同じ画面への訪問を区別できない。
    **E2E の `RT-413.1` で補う**（サインインの前に同じ `request_uri` を 2 回送り、2 回目でサインインすると認可でき、その後は使えない。#413。クライアントは `TestClient`）
- **落ちるのが正しいモジュール**（Conformance Suite 5.3.4 の求める受け方が、今の仕様と食い違う）
  - **FAPI 1.0 Advanced の大半**：Conformance Suite のクライアントは、**トークン エンドポイントへの要求で client_assertion の `aud` をトークン エンドポイントの URL にする**（PAR では issuer）。
    **RFC 10070 §4 はトークン エンドポイントの URL を audience にすることを禁じた**ので、MPAS は `invalid_client` で断る（#398。設定で以前の受け方に戻す分岐は作っていない）。
    `par-test-pushed-authorization-url-as-audience-for-client-JWT-assertion`・`par-token-endpoint-url-as-audience-for-client-JWT-assertion` も同じ理由で落ちる（RFC 10070 §5）
  - **`oidcc-dynamic` の、トークン エンドポイントまで進むモジュール**（`oidcc-server`・`oidcc-idtoken-rs256`・`oidcc-refresh-token`・`oidcc-refresh-token-rp-key-rotation`・`oidcc-registration-jwks-uri`・`oidcc-redirect-uri-query-OK`・`oidcc-request-uri-signed-rs256`）：動的登録したクライアントも `private_key_jwt` で、**トークン エンドポイントへの要求の `aud` をトークン エンドポイントの URL にする**ので、同じ理由（#398）で `invalid_client` になる。**`oidcc-ensure-client-assertion-with-iss-aud-succeeds`**（`aud` を issuer にする）**は通る。****`oidcc-request-uri-signed-rs256` は、外部の `request_uri` の認可要求は通り（#374）、トークン エンドポイントで止まる**
  - **FAPI-CIBA は落ちない**：CIBA の流れ（`/ciba_authz` と、`/token` の CIBA のグラント）は以前のまま、トークン エンドポイントの URL も受ける（RFC 10070 は CIBA を直接の対象にしていない。#398）
  - FAPI 1.0 Advanced の `test-array-as-audience-for-client-JWT-assertion`：client_assertion の `aud` を `[issuer, ダミー]` にして、受けることを求める。**RFC 10070 §4（RFC 7523 §3 の 3 を置き換えた）は、issuer を唯一の値としない JWT を断ることを求める**ので、MPAS は `invalid_client` で断る（モジュールの求める受け方は、置き換えられた RFC 7523 §3 の 3（「含む」）に沿う。#397）
  - **#398 で止まるモジュールの、トークン エンドポイントより後ろの判定は、確かめてある**（2026-11-21。#415）。
    上の FAPI 1.0 Advanced の 17 件（`aud` の受け方そのものを確かめる 3 件を除く）と `oidcc-dynamic` の 7 件を、**`aud` を一時的に緩めた手元の版**で回した：**PASSED 22・REVIEW 1・WARNING 1**（REVIEW は `par-attempt-reuse-request_uri` のエラー画面の写し、WARNING は下の「OP の不適合で落ちていたモジュール（直した）」の #421）。
    Conformance Suite は、release-v5.3.4 が最新で、master でも `aud` の既定はトークン エンドポイントの URL のまま（2026-11-21）。**版を上げても回せない**ので、リリースの前に確かめ直すなら、同じ手順で回す：
    1. `root\programs\CommonLibrary\TokenProviders\CmnEndpoints.ClientAuthentication.cs` の `ClientAssertionAudiences` の最後の `return` に、トークン エンドポイントの URL（`tokenUrl`）を足す（**コミットしない**。fapi2 の登録は別の分岐で issuer だけのまま）
    2. `..\E2E\1_PublishIdP.ps1` で発行し、`fapi1-adv-private-key-jwt-par`・`oidcc-dynamic` を回す
    3. **戻して発行し直す**（発行物は E2E と共用。戻さないと、E2E のコンテナに緩い版が残る）。ワーキング ツリーがクリーンなことを確かめる
- **環境の不足で落ちていたモジュール（#425 で足した資源で、どれも PASSED）**（#416。`fapi2-sp-plain-oauth`・`fapi2-sp-client-credentials`）
  - **資源の段**（`resource.resourceUrl` への要求に 200・201 を求める）で 403 になっていた。資源に `/userinfo` を使っていたが、**MPAS の `/userinfo` は `openid` の無いトークンを `insufficient_scope` で断る**（OIDC Core 1.0 §5.3・RFC 6750 §3.1。`RT-294.80`）
  - **#425 で、`openid` を求めないテスト用の資源 `/TestResource` を足し**（`IsDebug` で、`IsLockedDownTestEndpoints` が false のときだけ開く。照合は `/userinfo` と同じ部品。`RT-425.*`）、**この 2 プランだけ `resourceUrl` を置き換える**（`RunTestPlan.ps1` の `ResourcePath`）。**ほかの FAPI のプランは `/userinfo` のまま**（2026-11-24）
- **OP の不適合で落ちていたモジュール（直した）**
  - `fapi2-sp-plain-oauth` の `ensure-request-object-without-redirect-uri-fails`・`ensure-redirect-uri-in-authorization-request`：fapi2 の登録で、`openid` の無い PAR の要求を `redirect_uri` 無しで受けていた（FAPI 2.0 Security Profile §5.3.2.2 の 6）。
    **#422 で直し、どちらも PASSED**（2026-11-23。PAR が `400` で断るので、REVIEW も出なくなった）。後者は、直す前は Conformance Suite の自動の判定では資源の段まで進んで落ちていた（#417 で REVIEW の材料を見て、#422 に数え直した）
  - `fapi2-sp-mtls-dpop` の、資源まで進むモジュール（21 件）：`tls_client_auth` で認証したクライアントのトークンが、DPoP だけでなくクライアント証明書にも縛られ、資源の段で 401 になっていた（RFC 8705 §4・§3.4）。
    **#423 で直し、21 件とも PASSED**（2026-11-23。証明書を必須にしていない登録で DPoP の証明が在れば、DPoP の鍵だけに縛る）。縛り方の違う `fapi2-sp-mtls`・`fapi2-sp-private-key-jwt-dpop`・`fapi2-sp-private-key-jwt-mtls` も回し、前と同じ数だった
  - **WARNING だったもの**：`attempt-reuse-authorisation-code-after-one-second`（FAPI 1.0 Advanced）・`attempt-reuse-authorization-code-after-one-second`（FAPI 2.0）・`oidcc-codereuse-30seconds`（OIDC の `oidcc-basic`・`oidcc-hybrid` と、その form_post）：
    認可コードの 2 回目の引き換えは断るが、**1 回目で出したアクセス トークンが失効しなかった**（`EnsureHttpStatusCodeIs4xx`。RFC 6749 §4.1.2 の SHOULD。[`ANALYSIS-IdP.md`](../../root/programs/ANALYSIS-IdP.md) の E-13 と同じ欠け）。
    **#421 で直し、どれも PASSED**（2026-11-23。再利用されたら、そのコードから出したトークンを失効させる）。全 25 プランを回し、ほかに変わったのは、上の「サインインのボタンを押しても画面が変わらない」事象の 4 件だけだった
- **#416 で足したプランの結果**（2026-11-21。FAILED の内訳は上の仕分け）

  | `-Plan` | PASSED | FAILED | REVIEW | SKIPPED | WARNING | FAILED の内訳 |
  |---|---:|---:|---:|---:|---:|---|
  | `fapi2-sp-private-key-jwt-mtls` | 36 | 2 | 3 | 2 | 0 | 自動では回せない 2 |
  | `fapi2-sp-mtls-dpop` | 40 | 2 | 3 | 1 | 0 | 自動では回せない 2（#423 を直した後。2026-11-23。直す前は PASSED 20・FAILED 23・REVIEW 2・WARNING 0 で、#423 で 21） |
  | `fapi2-sp-plain-oauth` | 40 | 2 | 3 | 1 | 0 | 自動では回せない 2（#425 で資源を足した後。2026-11-24。足す前は PASSED 25・FAILED 18・REVIEW 2 で、資源の段で 16。#422 を直す前は PASSED 23・FAILED 20 で、#422 で 2）。**REVIEW の判定は基準と同じ**（7 件） |
  | `fapi2-sp-client-credentials` | 14 | 0 | 0 | 1 | 0 | 無し（#425 で資源を足した後。2026-11-24。足す前は PASSED 8・FAILED 6 で、資源の段で 6） |
  | `fapi2-ms-mtls` | 44 | 2 | 3 | 2 | 0 | 自動では回せない 2 |
  | `fapi2-ms-signed-plain-response` | 58 | 2 | 3 | 3 | 0 | 自動では回せない 2 |
  | `fapi2-ms-unsigned-jarm` | 45 | 2 | 3 | 2 | 0 | 自動では回せない 2 |
  | `fapi1-adv-mtls-par` | 43 | 2 | 3 | 1 | 0 | 自動では回せない 2 |
  | `fapi-ciba-mtls-poll` | 29 | 1 | 0 | 2 | 0 | 自動では回せない 1（`user-rejects-authentication`） |

  - **WARNING は、#421 を直した後の数**（2026-11-23。直す前は、`fapi2-sp-plain-oauth`・`fapi2-sp-client-credentials`・`fapi-ciba-mtls-poll` を除いて WARNING 1 で、PASSED が 1 少なかった。どれも #421。上の「OP の不適合で落ちていたモジュール（直した）」）。
    **#421 の全プランの実行では、`fapi2-ms-mtls`・`fapi2-sp-plain-oauth` で、上の「サインインのボタンを押しても画面が変わらない」事象が 1 件ずつ出た**（表の数は、それを除いた数。`fapi2-sp-plain-oauth` は `ensure-pkce-code-verifier-required`、`fapi2-ms-mtls` は `ensure-request-object-with-nbf-8-seconds-in-the-future-is-accepted`。どれもサインインの画面で止まり、認可コードを出す前）
  - **#429 で、fapi2 の登録は送信者の拘束（DPoP か MTLS）を、登録の項目によらず必須にした**（FAPI 2.0 Security Profile §5.3.2.1 の 4）。**FAPI 2.0 の 10 プラン（SP 6・MS 4）を回し、#421 の全プランの実行から落ちたモジュールは無かった**（2026-11-24。Conformance Suite のクライアントは、どのプランでも DPoP か MTLS で縛るため）。違ったのは、サインインのボタンの事象だけ（#421 で事象に当たった 2 件は今回は通り、別の 1 件が当たった。`fapi2-ms-unsigned-jarm` の `ensure-dpopproof-with-iat-10seconds-after-succeeds` で、PAR は通り、サインインの画面で止まった）
  - **FAPI 1.0 Advanced の MTLS は、#398 で止まらない**（`client_assertion` を使わない）。`private_key_jwt` のプランで #398 の先にある判定を、版を緩めずに確かめられる
  - `fapi2-ms-signed-plain-response` は、#416 のときは FAILED 3 で、その 1 つは上の「サインインのボタンを押しても画面が変わらない」事象だった（1 回目は `par-without-duplicate-parameters`、回し直すとそれは通り、`ensure-authorization-request-without-nonce-success` が同じ形で落ちた。**同じモジュールが続けて落ちてはいない**）
  - `fapi-ciba-mtls-poll` には、ほかに TIMEOUT が 1 つある（`ensure-authorization-request-with-potentially-bad-binding-message`。`fapi-ciba-private-key-jwt-poll` と同じ）
  - **2026-11-22 に、全 25 プランを Windows PowerShell 5.1 で通した**（それまでは PowerShell 7）。**どのプランも、上の表とこれまでの基準と同じ数**で、`fapi2-ms-signed-plain-response` も FAILED 2（自動では回せない 2）だった。
    サインインのボタンの事象は出なかった。所要は 2 時間 10 分（OIDC の 11 プランで 23 分。機械のメモリ不足で 19 番目のプランの途中で止まり、そのプランから回し直したので、2 回の分を足した）
- **#426 で足したプランの結果**（2026-11-25〜26。直した版で回した OIDC の 42 の組から。サインインのボタンの事象は除いた数で、事象に当たったモジュールは、次の実行か回し直しで通った）

  | `-Plan`（`-ResponseType`） | PASSED | FAILED | REVIEW | SKIPPED | WARNING | FAILED・TIMEOUT の内訳 |
  |---|---:|---:|---:|---:|---:|---|
  | `oidcc-basic-dynamic`・`oidcc-formpost-basic-dynamic` | 24 | 0 | 3 | 4 | 7 | 無し（静的な版より PASSED が 1・SKIPPED が 2 多いのは、動的登録の版だけのモジュール） |
  | `oidcc-implicit-dynamic`・`oidcc-formpost-implicit-dynamic` | 33 | 0 | 6 | 6 | 13 | 無し |
  | `oidcc-hybrid-dynamic`・`oidcc-formpost-hybrid-dynamic` | 63 | 0 | 9 | 9 | 21 | 無し |
  | `oidcc-rp-initiated-logout-dynamic`（6 つの `response_type`） | 3 | 0 | 8 | 0 | 0 | 無し（静的な版と同じ） |
  | `oidcc-frontchannel-rp-initiated-logout-dynamic`・`oidcc-backchannel-rp-initiated-logout-dynamic`（6 つずつ） | 2 | 0 | 0 | 0 | 0 | 無し（静的な版と同じ） |
  | `oidcc-mtls`・`oidcc-mtls-formpost` | 22 | 0 | 4 | 2 | 7 | TIMEOUT 1（`oidcc-server-rotate-keys`。自動では回せない） |
  | `oidcc-dynamic`（`code`・`code id_token`・`code token`・`code id_token token`） | 4 | 8 | 6 | 2〜3 | 1 | #398 で止まる 7 と `oidcc-userinfo-rs256`（見送った機能）。TIMEOUT 1（`oidcc-server-rotate-keys`）。SKIPPED は `code`・`code token` が 3（`oidcc-idtoken-unsigned`） |
  | `oidcc-dynamic`（`id_token token`） | 8 | 1 | 6 | 2 | 1 | `oidcc-userinfo-rs256`。TIMEOUT 1 |
  | `oidcc-dynamic`（`id_token`） | 8 | 0 | 6 | 2 | 1 | TIMEOUT 1 |

  - **REVIEW の判定は、どれも静的な版・`code` の組と同じ材料の形で、同じ合否**（下の「REVIEW の見方」）
  - 所要は、全 56 の組で 3 時間（OIDC の 42 の組で 75 分、うち #426 で足した 31 の組で 52 分。FAPI の 14 プランで 105 分）
  - **直す前の版（fixing 4 の時点）でも全 56 の組を回し、FAPI の 14 プランはこれまでの基準と同じ数**だった（違いはサインインのボタンの事象だけ）。**FAPI は、#426 の最後の段で変えたところ（動的登録の確かめ・Front-Channel Logout の画面）を通らない**ので、直した版では回し直していない
  - 直した版の回し直しは、機械のメモリ不足で 2 回止まり、止まったところから回し直した（止まる前に済んだ組の結果を使った）
- **対応を見送った機能のモジュール**
  - `oidcc-userinfo-rs256`（`oidcc-dynamic`）：**署名した UserInfo の応答**（OIDC Core 1.0 §5.3.2）を求める。**MPAS は対応を見送った**（任意の機能で、FAPI は求めない。[`ANALYSIS-IdP.md`](../../root/programs/ANALYSIS-IdP.md) の D-17。#414）ので、
    Discovery に `userinfo_signing_alg_values_supported` が無く、`CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256` で FAILED になる。
    **`oidcc-dynamic` の FAILED は、これと、上の #398 で止まる 7 つで全部**（2026-11-20）。
    **`code` 以外の `response_type`**（#426。2026-11-25）：`code id_token`・`code token`・`code id_token token` は `code` と同じ 8 つ（#398 の 7 つは、どれも `client_assertion` の `aud` がトークン エンドポイントの URL で `invalid_client`）。
    **`id_token`・`id_token token` はトークン エンドポイントへ進まないので、#398 で止まらない**（`oidcc-server`・`oidcc-idtoken-rs256`・`oidcc-redirect-uri-query-OK`・`oidcc-request-uri-signed-rs256` が PASSED。`oidcc-refresh-token`・`-rp-key-rotation`・`oidcc-registration-jwks-uri` はプランに出ない）。
    FAILED は、`id_token token` の `oidcc-userinfo-rs256` だけ（`id_token` はアクセス トークンが出ないので、プランに出ない）
- **飛ばされるのが正しいモジュール**（SKIPPED。`oidcc-dynamic`）
  - `oidcc-idtoken-unsigned`（`code`・`code token`。id_token を認可エンドポイントから受けない `response_type` だけに出る）：Discovery の `id_token_signing_alg_values_supported` に `none` が無い（署名の無い id_token は出さない。Conformance Suite も、認定では `none` を求めないと書く）
  - `oidcc-request-uri-unsigned`・`oidcc-ensure-request-object-with-redirect-uri`：Discovery の `request_object_signing_alg_values_supported` に `none` が無い（署名の無い Request Object は受けない）

**Discovery の検査の WARNING を、1 つだけ許す**（#385。`fapi2.json`・`fapi-ciba.json`・`oidcc-config.json` の `server.allow_unexpected_metadata_fields`）。
`CheckForUnexpectedParametersInServerMetadata`（RFC 8414 §2）は、Conformance Suite の知らないメタデータを警告にする。
**MPAS 独自の `request_object_endpoint`（`/ros` の広告）だけが当たる**ので、それを許す。**MPAS の広告は変えない**（`/ros` を Discovery で引いている RP を壊さない。#379 で決めた）

### `RunTestPlan.ps1`

**原本の `scripts\run-test-plan.py` と同じ REST の API を、PowerShell で呼ぶ**（Python と追加のパッケージを要らなくした）。
Conformance Suite は dev の構成なので、**API は認証なしで呼べる**。

| 段 | API |
|---|---|
| プランを作る | `POST api/plan?planName=…&variant=…`（本文は設定の JSON） |
| モジュールを起動する | `POST api/runner?test=…&plan=…`（**本文が無くても `Content-Type: application/json` が要る**。無いと 415） |
| 待つ・結果を読む | `GET api/info/{id}`（`status` が `FINISHED`・`INTERRUPTED` になるまで。**上限は `-ModuleTimeoutSec`**。ブラウザの自動操作が合わないと `WAITING` のまま止まる） |
| 報告書 | `GET api/plan/exporthtml/{id}`（zip。**`api/plan/{id}/exporthtml` は 404**。release-v5.3.4 で確かめた） |

- 終了コード：0（FAILED・INTERRUPTED・時間切れが無い）／1（どれかがある）／2（前提の誤り）
- **WARNING・REVIEW は失敗に数えない**（Conformance Suite の判定のまま、結果に出す）
- PowerShell 5.1・7 の両方で動く（自己署名の証明書の扱いを分けている。`root\11_CODING.md` 5 節）

### REVIEW の見方（`ExtractReview.ps1`。#417）

**REVIEW は、Conformance Suite が「画面の写しを上げて、人が合否を付ける」とする判定である。** 自動の実行では写しを上げないので、
**報告書のログに残った、自動操作のブラウザが受けた OP の応答**（WebRunner の `Scripted browser HTTP response`）と、**クライアント（Conformance Suite）へ返った応答**から合否を付ける。
`ExtractReview.ps1` は、`out\<プラン>-report.zip` を読んで、REVIEW の判定ごとに次を取り出す（Conformance Suite のコンテナは要らない）。

| 取り出すもの | 中身 |
|---|---|
| 判定 | 名前（`src`。`ExpectSecondLoginPage` など）・求められていること（`msg`）・原典（`requirements`） |
| OP の画面 | ブラウザが受けた応答の URL（ホストとパス）・状態コード・タイトル・本文の文字・リンクと画像 |
| 操作した画面 | 雛形の自動操作（`Login`・`Expect … error page` など）と、その画面のパス |
| クライアントへの応答 | `error`・`error_description`。無ければパラメタの名前だけ（`code` などの値は出さない）。**JARM は、署名だけの JWT の中身を読む** |
| モジュールの結果 | `testmodule_result` と、SUCCESS・INFO 以外の判定 |

- **区間**：ブラウザを OP へ送るたび（`Redirecting to …`）に区切り、REVIEW はその判定のある区間の材料で見る（**ログアウトの口では、REVIEW が送る直前に書かれる**ので、次の区間に入れる。**Conformance Suite 自身の画面（`/test/` の下の callback）でのブラウザの処理の終わりが REVIEW より後に書かれることがある**ので、それは区間の最後のブラウザの項目に数えない。#426 の `oidcc-rp-initiated-logout-only-state` で、REVIEW がサインインの区間に入った）
- **材料の形**（`Evidence`）：操作した画面・最後の OP の画面（状態コード・パス・タイトル）・クライアントへの応答を 1 行にしたもの。
  **エラー画面とサインアウトの確認の画面は、本文の文言**（`invalid_request Invalid redirect_uri.` などのエラーの種類と説明、確認の画面の理由）**も入れる**（タイトルだけでは、文言が変わっても「同じ」になる）。
  **実行ごとに変わる値**（クエリ・コード・`state`）と、配備ごとに変わる文字（画面の上の利用者名）は入れない。**サインインの画面などは、タイトルまで**（本文の変化は拾わない）
- 出力：`out\review\<プラン>.json` に詳細（**Git の管理外。Issue やコメントに貼らない**。合否と理由、要る文言だけを書く）。
  画面には、プランごとの数の表（基準と比べたなら `Same`・`Changed`・`New`・`Gone` の数）と、1 件ずつの中身（モジュール・バリアント・判定の名前・基準の判定と、材料の形を 1 行に 1 つ）を縦に並べて出す。
  **基準と比べたなら、違うものだけを出す**（すべて出すなら `-All`。バリアントと材料の形が長く、1 行の表にすると折り返して読めなかった。#417）
- **秘密を読まない**：ログの WebRunner の `commands`（テスト利用者のパスワード）と `config`（クライアントの秘密鍵）は、読む前に落とす
- `-Plan` で読むプランを絞れる（省くと、`out\` の `oidcc-*`・`fapi*` の報告書をすべて読む）。PowerShell 5.1・7 の両方で動く

**合否は、エージェントが材料を原典の節に照らして付け、人がその表を承認する**（[`QUALITY.md`](../../QUALITY.md) 2 節。#417）。付け方は次の 5 つ。

| 判定 | 意味 |
|---|---|
| 合（エラーを返した） | クライアントへ仕様どおりのエラーを返しており、エラー画面は要らない |
| 合（画面で確かめた） | OP の画面（本文の文字・操作した画面）が、求められていることを満たす |
| 合（受け付けた） | REVIEW が「断るなら、エラー画面を出す」と求めるもので、OP は受け付けた（受け付けたときの振る舞いは、自動の判定で見る） |
| 否 | 満たしていない → 原因ごとに起票する |
| 判断できない | ログに材料が無い（認証デバイスの画面など）→ 理由を書き、人に上げる |

**全プランの実行のたびに回し、基準 [`ReviewBaseline.csv`](ReviewBaseline.csv) と比べる**（#417 で決めた）。
基準は、プラン・モジュール・バリアント・判定の名前ごとに、材料の形（`Evidence`）・判定（`Verdict`）・理由・照らした節を持つ。
**材料の形が同じなら、合否を引き継ぐ。** 形が変わった・基準に無いもの・読んだプランで基準だけに在るもの（REVIEW が出なくなった）だけ、`out\review\<プラン>.json` を読んで合否を付け直し、基準を直す（終了コード 1）。

**今の基準**（2026-11-25 の全 56 の組の実行。REVIEW の判定は延べ 300・モジュールの名前 38・判定の種類 20。
それまでは 2026-11-22 の全 25 プランの実行で延べ 164（**#422 を直した後は 162**）。**#426 で足した 31 の組の 138 件は、どれも静的な版・`code` の組の同じ判定と材料の形が同じ**で、その合否を引き継いだ（`oidcc-mtls`・`-formpost` の `oidcc-redirect-uri-query-added` は、静的な `oidcc-basic` に無いので、`oidcc-dynamic` の同じ判定から））

| 判定 | 延べ | 中身 |
|---|---:|---|
| 合（画面で確かめた） | 204 | 2 回目のサインインの画面（`oidcc-max-age-1`・`oidcc-prompt-login`）、**登録した `logo_uri`・`policy_uri`・`tos_uri` を出したサインインの画面**（`oidcc-registration-logo-uri`・`-policy-uri`・`-tos-uri`。#427 で直した。2026-11-24）、`redirect_uri` の誤り・欠落のエラー画面、`request_uri` の使用済み・期限切れ・別のクライアントのエラー画面、ログアウトの誤りの理由を出した確認の画面と、サインアウトした後の画面 |
| 合（エラーを返した） | 41 | `response_type`・`nonce`（Implicit・Hybrid）の欠落、PAR を使わない要求・Request Object の無い要求に `invalid_request` |
| 合（受け付けた） | 53 | 長い `nonce`・`state`、Request Object の内と外の `nonce`・`state` の違い、外だけの `state` を、Request Object の値で受け付けた |
| 否 | 0 | **#427 を直す前は 3**：`oidcc-registration-logo-uri`・`-policy-uri`・`-tos-uri`（登録した値をサインインの画面に出していなかった。**OIDC Registration 1.0 §2 は SHOULD**）。**#427 で、認可の要求から来たサインインの画面と同意の画面に出すようにし、合にした**（2026-11-24）。**`fapi2-sp-plain-oauth` の 2 件（#422）は、直して REVIEW が出なくなったので、基準から消した**（2026-11-23。延べ 164 → 162） |
| 判断できない | 2 | FAPI-CIBA の `ensure-authorization-request-with-potentially-bad-binding-message`（認証デバイスの画面がログに無い。OP は `binding_message` を受け付けて端末へ送り、端末のアプリが出す。実物の端末で見るのは #417 の範囲の外） |

- **ログアウトの誤り**（`id_token_hint` の誤り・欠落、登録の無い `post_logout_redirect_uri`）は、Conformance Suite は「エラー画面」を求めるが、MPAS は**理由を出した確認の画面**を出し、RP へ戻さない。
  RP-Initiated Logout 1.0 §4 は、戻さないことを MUST とし、エラーの表示は MAY とする（§2 は、`id_token_hint` が無い・合わないとき、利用者に問うことを MUST とする）ので、合とした
- **`par-attempt-to-use-request_uri-for-different-client`** のエラー画面の文言は「`The client_id does not match the request object.`」で、`request_uri` の誤りとは書かないが、別のクライアントが預けた `request_uri` を断っている（RFC 9126 §2.2）ので、合とした
- 基準を直したら（不適合を直した・画面を変えた）、そのコミットで `ReviewBaseline.csv` も直す

## 生成物（Git の管理外）

| フォルダ | 中身 |
|---|---|
| `mongo\` | Conformance Suite の結果（MongoDB のデータ）。**消すと、画面の一覧も消える** |
| `keys\`・`logs\` | OP の DataProtection の鍵とログ |
| `out\` | 実行用の設定（**テスト利用者のパスワード・initial access token・FAPI のクライアントの秘密鍵を埋めたもの**）と、結果の JSON・報告書の zip |
| `certs\` | nginx の証明書と秘密鍵（`Prepare.ps1`。適合性テストの環境だけで使う自己署名） |
| `.env.cts` | compose に渡す値（`Prepare.ps1`。DCR の管理クライアントの所有者の利用者名、FAPI のクライアントの公開鍵） |
| `certs\fapi-client*.jwk.json`・`certs\mtls-client*` | FAPI のクライアントの秘密鍵とクライアント証明書（`Prepare.ps1`。**秘密鍵を含む**） |
| `hooks\`・`hooks-build\` | MTLS のテスト専用のフックと、その作業場所（`Prepare.ps1`） |
| `fcm\` | OP のプッシュ通知の送信箱（CIBA の承認の自動化。**`device_token` を含む**） |
