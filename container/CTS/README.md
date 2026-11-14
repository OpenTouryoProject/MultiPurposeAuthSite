# 適合性テスト（Conformance Suite）— `container\CTS\`（#350）

**OpenID Foundation の Conformance Suite（適合性テスト）を手元で起動し、MPAS（net10.0 版）を相手に回す**（`ANALYSIS-IdP.md` の **D-14**）。
**外部の基準を、最終的な正とする**（`QUALITY.md` 2 節）。E2E は、このリポジトリが書いたテストなので、書いた側と同じ読み違いを共有しうる。

- 原本：https://gitlab.com/openid/conformance-suite（ビルド済みのイメージ。`docker-compose-prebuilt.yml` を元にした）
- **版は固定する**（`release-v5.3.4`）。上げるときは、`docker-compose.yml` の server と nginx のタグを、同じ版に手で上げる
- **認定（certification）を取るためのものではない。** 手元で回して、不適合を見つけて直すためのもの
- **いつ回すか・結果の仕分け**は `QUALITY.md` 2 節と `root/TESTING.md` 5 節「適合性テスト」（リリースの前に全プラン、適合性テストで見つかった不適合を直すときにそのプラン）

## 手順

```powershell
cd container\E2E
.\1_PublishIdP.ps1          # OP の発行物と証明書（E2E と共用。MPAS を直したら、先にこれ）

cd ..\CTS
.\2_DockerComposeUp.bat     # Conformance Suite と OP を起動する（Conformance Suite の起動には 1〜2 分かかる。先に Prepare.ps1 を呼ぶ）
.\RunTestPlan.ps1 -Plan oidcc-basic    # プランを回す（下の表）
.\3_DockerComposeDown.bat   # 止める
```

| `-Plan` | Conformance Suite のプラン | 設定の雛形 |
|---|---|---|
| `oidcc-basic`・`oidcc-config` | `oidcc-basic-certification-test-plan`・`oidcc-config-certification-test-plan` | `oidcc-basic.json`・`oidcc-config.json` |
| `oidcc-implicit`・`oidcc-hybrid` | `oidcc-implicit-…`・`oidcc-hybrid-…`（**response_type ごとにモジュールが並ぶ**） | `oidcc-basic.json` |
| `oidcc-formpost-basic`・`-implicit`・`-hybrid` | `oidcc-formpost-*-certification-test-plan`（`response_mode=form_post`） | `oidcc-basic.json` |
| `oidcc-rp-initiated-logout`・`oidcc-frontchannel-rp-initiated-logout`・`oidcc-backchannel-rp-initiated-logout` | 同じ名前の `…-certification-test-plan`（`response_type=code`） | `oidcc-logout.json`（**クライアントはプランごとに別**） |
| `oidcc-dynamic` | `oidcc-dynamic-certification-test-plan`（`response_type=code`） | `oidcc-dynamic.json` |
| `fapi2-sp-private-key-jwt-dpop`・`fapi2-sp-mtls` | `fapi2-security-profile-final-test-plan`（`plain_fapi`・`openid_connect`・`simple`・`grant_management=disabled`。前者は `private_key_jwt`＋DPoP、後者は MTLS＋MTLS） | `fapi2.json`（**クライアントは 2 つずつ**。鍵とクライアント証明書を埋める） |
| `fapi2-ms-private-key-jwt-dpop` | `fapi2-message-signing-final-test-plan`（上の `private_key_jwt`＋DPoP に、署名した Request Object・JARM） | `fapi2.json`（クライアントは SP と同じ） |
| `fapi1-adv-private-key-jwt-par` | `fapi1-advanced-final-test-plan`（`plain_fapi`・`private_key_jwt`・`pushed`・`jarm`。**`plain_response`（Hybrid）ではない**：MPAS は fapi1 の登録に Hybrid を許さない（FA-1.4）。#370） | `fapi2.json`（クライアントは `client_mode=fapi1`） |
| `fapi-ciba-private-key-jwt-poll` | `fapi-ciba-id1-test-plan`（`plain_fapi`・poll・`private_key_jwt`・静的な登録） | `fapi-ciba.json`（**利用者の承認は、`RunTestPlan.ps1` が認証デバイスの代わりに送る**。下の「CIBA の承認」） |

- **FAPI のバリアントは、代表の組み合わせだけ**にしてある（軸を全部掛け合わせると数十通り。#350 の段階 4 で決めた）

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
- 配備で絞る方法（Linux・Windows・リバース プロキシ）は [`CONFIGURATION.md`](../../root/CONFIGURATION.md)「TLS の暗号スイートを絞る」

### FAPI の鍵・クライアント証明書と、MTLS（`Prepare.ps1`）

| 作る物 | 置き場所 | 使い道 |
|---|---|---|
| **EC P-256 の鍵**（2 つ。`client`・`client2`） | `certs\fapi-client{1,2}.jwk.json`（秘密鍵の JWK） | `private_key_jwt`・DPoP の署名。**秘密鍵は `RunTestPlan.ps1` が設定の `client.jwks` に埋め、公開鍵は `.env.cts` 経由で OP の登録（`jwk_ecdsa_publickey`）に渡す** |
| **クライアント証明書**（2 つ。自己署名の RSA） | `certs\mtls-client{1,2}.crt`・`.key` | `tls_client_auth` と、証明書に縛ったトークン。**Subject（`CN=CTS FAPI Client 1`・`2`）を OP の登録（`tls_client_auth_subject_dn`）に書く** |
| **MTLS のテスト専用のフック** | `hooks\MtlsTestHook.dll` | **OP の Kestrel に、クライアント証明書を求めさせる**（E2E・スタブと同じ。`DOTNET_STARTUP_HOOKS`。**要求するだけで必須にはしない**ので、ほかのプランは変わらない。**発行元を問わずに受け付ける**ので、テスト専用） |

- **鍵は ES256 にしてある。** OP の Discovery の `token_endpoint_auth_signing_alg_values_supported` は RS256・ES256 で、FAPI 2.0 は RS256 を認めない
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
| initial access token | **MPAS は、それの無い登録を受けない。** `RunTestPlan.ps1 -Plan oidcc-dynamic` が、回す直前に管理クライアントで `client_credentials` のトークンを取り、雛形の `@INITIAL_ACCESS_TOKEN@`（設定の `client.initial_access_token`）を埋める。期限はプラン 1 つ分より長くしてある（`DcrAccessTokenExpireTimeSpanFromSeconds=3600`。既定は 300 秒） |
| FAPI 2.0 のクライアント（8〜11 つ目。`client_mode=fapi2`） | 同上。8・9 は `private_key_jwt`（＋ DPoP）、10・11 は `tls_client_auth`（＋ 証明書に縛ったトークン）。**次を登録する**：`id_token_signed_response_alg=ES256`（**登録が無いと RS256 になり、FAPI 2.0 の検査で全部止まる**。#355）、**FAPI の要件の強制**（`require_pushed_authorization_requests`・`require_pkce`・`dpop_bound_access_tokens` か `tls_client_certificate_bound_access_tokens`。#346。**どれも既定は false で、立てないと PAR・PKCE の無い要求が通る**） |
| FAPI 1.0 Advanced のクライアント（12・13 番目。`client_mode=fapi1`） | 同上。`private_key_jwt`・`id_token_signed_response_alg=ES256`。鍵は FAPI 2.0 と同じ |
| CIBA のクライアント（15・16 番目。`client_mode=fapi_ciba`）と端末役（14 番目） | 同上。CIBA の認証要求の署名は ES256 固定なので、公開鍵は `jwk_ecdsa_publickey`。端末役は秘密だけを持ち、`AuthenticationDeviceClientIds` に挙げる |
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
- **まれに、サインインのボタンを押しても画面が変わらず、そのモジュールが FAILED になる**（`Unexpected URL for non-optional task`。段階 3 の通しで 3 回）。**どれも、サインインの要求（`POST /Account/Login`）が OP に届いていない**（OP の ACCESS ログで確かめた。Conformance Suite のブラウザ（HtmlUnit）の側で、ボタンのスクリプトが動かなかった）。回し直すと通るので、**同じモジュールだけで続けて落ちるかを見てから**、不適合として扱う

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
| FAPI 2.0 の `par-attempt-to-use-request_uri-for-different-client` | エラー画面（`The client_id does not match the request object`） |
| FAPI 2.0 の `par-attempt-reuse-request_uri`・`par-attempt-to-use-expired-request_uri` | 使用済み・期限切れの `request_uri` のエラー画面（`The request_uri is unknown, expired, or already used.`。#368）。**reuse は 1 回目を通常どおり進め、2 回目でこの画面を待つ**（callback を待つ手順の `match` は、Conformance Suite のホストから書く。認可の URL が `redirect_uri` に callback の URL を載せるため） |

- **REVIEW は、写しを人が見て合否を付ける項目である。** 自動では、待った画面が出たことまでしか確かめていない
- **ログアウトの確認の画面**：MPAS は、`id_token_hint` が無い・一致しない・要求に誤りがあるとき、確認の画面を出す（RP-Initiated Logout 1.0 §2 の MUST）。雛形では「Yes」を任意の手順で押す
- **自動では回せないモジュール**（FAPI 2.0。FAILED になるが、OP の不適合ではない）
  - `…-user-rejects-authentication`：利用者が同意を断る操作が要る。**MPAS は同意を記録した後は同意の画面を出さず、サインインの画面には取り消しのボタンが無い**
  - `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`：**1 回目のサインインの画面では何もせず、2 回目で入る**操作が要る。自動操作は、同じ画面への訪問を区別できない

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
- PowerShell 5.1・7 の両方で動く（自己署名の証明書の扱いを分けている。`root\CODING.md` 5 節）

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
