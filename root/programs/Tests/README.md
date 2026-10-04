# Tests

MultiPurposeAuthSite の**ビルド確認**と **E2E テスト**。

このリポジトリには CI が無く、動作確認は手作業だった。
そのため「コードを読んだ結論」と「実際の動作」がずれても気づけない。
ここは、**仕様への適合を実測で確かめる**ための場所。

| | |
|---|---|
| `TESTCASES.md` | **テストケースの原本。** 何を・何を根拠に確かめるのか（生成物） |
| `test.ps1` | サイトを起動して E2E テストを実行する |
| `E2ETests/` | xUnit のテスト プロジェクト（net10.0） |

**通しで回すときは `root` のスクリプトを使う。**
OpenTouryo が `root/programs/*.ps1` から `CS/*.bat` を呼ぶのと同じ構造で、
`root/*.ps1` が `programs/` のビルド bat と、この `test.ps1` を呼ぶ。

| | |
|---|---|
| `..\..\..\0_RunAll.ps1` | ビルド → テストの通し |
| `..\..\..\1_BuildAll.ps1` | ビルド bat を呼び、エラー・警告を集約する |
| `..\..\..\2_RunAllTests.ps1` | この `test.ps1` を呼び、TRX を読んで集約する |

## 方針

### ブラックボックスで測る

テストは、アプリを **HTTP で外から叩く**。
`CmnEndpoints` や `Helper` といった実装側のクラスは参照しない。

JWT のデコードも Request Object の署名も、テスト側で独立に実装している
（`Infrastructure/Jwt.cs` / `Infrastructure/RequestObject.cs`）。
**同じコードで作って同じコードで読むと、型や値の誤りを検出できない**ため。

### net10.0 版と net48 版に、同じテストを流す

このリポジトリはクロスコンパイルで下位互換版を維持している。
**「片方だけ直っている」状態を検出できること**を最優先にしているので、
テストは `[SkippableTheory]` ＋ `AllTargets` で両方に流す。

起動していない対象は **Skip** する（失敗にしない）。
net48 版は IIS Express での手動起動が前提で、常に動いているとは限らないため。

### 秘密情報をリポジトリに置かない

`TestUserPWD` / `client_secret` / pfx のパスワードは、
テスト実行時に**アプリ自身の構成ファイルから読み出す**
（`appsettings.json` / `app.config` は `.gitignore` 済み）。

`client_id` も直書きしない。環境ごとに違う（`CreateClientsIdentity.exe` で生成する）ので、
`client_name`（`TestClient` / `MVC_Sample` など）から引く。

**雛形にクライアントを足したときは、実設定にも足す。** 実設定は各自のものなので、
雛形（`_appsettings.json` / `_app.config`）を当て直すまでは登録されていない。
その間、そのクライアントを使うテストは **Skip** する（`Flows.SkipIfClientNotRegistered`）。

| client_name | 何のために登録してあるか |
|---|---|
| `TestClient5` | 登録の `scope` で、要求してよいスコープを制限（#198） |
| `TestClient6` | **クライアント単位で PKCE を必須**（`require_pkce`。#221） |

**構成ファイルに無いクライアントもある**（#224 / #264）。
雛形にも実設定にも足さずに済むので、**特定の組み合わせを試すためだけのクライアント**に使う。

**種データが、テスト利用者の登録（`saml2OAuth2Data`）として作る**（#264）。
表は **`CommonLibrary/Extensions/Sts/TestClients.cs`** にあり、
**`IsDebug` ＋ `TestUserPWD` のときだけ**作られる。

| client_name | 何か | 引き方 |
|---|---|---|
| `TestClient4_2` | `TestClient4`（fapi_ciba）の写しで、**登録種別だけ normal**。公開鍵ごと写すので、CIBA の要求の署名検証を通る | `Flows.InjectedRegistration` |
| `TestClient4_3` | 同じく写しで、**登録種別を既知でない値（`fapi_1`）**にしたもの。不正な登録値の扱いを測る | 同上 |
| `TestClient2_2` | `TestClient2`（fapi2）の写しで、**`tls_client_auth_subject_dn` をテスト専用の値**（`KnownClients.MtlsSubjectDn`）にしたもの。mTLS を測る（#226） | 同上 |
| `TestClient2_3` | `TestClient2_2` と同じ Subject で、**登録種別を既知でない値（`fapi_1`）**にしたもの | 同上 |
| `TestClient_2` | `TestClient`（normal）の写しで、**`client_secret` を記号を含む値**（`KnownClients.SymbolSecret`）にしたもの。Basic の符号化を測る（#237） | 同上 |
| `TestClient_3` | 同じく写しで、**`client_secret` に `:` を含む**（`KnownClients.ColonSecret`）。符号化しないと資格情報として読めない値（#237） | 同上 |
| `TestClient_4` | 同じく写しで、**`post_logout_redirect_uri` を登録**（`test_self_logout`）。ログアウト後に RP へ戻せるかを測る（#232） | 同上 |
| `TestClient_5` | 同じく写しで、**`subject_types = pairwise`**（#140 の段階 2） | 同上 |
| `TestClient_6` / `_7` | **写しただけ**（`subject_types` を書かない）。**既定が public になった**ことを 2 つの client_id で測る（#151 の段階 4） | 同上 |
| `TestClient_8`〜`_13` | 同じく写しで、**`id_token_signed_response_alg`** を `RS512` / `ES384` / `ES512` / `PS256` / `PS384` / `PS512` に（#129 の段階 2〜4）。`_8` は **`token_endpoint_auth_signing_alg = RS256`** も登録（#262） | 同上 |
| `TestClient_15` | 同じく写しで、**`redirect_uri_code` を `test_self_code_manage`** に（C-10）。**管理画面の自己テストの折り返し先が、登録値として通る**ことを測る | 同上 |
| `TestClient_16` | 同じく写しで、**`client_secret` を空（public）**にし、**`web_origins`** と**別オリジンの `redirect_uri_code`** を登録（#266）。**`web_origins` が勝つ**ことを測る | 同上 |

- **`client_name` は利用者名そのもの**である（`GetClientIdByName` が `CmnUserStore.FindByName` を引く）。
  **したがって 1 利用者 ＝ 1 クライアント登録**で、**この表のぶんだけテスト利用者が居る**
- **`client_id` は固定値。** E2E は構成ファイルを読む作りなので user store は読めない。
  **`Flows.KnownClients.SeededClientIds` と `Sts.TestClients.Entries` を同じ値にしておくこと**
- **`client_secret` を差し替えたものは、写す元の秘密では認証できない。**
  **`KnownClients.SymbolSecret` / `ColonSecret` も、表と同じ値にしておくこと**
- **`-Launch` は要らない。** **手で起動したサイトに対しても測れる**（種データはサイト側が作る）
- **サイトは `GET /Account/Login` でしか種データを作らない**（`CreateData`。#210 で踏んだ）。
  **`TargetTestBase.Client` が 1 度だけ呼んで揃えている**（`TargetInfo.EnsureSeedData`）。
  **これが無いと、サインインしないテストが 401 になる**（`RT-237.*` で踏んだ。
  **先に走る他のクラスがサインインしているかどうかに依存して、間欠で落ちる**）
- **`isResourceOwner` はどこでも分岐に使われていない**ので、**構成ファイルの登録と同じに振る舞う**

> **以前は `test.ps1 -Launch` が環境変数で差し込んでいた**（#224）。
> **net48 版だけ `OAuth2ClientsInformation` を一覧ごと差し替える**ため、
> **件数に上限があった**（#262 で踏んだ。`TESTING.md` 1 節）。**#264 で寄せた。**


**クレームの対応付け（`UserClaimsMapping`）も、同じやり方で差し込む**（#230）。

この実装は氏名・住所の項目を持たず、入れ物（`UnstructuredData`）の中身は導入する側が決めるので、
**「どのキーをどのクレームとして返すか」だけが設定**になっている。
テストは、画面（`/Manage/AddUnstructuredData`）から入れられる `usd1` / `usd2` を値の在り処にする。

| クレーム | 値の在り処 |
|---|---|
| `name` | `usd1` |
| `address.locality` | `usd2`（`address` オブジェクトの副フィールドとして組み立てられる） |
| `preferred_username` | `user:UserName`（`ApplicationUser` の項目。白名簿） |

差し込みが無いときは `RT-230` が Skip する（`claims_supported` を見て判定）。
値を入れたテストは、**最後に空へ戻す**（既定の利用者に入るので、他のテストへ持ち越さない）。

**テストの出力にトークンや秘密情報を書かないこと。**
`JsonResponse.ToString()` はキー名とエラーだけを出す。

## 実行

### いちばん簡単な方法

```powershell
cd root\programs\Tests
.\test.ps1 -Launch
```

**net10.0 版と net48 版の両方**を起動し、テストを流して、停止する。

| 対象 | 待ち受け | 立て方 |
|---|---|---|
| net10.0 | `https://localhost:44300` | Kestrel（`-Url` で変えられる） |
| net48 | `https://localhost:44302` | IIS Express（`-NetFxUrl` で変えられる） |

net48 版を測らないときは `-NoNetFx`。その分は Skip される。

### すでにサイトが動いている場合

```powershell
.\test.ps1
```

叩き先は、既定では**構成ファイルの `OAuth2AuthorizationServerEndpointsRootURI`**。
つまり、Visual Studio（IIS Express）で起動していれば、そのまま繋がる。

### 通しで回す

```powershell
cd root
.\0_RunAll.ps1           # ビルド → テスト
.\1_BuildAll.ps1         # ビルドだけ
.\1_BuildAll.ps1 -List   # ビルドの対象一覧
.\2_RunAllTests.ps1 -Launch
```

## 起動する URL について（重要）

**サイトは、構成ファイルに書かれた URL で待ち受けている必要がある。**

アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
サーバ自身が `OAuth2AuthorizationServerEndpointsRootURI` へ HTTP で折り返す。
叩き先と構成が食い違うと、その折り返しが接続不能になり **HTTP 500** になる。

**https で動かすこと。**
認証まわりの Cookie は `SameSite=None` で発行されるため、http では保持されない。
`max_age` を使うフロー（FAPI2）は `auth_time` Cookie を見るので、http だとエラー画面になる。

`test.ps1 -Launch` は、この 2 つを環境変数で揃えてから起動する。

```
OAuth2AuthorizationServerEndpointsRootURI
OAuth2ClientEndpointsRootURI
```

あわせて、プッシュ通知の送信箱 `FcmOutboxDirectory` を設定する（`Result/fcm/core`・`Result/fcm/netfx`）。
サイトは FCM に送らずここへファイルを書き、テストが認証デバイスの代わりに読む（`EX-8`）。

`appSettings` の `FxContainerization` が `ON` のとき、Open棟梁 は
**設定ファイルより環境変数を優先する**（net48 / net10.0 の両方）。
**キー名がそのまま環境変数名になる。** 接頭辞は付かない。

このため 2 つのサイトを別々の URL で同時に立てられる。

| 対象 | 既定 |
|---|---|
| net10.0（Kestrel） | `https://localhost:44300` |
| net48（IIS Express） | `https://localhost:44302` |

## 設定

`E2ETests/_testsettings.json` が雛形。
変えたいときは `testsettings.json` にコピーして編集する（`.gitignore` 済み）。

環境変数でも上書きできる。

| 環境変数 | 意味 |
|---|---|
| `MPAS_CORE_BASEURL` / `MPAS_NETFX_BASEURL` | 叩き先の URL |
| `MPAS_CORE_CONFIG` / `MPAS_NETFX_CONFIG` | 構成ファイルのパス（`root/programs` からの相対） |
| `MPAS_TESTUSER` | テスト ユーザ名（**両対象に効く**。接尾辞より強い） |
| `MPAS_CORE_TESTUSER_SUFFIX` | net10.0 版のテスト利用者の接尾辞（#260。`test.ps1` が `_core` を渡す） |
| `MPAS_NETFX_TESTUSER_SUFFIX` | net48 版のテスト利用者の接尾辞（同上。`_netfx`） |
| `MPAS_CORE_FCM_OUTBOX` / `MPAS_NETFX_FCM_OUTBOX` | プッシュ通知の送信箱（`-Launch` が設定する。無ければ CIBA の `EX-8` は Skip） |
| `MPAS_CONNSTR_SQL` / `MPAS_CONNSTR_ODP` / `MPAS_CONNSTR_NPS` | `-UserStoreType` で `sql` / `ora` / `npg` に切り替えるときの接続文字列（#207） |

`UserStoreType` の既定は `mem`。テスト ユーザは初回アクセスで作られ、
再起動で消えるので、テストの前後で状態を掃除する必要が無い。

### 利用者は 2 人いる

認証サイトは `IsDebug` のとき、**同じ `TestUserPWD` で 2 人**作る（`AccountController` の `CreateData`）。

| 利用者 | 使い道 |
|---|---|
| `super_tanaka@gmail.com`（`TestEnv.TestUserName`） | 既定。`SignedInClientAsync` が何も指定しなければこちら |
| `tanaka@gmail.com`（`TestEnv.SecondUserName`） | 「別の利用者」が要るとき（`EX-8.4`）と、「端末が無い利用者」が要るとき（`RT-210.1`） |

別の利用者でサインインするには、利用者名を渡す。

```csharp
using (IdPClient other = await this.SignedInClientAsync(targetKey, TestEnv.SecondUserName))
```

> **2 人目には、端末（`device_token`）を登録しないこと。**
> `RT-210.1`（#210）が「端末が登録されていない利用者」として使っているため、
> 登録すると、実行順によってそのテストが失敗するようになる。

**`sql` / `ora` / `npg` に切り替えられる**（`test.ps1 -UserStoreType`、#207）。
設定ファイルは書き換えず、環境変数で上書きする（`FxContainerization=ON` のため、
`GetConfigValue` と `GetConnectionString` のどちらも環境変数が優先される）。
切り替えると**状態が残る**ので、作り直したいときはデータベースを作り直す。
手順と前提は [`../../TESTING.md`](../../TESTING.md) 1 節「ストアを切り替える」。

## テストの構成

**`Tests/SmokeTests.cs` が土台。** サイトに届いているか、サインインできるか、
認可コード フローが通るか。**ここが倒れていたら、他の合否は読む意味がない。**

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/SmokeTests.cs` | `SM-n` | Discovery / JWK Set / サインイン / 認可コード フロー |

**次が `Tests/Basic/`。** OAuth 2.0 / OIDC の基本的な検証項目を、
仕様の根拠つきで並べたもの（TC-1 〜 TC-6）。

| ファイル | 対象 |
|---|---|
| `Tests/Basic/CommonSecurityTests.cs` | TC-1 state / redirect_uri / スコープ / 有効期限 |
| `Tests/Basic/AuthorizationCodeFlowTests.cs` | TC-2 正常系 / code 使い捨て / クライアント認証 / PKCE |
| `Tests/Basic/TokenResponseTests.cs` | TC-3.2 トークン応答の約束（キャッシュ制御。フローに依らない） |
| `Tests/Basic/ClientCredentialsTests.cs` | TC-5 クライアント資格情報（**OAuth 2.1 でも有効**） |
| `Tests/Basic/OidcTests.cs` | TC-6 id_token の中身と署名 / alg:none の拒否 / UserInfo |

**その次が `Tests/Extended/`。** 基本テストケースに含まれない、追加の仕様・拡張仕様（EX-1 〜 EX-8）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Extended/RefreshTokenTests.cs` | `EX-1` | refresh_token の更新・ローテーション・**再利用の検知と一族ごとの失効**（#188）・発行先との結び付け（RFC 6749 §6 / RFC 9700 / RFC 7009） |
| `Tests/Extended/RevocationTests.cs` | `EX-2` | トークンの失効（RFC 7009） |
| `Tests/Extended/IntrospectionTests.cs` | `EX-3` | トークンの問い合わせ（RFC 7662） |
| `Tests/Extended/DeviceAuthorizationTests.cs` | `EX-4` / `RT-246` | Device Authorization Grant（RFC 8628）。**自己テストのボタンから、承認して判定が画面に出るまで**（`RT-246.3`） |
| `Tests/Extended/HybridFlowTests.cs` | `EX-5` | OIDC Hybrid フロー（c_hash / at_hash） |
| `Tests/Extended/ResponseModeTests.cs` | `EX-6` | response_mode（fragment / form_post / JARM） |
| `Tests/Extended/JwtBearerTests.cs` | `EX-7` | JWT Bearer グラント（RFC 7523） |
| `Tests/Extended/CibaTests.cs` | `EX-8` | CIBA（認証デバイスとプッシュ通知は、テストで置き換える） |

PAR / JAR は、拡張仕様としては扱っていない（`request_uri` の経路は RT-197 で測っている）。

CIBA（`EX-8`）は、**認証デバイス（`authentication_device`）とプッシュ通知を、テストで置き換える。**
サイトは FCM に送らず送信箱（`FcmOutboxDirectory`）にファイルを書き、テストはそれを読んで、
認証デバイスと同じ要求（`/SetDeviceToken`・`/ciba_result`）を送る。送信箱は `-Launch` のときだけ設定されるので、
それ以外では `EX-8` は Skip する。認証リクエストのエラーの返し方は RT-196 で測っている（ES256 で署名した要求を `/ros` に登録する）。

**`Tests/Obsolete/` は、OAuth 2.1 で廃止されたフロー**（#220）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Obsolete/ImplicitFlowTests.cs` | `TC-3.1` | Implicit（フラグメント返却） |
| `Tests/Obsolete/PasswordTests.cs` | `TC-4` | ROPC |

**消さずに残す。** `-Launch` では有効にして起動するので、これまでどおり測る（後述）。
**一覧（報告書・`TESTCASES.md`）では最後尾に置く。**

**最後が `Tests/Issues/`。** 個別の Issue に対応する回帰テスト（RT）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Issues/TokenClaimTests.cs` | `RT-182` `RT-184` | `expires_in`、JWT のクレーム型 |
| `Tests/Issues/NonceTests.cs` | `RT-183` `RT-190` `RT-191` | nonce の要否と扱い |
| `Tests/Issues/ErrorResponseTests.cs` | `RT-185` `RT-187` | エラー応答 |
| `Tests/Issues/RedirectUriBindingTests.cs` | `RT-186` | `redirect_uri` の照合 |
| `Tests/Issues/HttpStatusTests.cs` | `RT-196` | エラー応答の HTTP ステータス（OAuth2 / OIDC の各エンドポイントと、認証デバイスの口） |
| `Tests/Issues/RequestObjectTests.cs` | `RT-197` | `request_uri`（JAR）経路の `redirect_uri` / PKCE の紐付け。`RT-188.4`（使い切り）もここ |
| `Tests/Issues/ScopeTests.cs` | `RT-198` | 宣言外のスコープ、登録の `scope` に無いスコープを発行しない |
| `Tests/Issues/CacheControlTests.cs` | `RT-218` | トークンを返す口の `Cache-Control: no-store` / `Pragma: no-cache` |
| `Tests/Issues/PkceTests.cs` | `RT-220` | PKCE : `client_secret` との併用、`plain`、`code_challenge` の要否 |
| `Tests/Issues/DiscoveryTests.cs` | `RT-189` | Discovery の項目と型（Device AuthZ の広告、boolean / 配列、mTLS の名前、暗号化と JARM の対） |
| `Tests/Issues/PushedAuthorizationTests.cs` | `RT-229` / `RT-246` | PAR（`/par`）: フォームと JAR の両方で預けられる／クライアント認証が要る／`request_uri` は渡せない。**自己テストの PAR ボタン**（Open棟梁 のクライアントで預けて認可する。`RT-246.1`） |
| `Tests/Issues/IssuerParameterTests.cs` | `RT-231` | 認可応答の `iss`（RFC 9207）。成功・失敗・JARM・Discovery の広告 |
| `Tests/Issues/MalformedJwtTests.cs` | `RT-241` | JWT でない値・`iss` の無い JWT・未登録のクライアントで **500 にしない**（`/ros` と `client_assertion`） |
| `Tests/Issues/AsymmetricAuthTests.cs` | `RT-239` | 認可コード以外でも `private_key_jwt` で認証する（`refresh_token` / `/revoke` / `/introspect`）。壊れたアサーションを断ること。**fapi2 が `refresh_token` を使えること**（`RT-239.5`） |
| `Tests/Issues/ClientAssertionTests.cs` | `RT-238` | `private_key_jwt` のクライアント認証（RFC 7523 §2.2 の `client_assertion`）。従来の `assertion` も通ること、`client_assertion_type` の検証、fapi2 がトークンを取れること |
| `Tests/Issues/UserClaimsTests.cs` | `RT-230` | `profile` / `address` のクレームを設定で対応付ける。スコープで括られること、空は返さないこと、`claims_supported` が対応付けから作られること |
| `Tests/Issues/MaxAgeTests.cs` | `RT-247` | **`max_age` を超えたときの応答**（再認証へ送る／`prompt=none` なら `login_required`／数値でなければ `invalid_request`）。**繰り返しにならないこと**も見る |
| `Tests/Issues/ConsentScreenTests.cs` | `RT-246` | **認可画面（同意）が「何を確かめる画面か」を出す**（`prompt` / `max_age` の効き方）／**結果画面がクライアント認証の方式を出す**（`RT-246.6`） |
| `Tests/Issues/Saml2AssertionTests.cs` | `RT-246` | **自己テストが SAML2 のアサーションを画面に出す**（Redirect / POST / 要求 POST ＋ 応答 Redirect の 3 経路。判定・署名の検証・Issuer の一致・XML・属性。`RT-246.4` 〜 `RT-246.7`） |
| `Tests/Issues/CibaRequestTests.cs` | `RT-233` / `RT-234` / `RT-243` / `RT-246` | CIBA の認証要求を `request`（署名付き JWT）で直接受け取る（CIBA Core §7.1.1）。`request_uri` との優先順位、署名の検証。**`aud` の検証・`jti` の使い切り・クライアント認証**（`RT-234`）。**自己テストの CIBA ボタン**（判定と理由が画面に出る。`RT-246.2`） |
| `Tests/Issues/EndSessionTests.cs` | `RT-232` | **RP からのログアウト**（`/end_session`）。Discovery の広告、GET と POST の両方、`post_logout_redirect_uri` の完全一致、`id_token_hint` が無いときの確認画面、`client_id` の食い違い、サインインしていないときもエラーにしないこと。**自己テストの口**（Starters のボタン ＝ `RT-232.8`、認可コードの結果画面のボタン ＝ `RT-232.9`） |
| `Tests/Issues/BasicCredentialsTests.cs` | `RT-237` | `client_secret_basic` の資格情報を **RFC 6749 §2.3.1 のとおり復号して照合する**。符号化した Basic で通ること、**符号化しない Basic でも通ること**（互換）、`:` を含む秘密は符号化したときだけ通ること |
| `Tests/Issues/LifetimeTests.cs` | `RT-188` | 認可コード / refresh_token / `request_uri` の**有効期限**。**`-ShortLifetimes` のときだけ回る**（下記） |

**`Tests/Fapi/` は、クライアント登録（`oauth2_oidc_mode`）ごとに通る経路**（#222）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Fapi/ClientModeTests.cs` | `FA-1` | `fapi1`（PKCE の経路だけが通る／`refresh_token` を発行しない／`client_secret` と PKCE の併用も、Hybrid も通らない） |
| 〃 | `FA-2` | `fapi2`（`client_secret` も PKCE も通らない。x509 が要る） |
| 〃 | `FA-3` | `device`（PKCE で通る。表の「PKCE の S256」の行） |
| 〃 | `FA-4` | Device AuthZ グラントは `normal` / `device` の登録にだけ許す（#224） |
| `Tests/Fapi/CibaClientModeTests.cs` | `FA-5` | CIBA を `fapi_ciba` 以外の登録（`TestClient4_2`）や、既知でない登録値（`TestClient4_3`）で使うと、**開始（`/ciba_authz`）で**断る |
| `Tests/Fapi/MtlsTests.cs` | `FA-6` | **mTLS**（#226）: `fapi2` は Subject が一致する証明書の認可コードで通る／証明書なし・不一致は `invalid_client`／既知でない登録値は証明書が一致しても通さない／**トークンの `cnf` は RFC 8705 の形式で、その証明書の要求でしか使えない**。**net48 版は `-NetFxMtls` のときだけ**（下記） |

判定は `ClientModePolicy` の表（経路 × 何を証明したか → 通す登録種別）による（#224）。
**登録種別で断るときのエラーは `unauthorized_client`**（RFC 6749 §5.2。#224 の段階 2 で揃えた）。
**全 16 行に、通ることを測るケースを当てた**（#245 の段階 1。下の「経路 × 証明の網羅」）。
**mTLS の 2 行は net10.0 版だけ**で、net48 版は `-NetFxMtls` のときだけ測る（`FA-6`）。

> 以前ここには「**E2E で守られていない行がある** : 認可コードの private_key_jwt」と書いてあった。
> **`RT-238.4`（#238）と `RT-239.5`（#239）で埋まっており、記述が古かった。**
> 残っていた空きは `refresh_token × mTLS` の 1 行だけで、#245 で `FA-6.5` を足した。

**有効期限（`RT-188`）は、`-ShortLifetimes` で起動したときだけ回る**（#188）。
既定の寿命（認可コード 600 秒・Request Object 300 秒・refresh_token 14 日）を待てないため、
寿命をごく短くして起動する。**既定の通しでは除外している**ので、`TESTCASES.md`（原本）にも載らない
（[`../../TESTING.md`](../../TESTING.md) 5 節）。

```powershell
.\2_RunAllTests.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"
```

**mTLS（`FA-6`）は、net10.0 版だけを測る**（#226）。
Kestrel は既定でクライアント証明書を要求せず、要求させても自己署名の証明書はチェーンの検証で落ちる。
そこで `test.ps1 -Launch` が、**テスト専用のフック `Tests/MtlsTestHook`** を `DOTNET_STARTUP_HOOKS` で
net10.0 版にだけ読ませ、発行元を問わずに受け付けさせる（**アプリのコードは変えない**。Development 以外では何もしない）。
証明書は、テストがその場で作る自己署名のもので、**証明書ストアには入れない**（`Infrastructure/TestCertificate.cs`）。
net48 版（IIS Express）は、IIS が自己署名の証明書をアプリより前で 403.16 として断るため、既定では測らない。
**準備（テスト用 CA をコンピューターの信頼されたルートに入れる。管理者権限）だけを手動で行い、
`-NetFxMtls` を付けて回す**（[`../../TESTING.md`](../../TESTING.md) 5 節）。付けなければ net48 版のケースは作らない。
**実測済み**（2026/09/23。net48 版でも `FA-6` の 4 件が通る）。

**`Tests/OAuth21/` は、OAuth 2.1 が許さない経路の抑止**（#222）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/OAuth21/ProfileTests.cs` | `21-1` | 締めた登録では Implicit / ROPC / PKCE 無しが塞がる |
| 〃 | `21-2` | アクセス トークンは Authorization ヘッダでのみ受け付ける |

**サーバ全体の設定は変えない。** `-Launch` は Implicit / ROPC を有効にして起動し、
`RequirePkce` も `false` のまま。**締めるのはクライアント単位の登録**
（`oauth2_oidc_mode` / `require_pkce`）なので、
**「サーバは開いているのに、このクライアントでは塞がる」**という対照が効く。

> **サーバ全体の `RequirePkce` / `RequirePkceS256` を `true` にしたときの挙動は測れない。**
> 設定ファイルを変えて起動し直す必要があるため（`CONFIGURATION.md` 11 節）。

**フォルダは、識別子の群に合わせている**（`Basic` = TC、`Extended` = EX、`Issues` = RT、
`Fapi` = FA、`OAuth21` = 21、`Obsolete` = 廃止されたフロー）。
ただし**厳密な一対一ではない。** 回帰テストが既存のケースを対照として使うことがあり、
`Tests/Issues/HttpStatusTests.cs` には EX が、`Tests/Extended/IntrospectionTests.cs` には
RT が混ざっている。**対照は近くに置いたほうが読めるので、そこは揃えていない。**

**すべてのテストが `TestReport` で記録を残す。**
識別子の体系は [`../../TESTING.md`](../../TESTING.md) を参照。

`Infrastructure/` は、テストから使う道具。

| ファイル | 役割 |
|---|---|
| `TestEnv.cs` | テスト対象（net10.0 版 / net48 版）と、その到達性 |
| `AppConfig.cs` | `appsettings.json` / `app.config` の読み取り |
| `IdPClient.cs` | サインイン、認可、トークン、UserInfo、失効・問い合わせ、デバイス認可、CIBA、認証デバイスの代わりの要求、自己テストの起動 |
| `FcmOutbox.cs` | プッシュ通知の送信箱（テスト用）の読み取り。認証デバイスの代わりに受け取る |
| `Flows.cs` | 認可コード フローの組み立て、トークンの更新・失効・問い合わせ、クライアントの解決 |
| `TestCertificate.cs` | mTLS 用のクライアント証明書。net10.0 版は自己署名をその場で作る（ストアに入れない）、net48 版は `CurrentUser\My` に用意したもの（#226） |
| `RequestObject.cs` | Request Object（CIBA の認証リクエストを含む）の組み立てと PAR への登録 |
| `JwtBearerAssertion.cs` | JWT Bearer グラント（RFC 7523）の assertion の組み立て |
| `JwsSigner.cs` | RS256 / ES256 の署名（Request Object・assertion・CIBA の要求で共用） |
| `Jwt.cs` | JWT のデコード（検証はしない）と、c_hash / at_hash の計算 |
| `Base64Url.cs` | BASE64URL の変換 |
| `Jwks.cs` | JWK Set での署名検証、alg:none 化・改竄（テスト用） |
| `TestReport.cs` | **テストの内容と結果を、それ自体で読める形に書き出す** |
| `Html.cs` | リダイレクトしなかったときの画面の要約、form_post のフォームの解析 |
| `Responses.cs` | 各エンドポイントの応答 |
| `TargetTestBase.cs` | 両ターゲットに同じテストを流す基底クラス |

**テストを足したり変えたりしたら、原本を作り直すこと。**

```powershell
cd root
.\2_RunAllTests.ps1 -Launch -UpdateTestCases
```

## 壊したときに通らないことの網羅（#245 の段階 2）

**「パラメタを 1 つ壊したら、認証・認可されない」を経路ごとに揃えた。**
異常系は Issue ごとに足してきたため、**同じ形の確認が、あるものと無いものに分かれていた。**
**既にあるものは数え、無いものだけを足した。**

| 壊すもの | 既にあったもの | 足したもの |
|---|---|---|
| `client_id` / `client_secret` | `TC-2.3`（誤り・存在しない）／`FA-6.2`（証明書）／`EX-4.6` | — |
| `redirect_uri` | `TC-1.3`（未登録）／`RT-186.2` `.3`（認可時と違う・省略） | `RT-245.4`（**パスの大文字小文字違い。#263 で直したので、いまは回帰**） |
| `code` | `TC-2.2` `RT-186.4`（使用済み）／`RT-188.1`（期限切れ） | **`RT-245.2`**（改竄・他クライアントでの交換） |
| `refresh_token` | `EX-1.2` `.3` `.4`／`RT-188.2` | — |
| `device_code` | `EX-4.5` `.7` | — |
| `code_verifier` | `TC-2.4`（不一致）／`RT-197.6` | **`RT-245.3`**（**欠落。C-22 として修正した**） |
| `client_assertion` | `RT-239.4`（署名）／`RT-241.2` `.3`（JWT でない・`iss`） | **`RT-245.5`**（`aud` 違い・`exp` 切れ） |
| Request Object / CIBA の `request` | `RT-233` `RT-234`（`aud`・`jti`）／`RT-241.1` | — |
| `scope` | `RT-198.1`〜`.4`／`TC-1.4` | — |
| `request_uri` を口をまたいで渡す | **無かった** | **`RT-245.1`**（`/par` ⇄ `/ciba_authz`） |

**この作業で、製品側の弱点が 2 件出た。**

| 出たもの | 扱い |
|---|---|
| **`code_challenge` を送ったコードが `code_verifier` 無しで交換できた** | **C-22 として修正**（#245。`RT-245.3` が守る） |
| `redirect_uri` の比較が大文字小文字を無視 | **C-10 として記録し、#263 で修正した**（`StringComparison.Ordinal`）。`RT-245.4` は**その挙動のときだけ Skip** する形で置いてあったので、**Skip を外すだけで回帰になった** |

**自己テスト側の取り違えも 1 件出た**（`RT-245.6`）。
「FAPI1 PC, PKCE」のボタンが、**S256 で計算した `code_challenge` を `plain` と宣言**していたため、
**このボタンは必ず失敗していた。** E2E が押していなかったので、押して固定した。

> **「壊したら通らない」だけでは足りない。**
> どのケースにも**対照（正しい値なら通る）**を入れている。
> **壊し方に関係なく全部落ちている**状態と区別できないため。

## 経路 × 証明の網羅（`ClientModePolicy` の表。#245 の段階 1）

**`CommonLibrary/TokenProviders/ClientModePolicy.cs` の表がそのまま仕様である**
（経路 × 何を証明したか → 通す登録種別。表に無い組み合わせは拒否）。
**その 16 行すべてに、通ることを測るケースを当てた。**

| 経路 | 証明 | 通す登録種別 | 測っているケース |
|---|---|---|---|
| Implicit | 問わない | normal | `21-1.1` |
| Hybrid | 問わない | normal | `FA-1.4` |
| 認可コード | `client_secret` | normal | `FA-1.1` |
| 認可コード | `client_secret` ＋ PKCE | normal | `FA-1.3` |
| 認可コード | PKCE plain | normal | `RT-220.2` |
| 認可コード | PKCE S256 | normal / fapi1 / device | `FA-1.1` / `FA-3.1` |
| 認可コード | `private_key_jwt` | normal / fapi1 / fapi2 / device | `RT-238.4` |
| 認可コード | mTLS | normal / fapi1 / fapi2 | `FA-6.1`（net10.0。net48 は `-NetFxMtls`） |
| `refresh_token` | `private_key_jwt` | normal / fapi1 / fapi2 | `RT-239.5` |
| `refresh_token` | mTLS | normal / fapi1 / fapi2 | **`FA-6.5`**（#245 で追加） |
| `refresh_token` | 問わない | normal | `FA-1.2` |
| ROPC | 問わない | normal | `FA-1.1` / `21-1.1` |
| `client_credentials` | 問わない | normal | `FA-1.1` |
| JWT Bearer | 問わない | normal | `EX-7` |
| CIBA | 問わない | fapi_ciba | `EX-8` / `FA-5.1` |
| Device AuthZ | 問わない | normal / device | `FA-4.1` |

**拒否される側**（表に無い組み合わせ）は `FA-2.1`（fapi2 × client_secret / PKCE）、
`FA-1.4`（fapi1 × Hybrid）、`FA-4.1` / `FA-5.1`（登録種別の違い）、
`FA-6.2` / `FA-6.3`（証明書の不一致・既知でない登録値）が守っている。

> **`refresh_token` の行は #239 の段階 3 で fapi1 / fapi2 に開いた。**
> その際、**更新後のトークンから登録種別のクレーム（`fapi`）が消えていた**
> （`ProtectFromPayload` に `normal` を固定で渡していた）。
> **#245 の段階 1 で `FA-6.5` を書いたときに実測して直した**（`FA-6.5` / `RT-239.5` が検証する）。

## 既定で無効な機能のテスト（`Tests/Obsolete/`）

**OAuth 2.1 で廃止されたフロー**（Implicit / ROPC）のテストは `Tests/Obsolete/` に置く（#220）。

- **消さない。** 設定で有効にしている環境のために残す
- **`-Launch` では、必ず測る。** `test.ps1` がサイトを起動する直前に、
  `EnableImplicitGrantType` / `EnableResourceOwnerPasswordCredentialsGrantType` を
  環境変数で `true` にする（`FxContainerization = ON` なので、キー名がそのまま環境変数名になる。
  RootURI の渡し方と同じ）。**設定ファイルは書き換えない。**
  無効のまま Skip にすると、**廃止したフローの回帰が効かなくなる**ため
- **テスト自身も discovery を見て Skip する**（`Flows.SkipIfGrantTypeNotSupportedAsync`）。
  `-Launch` を付けず、無効な環境へ向けて回したときのための保険
- **`Tests/Issues/` にも、同じ理由で Skip するテストがある**（`RT-190.1` / `RT-190.2` / `RT-198.2`）。
  置き場所ではなく、**依存する機能で決まる**
- **一覧では最後尾に出る。** `2_RunAllTests.ps1` が、報告書と `TESTCASES.md` の並びで
  `*.Tests.Obsolete.*` を後ろへ回す。**実行順は変えていない**（xUnit の既定のまま）。
  識別子は `TC-3.1` / `TC-4` のままなので、位置だけが動く

## 未修正の項目

**未修正だと分かっている項目は、期待する動作を書いたうえで `Skip` にしている。**
消さずに残すのは、直したときに `Skip` を外すだけで検証できるようにするため。
`Skip` の理由に、実測した日付と結果を書く。

**現在、未修正を理由に `Skip` にしているものは無い**（2026-10-03 時点）。

最後まで残っていた `RT-245.4`（`BrokenParameterTests`。`redirect_uri` の比較が大文字小文字を
無視していた。C-10）は、**#263 で直して Skip を外した。両ターゲットで通ることを確かめてある。**

> **それ以前に残っていたのは `RT-187.4`**（`ErrorResponseTests`。未知の `response_type` が、
> リダイレクトではなくエラー画面になる）で、これも解消済み。

> 対象ごとの `Skip`（「そのサイトが起動していない」）は、これとは別。
> `-Launch` を付けずに片方だけで回せば出る。

## 分かっていること（実測）

`request_uri` 経路について測った結果（#197）。

| | 修正前（2026/09/09, net10.0） | 修正後（2026/09/11, net10.0 / net48） |
|---|---|---|
| 認可コードの発行 | できる | できる |
| `redirect_uri` の照合 | **効いていない。** 誤った値でもトークンが出る | 誤った値は `invalid_grant` |
| PKCE（`code_challenge`） | 記録されないため、`code_verifier` を送ると `invalid_client`（**素通りではなく拒否**） | 正しい検証子で通り、誤った検証子は `invalid_client` |

修正前は、`AuthorizationCodeProvider.Create` がこれらの値を
**Request Object ではなくクエリ文字列から**読んでいたことによる。
#197 で、`request_uri` 経路では Request Object の値を使うように直した。

## 制約

- **FAPI2 のクライアントは、`client_secret` だけのトークン要求を受け付けない**
  （`unauthorized_client`。#224 の段階 2 までは `unsupported_grant_type`）。mTLS / private_key_jwt が要る。
  このため `redirect_uri` の照合は、`normal` モードのクライアントに
  自前の Request Object を渡して測っている。
- net48 版の起動には **IIS Express が要る**（`%ProgramFiles%\IIS Express`）。
  無い場合・ビルドされていない場合は、理由を出して**その分を Skip する**（失敗にしない）。
- 構成ファイルの既定では、net10.0 版と net48 版は同じ URL を指している。
  `-Launch` は環境変数で別のポートへ寄せるので**同時に測れる**が、
  手で立てるときは片方を別の URL にすること。
- CIBA のテスト（`RT-196.16` 〜 `196.18`、`EX-8`）は、構成ファイルの `SpRp_EcdsaPfxFilePath`（ES256 の秘密鍵）で要求に署名する。
  CIBA のクライアント（`TestClient4`）が登録している `jwk_ecdsa_publickey` と対になっていること。
  取り違えは検出して Skip する（[`../../TESTING.md`](../../TESTING.md) 5 節）。
