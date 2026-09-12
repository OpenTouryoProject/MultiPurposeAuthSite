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
| `MPAS_TESTUSER` | テスト ユーザ名 |
| `MPAS_CORE_FCM_OUTBOX` / `MPAS_NETFX_FCM_OUTBOX` | プッシュ通知の送信箱（`-Launch` が設定する。無ければ CIBA の `EX-8` は Skip） |

`UserStoreType` は `mem` を想定している。テスト ユーザは初回アクセスで作られ、
再起動で消えるので、テストの前後で状態を掃除する必要が無い。

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
| `Tests/Basic/ImplicitFlowTests.cs` | TC-3 フラグメント返却 / キャッシュ制御 |
| `Tests/Basic/PasswordAndClientCredentialsTests.cs` | TC-4・TC-5 パスワード / クライアント資格情報 |
| `Tests/Basic/OidcTests.cs` | TC-6 id_token の中身と署名 / alg:none の拒否 / UserInfo |

**その次が `Tests/Extended/`。** 基本テストケースに含まれない、追加の仕様・拡張仕様（EX-1 〜 EX-8）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Extended/RefreshTokenTests.cs` | `EX-1` | refresh_token の更新・ローテーション・発行先との結び付け（RFC 6749 §6 / RFC 9700） |
| `Tests/Extended/RevocationTests.cs` | `EX-2` | トークンの失効（RFC 7009） |
| `Tests/Extended/IntrospectionTests.cs` | `EX-3` | トークンの問い合わせ（RFC 7662） |
| `Tests/Extended/DeviceAuthorizationTests.cs` | `EX-4` | Device Authorization Grant（RFC 8628） |
| `Tests/Extended/HybridFlowTests.cs` | `EX-5` | OIDC Hybrid フロー（c_hash / at_hash） |
| `Tests/Extended/ResponseModeTests.cs` | `EX-6` | response_mode（fragment / form_post / JARM） |
| `Tests/Extended/JwtBearerTests.cs` | `EX-7` | JWT Bearer グラント（RFC 7523） |
| `Tests/Extended/CibaTests.cs` | `EX-8` | CIBA（認証デバイスとプッシュ通知は、テストで置き換える） |

PAR / JAR は、拡張仕様としては扱っていない（`request_uri` の経路は RT-197 で測っている）。

CIBA（`EX-8`）は、**認証デバイス（`authentication_device`）とプッシュ通知を、テストで置き換える。**
サイトは FCM に送らず送信箱（`FcmOutboxDirectory`）にファイルを書き、テストはそれを読んで、
認証デバイスと同じ要求（`/SetDeviceToken`・`/ciba_result`）を送る。送信箱は `-Launch` のときだけ設定されるので、
それ以外では `EX-8` は Skip する。認証リクエストのエラーの返し方は RT-196 で測っている（ES256 で署名した要求を `/ros` に登録する）。

**最後が `Tests/Issues/`。** 個別の Issue に対応する回帰テスト（RT）。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/Issues/TokenClaimTests.cs` | `RT-182` `RT-184` | `expires_in`、JWT のクレーム型 |
| `Tests/Issues/NonceTests.cs` | `RT-183` `RT-190` `RT-191` | nonce の要否と扱い |
| `Tests/Issues/ErrorResponseTests.cs` | `RT-185` `RT-187` | エラー応答 |
| `Tests/Issues/RedirectUriBindingTests.cs` | `RT-186` | `redirect_uri` の照合 |
| `Tests/Issues/HttpStatusTests.cs` | `RT-196` | エラー応答の HTTP ステータス（OAuth2 / OIDC の各エンドポイントと、認証デバイスの口） |
| `Tests/Issues/RequestObjectTests.cs` | `RT-197` | `request_uri`（JAR）経路の `redirect_uri` / PKCE の紐付け |
| `Tests/Issues/ScopeTests.cs` | `RT-198` | 宣言外のスコープ、登録の `scope` に無いスコープを発行しない |

**フォルダは、識別子の群に合わせている**（`Basic` = TC、`Extended` = EX、`Issues` = RT）。
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

## 未修正の項目

**未修正だと分かっている項目は、期待する動作を書いたうえで `Skip` にしている。**
消さずに残すのは、直したときに `Skip` を外すだけで検証できるようにするため。
`Skip` の理由に、実測した日付と結果を書く。

現在 `Skip` にしているもの。

- `RT-187.4`（`ErrorResponseTests`）
  未知の `response_type` が、リダイレクトではなくエラー画面（HTTP 200）になる。
  認可コードは発行されないので、安全側には倒れている。

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
  （`unsupported_grant_type`）。mTLS / private_key_jwt が要る。
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
