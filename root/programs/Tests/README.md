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

net10.0 版を `https://localhost:44300` で起動し、テストを流して、停止する。

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
appSettings__OAuth2AuthorizationServerEndpointsRootURI
appSettings__OAuth2ClientEndpointsRootURI
```

（net10.0 版の構成は環境変数で上書きできる。`__` が階層の区切り。）

## 設定

`E2ETests/_testsettings.json` が雛形。
変えたいときは `testsettings.json` にコピーして編集する（`.gitignore` 済み）。

環境変数でも上書きできる。

| 環境変数 | 意味 |
|---|---|
| `MPAS_CORE_BASEURL` / `MPAS_NETFX_BASEURL` | 叩き先の URL |
| `MPAS_CORE_CONFIG` / `MPAS_NETFX_CONFIG` | 構成ファイルのパス（`root/programs` からの相対） |
| `MPAS_TESTUSER` | テスト ユーザ名 |

`UserStoreType` は `mem` を想定している。テスト ユーザは初回アクセスで作られ、
再起動で消えるので、テストの前後で状態を掃除する必要が無い。

## テストの構成

**`Tests/Basic/` が入口。** OAuth 2.0 / OIDC の基本的な検証項目を、
仕様の根拠つきで並べたもの（TC-1 〜 TC-6）。

| ファイル | 対象 |
|---|---|
| `Tests/Basic/CommonSecurityTests.cs` | TC-1 state / redirect_uri / スコープ / 有効期限 |
| `Tests/Basic/AuthorizationCodeFlowTests.cs` | TC-2 正常系 / code 使い捨て / クライアント認証 / PKCE |
| `Tests/Basic/ImplicitFlowTests.cs` | TC-3 フラグメント返却 / キャッシュ制御 |
| `Tests/Basic/PasswordAndClientCredentialsTests.cs` | TC-4・TC-5 パスワード / クライアント資格情報 |
| `Tests/Basic/OidcTests.cs` | TC-6 id_token の中身と署名 / alg:none の拒否 / UserInfo |

以下は、疎通と、個別の Issue に対応する回帰テスト。

| ファイル | 識別子 | 対象 |
|---|---|---|
| `Tests/SmokeTests.cs` | `SM-n` | Discovery / JWK Set / サインイン / 認可コード フロー |
| `Tests/TokenClaimTests.cs` | `RT-182` `RT-184` | `expires_in`、JWT のクレーム型 |
| `Tests/NonceTests.cs` | `RT-183` `RT-190` `RT-191` | nonce の要否と扱い |
| `Tests/RedirectUriBindingTests.cs` | `RT-186` | `redirect_uri` の照合 |
| `Tests/ErrorResponseTests.cs` | `RT-185` `RT-187` | エラー応答 |
| `Tests/RequestObjectTests.cs` | `RT-197` | `request_uri`（JAR）経路の実測 |

**すべてのテストが `TestReport` で記録を残す。**
識別子の体系は [`../../TESTING.md`](../../TESTING.md) を参照。

`Infrastructure/` は、テストから使う道具。

| ファイル | 役割 |
|---|---|
| `TestEnv.cs` | テスト対象（net10.0 版 / net48 版）と、その到達性 |
| `AppConfig.cs` | `appsettings.json` / `app.config` の読み取り |
| `IdPClient.cs` | サインイン、認可、トークン、UserInfo、自己テストの起動 |
| `Flows.cs` | 認可コード フローの組み立て、クライアントの解決 |
| `RequestObject.cs` | Request Object の組み立てと PAR への登録 |
| `Jwt.cs` | JWT のデコード（検証はしない） |
| `Jwks.cs` | JWK Set での署名検証、alg:none 化・改竄（テスト用） |
| `TestReport.cs` | **テストの内容と結果を、それ自体で読める形に書き出す** |
| `Html.cs` | リダイレクトしなかったときの画面の要約 |
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
- `TC-1.4`（`Basic.CommonSecurityTests`、#198）
  **要求した `scope` が、そのままトークンに載る。** 許可された一覧との突き合わせも、
  クライアントごとの権限の確認も無い。`scopes_supported` に無い任意の文字列
  （`admin` など）も、認可サーバの署名付きで発行される。
- `RT-197.5`（`RequestObjectTests`、#197）
  `request_uri`（JAR）経路では `redirect_uri` が認可コードに紐付かず、
  **誤った `redirect_uri` を送ってもトークンが発行される。** #186 の対応が及んでいない。

## 分かっていること（実測）

`request_uri` 経路について、net10.0 版で測った結果（#197）。

| | 実測 |
|---|---|
| 認可コードの発行 | できる |
| `redirect_uri` の照合 | **効いていない。** 誤った値でもトークンが出る |
| PKCE（`code_challenge`） | 記録されないため、`code_verifier` を送ると `invalid_client` になる（**素通りではなく拒否**） |

いずれも `AuthorizationCodeProvider.Create` が、これらの値を
**Request Object ではなくクエリ文字列から**読んでいることによる。

## 制約

- **FAPI2 のクライアントは、`client_secret` だけのトークン要求を受け付けない**
  （`unsupported_grant_type`）。mTLS / private_key_jwt が要る。
  このため `redirect_uri` の照合は、`normal` モードのクライアントに
  自前の Request Object を渡して測っている。
- **net48 版は、このスクリプトからは起動しない。** IIS Express で起動しておくこと。
- net10.0 版と net48 版は、既定では同じ URL（`https://localhost:44300`）で
  構成されている。**同時には測れない。**
  片方を別の URL にするか、順番に実行する。
