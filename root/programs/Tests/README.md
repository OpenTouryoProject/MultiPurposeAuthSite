# Tests

MultiPurposeAuthSite の**ビルド確認**と **E2E テスト**。

このリポジトリには CI が無く、動作確認は手作業だった。
そのため「コードを読んだ結論」と「実際の動作」がずれても気づけない。
ここは、**仕様への適合を実測で確かめる**ための場所。

| | |
|---|---|
| `build.ps1` | net10.0 版 / net48 版 / テストを非対話でビルドし、警告とエラーを数える |
| `test.ps1` | サイトを起動して E2E テストを実行する |
| `E2ETests/` | xUnit のテスト プロジェクト（net10.0） |

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

### ビルドだけ

```powershell
.\build.ps1              # net10.0 / net48 / テスト
.\build.ps1 -Target core # net10.0 だけ
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

| ファイル | 対象 |
|---|---|
| `Tests/SmokeTests.cs` | Discovery / JWK Set / サインイン / 認可コード フロー |
| `Tests/TokenClaimTests.cs` | `expires_in`（#182）、JWT のクレーム型（#184） |
| `Tests/NonceTests.cs` | nonce の要否と扱い（#183 / #190 / #191） |
| `Tests/RedirectUriBindingTests.cs` | `redirect_uri` の照合（#186） |
| `Tests/ErrorResponseTests.cs` | エラー応答（#185 / #187） |
| `Tests/RequestObjectTests.cs` | `request_uri`（JAR）経路の実測 |

`Infrastructure/` は、テストから使う道具。

| ファイル | 役割 |
|---|---|
| `TestEnv.cs` | テスト対象（net10.0 版 / net48 版）と、その到達性 |
| `AppConfig.cs` | `appsettings.json` / `app.config` の読み取り |
| `IdPClient.cs` | サインイン、認可、トークン、UserInfo、自己テストの起動 |
| `Flows.cs` | 認可コード フローの組み立て、クライアントの解決 |
| `RequestObject.cs` | Request Object の組み立てと PAR への登録 |
| `Jwt.cs` | JWT のデコード（検証はしない） |
| `Html.cs` | リダイレクトしなかったときの画面の要約 |
| `Responses.cs` | 各エンドポイントの応答 |
| `TargetTestBase.cs` | 両ターゲットに同じテストを流す基底クラス |

## 未修正の項目

**未修正だと分かっている項目は、期待する動作を書いたうえで `Skip` にしている。**
消さずに残すのは、直したときに `Skip` を外すだけで検証できるようにするため。
`Skip` の理由に、実測した日付と結果を書く。

現在 `Skip` にしているもの。

- `ErrorResponseTests.未知のresponse_typeはunsupported_response_typeでリダイレクトする`
  未知の `response_type` が、リダイレクトではなくエラー画面（HTTP 200）になる。
  認可コードは発行されないので、安全側には倒れている。
- `RequestObjectTests.request_uri経路でもredirect_uriが照合される`
  `request_uri`（JAR）経路では `redirect_uri` が認可コードに紐付かず、
  **誤った `redirect_uri` を送ってもトークンが発行される。** #186 の対応が及んでいない。

## 分かっていること（実測）

`request_uri` 経路について、2026/09/08 に net10.0 版で測った結果。

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
