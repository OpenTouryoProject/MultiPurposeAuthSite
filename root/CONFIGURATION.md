# CONFIGURATION.md — 設定ファイルの扱い

対象: `root/programs`（net48 版 / net10.0 版）
配置: `root`

本書は**「設定がどこにあり、どう読まれ、どう上書きされ、どこで踏むか」**を扱う。
**個々のキーが何を意味するかは書かない。** それは値の隣（雛形のコメント）にある。

> **一次情報は本書ではない。** 迷ったら次を見ること。
>
> | 内容 | 一次情報 |
> |---|---|
> | 各キーの意味 | `_appsettings.json` / `_app.config` のコメント |
> | 秘密の報告方法 | [`../SECURITY.md`](../SECURITY.md) |
> | ビルド | [`BUILDING.md`](BUILDING.md) |
> | テストからの参照 | [`TESTING.md`](TESTING.md) |

---

## 1. 設定ファイルの種類

| ターゲット | 実体 | 雛形 | 行数 |
|---|---|---|---|
| net10.0 | `programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json` | `_appsettings.json` | 約 364 |
| net48 | `programs/MultiPurposeAuthSite/MultiPurposeAuthSite/app.config` | `_app.config` | 約 390 |

**実体は 2 つとも `.gitignore` 済み。** 実際の資格情報を含むため。

```
/root/programs/MultiPurposeAuthSite/MultiPurposeAuthSite/app.config
/root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json
/root/programs/Tests/E2ETests/testsettings.json
```

**設定を変えたら、雛形（`_` 付き）にも反映する。** clone した人が見るのは雛形だけである。

## 2. net10.0 — `appsettings.json`

3 つのセクションを持つ。

```json
{
  "connectionStrings": { ... },
  "sessionState":      { ... },
  "appSettings":       { ... }   ← ほとんどはここ
}
```

**コメント（`//`）と末尾カンマを含む JSONC である。** 素の `JsonSerializer` では読めない。
機械で読むときは次を指定する。

```csharp
new JsonDocumentOptions()
{
    CommentHandling  = JsonCommentHandling.Skip,
    AllowTrailingCommas = true
}
```

### 環境変数で上書きできる

**階層の区切りは `__`（アンダースコア 2 つ）。**

```
set appSettings__OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44300
```

**net48 版にはこの仕組みが無い。** これは ASP.NET Core の構成の仕組みである。
ただし、次の `FxContainerization` は**両方で使える。**

### `FxContainerization` — 環境変数を優先する（net48 / net10.0 の両方）

`appSettings` の `FxContainerization` を `ON` にすると、
Open棟梁 の `GetConfigParameter` が**設定ファイルより環境変数を優先する。**

```
<add key="FxContainerization" value="ON" />   app.config
"FxContainerization": "ON",                   appsettings.json
```

**キー名がそのまま環境変数名になる。** 接頭辞は付かない。

```
set OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44302
set OAuth2ClientEndpointsRootURI=https://localhost:44302
```

`root/programs/Tests/test.ps1 -Launch` は、これを使って
**2 つのサイトを別々の URL で同時に立てている**（[`TESTING.md`](TESTING.md) 4 節）。
net48 版を `app.config` の URL に置く必要がないのは、この仕組みによる。

> **`ON` にしただけでは、動きは変わらない。**
> 環境変数が定義されていなければ、設定ファイルの値が使われる。

## 3. net48 — `app.config`

**`Web.config` から取り込まれる外部 `appSettings` ファイルである。**

```xml
<!-- Web.config -->
<appSettings file="app.config" />
```

このため **`app.config` のルート要素は `<configuration>` ではなく `<appSettings>`。**
`<configuration><appSettings>` を期待して読むと、何も取れない。

```xml
<appSettings>
  <add key="OAuth2AuthorizationServerEndpointsRootURI" value="https://localhost:44300/MultiPurposeAuthSite" />
  ...
</appSettings>
```

## 4. クライアントの登録 — `OAuth2ClientsInformation`

**同じ内容が、2 つの形で入っている。**

| ターゲット | 形 |
|---|---|
| net10.0 | **入れ子の JSON オブジェクト** |
| net48 | **JSON 文字列**（`value='...'` の中に丸ごと） |

```json
"OAuth2ClientsInformation": {
  "67d328bfe8604aae83fb15fa44780d8b": {
    "client_secret": "...",
    "redirect_uri_code": "test_self_code",
    "client_name": "TestClient",
    "subject_types": "uname",         // public, pairwise, uname
    "jwk_rsa_publickey": "..."
  },
  ...
}
```

**`client_id` は環境ごとに違う。** `CommandLineTools` の `CreateClientsIdentity.exe` で生成する。
このため、**コードやテストに `client_id` を直書きしない。** `client_name` から引くこと。

| `client_name` | 用途 |
|---|---|
| `TestClient` | 自己テスト用（`redirect_uri` は `test_self_code` / `test_self_token`） |
| `TestClient1` | FAPI1 |
| `TestClient2` | FAPI2（Request Object を使う） |
| `TestClient3` | Device Authorization Grant。**`client_secret` を持たない**（パブリック クライアント） |
| `TestClient4` | CIBA |
| `TestClient5` | 登録の `scope` で、要求してよいスコープを制限した例（#198、E2E テスト用） |
| `MVC_Sample` ほか | 絶対 URL の `redirect_uri` を持つサンプル |

### `scope` — 要求してよいスコープ（任意）

**クライアントごとに、発行してよいスコープを制限する。** RFC 7591 §2 の client metadata と同じく、
スペース区切りで並べる。

```json
"scope": "openid profile email"
```

発行するスコープは、次の 3 つをすべて満たすものになる。

1. クライアントが要求した
2. Discovery の `scopes_supported` にある（認可サーバが扱う）
3. 登録の `scope` にある

| 登録 | 扱い |
|---|---|
| **項目が無い** | 3 は見ない（`scopes_supported` の範囲だけ）。**既存の登録はこのまま動く** |
| 空文字列 | どのスコープも許さない |

要求を拒否（`invalid_scope`）するのではなく、許されないスコープを外して発行する。
外したときは、トークン応答の `scope` に実際に発行したものを返す（RFC 6749 §5.1）。

> `CreateClientsIdentity` はこの項目を出力しない。必要なクライアントにだけ、手で足す。

### `redirect_uri` の記号

`test_self_code` / `test_self_token` は URL ではなく**記号**である。
サーバが `CmnEndpoints.GetRedirectUriFromConstr` で実 URL に解決する。

```
test_self_code  → OAuth2ClientEndpointsRootURI + OAuth2AuthorizationCodeGrantClient_Account
test_self_token → OAuth2ClientEndpointsRootURI + OAuth2ImplicitGrantClient_Account
```

**`OAuth2AuthorizationServerEndpointsRootURI` ではなく `OAuth2ClientEndpointsRootURI` を使う。**
既定では同じ値だが、変えるときは両方見ること。

## 5. ルート URI と、自己テストの折り返し（重要）

```
OAuth2AuthorizationServerEndpointsRootURI   認可サーバ側のエンドポイントの根
OAuth2ClientEndpointsRootURI                クライアント側（自己テストの受け口）の根
```

既定はどちらも `https://localhost:44300/MultiPurposeAuthSite`。
これは **IIS Express の仮想ディレクトリ**を前提とした値である。

**アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
サーバ自身がこの URL へ HTTP で折り返す。**

```
POST /Home/Saml2OAuth2Starters
  → サーバが OAuth2AuthorizationServerEndpointsRootURI + /ros へ POST（Request Object の登録）
  → 返ってきた request_uri で /authorize へリダイレクト
```

**待ち受け URL と食い違うと、この折り返しが接続不能になり HTTP 500 になる。**

### Kestrel（`dotnet run`）で動かす場合

`launchSettings.json` の `applicationUrl` はパスを含むが、
**Kestrel は仮想ディレクトリを持たない**（`UsePathBase` も呼んでいない）ので、
`/MultiPurposeAuthSite/...` は 404 になる。

環境変数で構成側を合わせる。

```
set ASPNETCORE_ENVIRONMENT=Development
set appSettings__OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44300
set appSettings__OAuth2ClientEndpointsRootURI=https://localhost:44300
dotnet run --urls https://localhost:44300
```

`FxContainerization` が `ON` なら、**接頭辞なし**の `OAuth2...` でも上書きできる（2 節）。
net48 版と書き方が揃うので、両方を扱うスクリプトはそちらを使っている。

### https で動かすこと

**認証まわりの Cookie は `SameSite=None` で発行される。**
`Secure` が伴わないため、**http では保持されない。**

`max_age` を使うフロー（FAPI2）は `auth_time` Cookie を見るので、
http で動かすと認可エンドポイントがエラー画面になる。

## 6. 秘密の扱い

**`app.config` / `appsettings.json` の内容を、報告・コミット メッセージ・Issue 本文に転記しない。**

含まれるもの。

- `TestUserPWD`
- `OAuth2ClientsInformation` の各 `client_secret`
- `connectionStrings` のパスワード
- `RsaPfxPassword` / `EcdsaPfxPassword` / `SpRp_*PfxPassword`

設定の変更を共有するときは、**雛形（`_app.config` / `_appsettings.json`）側に書く。**
雛形の値はプレースホルダ（`[password of TestUser]` など）である。

E2E テストは、**実行時にアプリ自身の構成ファイルから読み出す。**
テスト コードにもテスト設定にも、秘密は書かない（[`TESTING.md`](TESTING.md) 9 節）。

## 7. `UserStoreType`

```json
"UserStoreType": "mem",   // mem / sql / ora / npg
```

| 値 | 意味 |
|---|---|
| `mem` | メモリ。**再起動で消える。** テスト ユーザは初回アクセスで作られる |
| `sql` | SQL Server |
| `ora` | Oracle |
| `npg` | PostgreSQL |

E2E テストは `mem` を想定している。**前後で状態を掃除する必要が無い**のが理由。

## 8. 証明書

```json
"RsaPfxFilePath":      "C:/root/files/resource/X509/SHA256RSA_Server.pfx",
"EcdsaPfxFilePath":    "C:/root/files/resource/X509/SHA256ECDSA_Server.pfx",
"SpRp_RsaPfxFilePath": "C:/root/files/resource/X509/SHA256RSA_Client.pfx",
"SpRp_ClientCertPfxFilePath": "C:/root/files/resource/X509/SHA256RSAClientCert.pfx"
```

`RsaPfx*` はサーバ（トークンの署名）、`SpRp_*` はクライアント側（Request Object の署名、mTLS）。

**絶対パスで書かれている。** リポジトリの `root/files/resource/X509` を、
そのパスへ配置するか、値を書き換える。生成用のバッチが同じフォルダにある。

## 9. 機械で読むときの落とし穴

E2E テストの `AppConfig.cs` が実際に踏んだもの。同じことをするときは注意する。

### XML の属性値は、改行が空白に潰れる

XML 1.0 §3.3.3 のとおり、パーサは属性値の改行を空白へ正規化する。
`OAuth2ClientsInformation` は **`//` コメント付きの JSON** なので、
`XDocument` から取ると 1 行になり、**最初の `//` が以降を全部飲む。**

生のファイル テキストから取り直すこと。

### `//` を含む URL

雛形のコメントを正規表現で落とそうとすると、`https://...` の `//` まで消える。
**JSON パーサのコメント処理（`JsonCommentHandling.Skip`）を使うこと。**

## 10. net48 / net10.0 の対応表

| | net48 | net10.0 |
|---|---|---|
| 設定ファイル | `app.config`（`Web.config` から `file=` で取り込み） | `appsettings.json` |
| ルート要素 / セクション | `<appSettings>` | `appSettings` |
| コメント | XML コメント ＋ JSON 文字列内の `//` | JSONC の `//` |
| 環境変数で上書き | `FxContainerization=ON`（キー名そのまま） | `appSettings__<キー>` ／ `FxContainerization=ON` |
| クライアント登録 | JSON **文字列** | JSON **オブジェクト** |
| 既定の起動 | IIS Express | IIS Express / Kestrel |
| パッケージ | `packages.config` ＋ `PackageReference` | `PackageReference` |

**両者は共通ライブラリを使う別アプリである。** 片方にしか無い問題があり得る。
