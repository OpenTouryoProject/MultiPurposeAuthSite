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
| net10.0 | `programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json` | `_appsettings.json` | 約 520 |
| net48 | `programs/MultiPurposeAuthSite/MultiPurposeAuthSite/app.config` | `_app.config` | 約 480 |

**実体は 2 つとも `.gitignore` 済み。** 実際の資格情報を含むため。

> **4 つは、キーの並びも説明も揃えてある。**
> **`_appsettings.json` が元**で、そこから
> `_app.config` / `appsettings.json` / `app.config` へ写す。
>
> | | |
> |---|---|
> | **値** | **ターゲットごとに違う**（net48 はパスが Windows 形式、URL に仮想パスが付く）ので、**写さない** |
> | **net48 だけの設定** | `webpages:*` / `PreserveLoginUrl` / `ClientValidationEnabled` / `UnobtrusiveJavaScriptEnabled`。**先頭にまとめてある** |
> | **net10.0 だけの設定** | `SessionStoreType` / `SessionStoreConnectionString` / `FIDOServerMode` / `DataProtectionKeyPath` / `UseHttpsRedirection` / `CookieSecurePolicy` / `UseForwardedHeaders` / `ForwardedHeadersKnownProxies` / `FxXMLTCDefinition` / `FxXMLTMInProcessDefinition`。**説明ごと `_app.config` には写さない** |
>
> **片方だけ直すとズレる。** **並べ替えや説明の加筆は、4 つとも同じ形にすること。**

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

> **設定ファイルに無いキーは、環境変数だけでは効かない**（実測。2026-09-17）。
> 上書きであって、追加ではない。**新しいキーを試すときは、先にファイルへ足すこと。**
>
> **ただし、「節」として読む設定は例外**（実測。2026-09-22、#224）。
> クライアント一覧（`OAuth2ClientsInformation`）は節ごと読む（`GetAnyConfigSection`）ので、
> `appSettings__OAuth2ClientsInformation__<client_id>__<項目>` で**ファイルに無いクライアントを足せる。**
> 1 個の値として読むキー（`GetConfigValue`）は、上のとおり足せない。
> net48 はクライアント一覧を 1 個の値（JSON 文字列）として読むので、
> `FxContainerization=ON` のうえで `OAuth2ClientsInformation` を**一覧ごと差し替える**必要がある。
> **E2E は、これを使っていない**（#264）。テスト専用のクライアントは
> **利用者の登録（`saml2OAuth2Data`）として種データで作る**ので、
> **net48 の「一覧ごと差し替える」が要らない**（`Tests/README.md`）。
> **一覧ごと差し替えると、環境ブロックの 32,767 文字に当たる**（`TESTING.md` 1 節）。

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

### `FcmOutboxDirectory` — プッシュ通知の送信箱（テスト用）

**本番では空のままにする。** 設定すると、サーバはプッシュ通知（CIBA、2FA のモバイル アプリ）を FCM に送らず、
このディレクトリに JSON ファイルとして書く。E2E テストが、認証デバイスの代わりにそれを読む（#196）。
送信箱を使うときは、Firebase の資格情報（`FirebaseServiceAccountKey`）を読まない。

`root/programs/Tests/test.ps1 -Launch` が、上の `FxContainerization` の仕組みで、**環境変数として**サイトごとに設定する
（`Tests/E2ETests/Result/fcm/core`・`…/netfx`）。構成ファイルに書く必要は無い。

> **ファイルには、device_token や 2FA のコードがそのまま書かれる。**

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
    // "subject_types" は書かなければ public（既定。下記）
    // "id_token_signed_response_alg" は書かなければ RS256（既定。下記）
    // "token_endpoint_auth_signing_alg" / "request_object_signing_alg" は
    //   書かなければ絞らない（#262。下記）
    "jwk_rsa_publickey": "..."
  },
  ...
}
```

**`client_id` は環境ごとに違う。** `CommandLineTools` の `CreateClientsIdentity.exe` で生成する。
このため、**コードやテストに `client_id` を直書きしない。** `client_name` から引くこと。

### `redirect_uri` は 1 クライアントに n 件登録できる（#306）

**`redirect_uri_code` / `redirect_uri_token` は、空白区切りで複数書ける。**

```json
"redirect_uri_code": "https://rp.example.com/callback https://localhost:5001/callback"
```

| | |
|---|---|
| **何に効くか** | **開発・ステージング・本番を 1 つの `client_id` で共存**させられる。**Web とモバイルのカスタム スキーム**（`com.example.app:/oauth2redirect`）**も 1 件で扱える** |
| **区切りは空白** | **URI に空白は入らない**（RFC 3986 §2。入れるなら `%20`）ので曖昧にならない。**カンマは使わない** — **`sub-delims` に含まれ、URI に入り得る**（同 §2.2）。**`scope` が空白区切り**（RFC 6749 §3.3）なのと同じ流儀 |
| **照合** | **要求の `redirect_uri` が、登録のいずれかと完全一致**すればよい（`Ordinal`。**前方一致にはしない**。#263 / C-10） |
| **管理画面** | **1 行の入力のまま**（空白で区切って入れる） |
| **DB** | **`Saml2OAuth2Data` の列幅が 2000 文字**（`Const.MaxLengthOfUriList`）。**列は増やしていない** |

**要求で `redirect_uri` を省略できるかは、登録の件数で決まる。**

| 登録の件数 | 要求で省略したとき |
|---|---|
| **1 件** | **その 1 件を使う**（**従来どおり**。既存の配備・既存の RP はそのまま動く） |
| **2 件以上** | **`invalid_request`** — **どれを使うべきか決められない。****RFC 6749 §3.1.2.3 は、複数登録しているなら要求に含めること**としている |
| 0 件 | **`invalid_request`**（従来どおり。未登録） |

> **1 本から 2 本に増やした時点で、その RP は `redirect_uri` を送る必要がある。**
> **多くの RP は既に送っている**（OIDC Core §3.1.2.1 は常に必須としている）。

> **記号**（`test_self_code` など。下の「折り返し先の記号」）**は要素ごとに解決される。**
> **記号と絶対 URL を混ぜて並べてよい。**

> **既存のデータベースには列幅の変更が要る**（#306）。
> **`Create_UserStore.sql` を流し直す**か、**`ALTER` で広げる。**
>
> ```sql
> -- SQL Server
> ALTER TABLE [Saml2OAuth2Data] ALTER COLUMN [RedirectUriCode]  [nvarchar](2000) NULL
> ALTER TABLE [Saml2OAuth2Data] ALTER COLUMN [RedirectUriToken] [nvarchar](2000) NULL
>
> -- Oracle
> ALTER TABLE "Saml2OAuth2Data" MODIFY ("RedirectUriCode" NVARCHAR2(2000));
> ALTER TABLE "Saml2OAuth2Data" MODIFY ("RedirectUriToken" NVARCHAR2(2000));
>
> -- PostgreSQL
> ALTER TABLE Saml2OAuth2Data ALTER COLUMN RedirectUriCode  TYPE varchar(2000);
> ALTER TABLE Saml2OAuth2Data ALTER COLUMN RedirectUriToken TYPE varchar(2000);
> ```
>
> **広げないままでも、1 本だけの登録は従来どおり入る**（512 文字まで）。

> **`post_logout_redirect_uri` と `redirect_uri_saml`（ACS）は 1 本のまま**である。
> **同じ形の課題だが、別の論点を持つ**（ACS は「返す先は常に登録値」。#276）ので、
> **#306 では触っていない。**

> **`web_origins`（#265）は、元から空白・カンマ区切りの列挙**である。
> **入力の上限だけが 1 本ぶんのままだった**ので、#306 で列挙用に揃えた（列は元から無制限）。

### `subject_types` — `sub` に何を入れるか

| 値 | `sub` | |
|---|---|---|
| **`public`** | 利用者の内部 ID | **既定**（OIDC Core 8 章） |
| `pairwise` | **クライアントごとに違う PPID** | OP だけが戻せる（#140 の段階 2） |

**扱うのはこの 2 つだけである**（#151 の段階 5）。
**書かなければ `public`** で、**画面（`Manage/AddSaml2OAuth2Data`）の選択肢も、この 2 つ**になる。

> **`sub` は「その RP の中で利用者を指す識別子」**で、表示や照合のための属性ではない。
> **利用者名を渡したいなら `UserClaimsMapping` で `preferred_username` に対応付ける**
> （#151 の段階 1。下の設定表）。

#### 独自値 `uname` は廃止した（#151 の段階 5）

**かつては `uname`（`sub` に利用者名を入れる独自値）が在り、それが既定だった。**

| | |
|---|---|
| 何が問題だったか | **以前は「利用者名＝メアド」**だったので、**`sub` としてメアドが全ての RP に渡っていた** |
| 代わり | **`preferred_username`**（#151 の段階 1） |
| 廃止の順序 | 段階 4 で**既定を `public` に**、段階 5 で**値そのものを廃止** |

**設定に `"subject_types": "uname"` が残っていても、エラーにはならない。**
**`pairwise` 以外は `public` として扱う**ので、**`public` と同じ振る舞いになる。**
**`subject_types_supported` にも出さない。**

#### 既定値を変えても、発行済みの `sub` は動かない

**RP は `sub` を利用者の主キーとして保存する。** 値が変わると、**RP 側では全員が別人になる。**

**そうならないのは、発行した `sub` を表に記録しているため**である（#151 の段階 2。`SubjectIdProvider`）。

| | |
|---|---|
| **既に `sub` を発行した（クライアント × 利用者）** | **表の値を返し続ける**（＝ 以前と同じ値。昔の利用者名のままのこともある） |
| **まだ発行していない組み合わせ** | **いまの設定（既定は `public`）で作る** |

**つまり、既定値の変更が効くのは「これから」だけである。**
**既存の配備で `sub` を `public` に揃えたいなら、表の行を消す**ことになる
（消すと、その RP から見て別人になる）。

### `id_token_signed_response_alg` — 署名アルゴリズム（#129 の段階 2〜4）

| 値 | ダイジェスト | パディング | 鍵 | 設定キー | |
|---|---|---|---|---|---|
| **`RS256`** | SHA-256 | PKCS #1 v1.5 | RSA | `RsaPfxFilePath` | **既定**（書かなければこれ） |
| `RS384` | SHA-384 | 同上 | **同じ RSA の鍵** | 同上 | |
| `RS512` | SHA-512 | 同上 | **同じ RSA の鍵** | 同上 | |
| `PS256` | SHA-256 | **RSASSA-PSS** | **同じ RSA の鍵** | 同上 | #129 の段階 4。**FAPI が求める値** |
| `PS384` | SHA-384 | **RSASSA-PSS** | **同じ RSA の鍵** | 同上 | 同上 |
| `PS512` | SHA-512 | **RSASSA-PSS** | **同じ RSA の鍵** | 同上 | 同上 |
| `ES256` | SHA-256 | － | EC（**P-256**） | `EcdsaPfxFilePath` | |
| `ES384` | SHA-384 | － | EC（**P-384**） | `Ecdsa384PfxFilePath` | #129 の段階 3 |
| `ES512` | SHA-512 | － | EC（**P-521**） | `Ecdsa512PfxFilePath` | 同上。**曲線は 521**（512 ではない） |

**access_token と id_token の両方に効く**（2 つは同じ alg になる）。
**既知でない値を書いた登録は、入口で拒否される**（`unauthorized_client`。#224 と同じ方針）。
**画面（`Manage/AddSaml2OAuth2Data`）からも選べる**（選択肢も下の表から作る）。

**鍵は 4 本で、alg は 9 つある。**

| | |
|---|---|
| **RSA は 1 本**（`RS*` と `PS*` の 6 つが共有） | **`kid` は kty / n / e から作る**ので、**6 つで同じ値**になる。RP は同じ鍵で検証でき、**どのダイジェストとパディングかはヘッダの `alg` が伝える**。**`jwkcerts` に鍵を足す必要は無い** |
| **EC は 3 本**（`ES256` / `ES384` / `ES512`） | **曲線が alg に紐づく**（JWA）ので、**鍵そのものが別**。`kid` も別になる |

> **`jwkcerts` の JWK の `alg` は `RS256` のまま**である（RSA の 1 本に対して 1 件なので、
> 6 つを書き分けられない）。**それでよい** ——
> RFC 7517 の `alg` は「用途」で任意であり、**この実装は `kty` で照合する。**

**alg → 鍵の対応は `SigningKeys`（`CommonLibrary/TokenProviders`）の表 1 か所**にあり、
**発行・検証・Discovery の広告・`jwkcerts` の生成が、すべてその表を見る**（#129 の段階 3 / D-9）。

> **CIBA（`oauth2_oidc_mode=fapi_ciba`）は `ES256` 固定**で、登録値では上書きしない
> （FAPI-CIBA が `PS256` / `ES256` を求めるため）。
> **JARM（`authorization_signing_alg_values_supported`）も `RS256` のまま。**

## 検証する側の alg を、クライアント単位で絞る（#262）

**`id_token_signed_response_alg`（上記）は「発行する側」である。**
**こちらは「受ける側」** — **そのクライアントから、どの alg で来るか**を宣言する
（OIDC Registration 1.0 §2）。

| 登録項目 | 効く口 | 書ける値 |
|---|---|---|
| `token_endpoint_auth_signing_alg` | `/token` の `client_assertion`（`private_key_jwt`） | **`RS256` / `ES256`** |
| `request_object_signing_alg` | Request Object（`/ros` / `/par` / `request`） | **`RS256`** |

**どちらも、書かなければ絞らない**（＝ 従来どおり）。**画面からも選べる**（先頭が「絞らない」）。

### 何が変わるか

**`client_assertion` で効く。**

**クライアントが RSA と ECDSA の公開鍵を両方登録していると、
`RS256` でも `ES256` でも認証が通る**（登録された鍵を順に試すため）。
**`token_endpoint_auth_signing_alg` を書くと、その alg だけに絞れる。**

| 登録 | 振る舞い |
|---|---|
| 書かない | **両方通る**（従来どおり） |
| `RS256` | **`ES256` のアサーションは通らない** |
| **書ける値の外**（例 : `PS256`） | **通らない**（不正な登録として拒否。#224 と同じ方針） |

**E2E** : `RT-262.1`（絞ると `ES256` が通らない）／`RT-129.1`（絞らなければ両方通る）。

### `request_object_signing_alg` は、いま書ける値が 1 つだけ

**受ける側は `RS256` 固定**である（上流の `RequestObject.Verify` が `JWS_RS256_Param` 決め打ち）。
**そのため、絞っても結果は変わらない。**

**それでも項目を用意してある。**
`request_object_signing_alg_values_supported`（広告）に対して
**登録側の項目が無いという非対称を、先に解消しておくため**である。
**受ける alg が増えた時点で、値を書けるようになるだけ**になる。

> **CIBA の `request` は対象外**である。**`ES256` 固定**で、
> **仕様でも別の登録項目**（`backchannel_authentication_request_signing_alg`）になっている。

### 一覧は 1 か所から作る

**受ける集合は `CmnEndpoints.TokenEndpointAuthSigningAlgs` /
`CmnEndpoints.RequestObjectSigningAlgs`** にあり、
**広告（Discovery）と、登録値の検証と、画面の選択肢が、同じものを見る。**
（発行する側が `SigningKeys` の表 1 か所を見るのと、同じ考え方。#129 の段階 3）

### 署名鍵の入れ替え（ローテーション。D-9）

**RP は `jwkcerts` をキャッシュする。** したがって**順序が要る。**

| | すること | なぜ |
|---|---|---|
| 1 | 新しい鍵を作り、**`jwkcerts` に先に載せる**（まだ署名には使わない） | **RP が新しい `kid` を引けるようにしてから**署名を切り替える |
| 2 | **RP のキャッシュが切れるのを待つ** | キャッシュの寿命は RP 側の都合。待たないと「知らない `kid`」で弾かれる |
| 3 | **設定の `*PfxFilePath` を新しい鍵に向け、再起動** | ここから新しい `kid` で署名が始まる |
| 4 | **旧いトークンの寿命が過ぎたら、旧い `kid` を `jwkcerts` から外す** | `OAuth2AccessTokenExpireTimeSpanFromMinutes` を過ぎれば、旧い鍵で検証する相手はいない |

**1 は `CreateJwkSetJson` が行う**（`CommandLineTools`）。

```
CreateJwkSetJson.exe
```

**このツールは `SigningKeys` の表を回して、`jwkcerts` に載せる鍵を決める**
（表をソース参照しているので、**アプリが署名に使う鍵と食い違わない**）。
**追記しかしない**ので、**1 を繰り返しても旧い鍵は消えない。**
**4（旧い鍵を外す）は `JwkSet.json` を手で編集する**（＝ 消すのは人が決める）。

> **広告（Discovery）と公開鍵（`jwkcerts`）が揃っていることは E2E で測っている**（`RT-129.6`）。
> **表に alg を足したのに `CreateJwkSetJson` を回していない**という食い違いは、そこで落ちる。

### 利用者名とメアド（#151 の段階 3）

**利用者名とメアドは、別の項目である。** **サインインはどちらでも通る。**

| | |
|---|---|
| サインインの入力 | **1 つの欄**（「利用者名またはメアド」）。**`@` を含めばメアド**として引く |
| 利用者名 | **`@` を使えない**（含めると、入力がどちらなのか決まらなくなる） |
| メアド | **常に在って一意**（`FindByEmailAsync` が成り立つ必要がある） |

> **`RequireUniqueEmail` の設定は削除した。**
> 以前は「利用者名＝メアド」か「メアドを持たない」の二択だった。
> **両方でサインインできるようにしたので、二択が成り立たない**
> （メアドを外すと、サインインもパスワード再設定もできなくなる）。
>
> **既存の配備は、そのまま動く。** **既存の利用者名は書き換えていない**ので、
> **メアド形式の利用者名が残る。** その利用者は**メアドとして引かれる**が、
> **値が同じなので同じ利用者に当たる。**
> **`@` の禁止は、新しく作る・変えるときだけ掛かる。**

**画面を 2 つ削除した**（#151 の段階 3 で引退させ、**段階 5 で消した**）。

| 消した画面 | なぜ在ったか |
|---|---|
| `Manage/AddEmail` | **メアドを持たない利用者**に、後から足すためのもの |
| `Manage/RemoveEmail` | 同様に、外すためのもの |

**メアドは常に在って一意**（サインインの識別子）になったので、どちらも成り立たない
（外すと、サインインもパスワード再設定もできなくなる）。
**アクションもビューも無いので、叩くと 404 になる。**

**メアドの変更は `Manage/ChangeEmail`**（門番は `CanEditEmail`）、
**利用者名の変更は `Manage/ChangeUserName`**（門番は `AllowEditingUserName`）。

#### ID 連携・外部ログインで作られる利用者名（#151 の段階 4）

**上流が返す `sub` は、利用者名ではない**（既定が `public` ＝ 利用者 ID）。
**そこで、下流が新規に作るときの名前は、この順で決める。**

| 順 | 使う値 | いつ |
|---|---|---|
| 1 | **`preferred_username`** | 上流が返していて、利用者名として使えるとき |
| 2 | **メアドの `@` より前** | 返っていないとき |

> **`sub` は見ない。** 段階 4 より前の上流（`subject_types=uname`）では `sub` が利用者名だったが、
> **下位互換は維持しない**と決めてある。
>
> **結び付ける鍵はメアド**なので、**名前がどちらになっても、同じ利用者に結び付く。**
> ここで決まるのは**新規に作るときの名前だけ**である。
>
> **上流（相手の OP）に `preferred_username` を出してもらうには、上流側の設定が要る**
> （`UserClaimsMapping`）。**汎用認証サイト同士なら、上流にこれを入れる。**
> **ID 連携の要求スコープには `profile` が入っている**ので、対応付けがあれば返る。

| `client_name` | 用途 |
|---|---|
| `TestClient` | 自己テスト用（`redirect_uri` は `test_self_code` / `test_self_token`） |
| `TestClient1` | FAPI1 |
| `TestClient2` | FAPI2（Request Object を使う） |
| `TestClient3` | Device Authorization Grant。**`client_secret` を持たない**（パブリック クライアント） |
| `TestClient4` | CIBA |
| `TestClient5` | 登録の `scope` で、要求してよいスコープを制限した例（#198、E2E テスト用） |
| `TestClient6` | **クライアント単位で PKCE を必須**（`require_pkce`。#221、E2E テスト用） |
| `MVC_Sample` ほか | 絶対 URL の `redirect_uri` を持つサンプル |

> **自己テスト画面は、この名前で選んでいる**（`HomeController`）。**消すと画面が動かない。**

> **E2E だけが使うクライアントは、ここには無い**（#264）。
> **テスト利用者の登録（`saml2OAuth2Data`）として種データが作る**
> （`CommonLibrary/Extensions/Sts/TestClients.cs`。`IsDebug` ＋ `TestUserPWD` のときだけ）。
> **一覧を環境変数で差し替えると、環境ブロックの 32,767 文字に当たる**ため
> （`TESTING.md` 1 節）。

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

### `post_logout_redirect_uri` — ログアウト後の戻り先（任意。#232）

**RP からのログアウト（`/end_session`）の後に、RP へ戻してよい URL。**
OpenID Connect RP-Initiated Logout 1.0 §3.1 の `post_logout_redirect_uris` に当たる
（仕様は配列だが、既存の `redirect_uri_*` と同じく**1 本**で持つ）。

```json
"post_logout_redirect_uri": "https://rp.example.com/logged_out"
```

| 登録 | 扱い |
|---|---|
| **項目が無い** | **ログアウトはできるが、RP へは戻さない**（自サイトの画面に戻る） |
| 有る | **完全一致**したときだけ戻す（**大文字小文字も区別する**。§3 は exactly match） |

**口（エンドポイント）の URL は、設定キー `OAuth2EndSessionEndpoint`**（既定 `/end_session`）。
**既に配備された設定ファイルに無くても動く**（無ければ既定値を使う）。Discovery の
`end_session_endpoint` にも、この値が出る。

**`id_token_hint` が無い要求では、登録が有っても戻さない**（§3 の MUST）。
戻り先の正しさを確かめる手段が無いため。

> `CreateClientsIdentity` はこの項目を出力しない。必要なクライアントにだけ、手で足す。
> 画面（`/Manage/AddSaml2OAuth2Data`）から登録したクライアントでも設定できる。

### `redirect_uri` の記号

`test_self_code` / `test_self_token` は URL ではなく**記号**である。
サーバが `CmnEndpoints.GetRedirectUriFromConstr` で実 URL に解決する。

```
test_self_code        → OAuth2ClientEndpointsRootURI + OAuth2AuthorizationCodeGrantClient_Account
test_self_token       → OAuth2ClientEndpointsRootURI + OAuth2ImplicitGrantClient_Account
test_self_logout      → OAuth2ClientEndpointsRootURI + /Home/Index（post_logout_redirect_uri 用。#232）
```

| | |
|---|---|
| **新規登録** | `redirect_uri_code` の**既定が `test_self_code`** になっている。そのまま動作確認できる |
| **動作確認の後** | **自分の RP の折り返し先に書き換える**（**空白区切りで n 件書ける**。#306。4 節） |

> **`test_self_code_manage` という記号も在った**（C-10）。
> **管理画面の「トークンを取る」の折り返し先**で、**新規登録の既定**でもあった。
> **その画面は廃止された**ので、**記号ごと落とし、既定を `test_self_code` に戻した。**
>
> **その前には、この URL だけ「登録を確かめずに通す」分岐が `CheckRedirectUri` に在った**（C-10）。
> **`IsLockedDownTestEndpoints` の対象外で、本番で閉じられなかった**ので、分岐を消した。
> **分岐が無いことは、いまも `RT-C10.1` が測っている。** **例外は無い。**

**`OAuth2AuthorizationServerEndpointsRootURI` ではなく `OAuth2ClientEndpointsRootURI` を使う。**
既定では同じ値だが、変えるときは両方見ること。

### `redirect_uri` は、登録値と 1 文字も違っていてはならない（#263）

**照合は単純文字列比較である**（RFC 6749 §3.1.2.3 が指す RFC 3986 §6.2.1 /
OIDC Core §3.1.2.1 の exact match）。**大文字小文字も、末尾の `/` の有無も区別する。**

```
登録 : https://rp.example.com/Callback
要求 : https://rp.example.com/callback   → 通らない（invalid_request）
要求 : https://rp.example.com/Callback/  → 通らない（invalid_request）
```

**#263 より前は、大文字小文字を無視していた**（`ToLower()` 同士で比べていた）。
**登録と大文字小文字が違う `redirect_uri` を送っている RP は、認可に失敗するようになる。**
**登録どおりに送っている RP には影響しない。**

> **`post_logout_redirect_uri` は、#232 の時点から同じ比較である**（`StringComparison.Ordinal`）。
> **`redirect_uri` だけが揃っていなかったので、揃えた。**

### CORS — ブラウザから叩ける口を絞る（#265）

**口の性質ごとに CORS を分けている。** **両系統で同じ振る舞い**である
（仕組みは違う。net10.0 版はポリシー、net48 版は Web API の属性）。

| 口 | 方針 |
|---|---|
| `.well-known/openid-configuration` / `jwkcerts` / `samlmetadata` | **常に全開**（公開情報。RP の検出に使う） |
| `/userinfo` / `/token` / `/SetDeviceToken` / `/ciba_result` / `/2fa_result` | **許すオリジンだけ** |
| `/revoke` / `/introspect` / `/device_authz` / `/ciba_authz` / `/par` / `/ros` | **CORS を付けない**（ブラウザから叩く口ではない） |

**`Access-Control-Allow-Credentials` は付けない**（Cookie は飛ばない）。

#### クライアント単位で書ける — `web_origins`（#266）

**クライアント登録に `web_origins` を書くと、そのオリジンだけが許される。**
**構成ファイルと画面（`/Manage/AddSaml2OAuth2Data`）の両方**で使える。

```json
"web_origins": "https://spa.example https://spa2.example:8443"
```

| | |
|---|---|
| **書いたとき** | **その値だけ**（`redirect_uri_*` からは導出しない） |
| **空のとき** | **`redirect_uri_*` から導出**（下記） |
| **効く範囲** | **public クライアントのみ**（`client_secret` を持たないもの） |

> **Keycloak の Web origins、Auth0 の `web_origins`、
> Duende IdentityServer の `AllowedCorsOrigins` に相当する。**

#### 空なら、`redirect_uri` から導く

**設定を書かなくてよい。**
**public クライアント（`client_secret` を持たないもの）の `redirect_uri_*`**
から、オリジンを取る。**構成ファイルと画面登録の両方を見る**（#266）。

```json
"AuthenticationDevice_Web": { "redirect_uri_code": "http://localhost:5610/" }
```

→ **`http://localhost:5610` が許される。**

**SPA の `redirect_uri` は、必ずその SPA のオリジン上にある**ので、
**クライアントを登録すれば、CORS のための作業は要らない。**

> **Keycloak の Web origins の既定値 `+`（Valid Redirect URIs のオリジンを使う）と、
> Entra ID の SPA プラットフォームと同じ考え方**である。

**記号（`test_self_code` など）は解決してから取る。**
**カスタム スキーム**（`com.opentouryo:/oauthredirect`）**は落とす** — ブラウザの話ではないため。

#### `CorsAllowedOrigins` — 導出で拾えないものを足す（任意）

```json
"CorsAllowedOrigins": "https://spa.example https://spa2.example:8443"
```

- **区切りは空白かカンマ。** **末尾の `/` は付けない**（CORS の比較はオリジン同士）
- **`*` は書かない。** 落とすので許可されず、`ProductionCheck` が警告する
- **画面から登録した SPA も、導出に含まれる**（#266）。**ここに足す必要は無い。**
  `CorsAllowedOrigins` は、**どちらの登録にも書けないものを足すための口**である

#### 影響しないもの

| | 理由 |
|---|---|
| **サーバサイドの Web RP**（confidential） | `/token` は**サーバ間**で呼ぶ。ブラウザがするのは `/authorize` への遷移と戻りだけ |
| **ネイティブ / デスクトップ / モバイル** | **CORS を課すのはブラウザ**で、HTTP スタック直叩きは `Origin` を送らない |
| **同一オリジンの呼び出し** | **CORS は、別オリジンのときだけ働く。** 自己テスト画面からの呼び出しは、既定では同一オリジン |

> **WebView / Electron / Cordova / Flutter Web は、ブラウザ実行なので対象**である。
> 同梱の認証デバイスの web ビルドがこれに当たる（`AuthenticationDevice_Web` の登録から導出される）。

> **許可オリジンはキャッシュしない**（#271）。**毎回作るので、登録の変更が即座に効く。**
>
> 以前は 60 秒のキャッシュを持ち、保存時に捨てていた（#266）。
> **捨てられない経路が 2 つあった** — **複数インスタンスの他のインスタンス**と、
> **利用者の削除（`UsersAdmin`）で登録が FK で消える場合**である。
> **後者は、消した登録のオリジンが最長 60 秒許され続けるということである。**
>
> **引くのは `Origin` 付きの要求のときだけ**で、**読むのは URI 関連の 6 列だけ**（#270）。
> **公開情報の口は全開なので、この一覧を引かない。**

### 動的クライアント登録（RFC 7591 / 7592）— `EnableDynamicClientRegistration`（#307 の段階 1〜5-a）

**クライアント登録を WebAPI で行う。** **既定は無効**で、**開けると `/register` が出来る。**

```jsonc
// net10.0（appsettings.json）
"EnableDynamicClientRegistration": "false",   // **既定は false**（口そのものを張らない）
"DcrRegistrationEndpoint": "/register",       // 未設定・空なら /register
"DcrAccessTokenExpireTimeSpanFromSeconds": "300"  // 未設定・0 以下なら 300 秒
```

```xml
<!-- net48（app.config） -->
<add key="EnableDynamicClientRegistration" value="false" />
<add key="DcrRegistrationEndpoint" value="/register" />
<add key="DcrAccessTokenExpireTimeSpanFromSeconds" value="300" />
```

| | |
|---|---|
| **無効のとき** | **経路を張らない**（`404`）。**Discovery に `registration_endpoint` を出さない**。**専用 scope も広告しない** |
| **有効のとき** | `POST <DcrRegistrationEndpoint>` が開き、**Discovery に `registration_endpoint` が載る** |

**`IsLockedDownTestEndpoints` の対象ではない** — **これは本番で使う口**である。
**テスト用の口（`/TestHybridFlowWebAPI` ほか）とは別に、このキーで開閉する。**

#### 叩くには、専用 scope のアクセス トークンが要る

**この口は Bearer で守られている**（`/userinfo` と同じ形）。
**`client_registration` という専用の scope を持つトークンだけが通る**（無ければ `403`）。

**取り方は 2 つある**（#307 の段階 5-b で `client_credentials` を足した）。

```
# (1) client_credentials — **利用者のパスワードが要らない**（CI / IaC 向き）
POST /token
grant_type=client_credentials&client_id=<管理 API 用>&client_secret=<秘密>
&scope=client_registration

# (2) ROPC — **登録の所有者として入る**（段階 1 からの経路）
POST /token
grant_type=password&client_id=<管理 API 用>&client_secret=<秘密>
&username=<登録の所有者>&password=<パスワード>&scope=client_registration
```

| | |
|---|---|
| **`client_credentials` を推す** | **利用者のパスワードを CI に置かない。** **`EnableResourceOwnerPasswordCredentialsGrantType` を開けなくてよい**（OAuth 2.1 で外れたグラント） |
| **`client_credentials` は細い道で通る** | **`EnableDynamicClientRegistration` が true なら、`EnableClientCredentialsGrantType` が false でも、この scope のときだけ通る** — **「CI から登録を作る」ために、グラント全体を開けさせない**ためである（**専用 scope が出ない要求は `unsupported_grant_type`**） |
| **ROPC も残す** | **既存の配備を壊さない。** **ROPC で取るなら `EnableResourceOwnerPasswordCredentialsGrantType` も開ける** |
| **トークンは絞られる** | **どちらの経路でも、scope は `client_registration` 1 本だけ**になり（他を一緒に要求しても外す）、**有効期限は `DcrAccessTokenExpireTimeSpanFromSeconds`**（配備ぜんたいの 360 分ではない） |
| **Discovery** | **動的登録が有効なら `grant_types_supported` に `client_credentials` が載る**（**口が受け付ける事実**）。**「その scope しか出ない」ことは Discovery では表せない** |

##### 所有者は、どう決まるか（#307 の段階 5-b）

**作られる登録の所有者は、トークンから決まる。**

| トークン | 所有者 |
|---|---|
| **ROPC**（利用者が居る） | **`sub` の利用者**（**`aud` と組で引く** — `sub` は PPID になり得る） |
| **`client_credentials`**（利用者が居ない） | **認証したクライアントの所有者**（下の表） |

| 認証したクライアントの出どころ | 所有者 |
|---|---|
| **構成ファイル**（`OAuth2ClientsInformation`） | **`owner` 属性**（**利用者名**）の利用者 |
| **登録の表**（`Saml2OAuth2Data`） | **`OwnerUserId`**（`Users.Id`） |

**どちらも決まらなければ `403` ＋ `access_denied`** である。

| 決まらない場合 | |
|---|---|
| **`owner` を書いていない構成ファイルのクライアント** | **配備全体のもの**で、1 人の持ち物ではない |
| **`owner` の利用者が居ない** | **設定の誤り**（**利用者名を変えた後に直し忘れた**ときも、ここ） |
| **所有者の無い登録**（E2E の種データ） | **`OwnerUserId` が空** |

> **`401` ではなく `403` である。** **トークンは正しい**ので、
> **`401`（取り直せ）では誤誘導になる。**
>
> **見分けは `sub` でしている** — **`client_credentials` のトークンは `sub` にクライアント名が入る。**
> **そこまで確かめるのは、「利用者が消えたトークン」を
> クライアントの所有者に付け替えないため**である（**別人の持ち物として登録が増えてしまう**）。

> **構成ファイルが「名前」なのは、人が書く物だから**である（`Users.Id` は書けない）。
> **利用者名を変えたら、設定も直すこと。**
> **登録の表の側は id なので切れない**（段階 5-a-1 でそう移した）。

> **専用 scope は、登録に明記したクライアントにしか出さない。**
> **他の scope の「登録が無ければ制限しない」とは、逆の倒し方である** —
> **登録を作れる強い権限なので、既定で持たせてはならない。**
>
> **配るのは、構成ファイル（`OAuth2ClientsInformation` の `scope`）か**
> **管理画面（`/Manage/AddSaml2OAuth2Data` の `scope`）からだけ。**
> **動的登録で `client_registration` を登録しようとすると `invalid_client_metadata` で断る**
> （**自分と同じ強さの権限を、自分で配らせない**）。

#### 1 利用者 n クライアント（#307 の段階 5-a）

**1 人が、いくつでも登録できる。** **上限は設けていない。**

```
POST /register   →  201（1 件目）
POST /register   →  201（2 件目。**別の client_id / client_secret / registration_access_token**）
```

**段階 1 では 2 件目を `403` ＋ `access_denied` で断っていた。**
**絞っていたのは仕様の要求ではなく、器の都合である。**

| | 段階 1 〜 4 | 段階 5-a |
|---|---|---|
| **所有者の置き場所** | **`Users.ClientID`**（**利用者の行に 1 枠**。NOT NULL ＋ 一意索引） | **`Saml2OAuth2Data.OwnerUserId`**（**登録の行ごと**。`Users.Id` を指す） |
| **外部キー** | `Saml2OAuth2Data.ClientID` → `Users.ClientID` | **`Saml2OAuth2Data.OwnerUserId` → `Users.Id`**（`ON DELETE CASCADE`） |
| 1 人が持てる件数 | **1 件**（2 件目は `403`） | **n 件** |
| 上限 | — | **無い**（**洪水はレート制限で受ける**。#305 の段階 3。口の名前 `register`） |

**1 対 n にするには、結び付きを「n の側」に持たせる**（**1 の側には n 個置けない**）。
**それが「所有者の置き場所を移す」ということ**である。

> **`Users.ClientID` は、列ごと落とした。**
> **残して未使用にすると、DDL と食い違う**（**列が無いのに `INSERT` が書く**）。
> **`ApplicationUser.ClientID` のプロパティも落とした。**

##### 落としたことで、2 つの歪みが消えた

| | |
|---|---|
| **「宙に浮いた `client_id`」** | **`ApplicationUser.ClientID` の既定値が毎回 `Guid.NewGuid()`** だったので、**登録の無い利用者にも値が入っていた**。**`Register` がそれを掃除していた** |
| **「`DELETE` で空にできない」** | **NOT NULL ＋ 一意索引 ＋ 外部キー**に当たり、**空にすると `sql` で `DELETE` が `500`** になった（**`mem` では出なかった**。#307 の段階 2 で踏んだ） |

##### 所有者は `Users.Id` で持つ（名前ではない）

| 列 | 中身 | 役 |
|---|---|---|
| **`OwnerUserId`** | **`Users.Id`** | **所有者の鍵。** **利用者名を変えても切れない** |
| `ClientName` | **所有者の利用者名** | **ラベル。** `Helper.GetClientName` が「登録が在るか」の判定と、`client_credentials` の `sub` に使う |

**`OwnerUserId` は空のことがある。**

| | |
|---|---|
| **E2E の種データ**（#264） | **所有者を持たない**（**構成ファイルのクライアントと同じ立場** ＝ 配備全体のもの） |
| 移行中の行 | **`UPDATE` で埋め損ねた行**（下の移行手順） |

> **以前は、種データのクライアント 1 件につき利用者 1 人を作っていた** —
> **外部キーを満たすためだけ**である。**張り替えたので、その利用者はもう作らない。**

##### 管理画面は、n 件を並べる（段階 5-a-2）

**`/Manage/Saml2OAuth2DataList` が、自分の登録を並べる**（`DataProvider.GetByOwner`）。

| 画面 | 役 |
|---|---|
| **`/Manage/Index`** | **件数 ＋ 一覧への導線 1 本**（**ここでは追加も削除もしない**） |
| **`/Manage/Saml2OAuth2DataList`** | **一覧。** **行ごとに「編集」と「削除」** ＋ **「新しいクライアントを登録する」** |
| **`/Manage/AddSaml2OAuth2Data`** | **`?clientId=…` で編集、引数なしで新規**（**従来の 3 回押しは、新規の経路**） |

**一覧に出すのは 4 列**（`client_id` / モード / `redirect_uri`（認可コード）/ **登録の経路**）。

> **`client_secret` は一覧に出さない**（**編集の画面で見せる**）。
> **行の VM は、その値を持っていない** — **出し忘れでは防げない**ので、器ごと分けてある
> （`registration_access_token` も同じ）。
>
> **「登録の経路」は `registration_access_token` の有無で見ている** —
> **動的登録で作られた行は、RP が管理 API（RFC 7592）でも直せる**ことが分かる。

###### 他人の登録に触れないこと

**`clientId` は URL とフォームから来る**ので、**所有者の照合はサーバ側で行う**
（`DataProvider.GetByOwnerAndClientID`）。

| 送られたもの | 画面 |
|---|---|
| **自分の登録の `client_id`** | **編集できる / 消せる** |
| **他人の `client_id`** | **`Error` 画面**（**新規としても開かない** — **他人の行を上書きさせない**） |
| **所有者の無い登録**（構成ファイル発・種データ） | **同じく `Error`**（**配備全体のものなので、1 人の持ち物にしない**） |
| **在りもしない `client_id`** | **同じく `Error`**（**「在るが自分の物でない」と撃ち分けない**） |
| **空の `clientId`**（削除） | **何も消さない**（**先頭 1 件を黙って消さない**） |

**編集では `client_id` を作り直せない。**
**作り直すと別のクライアントになり、更新ではなく新規の登録になる** —
**`registration_access_token` も引き継げないので、管理 API から触れなくなる。**

###### 「その人のクライアント 1 つ」で足りる所

| | |
|---|---|
| **自己テストの「ログイン・ユーザの Client」** | `Helper.GetClientIdByName(利用者名)` |
| **認可ログの `User Account`** | 同上（**ログの 1 行**） |

> **`client_id` の昇順で先頭**を使う（**段階 5-a-2 で並びを決めた**）。
> **`mem` も方言 3 つも同じ順**にしてある（`DataProvider.GetByOwner` の `ORDER BY`）。
> **決めていないと、一覧の行が毎回入れ替わる。**

##### DDL — 既存の配備は、4 つの文を流す（#307 の段階 5-a）

**順番が大事である。** **`2` を先にやらないと、所有者が分からなくなる。**

```sql
-- SQL Server
-- 1. 足す
ALTER TABLE [Saml2OAuth2Data] ADD [OwnerUserId] [nvarchar](38) NULL;
-- 2. **退避**（Users.ClientID を落とす前に、所有者を写す）
UPDATE [Saml2OAuth2Data] SET [OwnerUserId] =
    (SELECT [Id] FROM [Users] WHERE [Users].[ClientID] = [Saml2OAuth2Data].[ClientID]);
-- 3. 外部キーを張り替える
ALTER TABLE [Saml2OAuth2Data] DROP CONSTRAINT [FK.Saml2OAuth2Data.Users_ClientID];
ALTER TABLE [Saml2OAuth2Data] WITH CHECK ADD CONSTRAINT [FK.Saml2OAuth2Data.Users_OwnerUserId]
    FOREIGN KEY([OwnerUserId]) REFERENCES [Users] ([Id]) ON DELETE CASCADE;
-- 4. 最後に、一意索引 → 列
DROP INDEX [ClientIDIndex] ON [Users];
ALTER TABLE [Users] DROP COLUMN [ClientID];
```

```sql
-- Oracle
ALTER TABLE "Saml2OAuth2Data" ADD ("OwnerUserId" NVARCHAR2(38) NULL);
UPDATE "Saml2OAuth2Data" SET "OwnerUserId" =
    (SELECT "Id" FROM "Users" WHERE "Users"."ClientID" = "Saml2OAuth2Data"."ClientID");
ALTER TABLE "Saml2OAuth2Data" DROP CONSTRAINT "FK.Saml2OAuth2Data.Users_ClientID";
ALTER TABLE "Saml2OAuth2Data" ADD CONSTRAINT "FK.Saml2OAuth2Data.Users_OwnerUserId"
    FOREIGN KEY("OwnerUserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
ALTER TABLE "Users" DROP CONSTRAINT "ClientIDIndex";
ALTER TABLE "Users" DROP COLUMN "ClientID";
```

```sql
-- PostgreSQL（引用符なしなので、識別子は小文字に畳まれる）
ALTER TABLE Saml2OAuth2Data ADD COLUMN OwnerUserId varchar(38) NULL;
UPDATE Saml2OAuth2Data SET OwnerUserId =
    (SELECT Id FROM Users WHERE Users.ClientID = Saml2OAuth2Data.ClientID);
ALTER TABLE Saml2OAuth2Data DROP CONSTRAINT FK_Saml2OAuth2Data_Users_ClientID;
ALTER TABLE Saml2OAuth2Data ADD CONSTRAINT FK_Saml2OAuth2Data_Users_OwnerUserId
    FOREIGN KEY(OwnerUserId) REFERENCES Users (Id) ON DELETE CASCADE;
DROP INDEX ClientIDIndex;
ALTER TABLE Users DROP COLUMN ClientID;
```

> :warning: **これは、振る舞いが変わる変更である。**
> **これまで `403` で断っていた 2 件目の登録が、通るようになる。**
> **管理画面から作った登録も、所有者の持ち方が変わる**（**画面の見え方は、まだ同じ**）。

##### 利用者を消したら、その人の登録は全部消える

**新しい外部キーも `ON DELETE CASCADE`** である（**従来と同じ**）。
**`OwnerUserId` が空の登録は残る**（**持ち主が居ないため**。種データがそれ）。

#### 受け付けるメタデータ（RFC 7591 §2）

```
POST /register
Authorization: Bearer <client_registration の AT>
Content-Type: application/json

{ "redirect_uris": ["https://rp.example.com/cb"], "scope": "openid email" }
```

| メタデータ | 扱い |
|---|---|
| **`redirect_uris`**（必須） | **絶対 URI で、フラグメント禁止**（RFC 6749 §3.1.2）。**ワイルドカードは受けない。** **`code` を使う登録は `redirect_uri_code`、`token` / `id_token` を使う登録は `redirect_uri_token` の列に入る**（両方使うなら両方に） |
| **`grant_types`** | **既定は `authorization_code`**（§2）。**この配備が広告しているものだけ** |
| **`response_types`** | **既定は `code`**。**`code` を使うなら `authorization_code`、`token` / `id_token` を使うなら `implicit` が要る**（§2 の対応） |
| `scope` | **`scopes_supported` の範囲内**。**`client_registration` は断る** |
| `client_uri` / `logo_uri` / `tos_uri` / `policy_uri` / `contacts` / `software_id` / `software_version` | **保存して返すだけ** |
| `subject_type` / `id_token_signed_response_alg` | 既にある列に入る（扱えない値は断る） |
| **`token_endpoint_auth_method`** | **4 つとも登録できる**（段階 3）。**`private_key_jwt` は `jwks`、`tls_client_auth` は `tls_client_auth_subject_dn` が要る**（無ければ断る）。**下の「クライアント認証の方法」** |
| **`jwks`** | **受け付ける**（段階 3）。**RSA 1 本 ＋ EC 1 本まで**（列が 1 本ずつ）。**同じ種類が 2 本来たら断る** |
| **`tls_client_auth_subject_dn`** | **受け付ける**（段階 3。RFC 8705 §2.1.2）。**照合は完全一致** |
| **`token_endpoint_auth_signing_alg`** | **受け付ける**（段階 3）。**`RS256` / `ES256`**。**空なら絞らない**（#262） |
| **`jwks_uri`** | **断る**（`invalid_client_metadata`）。**鍵を URL から引く実装が無い** — **クライアント認証の経路が同期**で、取得を差し込めない（**別 Issue**）。**受け取って無視すると、`private_key_jwt` が黙って通らなくなる** |
| **`software_statement`** | **受け付ける**（段階 4）。**信頼する発行者が署名した JWT**で、**主張した値は本文（plain JSON）に勝つ**。**信頼する発行者を 1 件も設定していなければ断る**（`unapproved_software_statement`。従来どおり）。**下の「`software_statement`」** |
| **`client_name`** | **受け取っても無視する**（§3.2.1 が認めている）。**`ClientName` の列は利用者名**であり、**`Helper.GetClientName` が「登録が在るか」の判定に使っている。** **応答にも入れない** |
| 上記以外 | **無視する**（§3.2.1） |

**応答は `201 Created`**（§3.2.1）。`client_id` / `client_secret` /
`client_id_issued_at` / `client_secret_expires_at`（**`0` ＝ 期限なし**）と、
**登録された内容**を返す。

| 誤り | 状態 |
|---|---|
| メタデータの不備 | **`400`** ＋ `invalid_redirect_uri` / `invalid_client_metadata` / **`invalid_software_statement`** / `unapproved_software_statement`（§3.2.2） |
| トークンが無い・無効 | **`401`** ＋ `WWW-Authenticate: Bearer`（RFC 6750 §3.1） |
| scope が足りない | **`403`** ＋ `insufficient_scope` |
| 無効の配備 | **`404`**（口が無い） |

**レート制限の対象**である（#305 の段階 3。口の名前は `register`）。
**誰がいつ登録したかはオペレーション ログに残る**（`client_secret` は書かない）。

#### 登録した `scope` / `grant_types` / `response_types` は、実際に効く（#307 の段階 1）

**保存して返すだけにはしていない。**
**登録が「`code` だけ」と言っているのに認可サーバが他も通すのでは、登録の意味が無い。**

| 登録 | どこで効くか |
|---|---|
| **`scope`** | **トークンを出すとき**（`Helper.FilterSupportedScopes`）。**範囲外は外して発行する**（断らない。RFC 6749 §3.3） |
| **`response_types`** | **認可エンドポイント**（`CmnEndpoints.CheckAuthZEndpoint`）。**利用者を操作させる前に `unauthorized_client` で断る** |
| **`grant_types`** | **トークン エンドポイント**（`CmnEndpoints.CheckClientMode` の手前）。`unauthorized_client` |

> **`ClientModePolicy`（`oauth2_oidc_mode`）とは役割が違う。**
>
> | | 何を見るか |
> |---|---|
> | **`grant_types` / `response_types`** | **そのクライアントが、その経路を登録したか**（RP の申告） |
> | `ClientModePolicy` | **その登録種別（normal / fapi1 / fapi2…）に、その経路と証明を許すか**（AS の方針） |

**列が空なら絞らない。** **既存の登録はこの列を持たない**ので、
**RFC 7591 §2 の既定（`authorization_code` / `code`）を当てはめてはならない** —
**当てはめると「`code` 以外が通らなくなる」破壊になる。**
**既定を書き込むのは、動的登録で作るときだけ**である。

> **`scope` の絞りは、これまで構成ファイルのクライアントにしか効いていなかった。**
> **`Helper.GetClientScopes` が構成ファイル（`OAuth2ClientsInformation`）だけを見ていた**ため、
> **DB に登録したクライアント（管理画面・動的登録）は「登録が無い」扱いになり、**
> **#198 の後半（クライアントごとの絞り）が一切効いていなかった**
> （`scopes_supported` の絞りだけが効いていた）。**#307 の段階 1 で、DB も見るようにした。**

#### クライアント認証の方法 — `token_endpoint_auth_method`（#307 の段階 3）

**このクライアントが自分を証明する方法**である（RFC 7591 §2。**値は 1 つ**）。
**登録された方法でなければ、認証を通さない。**

| 登録 | 通る証明 |
|---|---|
| **空**（未登録） | **`client_secret_basic` と `client_secret_post`**（**暗黙に許す**） |
| `client_secret_basic` / `client_secret_post` | 同じ（**明示しても変わらない**） |
| **`private_key_jwt`** | **`client_assertion` だけ**（**秘密では通らない**） |
| **`tls_client_auth`** | **クライアント証明書だけ**（同じ） |
| **既知でない値** | **通さない**（登録の誤り。#224 の段階 2 と同じ方針） |

> **つまり「強い方法は明示が要る」。**
> **鍵や DN を登録しただけでは、その方法では通らない。**
> **以前は「登録されている資格のどれかで通る」**作りだったので、
> **鍵を登録しても秘密でも入れた** ＝ **登録で求めた強さが効かなかった。**

**効く口**は、`/token`（認可コード・`refresh_token`・`client_credentials` ほか）・
`/par`・`/revoke`・`/introspect`・`/ciba_authz` である
（**クライアント認証を行う所すべて**）。

| 効かない所 | なぜ |
|---|---|
| **SAML2 の `AuthnRequest` の署名検証** | **クライアント認証ではない**（登録された鍵を、別の用途で使っている） |
| **Request Object（JAR）の署名検証** | 同じ（`request_object_signing_alg` の側） |
| **JWT Bearer の認可グラント**（RFC 7523 §2.1） | **自前で署名を検証する経路**で、クライアント認証を通らない |
| **秘密を持たないクライアント**（public ＋ PKCE） | **認証しない**（RFC 6749 §3.2.1）。**扱いは変えていない** |

##### :warning: 既存の配備は、設定に 1 行足す必要がある

**`private_key_jwt` や mTLS を使っているクライアントは、方法を明記しないと認証できなくなる。**
**構成ファイル（`OAuth2ClientsInformation`）にも、項目を足した。**

```jsonc
"6336f8ff137044c4a30bbbdcd6c2cf5b": {
  "client_name": "TestClient2",
  "oauth2_oidc_mode": "fapi2",
  "token_endpoint_auth_method": "private_key_jwt",   // ← 足す（段階 3）
  "jwk_rsa_publickey": "..."
}
```

**管理画面から登録したクライアント**（`Saml2OAuth2Data`）は、
**`/Manage/AddSaml2OAuth2Data` の「クライアント認証の方法」で選ぶ。**

> **雛形（`_appsettings.json` / `_app.config`）は直してある**ので、
> **新しく作る配備では、そのまま動く。**

##### 気をつける所

| | |
|---|---|
| **`client_secret_basic` と `client_secret_post` は区別しない** | **どちらで来たかを、認証の層は知らない**（口が同じ形に正規化して渡す）。**どちらを登録しても、両方が通る** |
| **`client_secret` は、方法に関わらず発行する** | **秘密しか使えない口が在る**ため（**デバイス フローは `client_assertion` を読まない**）。**登録した方法以外では通らない**ので、**秘密が在っても弱くならない** |
| **`device_code` ＋ `private_key_jwt` は登録できない** | **RFC 8628 の口が `client_assertion` を読まない**ので、**永久に認証できない登録になる。** **`tls_client_auth` は通る**（証明書は口に渡っている） |
| **`PUT` で方法を省くと、秘密ベースに戻る** | **§2.2 のとおり**（省略は削除要求）。**ただし鍵と DN は持ち越す** — **管理画面から入れた鍵を消してはならない。** **方法を明記するなら、材料も毎回送ること** |
| **`jwks` は RSA 1 本 ＋ EC 1 本まで** | **列が 1 本ずつ**だから。**同じ種類が 2 本来たら断る** — **先頭を採ると、もう一方の鍵で署名したときに失敗する** |

#### DDL — `Saml2OAuth2Data` に 11 列足す（#307 の段階 1）

**既存の列は変えていない**ので、**既存のデータベースは `ALTER` で足りる**（流し直しも可）。
**末尾に足してある**ので、**`ALTER … ADD` と作り直した `CREATE` で、物理的な並びも揃う。**

```sql
-- SQL Server
ALTER TABLE [Saml2OAuth2Data] ADD
    [Scopes] [nvarchar](2000) NULL,
    [GrantTypes] [nvarchar](256) NULL,
    [ResponseTypes] [nvarchar](256) NULL,
    [JwksUri] [nvarchar](512) NULL,
    [ClientUri] [nvarchar](512) NULL,
    [LogoUri] [nvarchar](512) NULL,
    [TosUri] [nvarchar](512) NULL,
    [PolicyUri] [nvarchar](512) NULL,
    [Contacts] [nvarchar](2000) NULL,
    [SoftwareId] [nvarchar](256) NULL,
    [SoftwareVersion] [nvarchar](64) NULL
```

```sql
-- Oracle（1 文で複数列を足せる）
ALTER TABLE "Saml2OAuth2Data" ADD (
    "Scopes" NVARCHAR2(2000) NULL,
    "GrantTypes" NVARCHAR2(256) NULL,
    "ResponseTypes" NVARCHAR2(256) NULL,
    "JwksUri" NVARCHAR2(512) NULL,
    "ClientUri" NVARCHAR2(512) NULL,
    "LogoUri" NVARCHAR2(512) NULL,
    "TosUri" NVARCHAR2(512) NULL,
    "PolicyUri" NVARCHAR2(512) NULL,
    "Contacts" NVARCHAR2(2000) NULL,
    "SoftwareId" NVARCHAR2(256) NULL,
    "SoftwareVersion" NVARCHAR2(64) NULL
);
```

```sql
-- PostgreSQL（引用符なしなので、識別子は小文字に畳まれる）
ALTER TABLE Saml2OAuth2Data
    ADD COLUMN Scopes varchar(2000) NULL,
    ADD COLUMN GrantTypes varchar(256) NULL,
    ADD COLUMN ResponseTypes varchar(256) NULL,
    ADD COLUMN JwksUri varchar(512) NULL,
    ADD COLUMN ClientUri varchar(512) NULL,
    ADD COLUMN LogoUri varchar(512) NULL,
    ADD COLUMN TosUri varchar(512) NULL,
    ADD COLUMN PolicyUri varchar(512) NULL,
    ADD COLUMN Contacts varchar(2000) NULL,
    ADD COLUMN SoftwareId varchar(256) NULL,
    ADD COLUMN SoftwareVersion varchar(64) NULL;
```

**幅は既存の流儀に合わせてある** — URI は **512**（`Const.MaxLengthOfUri`）、
空白区切りの列挙は **2000**（Oracle の `NVARCHAR2` の上限。#306 と同じ理由）、
`grant_types` / `response_types` は **256**（既知の値しか入らない）。

**`response_types` は、要素の中の空白を `+` にして入れる**
（`code id_token` → `code+id_token`）。**空白は区切りだから**である。
**比較のときに空白へ戻す。**

**画面（`/Manage/AddSaml2OAuth2Data`）にも、この 11 項目が出る** —
**登録の内容であり、画面と WebAPI で持てる項目をずらさない**ため。

#### 管理 API（RFC 7592）— `GET` / `PUT` / `DELETE`（#307 の段階 2）

**登録の応答に、管理の口とその鍵が入る**（RFC 7592 §3 で、**どちらも REQUIRED**）。

| | |
|---|---|
| **`registration_client_uri`** | **`…/register/{client_id}`**（絶対 URI）。**サーバが渡す** — **クライアントに組み立てさせない**（Appendix B） |
| **`registration_access_token`** | **その 1 件だけに効く Bearer トークン。** **返るのは、この 1 回だけ**（**保管しているのはハッシュ**なので、**再表示できない**） |

**3 つの口**（どれも `Authorization: Bearer <registration_access_token>`）。

| | |
|---|---|
| **`GET`** | **登録の全体を返す**（`200`）。**`client_secret` は返さない** |
| **`PUT`** | **全置換**（`200`）。**`client_id` は必須・一致必須。** **`client_secret` を入れるなら一致必須**（**自分で決めさせない**） |
| **`DELETE`** | **`204`（本体なし）。** **同意も落とす**（**所有者の行は触らない。下の節**）。**同じ利用者が登録し直せる** |

**専用 scope（`client_registration`）のアクセス トークンでは叩けない** —
**作る権限と、直す権限は別物**である（§2 : クライアントは `registration_access_token` を使うこと）。

```bash
# 読む
curl -X GET  "https://localhost:44300/MultiPurposeAuthSite/register/<client_id>" \
     -H "Authorization: Bearer <registration_access_token>"

# 直す（全置換。client_id を入れること）
curl -X PUT  "https://localhost:44300/MultiPurposeAuthSite/register/<client_id>" \
     -H "Authorization: Bearer <registration_access_token>" \
     -H "Content-Type: application/json" \
     -d '{"client_id":"<client_id>","redirect_uris":["https://rp.example/cb"],"scope":"openid"}'

# 消す
curl -X DELETE "https://localhost:44300/MultiPurposeAuthSite/register/<client_id>" \
     -H "Authorization: Bearer <registration_access_token>"
```

##### 誤りの形

| 何が起きたか | 返すもの |
|---|---|
| **トークンが無い・偽・他の登録のもの・知らない `client_id`** | **`401` ＋ `invalid_token`**（§2.1 〜 §2.3 の MUST）。**`404` にしない** — **「在るが触れない」と「無い」を、外から区別させない** |
| `client_id` が無い / 一致しない、`client_secret` が一致しない、**専用 scope の自己付与**、`scope` が未対応 | **`400` ＋ `invalid_client_metadata`** |
| `redirect_uris` が無い・形が不正 | **`400` ＋ `invalid_redirect_uri`** |
| 本体が JSON でない | **`400` ＋ `invalid_request`** |
| **この配備で動的登録を開けていない** | **`404`**（**口そのものを張らない**） |

##### `PUT` は全置換である（いちばん間違えやすい所）

**§2.2 : クライアントは、返された全てのメタデータを入れること。省いた項目は「消す要求」として扱われる。**
**差分更新（`PATCH`）は仕様に無い** ので、**`GET` で読んで、直して返す**のが前提である。

| | 列 |
|---|---|
| **要求から作り直す**（**省いたら消える**） | `redirect_uris` / `scope` / `grant_types` / `response_types` / `client_uri` / `logo_uri` / `tos_uri` / `policy_uri` / `contacts` / `software_id` / `software_version` / `subject_type` / `id_token_signed_response_alg` |
| **持ち越す**（**要求では変えられない**） | `client_id` / `client_secret` / `ClientName`（所有者の利用者名）/ `ClientMode` / `RequirePkce` / `registration_access_token` のハッシュ ＋ **動的登録では設定できない列**（`RedirectUriSaml` / `PostLogoutRedirectUri` / `WebOrigins` / `Jwk*` / `TlsClientAuthSubjectDn` / `TokenEndpointAuthSigningAlg` / `RequestObjectSigningAlg`） |

> **動的登録で設定できない列を持ち越すのは、全置換の例外ではない** —
> **それらは「このクライアントが動的登録で登録したメタデータ」ではない。**
> **管理画面から入れた値を、`PUT` で消してはならない。**

**気をつける所が 3 つある。**

| | |
|---|---|
| **`scope` を省くと、絞りが消える** | **列が空 ＝ 絞らない**（段階 1 の決め）。**省略は「狭める」ではなく「広がる」**（この配備が支える `scope` 全部になる）。**`client_registration` だけは、明記しても断る** |
| **`redirect_uris` は省けない** | **OIDC DCR 1.0 §2 で REQUIRED**。省いたら `400` なので、**うっかり全消しは起こらない** |
| **`grant_types` / `response_types` を省くと、狭まる** | **RFC 7591 §2 の既定**（`authorization_code` / `code`）**が書かれる。** `refresh_token` や `implicit` は、**書かなければ消える** |

**読み取り専用の 4 つ**（`registration_access_token` / `registration_client_uri` /
`client_id_issued_at` / `client_secret_expires_at`）**は、入っていても無視する。**
**§2.2 は「入れるな」と書くが、断ると「`GET` して直して返す」が成り立たない。**

##### トークンは回さない

**§5 / A.1 は「読み出し・更新のときに新しいトークンを出してよい」（MAY）としているが、回さない。**
**回すと、どちらが有効か取り違えた RP が、管理できなくなる。**
**`GET` / `PUT` の応答では、提示されたトークンをそのまま返す**
（**こちらはハッシュしか持たない**ので、**こうでなければ §3 の REQUIRED を満たせない**）。

**`client_id_issued_at` は `GET` / `PUT` では返さない** — **保管していない**
（RFC 7591 §3.2.1 で任意）。**発行時の `201` だけが返す。**

##### 管理画面との噛み合い

| | |
|---|---|
| **画面の保存では、トークンを持ち越す** | **画面の保存は行を丸ごと上書きする**ので、**持ち越さないと消える**（RP が管理 API を使えなくなる）。**画面には出さない** |
| **画面で `client_id` を作り直すと、管理 API では触れなくなる** | **別のクライアントになる**ので、**そのトークンは、もう効いてはならない** |
| **画面で作った登録・段階 1 で作った登録には、トークンが無い** | **この口では触れない**（`401`）。**所有者は、画面で自分の 1 件を編集・削除できる**（`/Manage/AddSaml2OAuth2Data`） |

##### 削除したクライアントのトークン（✅ 修正済み。#307 の段階 2）

**`DELETE` で登録を消すと、そのクライアントのアクセス トークンも、その場で通らなくなる**
（RFC 7592 §2.3 : 削除したら、そのクライアントのトークンを無効にすべき）。

> **以前は通っていた** — **アクセス トークンの検証にある「クライアントがまだ在るか」の確認が、
> 効いていなかった**（`Helper.GetClientSecret` は**未登録でも空文字を返す**ので、
> `!= null` の判定が常に真だった）。**`Helper.HasClient` で「行が在るか」を見るようにした。**
> **画面の `RemoveSaml2OAuth2Data` でも、設定からの撤去でも、同じように止まる。**

**限界** : **外部のリソース サーバが、自前で JWT を検証する場合は止まらない**
（**鍵と `exp` だけで通る**ため。**`/revoke` と同じ限界**である）。
**この IdP の検証を通る口（`/userinfo` ほか）では止まる。**

##### `DELETE` は、所有者の行を触らない

**消すのは登録の行だけ**である（**同意も落とす**）。**利用者（`Users`）の行は触らない。**

| | |
|---|---|
| **所有者の持ち方** | **`Saml2OAuth2Data.OwnerUserId`**（**登録の行ごと**。#307 の段階 5-a-1）。**行が消えれば、結び付きも一緒に消える** |
| **登録し直せる** | **同じ利用者が、何件でも作れる**（**上限は無い**） |
| 管理画面 | **`RemoveSaml2OAuth2Data` も、登録の行だけを消す** |

> **段階 1 〜 4 は `Users.ClientID`（利用者の行の 1 枠）で所有者を持っていた**ので、
> **「`DELETE` でそこを空にするか」が論点だった** — **空にできなかった。**
> **NOT NULL ＋ 一意索引（`ClientIDIndex`）＋ `Saml2OAuth2Data` からの外部キー**に当たり、
> **`sql` で `DELETE` が `500`** になった（**`mem` には制約が無いので出なかった**。
> 段階 2 の実測。**`RT-307.11` と `RT-307.12` が捕まえた**）。
>
> **段階 5-a-1 で `Users.ClientID` を列ごと落としたので、この論点そのものが消えた。**

##### DDL — `Saml2OAuth2Data` に 1 列足す（#307 の段階 2）

```sql
-- SQL Server
ALTER TABLE [Saml2OAuth2Data] ADD
    [RegistrationAccessToken] [nvarchar](128) NULL
```

```sql
-- Oracle
ALTER TABLE "Saml2OAuth2Data" ADD ("RegistrationAccessToken" NVARCHAR2(128) NULL);
```

```sql
-- PostgreSQL（引用符なしなので、識別子は小文字に畳まれる）
ALTER TABLE Saml2OAuth2Data ADD COLUMN RegistrationAccessToken varchar(128) NULL;
```

**入るのはハッシュ**（SHA-256 を base64 にすると 44 文字。**替えても入るように 128**）。
**暗号化（`SecretProtector`。#297）はしない** — **照合しかしない**ので、**元に戻す必要が無い。**
**画面には出さない。**

##### DDL — `Saml2OAuth2Data` に 1 列足す（#307 の段階 3）

```sql
-- SQL Server
ALTER TABLE [Saml2OAuth2Data] ADD
    [TokenEndpointAuthMethod] [nvarchar](32) NULL
```

```sql
-- Oracle
ALTER TABLE "Saml2OAuth2Data" ADD ("TokenEndpointAuthMethod" NVARCHAR2(32) NULL);
```

```sql
-- PostgreSQL（引用符なしなので、識別子は小文字に畳まれる）
ALTER TABLE Saml2OAuth2Data ADD COLUMN TokenEndpointAuthMethod varchar(32) NULL;
```

**空は「明示なし」**＝ **`client_secret_basic` / `client_secret_post` を暗黙に許す**
（上の「クライアント認証の方法」）。**既存の行は空のまま**でよい —
**秘密で認証しているクライアントは、そのまま動く。**
**`private_key_jwt` / mTLS のクライアントだけ、値を入れること。**

##### レート制限（#305 の段階 3）

**管理 API は、登録そのものとは別のバケツで数える**（口の名前 `register_mgmt`）。
**パスに `client_id` が入る**ので、**前方一致で見る。**
**管理の洪水で、登録そのものを止めないため**である。

#### `software_statement` — 署名付きの主張を受ける（#307 の段階 4）

**クライアントの登録内容を、信頼する発行者が署名した JWT で保証させる**（RFC 7591 §2.3）。

```jsonc
// net10.0（appsettings.json）
"SoftwareStatementIssuers": {
  "vendor1": {
    "display_name": "Vendor 1",            // ログに出す名前（空なら鍵）
    "enabled": "true",                      // 空・未設定は true
    "issuer": "https://vendor.opentouryo.com",  // **期待する iss**（完全一致）
    "cer_file_path": "C:/root/files/resource/X509/SHA256RSA_Client.cer",
    "alg": "RS256"                          // **ヘッダの alg と照合する**（空なら RS256）
  }
},
"RequireSoftwareStatement": "false"          // **既定は false**
```

```xml
<!-- net48（app.config。OAuth2ClientsInformation と同じく 1 本の JSON 文字列） -->
<add key="SoftwareStatementIssuers" value='{"vendor1":{"issuer":"https://vendor.opentouryo.com","cer_file_path":"C:/root/files/resource/X509/SHA256RSA_Client.cer","alg":"RS256"}}' />
<add key="RequireSoftwareStatement" value="false" />
```

##### 鍵は「発行者ごと」である。クライアントごとではない

**ここで一番取り違えやすい所**である。

| | 誰の鍵か | 件数 | どこに登録するか |
|---|---|---|---|
| **`jwks`** / **`tls_client_auth_subject_dn`**（段階 3） | **そのクライアント自身** | **クライアントごとに 1 件** | **`Saml2OAuth2Data` の列**（動的登録 / 管理画面） |
| **`cer_file_path`**（段階 4） | **主張を書いた側** — **ソフトウェアの発行元、またはエコシステムの名簿** | **発行者ごとに 1 件**（配備全体で数件） | **設定ファイル** |

**`software_statement` は 1 つのソフトウェアに 1 枚配られ、その全ての配置が同じものを提示する**
（RFC 7591 §2 の `software_id` は「全インスタンスで同じ値」）。
**だから、登録されるクライアントが 100 件になっても、検証鍵は発行者 1 件につき 1 つで足りる。**

```
ベンダー（または名簿）が 1 回署名  →  ソフトウェアに同梱される
                                        → A 社の配置が POST /register に添えて出す
                                        → B 社の配置も、同じ statement を出す
```

**設定ファイルに置いているのは、件数が数件で、増減が稀だから**である
（**提携先が増えたときだけ**）。**管理画面は用意していない** —
**`.cer` をファイルとして受け取る仕掛けが別途要り**、
**配備全体の信頼の決めなので、1 利用者の持ち物でもない。**
**ID 連携の上流が設定 →（#292 の段階 2 で）DB ＋ 管理画面へ移ったのと同じ道**は通せるが、
**それは DDL ＋ 両アプリの画面**である（別段階）。

##### 主張は、本文（plain JSON）に勝つ

**`software_statement` は、要求の本文の中に入れる「署名済みの JWT 1 本」**である。
**同じ項目が 2 か所に現れ得る。**

```jsonc
POST /register
{
  "redirect_uris": ["https://attacker.example.com/cb"],  // plain JSON（誰でも書ける）
  "scope":         "openid email",                        // plain JSON
  "software_statement": "eyJhbGciOi..."                   // 署名済み。中に redirect_uris が在る
}
```

| 項目 | どこに在るか | 入る値 |
|---|---|---|
| **`redirect_uris`** | **両方** | **statement の値**（**statement が勝つ**。§2.3 は **MUST**） |
| `scope` | 本文だけ | **そのまま使う** |
| `software_id` / `software_version` | statement だけ | **そのまま使う** |
| `iss` / `aud` / `exp` / `nbf` / `iat` / `jti` | statement の **JWT のクレーム** | **メタデータとして扱わない**（検証に使うだけ） |

**これが機能の要点**である — **ベンダは security に効く項目（折り返し先・`grant_types`・
認証方法）を statement で固定し**、**配置ごとに変わる項目は本文に書かせる。**
**配置側が折り返し先を勝手な所に書き換えても、statement が上書きして効かない。**

**食い違っても断らない。** **statement を採り、オペレーション ログに残す**
（**上書きした項目の名前だけ。値は書かない**）。**優先順位を仕様が MUST で定めている**ためである。

**`software_statement` 自身は、保管しない。** **応答にも返さない**（§3.2.1 で任意）。
**＝ この段階で列は増えていない**（**既存の配備に `ALTER` が要らない**）。

##### 断り方（RFC 7591 §3.2.2）

**順に見る。** **1 番目が先なのは、既存の配備の振る舞いを変えないため**である。

| 順 | 見るもの | 誤り |
|---|---|---|
| 1 | **信頼する発行者が 0 件**（段階 4 の設定を書いていない） | **`unapproved_software_statement`**（**従来どおり**） |
| 2 | JWT として読めない・署名の部分が無い | `invalid_software_statement` |
| 3 | **`iss` が無い**（§2.3 は必須） | `invalid_software_statement` |
| 4 | **`iss` が信頼一覧に無い** | **`unapproved_software_statement`** |
| 5 | ヘッダの `alg` が、登録された `alg` と違う | `invalid_software_statement` |
| 6 | **署名が合わない** | `invalid_software_statement` |
| 7 | **`exp` が切れている**（**在るときだけ**見る） | `invalid_software_statement` |
| 8 | **`aud` が `IssuerId` でない**（**在るときだけ**見る） | `invalid_software_statement` |

> **`aud` の扱いは、仕様が定めていない。** **在るときだけ照合する。**
> **在るのに見ないと、他の認可サーバへ出した保証が、そのまま通る。**
> **`iat` / `nbf` は見ない**（`exp` が在れば足りる）。

**主張されたメタデータも、重ねた後に同じ検査を通る** —
**署名が付いていても、この配備が扱えない値は通らない**（`invalid_client_metadata`）。
**`client_registration` scope の自己付与も、statement 経由では通らない。**

##### 2 つの専用トークンとは、役が違う

**statement は、どちらのトークンも置き換えない。**

| 問い | 答えるもの |
|---|---|
| **登録を作ってよいか** | **`client_registration` scope のアクセス トークン**（段階 1） |
| **その登録を直してよいか** | **`registration_access_token`**（段階 2） |
| **書かれている内容を信じてよいか** | **`software_statement`**（段階 4） |
| **認証のときに本人か** | **`token_endpoint_auth_method`**（段階 3） |

**statement はソフトウェアに同梱されて配布される ＝ 秘密ではない。**
**認可の代わりに使うと、そのソフトを持っている人は誰でも登録できる口になる。**
**RFC 7591 §1.2 の「アクセス トークンを要らない開いた登録口」は、この配備では採らない。**

**判定の順は「認可が先、内容は後」**である。

```
404 → 401（AT）→ 403（scope / 2 件目）→ 400（メタデータ。ここで statement を見る）→ 201
```

**認可されていない相手に、自分の statement が信頼されているかを教えない** —
**信頼一覧の中身を、外から探らせないため**である。

##### `RequireSoftwareStatement` — 審査を通したソフトウェアだけ登録させる

**`true` にすると、statement の無い登録を断る**（`400` ＋ `invalid_client_metadata`）。
**`POST /register` と `PUT`（RFC 7592）の両方に効く。**

> **`PUT` に効かせるのが要点である。**
> **statement を保管していない**ので、**`PUT` で省かれたら「主張されていた値」を思い出せない。**
> **効かせないと、`PUT` の本文で自分の値に書き換えられる**（§2.2 は全置換）。

| 値 | |
|---|---|
| **`false`（既定）** | **従来どおり。** 添えれば効き、添えなくても登録できる |
| **`true`** | **毎回添えること。** **`PUT` でも毎回**（省くと `400`） |

**信頼する発行者を 1 件も書かずに `true` にすると、動的登録は通らなくなる**
（**必須なのに、どの statement も approved にならない**）。

##### 気をつける所

| | |
|---|---|
| **`.cer` が読めないとき** | **`unapproved_software_statement`** に倒す（**statement が壊れている訳ではない**）。**理由はオペレーション ログに残る** |
| **`alg` を間違えて書くと、全部断られる** | **ヘッダと照合する**ので、**発行者が `ES256` で署名しているのに `RS256` と書けば通らない。** **`alg` を外から選ばせない**ための形である |
| **`iss` は完全一致** | 前方一致・部分一致は見ない。**末尾の `/` の有無でも違う値**である |
| **鍵の入れ替え（ロールオーバー）は、この段階では出来ない** | **引くのは `iss` が一致する最初の行だけ**なので、**同じ `iss` の行を 2 つ書いても、新旧を並べて試すことはしない。** **入れ替えるときは、発行者に新しい鍵で署名し直してもらい、行を差し替える**（**その間、古い statement は通らない**）。**新旧を並べたいなら、`Find` を「一致する全ての行で試す」に変える必要がある** — **段階 5 以降の話**である |
| **`jwks_uri` のように URL から引く形は無い** | **登録の口は同期**で、取得を差し込めない（`jwks_uri` を断っているのと同じ理由。**別 Issue**） |
#### まだ出来ないこと（段階 5 以降）

| | いつ |
|---|---|
| **管理画面の一覧化**（**n 件を並べて、足す・消す**） | **段階 5-a-2**（**器は段階 5-a-1 で済んでいる**） |
| **`client_credentials` 経路**（**人のパスワードを要らなくする**） | **段階 5-b**（**所有者を「認証したクライアントの所有者」から引く** ＋ 設定ファイルに `owner` を 1 属性） |
| **発行者ごとに許す範囲を絞る**（この発行者は `openid` だけ、など） | **段階 5 以降**（**いまは「信じるか、信じないか」の 2 択**） |
| **発行者の鍵の入れ替え**（新旧を並べて試す）／**発行者の登録を DB ＋ 管理画面へ** | **段階 5 以降**（`IdFederationUpstreams` が #292 の段階 2 で通った道） |
| **`jwks_uri`**（鍵を URL から引く） | **別 Issue**（**クライアント認証の経路を非同期にする**。`/token` ほか全ての口から同期で呼ばれている） |
| OIDC DCR §2 の残り（`application_type` / ログアウトの URI など） | D-1-2 と併せて |

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

### リバース プロキシや TLS 終端の背後に置く（#279）

**プロキシが https で受けて、アプリへは http で渡す配備**
（ALB / nginx / Front Door、コンテナの前段）では、
**アプリは「自分は http で呼ばれた」と思っている。**

| 見るもの | 何が起きるか |
|---|---|
| `Request.Scheme` | `http`。**`issuer` やリダイレクト先の URI が http で組まれる** |
| `Request.IsHttps` | `false`。**`Secure` を伴う Cookie の判定が狂う** |
| `UseHttpsRedirection` | **転送先のポートが判らないので、黙って素通りする** |

**転送ヘッダの取り込みを、設定で切り替えられる**（上流 Open棟梁 #549）。

```json
// appsettings.json
"UseForwardedHeaders": "on",
"ForwardedHeadersKnownProxies": "10.0.0.4, 10.0.0.5",
"UseHttpsRedirection": "on",
"CookieSecurePolicy": "always",
```

- **`UseForwardedHeaders` はパイプラインの先頭で呼んでいる**（`Startup.Configure`）。
  後ろに置くと、**それより前に動いたものが古いスキームを見る**
- **`KnownProxies` / `KnownIPNetworks` は空にしてから詰めている。**
  既定は `127.0.0.1` / `::1` だけで、**コンテナ間のプロキシは別のアドレスから来るため弾かれる**
- **`ForwardedHeadersKnownProxies` を書かないと、転送ヘッダを送った相手を問わない。**
  **プロキシを経由せずアプリに直接届く経路があるなら、列挙すること**
- **`UseHttpsRedirection` には転送先のポートが要る。**
  `ASPNETCORE_HTTPS_PORT`（**単数形**。`ASPNETCORE_HTTPS_PORTS` ではない）か、上の転送ヘッダ経由。
  **判らないときは例外にならず、リダイレクトしないだけ**なので気付きにくい

> **Cookie ポリシーは DI 側に一本化した**（#279。`services.Configure<CookiePolicyOptions>`）。
> **`app.UseCookiePolicy()` に引数を渡す overload は、DI の設定を読まない。**
> **`SameSite=None` の明示は外していない** — **外すと `samesite` 属性ごと出なくなり**（実測）、
> **ブラウザ側の既定（Chrome は `Lax`）になる**ため。**ID 連携の戻りで Cookie が送られなくなる。**

**ここに挙げたのはすべて net10.0 版だけである**（net48 版は IIS 側の設定）。

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

### user store に入る秘密を暗号化する — `UserStoreSecretPassword`（#297）

**DB に入る `client_secret` を、暗号化して保管できる。**

| 設定キー | |
|---|---|
| **`UserStoreSecretPassword`** | **暗号化する鍵（パスワード）。** **空なら暗号化しない**（平文のまま ＝ 従来どおり） |

**対象は 3 列**である（**どれも「元に戻せる形」でなければならない**）。

| 表 | 列 | なぜ戻せる形が要るか |
|---|---|---|
| `Saml2OAuth2Data` | `ClientSecret` | **クライアント認証で照合し、管理画面で再表示する** |
| `IdFederationUpstreams` | `ClientSecret` | **上流へ送る**（`/token` のクライアント認証） |
| `IdFederationUpstreams` | **`SigningPfxPassword`** | **`.pfx` を開くために使う**（#292 の段階 4-b） |

**だからハッシュは取れない。** **対称鍵で暗号化する。**

| | |
|---|---|
| 暗号 | **AES-CBC（PKCS7）** ＋ **PBKDF2(SHA-256, 10 万回)** |
| 形 | **`enc:v1:` ＋ base64(salt 16 ＋ IV 16 ＋ 暗号文)** |
| salt / IV | **1 件ごとに作る**（**同じ秘密でも、毎回違う暗号文になる**） |
| 印 | **先頭の `enc:v1:`**（**暗号文か平文かを、見れば分かる**） |
| 実装 | `Extensions/Sts/SecretProtector`。**保存と読み出しの境目は Provider の 2 か所だけ** |

**実測（2026/10/14。SQL Server）** : `Saml2OAuth2Data.ClientSecret` は
**`enc:v1:…`（115 文字）**で入っている（**平文に見える 4 行は空文字** ＝ public クライアント）。

> **列は 512 に広げた**（3 方言とも）。**暗号文は平文より長くなる。**

> **Open棟梁 の `SymmetricCryptography` は使っていない。**
>
> **最初は使おうとして、`EncryptString` がスタック オーバーフローでプロセスを落とした**
> （Open棟梁 [#608](https://github.com/OpenTouryoProject/OpenTouryo/issues/608)。
> **複製の更新で直っている**ことは実測で確かめた）。
>
> **直った後も、こちらで組んだ形を残している。** **理由は暗号の形である。**
>
> | | `SymmetricCryptography`（実測 2026/10/14） | **この実装** |
> |---|---|---|
> | salt / IV | **持たない**（**同じ平文が毎回同じ暗号文**になる） | **1 件ごとに作る** |
> | 同じ秘密を使う登録 | **暗号文が一致するので、外から分かる** | **分からない** |
>
> **標準 API（`Aes` ＋ `Rfc2898DeriveBytes`）で組んでいる**（net48 / net10.0 とも同じ形。
> **鍵の導出だけ `#if NETFX` で分ける** — net48 に `Rfc2898DeriveBytes.Pbkdf2`（静的）が無い）。

> **導いた鍵はキャッシュする**（`salt` ごと）。
> **`client_secret` はクライアント認証のたびに読む**ので、
> **キャッシュが無いと 1 回ごとに 10 万回の導出が走る** —
> **実測で E2E の通しが 137 秒 → 922 秒**になった。

**この設定で守れるのは「DB を見られたとき」である。**

| | |
|---|---|
| 守れる | **DB だけを見られたとき**（行をそのまま読んでも、秘密は読めない） |
| **守れない** | **設定ファイルを見られたとき**（**この鍵も、そこに在る**）。**ファイルの権限で守る** |

**本番では、この鍵を設定ファイルに直接書かないこと**（環境変数・秘密の管理機構から渡す）。

> **既存の平文の行の移行は、この Issue では扱っていない**（#297 の決め事）。
> **印が無い値は、そのまま返す**ので、**鍵を後から設定した配備では、
> 書き直した行から順に暗号文になる。**
> **まとめて変換する道具は、別途である。**

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

E2E テストは既定で `mem` を使う。**前後で状態を掃除する必要が無い**のが理由。
`sql` / `ora` / `npg` に切り替えても回せる（[`TESTING.md`](TESTING.md) 1 節「ストアを切り替える」、#207）。

> **`sql` / `npg` を使っている既存環境は、`CibaData` に `UserId` 列の追加が要る。**
> CIBA の返答（`/ciba_result`）は、**要求が誰宛てだったか**を照合してから結果を書き込む。
> その宛先を持つ列で、`Create_UserStore.sql` には入れてあるが、
> **作成済みのデータベースには自動では増えない。**
>
> ```sql
> ALTER TABLE [CibaData] ADD [UserId] [nvarchar](128) NULL;   -- SQL Server
> ALTER TABLE CibaData ADD UserId varchar(128) NULL;          -- PostgreSQL
> ```
>
> 列が無いと、CIBA の要求の登録（`INSERT`）が失敗する。
> なお**列を足す前の保留中の要求は、承認できない**（宛先が記録されていないため）。
> `ora` にも `DeviceAuthZData` / `CibaData` を追加した（#206）。
> **`ora` の既存環境は、列ではなく表ごと足す**（元々この 2 表が無かったため）。
> 実機（`gvenzl/oracle-free:23-slim`）で E2E を通してある（#208）。
> `NVARCHAR2(800)` の列への一意制約も、`db_block_size` 8192・`max_string_size` STANDARD の
> 既定のままで作成された。

> **クライアント登録（`Saml2OAuth2Data`）は、JSON 1 列から専用列になった**（#270）。
>
> **`UnstructuredData` 列は無くなり、`ClientID` 以下 17 列になった**
> （`ClientSecret` / `RedirectUri*` / `WebOrigins` / `Jwk*` / `*Alg` / `ClientMode` /
> `RequirePkce` / `ClientName` など。列名は属性名と同じ）。
>
> **移行用のスクリプトは置いていない。** 既存のデータベースは次のどちらか。
>
> - **`Create_UserStore.sql` を流し直す**（E2E 用の `store/` は使い捨てなのでこれ）
> - **`ALTER` で 16 列を足し、画面から再登録する**
>
> **列を足しただけでは、登録済みのクライアントは読めない**
> （古い JSON は読まないため。**値を残したい場合は、落とす前に JSON 関数で列へ写せる**
> — SQL Server `JSON_VALUE`、PostgreSQL `::json ->>`、Oracle `JSON_VALUE`）。
>
> **`RequirePkce` だけは `NOT NULL`** なので、`ALTER` で足すときは既定値が要る。

> **同意（consent）を記録する表を足した**（#272 の段階 2）。
>
> ```sql
> CREATE TABLE [ConsentGrant](
>     [UserId] [nvarchar](38) NOT NULL,        -- *PK
>     [ClientID] [nvarchar](256) NOT NULL,     -- *PK
>     [Scopes] [nvarchar](1024) NOT NULL,      -- 許可した scope（空白区切り。辞書順）
>     [CreatedDate] [smalldatetime] NOT NULL,
>     [UpdatedDate] [smalldatetime] NOT NULL
> )
> ```
>
> **これが無いと `prompt=none` の判定ができない。**
> 以前は**記録を持たず、`prompt=none` で無条件に同意画面を飛ばしていた**
> （`ANALYSIS-IdP.md` の C-3）。
>
> **既存のデータベースにはこの表が要る。**
> **`Create_UserStore.sql` を流し直す**か、**表を 1 つ足す**
> （`Users.Id` への FK（`ON DELETE CASCADE`）も張る。おかないと利用者を消しても同意が残る）。
> **表が無いと、認可が通らなくなる**（同意の読み書きで落ちる）。
>
> **設定キーは置いていない。** **常に仕様どおり**である。
> **記録が無いクライアントの `prompt=none` は `consent_required`** になるので、
> **初回は必ず同意画面を通る**（一度通せば、その後は飛ぶ）。
>
> **利用者は `/Manage/ConsentGrants` から取り消せる。**
> **発行済みのトークンは失効しない**（そちらは `/revoke`。RFC 7009）。

> **ID 連携の連携キーの幅を広げた**（#292）。
>
> | 列 | 以前 | いま | 入る値 |
> |---|---|---|---|
> | `UserLogins.LoginProvider` | 128 | **512** | **相手の `iss` / entityID**（URI なので `Const.MaxLengthOfUri` と同じ） |
> | `UserLogins.ProviderKey` | 128 | **256** | **相手の `sub` / `NameID`**（`sub` は 255 文字以内、persistent な `NameID` は 256 文字以内と決まっている） |
>
> **上流が n 件になると、長い値を踏む確率が上がる**（#292）。
> **溢れたときに切り詰めはしない** — **連携のサインインが `INSERT` で落ちる。**
>
> **既存のデータベースは、`Create_UserStore.sql` を流し直すか、列を広げる。**
> **SQL Server は PK を落としてから広げ、張り直す**（他の 2 つは `MODIFY` / `TYPE` だけでよい）。
>
> ```sql
> -- SQL Server
> ALTER TABLE [UserLogins] DROP CONSTRAINT [PK.UserLogins];
> ALTER TABLE [UserLogins] ALTER COLUMN [LoginProvider] [nvarchar](512) NOT NULL;
> ALTER TABLE [UserLogins] ALTER COLUMN [ProviderKey] [nvarchar](256) NOT NULL;
> ALTER TABLE [UserLogins] ADD CONSTRAINT [PK.UserLogins] PRIMARY KEY NONCLUSTERED
>     ([UserId] ASC, [LoginProvider] ASC, [ProviderKey] ASC);
>
> -- Oracle
> ALTER TABLE "UserLogins" MODIFY ("LoginProvider" NVARCHAR2(512), "ProviderKey" NVARCHAR2(256));
>
> -- PostgreSQL
> ALTER TABLE userlogins ALTER COLUMN loginprovider TYPE varchar(512);
> ALTER TABLE userlogins ALTER COLUMN providerkey   TYPE varchar(256);
> ```
>
> **PK は 3 列で (38 + 512 + 256) × 2 = 1612 バイト**になる。
> **SQL Server 2016 以降が前提**である（索引キーの上限が 1700 バイト）。
> **2014 以前の上限は 900 バイト**なので、**この定義は上限を超える**
> （可変長の列なので、作成は警告で通り、**長い値を入れたときに失敗する**）。
> **2014 以前では未検証**である。**実機で測ったのは 2022**（`store/` のコンテナ）。
>
> **Oracle・PostgreSQL は、既定の設定のまま収まる**
> （Oracle は `db_block_size` 8192 で索引キーが約 6398 バイトまで、
> PostgreSQL の btree は約 2704 バイトまで）。

**3 つの DDL がミラーかどうかは、機械的に確かめられる。**

```powershell
cd root
.\CompareDdl.ps1           # 差があれば赤く出て、終了コードが 1 になる
.\CompareDdl.ps1 -Detail   # 差の無いテーブルも並べる
```

`Create_UserStore.sql`（テーブルと列）と `Select_UserStore.sql`（SELECT 対象）の**両方**を見る。
**型は比べない**（`nvarchar(max)` と `NVARCHAR2(2000)` のように、対応はするが同一ではない）。
**SQL が実行できるかは分からない。** それは、ストアを切り替えて E2E を回して確かめる
（[`TESTING.md`](TESTING.md) 1 節「ストアを切り替える」、#207）。

### セッションの置き場 — `SessionStoreType`（#256）

**`UserStoreType` とは別のストアである。** 利用者やトークンではなく、
**画面のセッション**（`HttpContext.Session`）の置き場を決める。

```json
"SessionStoreType": "mem",   // mem / sql / redis
"SessionStoreConnectionString": "",
```

| 値 | 置き場 | 複数インスタンス |
|---|---|---|
| `mem` | プロセス内（`AddDistributedMemoryCache`） | **共有されない** |
| `sql` | SQL Server のテーブル（`AddDistributedSqlServerCache`） | 共有される |
| `redis` | Redis（`AddStackExchangeRedisCache`） | 共有される |

**雛形の既定は `mem`で、キーを書かなければも `mem`。**
**単一インスタンスなら、これで正しい**（既存の配備も従来どおり動く）。
**インスタンスを増やすなら `redis` または `sql` にする**（次項）。

**net10.0 版だけが読む。** net48 版は `Web.config` の `sessionState` で選ぶ
（`InProc` / `StateServer` / `SQLServer` / Oracle は `Custom`）。雛形は `StateServer` で、
**ASP.NET 状態サービス（`aspnet_state`）が止まっていると画面が 500 になる**
（[`TESTING.md`](TESTING.md) 8 節）。

#### `mem` のままスケールアウトすると、途中で失敗する

**セッションに置いているのは、途中の状態である。** 要求が別のインスタンスへ回ると読めない。

| 置いているもの | 壊れるとどうなるか |
|---|---|
| ID 連携の `state` / `nonce` / `code_verifier` | 上流から戻った先が別のインスタンスだと、照合できずサインインが失敗する |
| 管理画面の `access_token` / `get_oauth2_token_state` | 「OAuth2 のトークンを取得」以降の操作ができない |
| FIDO2 の challenge | 登録・認証が成立しない |
| 自己テスト画面の値 | 画面の往復が途切れる |

**実測では 14 キー・46 か所がセッションを使っている**（net10.0 版）。
**Cookie へ寄せる案は採らなかった**（量と、`access_token` を Cookie に置きたくないため）。

#### `sql` はテーブルが要る

```powershell
sqlcmd -S localhost,1433 -U sa -P '...' -i root\files\resource\MultiPurposeAuthSite\Sql\sqlserver\Create_SessionCache.sql
```

**`dotnet sql-cache create` が作るものと同じスキーマ**である（列名・型・索引を変えると動かない）。
スキーマ名・テーブル名は `Const.SessionCacheSchemaName` / `Const.SessionCacheTableName` に
置いてあり、**設定キーにはしていない**（DDL とコードを食い違わせないため）。

> **`Create_UserStore.sql` は DATABASE を作り直す。**
> 後から流すと `SessionCache` は消える。**UserStore を作り直したら、これも流し直す。**

#### `redis` は方言に依らない

**Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い。**
`UserStoreType` が `ora` / `npg` の配備でセッションを共有するなら、**`redis` を選ぶ。**
（3 方言が揃わない唯一の設定である。）

#### 接続文字列が無ければ、起動時に落とす

**`mem` 以外で `SessionStoreConnectionString` が空なら、`ConfigureServices` で例外を投げる。**
`IDistributedCache` は**最初にセッションを触った時に**落ちるので、
そのままだと**起動は通り、画面が 500 を返すだけで理由が分からない。**

```
Unhandled exception. System.InvalidOperationException:
SessionStoreType が SqlServer なので、SessionStoreConnectionString が必要です。
```

### SAML2（#276）

**実装しているのは SP-initiated Web Browser SSO Profile** である（最も初歩的なもの）。
**SLO・アサーションの暗号化・Artifact バインディング・IdP-initiated（未承諾応答）は持っていない。**

| 設定キー | 既定 | |
|---|---|---|
| `Saml2RequestEndpoint` | `/saml2request` | **IdP の口**（SSO）。メタデータの `SingleSignOnService` にこの値が出る |
| `Saml2ResponseEndpoint` | `/Account/AssertionConsumerService` | **自己テストの SP の口**（`redirect_uri_saml` を `test_self_saml` で登録したときの展開先） |
| `Saml2AssertionExpireTimeSpanFromMinutes` | `30`（**分**） | **アサーションの有効期限**（#276）。**書かなければ `OidcIdTokenExpireTimeSpanFromMinutes` を使う**（従来の振る舞い） |
| `RsaPfxFilePath` | — | **応答の署名鍵**。メタデータの `KeyDescriptor` に、対応する証明書（`SpRp_RsaCerFilePath`）が出る |

クライアントの登録（`OAuth2ClientsInformation` または管理画面）側は次の 2 つ。

| 登録項目 | |
|---|---|
| `redirect_uri_saml` | **ACS URL**（`AssertionConsumerServiceURL`） |
| `jwk_rsa_publickey` | **`AuthnRequest` の署名を検証する鍵**（OAuth2 側と共用） |

> `saml_name_id_format` という登録項目が雛形に書かれているが、**実装は読んでいない。**
> **`NameID` の形は、要求の `NameIDPolicy` だけで決まる。**

#### ID 連携の 4 つの脚（#286 / #289 / #290 / #291）

**ID 連携では、この IdP が真ん中に立つ。** **下流 IdP（＝この配備）と呼ぶ。**

```
SPRP→(1)→下流IdP→(2)→上流IdP
SPRP←(4)←下流IdP←(3)←上流IdP
```

| 脚 | 何が流れるか | 署名する側 | 検証する側 | 検証鍵（設定） |
|---|---|---|---|---|
| **(1)** | **SPRP の要求**（`AuthnRequest` / 認可要求） | SPRP | **下流 IdP** | **クライアント登録の `jwk_rsa_publickey`**（**相手ごと**） |
| **(2)** | **下流 IdP の要求**（`AuthnRequest` / 認可要求） | **下流 IdP** | 上流 IdP | **上流に登録した自分の公開鍵**（上流側の設定） |
| **(3)** | **上流 IdP の応答**（アサーション / `id_token`） | 上流 IdP | **下流 IdP** | **`IdFederation*`**（下の 2 節） |
| **(4)** | **下流 IdP の応答**（アサーション / `id_token`） | **下流 IdP** | SPRP | **この配備の証明書**（`/samlmetadata` / `/jwkcerts` で広告する） |

**protocol で、署名する脚が違う。**

| | (1) 要求 | (2) 要求 | (3) 応答 | (4) 応答 |
|---|---|---|---|---|
| **SAML2** | **署名する**（SP が署名し、**下流は登録値で検証**） | **署名する**（`SpRp_RsaPfxFilePath` ＝ `*_Client.pfx`） | **署名する** | **署名する**（`RsaPfxFilePath` ＝ `*_Server.pfx`） |
| **OIDC** | **しない**（`client_secret` ＋ PKCE。**`client_assertion` / Request Object を使う登録だけ、同じ `jwk_rsa_publickey` で検証**） | **しない**（`client_secret_post` ＋ PKCE） | **署名する**（`id_token`） | **署名する**（`id_token` / JARM） |

> **SAML2 は要求にも応答にも署名が在り、OIDC は応答だけ**である。

> **E2E では、上流だけ別の RSA 鍵を使う**（#293 の段階 1）。
> **`store/docker-compose.yml` の upstream が `RsaPfxFilePath` / `SpRp_RsaCerFilePath` /
> `JwkSetFilePath` を `*_Upstream` に向けている。**
>
> | | 公開している RSA の `kid`（実測 2026/10/13） |
> |---|---|
> | 上流（44301） | `ZB2dUcdK9F7wPQ38…`（`SHA256RSA_Upstream.cer`） |
> | 下流（44303） | `W8YPrSZDTP6XB0VT…`（`SHA256RSA_Server.cer`） |
>
> **以前は同じ鍵だった**ので、**(3) の検証鍵を (4) の鍵と取り違えても通ってしまっていた。**
> **分けたので、取り違えると落ちる**（`TESTING.md` の歯抜け）。
> **EC の 3 本は共有のまま**（RSA だけを分けた）。

> **(2) の署名も、上流が検証する**（#293 の段階 2）。
> **雛形の `IdFederation` クライアントと、`store/` の E2E のクライアント 3 件に
> `jwk_rsa_publickey` を登録した**（値は **`*_Client.cer` の JWK** ＝ 下流が (2) の署名に使う鍵の対）。
>
> **以前は登録していなかったので、上流は「鍵がない場合は、通す」経路に入り、
> 署名が検証されていなかった**（`CmnEndpoints.VerifySamlRequest`）。
>
> **相互運用では、上流に自分の公開鍵を登録してもらうこと。**
> **OIDC の (2) には署名が無い**ので、この登録は SAML2 のためである。

**問題だったのは (3) である。**

**(3) の検証鍵を、Open棟梁 は設定から 1 本だけ選んでいた**
（`SAML2Client.VerifyResponse` / `CmnJwtToken.Verify`）。
**その 1 本（`SpRp_*CerFilePath`）は、この配備では (4) で広告する自分の証明書**でもある。

| | |
|---|---|
| **分けられなかった理由** | **上流の証明書に差し替えると、(4) が壊れる**（**他人の証明書を広告することになる**） |
| **どう解いたか** | **(3) の鍵を、呼び出し側から渡せるようにした**（Open棟梁 [#600](https://github.com/OpenTouryoProject/OpenTouryo/issues/600) / [#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601)） |
| **渡す値の置き場** | **`IdFederation*` のキー**（#286 / #289 / #291）。**共通設定（`SpRp_*` / `JwkSetUri`）は触らない**（#290。8 節） |

#### 上流 IdP を n 件登録する — `IdFederationUpstreams`（#292 の段階 1）

**上流は n 件登録できる。** **1 件につき、画面の導線（ボタン）が 1 つ出る。**

| 設定キー | |
|---|---|
| **`IdFederationUpstreams`** | **鍵 → 属性の辞書**（`OAuth2ClientsInformation` と同じ流儀。net48 は JSON 文字列 1 本、net10.0 は節） |

**鍵は短い識別子**である。**導線が送る値・Session に控える値・ログに出る値**になる。

| 属性 | | OIDC | SAML2 |
|---|---|---|---|
| `display_name` | 画面に出す名前（空なら鍵） | ○ | ○ |
| `protocol` | **`oidc` / `saml2`**（空なら `oidc`） | ○ | ○ |
| `enabled` | **空なら有効**（`false` で無効） | ○ | ○ |
| **`issuer`** | **期待する `iss`（OIDC）/ `entityID`（SAML2）** — **メタデータ・discovery の照合に使う** | ○ | ○ |
| **`client_id`** | **上流に登録された、自分の `client_id`**（**SAML2 でも要る** — SP の `Issuer` は `http://<client_id>`） | ○ | ○ |
| `client_secret` | 同上 | ○ | － |
| `discovery_url` | 上流の discovery（空なら `authorize_endpoint` の基底から組み立て） | ○ | － |
| `jwk_set_uri` | 上流の JWK Set（**書けば discovery を読まない**。#290） | ○ | － |
| `metadata_url` | 上流のメタデータ（#291） | － | ○ |
| `cer_file_path` | 上流の署名証明書（**倒れ先**） | ○ | ○ |
| `authorize_endpoint` / `token_endpoint` / `userinfo_endpoint` | 上流の口 | ○ | － |
| `sso_endpoint` | 上流の SSO の口（**倒れ先**。メタデータが先） | － | ○ |
| **`signing_pfx_file_path`** | **この上流へ送る `AuthnRequest` に署名する鍵**（#292 の段階 4-a。**空なら共通設定**） | － | ○ |
| `signing_pfx_password` | 上記 `.pfx` のパスワード（**空なら共通設定**。**DB では暗号化して保管する**。#297） | － | ○ |

```jsonc
"IdFederationUpstreams": {
  "upstream1": {
    "display_name": "Upstream IdP (OIDC)", "protocol": "oidc", "enabled": "true",
    "issuer": "https://ssoauth.opentouryo.com",
    "client_id": "...", "client_secret": "...",
    "discovery_url": "https://localhost:44301/.well-known/openid-configuration",
    "jwk_set_uri": "", "cer_file_path": "C:/root/files/resource/X509/SHA256RSA_Server.cer",
    "authorize_endpoint": "https://localhost:44301/authorize",
    "token_endpoint": "https://localhost:44301/token",
    "userinfo_endpoint": "https://localhost:44301/userinfo"
  },
  "upstream1_saml2": {
    "display_name": "Upstream IdP (SAML2)", "protocol": "saml2",
    "issuer": "https://ssoauth.opentouryo.com", "client_id": "...",
    "metadata_url": "https://localhost:44301/samlmetadata",
    "sso_endpoint": "https://localhost:44301/saml2request",
    "cer_file_path": "C:/root/files/resource/X509/SHA256RSA_Server.cer"
  }
}
```

**折り返し口は、共通設定のまま**である（#290 の規則）。

| | 置き場 | なぜ |
|---|---|---|
| **相手ごとの値** | **`IdFederationUpstreams` の各行** | 相手が n 件になれば n 件要る |
| **折り返し口**（`IdFederationRedirectEndpoint` / `IdFederationSaml2ResponseEndpoint`） | **共通設定** | **自分の URL なので、相手ごとに変わらない。** **全ての上流に、同じ 1 本を登録する**（#263。1 文字も違ってはならない） |
| 自分の署名鍵 | **(1) の署名は共通設定**（`SpRp_RsaPfxFilePath` ほか）。**(2) は上流ごとに替えられる**（`signing_pfx_file_path`。#292 の段階 4-a・4-b。**設定でも DB でもよい**） | **Open棟梁 [#606](https://github.com/OpenTouryoProject/OpenTouryo/issues/606) で鍵を渡せるようになった**ので、相手ごとに持てる |

> **どの上流から戻ってきたかは、Session で引く**（開始処理が鍵を控える）。
> **口を相手ごとに分ける案は採らなかった** — **登録値が増え、`redirect_uri` の取り違えが起きやすい。**

**従来の単数キーは、そのまま動く。**

| | |
|---|---|
| **`IdFederationUpstreams` が空** | **従来のキーから 1〜2 件を組み立てる**（鍵は `default` / `default_saml2`） |
| 組み立てに使う値 | OIDC : `SpRp_Isser` / `OAuth2AndOidcClientID` / `OAuth2AndOidcSecret` / `IdFederationOidcDiscoveryUrl` / `IdFederationJwkSetUri` / `IdFederationOidcCerFilePath` / `IdFederation{Authorize,Token,UserInfo}Endpoint`<br>SAML2 : `IdFederationSaml2IssuerId` / `OAuth2AndOidcClientID` / `IdFederationSaml2MetadataUrl` / `IdFederationSaml2RequestEndpoint` / `IdFederationSaml2CerFilePath` |
| **書いたときの優先** | **`IdFederationUpstreams` が勝つ**（従来のキーは読まれない） |

> **1 件の配備は、見た目も POST も変わらない。**
> **1 件目のボタンの `id` は従来どおり**（`id_federation_signin` / `id_federation_saml2_signin`）、
> **押したときに送る `submitButtonName` も同じ**である。
> **どの上流かは、別の欄（`IdpKey`）で送る** — **空なら先頭の 1 件。**

##### user store にも置ける（#292 の段階 2）

**同じ項目を、DB の `IdFederationUpstreams` 表にも置ける。**
**管理画面（`/IdFederationAdmin`）から足せる**ので、**設定ファイルを書き換えずに増やせる。**

| | |
|---|---|
| **読む順** | **設定 → user store。** **同じ鍵なら設定が勝つ**（設定で固定した配備が、行で黙って変わらない） |
| **画面が編む範囲** | **user store の行だけ**（設定ファイルの行は、画面に出ない） |
| 認可 | **`UsersAdmin` / `RolesAdmin` と同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`） |
| 置き場 | **`UsersAdmin` の隣**（**上流の登録は配備全体のもの**で、`Manage/AddSaml2OAuth2Data`（自分のクライアント登録）とは所有者が違う） |
| DDL | **3 方言 ＋ `mem`**（`root/files/resource/MultiPurposeAuthSite/Sql/*/Create_UserStore.sql`） |

**列は設定の属性と同じ**で、**`UpstreamKey` が設定の「鍵」に当たる**
（`Key` は方言の予約語なので避けた）。

**秘密の列は、暗号化して保管する**（#297。`UserStoreSecretPassword`。上の 6 節）。
**`ClientSecret` と `SigningPfxPassword` が対象**で、**どちらも読むときに平文へ戻す**
（**上流へ送る値・`.pfx` を開く値なので、ハッシュは取れない**）。

> **`SigningPfxFilePath` / `SigningPfxPassword` は、段階 4-b で足した列**である
> （**設定の行の `signing_pfx_file_path` / `signing_pfx_password` と同じもの**）。
> **列を足したので、古い DB では落ちる** — **作り直すこと**（`TESTING.md`）。

**上流が n 件になると、「2 つの IdP から来た同じ人」が現れる。**
**この製品は、検証済みのメアドで既存アカウントに結ぶ**（アカウント リンク）。

| 順 | 引き方 | |
|---|---|---|
| 1 | **連携キー `(iss, sub)`** | **上流ごとに別の行**（`UserLogins`） |
| 2 | **メアド** | **引けたら、その利用者に `(iss, sub)` を足す** |

**守りは「メアドが検証済みであること」**である（#140 の段階 1。`Sts.AccountLink`）。
**測定は `CN-5.6`**（#292 の段階 1）。

#### (3) の検証鍵 — OIDC（#289 / #290）

**上流の `id_token`（＝ (3)）の署名を検証する鍵である。**
**OIDC は応答にだけ署名が在る**ので、**OIDC の ID 連携で要る鍵は、これだけ**である
（**(2) は署名しない** — `client_secret_post` ＋ PKCE）。

| 設定キー | 雛形の値 | |
|---|---|---|
| `IdFederationJwkSetUri` | （空） | **上流の JWK Set の URL**。**書けば discovery を読まない**（#290） |
| `IdFederationOidcDiscoveryUrl` | `https://localhost:44301/.well-known/openid-configuration` | **上流の discovery**。**空なら `IdFederationAuthorizeEndpoint` の基底から組み立てる** |
| `IdFederationOidcCerFilePath` | `…/X509/SHA256RSA_Server.cer` | **上流の `id_token` の署名を検証する証明書**（`.cer` のパス）。**空なら従来どおり** |

**どれかを書けば、上流の鍵で検証する**（Open棟梁 [#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601) の版へ、
**鍵・`iss`・`aud` を渡す**）。

| 渡すもの | 値 |
|---|---|
| 鍵 | **上の 3 本から決める**（下の「鍵の出どころは 4 段」） |
| `iss` | **`SpRp_Isser`**（Open棟梁 のクライアント役の設定。**相手の Issuer** である） |
| `aud` | **`OAuth2AndOidcClientID`**（上流に登録した自分の `client_id`） |

**空なら、Open棟梁 が設定から鍵を選ぶ**（従来どおり）。
**ただし、この配備はそこで「自分の JWK Set を `kid` で引く」枝に入る**
（`CmnJwtToken.Verify` が「自分は認可サーバか」で分岐するため。Open棟梁 #601）。

> **開発用の上流は同じ雛形の鍵**なので、**`kid` が一致して検証できてしまう。**
> **鍵の違う OP が相手なら、`kid` が引けず、設定の `.cer` に落ちて失敗する**
> （**失敗側に倒れる**ので安全性の問題ではないが、**連携できない**）。
> **このキーを書くのが、その対処である。**

**`CanIdFederationByOidc` には入れていない** — **空でも ID 連携は成立する**ためである
（SAML2 側の 4 本とは扱いが違う）。

**鍵の出どころは 4 段**である。

| 順 | 出どころ | ロールオーバー |
|---|---|---|
| 1 | **設定の `IdFederationJwkSetUri`**（上流の JWK Set を直に指す。#290） | **追随する**（`kid` が引けなければ取り直す）。**`issuer` の照合は無い** |
| 2 | **上流の discovery → `jwks_uri` → `kid`**（#289 の段階 2） | **追随する**。**`issuer` を照合する** |
| 3 | **設定の `.cer`**（`IdFederationOidcCerFilePath`） | **追随しない**（上流が鍵を替えたら置き直す） |
| 4 | **渡さない**（従来どおり） | － |

**取得は、1 と 2 のどちらも 1 分に 1 回まで**（`kid` が引けないときだけ取り直す）。

**discovery の在り処は、設定 → 口の基底から組み立て**の順で決まる。

| 順 | |
|---|---|
| 1 | **`IdFederationOidcDiscoveryUrl`**（**SAML2 側の `IdFederationSaml2MetadataUrl` と対称**） |
| 2 | **`IdFederationAuthorizeEndpoint` の基底**（`https://host/authorize` → `https://host/.well-known/openid-configuration`） |

> **組み立てだけでは足りない配備がある。**
> **パスの下に discovery を置く OP**（`https://host/tenant/v2.0/.well-known/openid-configuration`）
> **には、基底だけでは当たらない。** **そのため、設定でも与えられるようにしてある。**

> **`iss` そのものから引かない。** **この製品の `IssuerId` は論理名**であり
> （雛形は `https://ssoauth.opentouryo.com`）、**待ち受けている URL とは別**である
> （実測 : 開発・E2E の上流は `https://localhost:44301`）。

**discovery の `issuer` が `SpRp_Isser` と一致しなければ、その鍵は使わない**
（**設定の URL を差し替えられた配備で、別の発行者の鍵を信じないため**）。
**引けなければ 2 段目に倒れる**ので、**discovery が落ちていても ID 連携は止まらない。**

#### (2) の宛先と (3) の検証鍵 — SAML2（#286 の段階 1 / 段階 2）

**この IdP が、上流の IdP に対して SP になるときの設定である。**
**OIDC の `IdFederation*Endpoint`（4 本）とは別に持つ。**

**SAML2 は要求にも署名が在る**ので、**(2) の宛先（上流の SSO）と、自分の署名鍵**も要る。

| 脚 | 使う値 |
|---|---|
| **(2)** 送る要求 | 宛先は `IdFederationSaml2RequestEndpoint`（またはメタデータの `SingleSignOnService`）。**署名鍵は `SpRp_RsaPfxFilePath`**（Open棟梁 の `SAML2Client.CreateRedirectRequest` が読む） |
| **(3)** 受ける応答 | 検証鍵は `IdFederationSaml2CerFilePath`（またはメタデータの `KeyDescriptor`）。**期待する Issuer は `IdFederationSaml2IssuerId`** |

| 設定キー | 雛形の値 | |
|---|---|---|
| `IdFederationSaml2RequestEndpoint` | `https://localhost:44301/saml2request` | **`AuthnRequest` を送る先**（上流の SSO の口） |
| `IdFederationSaml2ResponseEndpoint` | `…/Account/IDFederationAssertionConsumerService` | **応答を受け取る自分の口**（**上流の `redirect_uri_saml` に登録する値**） |
| `IdFederationSaml2IssuerId` | `https://ssoauth.opentouryo.com` | **期待する上流の Issuer**（EntityID） |
| `IdFederationSaml2CerFilePath` | `…/X509/SHA256RSA_Server.cer` | **上流の署名を検証する証明書**（`.cer` のパス） |

**雛形の既定は、OIDC の `IdFederation*Endpoint` と同じ**
（**上流は `store/` のコンテナ**。`https://localhost:44301`。**E2E は環境変数で上書きする**）。

**1 本でも空なら、SAML2 の ID 連携は無効**である（`Config.CanIdFederationBySaml2`）。
**押しても成立しない導線を出さない**ため、**サインイン画面のボタンも出さない。**

> **証明書は、開発用の上流が同じ雛形の鍵を使っているので、結果として
> `SpRp_RsaCerFilePath` と同じファイルを指す**（実測で modulus が一致する）。
> **値が同じでも、キーは分ける** — **役が違う**ためである（次の節）。

**値の出どころは、上流の `/samlmetadata` である**（実測）。
**メタデータの URL を書けば、`SingleSignOnService` と署名証明書は、そこから引く**（#291。下記）。
**書かなければ、人が見て書き写す。**

| 設定キー | 上流のメタデータの、どこ |
|---|---|
| `IdFederationSaml2RequestEndpoint` | `IDPSSODescriptor` ＞ `SingleSignOnService`（HTTP-Redirect）の `Location` |
| `IdFederationSaml2IssuerId` | `EntityDescriptor` の `entityID` |
| `IdFederationSaml2CerFilePath` | `KeyDescriptor use="signing"` ＞ `X509Certificate`（**取り出して `.cer` として置く**） |

> **メタデータから引く仕組みは、#291 で入った**（下記）。
> **以下は、メタデータを使わない（URL を書かない）配備の手順**である。
>
> **以前ここには「メタデータから自動で引く仕組みは、まだ無い」と書いてあった。**
> **Open棟梁 の `SAML2Bindings` には `CreateMetadata`（作る側）しか無い。**
> **また、同梱のメタデータは署名されていない**（実測）ので、**信頼の根拠は TLS だけ**になる。
> **いまは、配備時に手で置く。**

**導線と口**（段階 2）。

| | |
|---|---|
| **サインイン画面のボタン** | **設定が揃っているときだけ出す**（`CanIdFederationBySaml2`）。**OIDC 側も同じにした**（`CanIdFederationByOidc`） |
| **口** | `/Account/IDFederationAssertionConsumerService`（**`IsLockedDownTestEndpoints` で閉じない**。本番の導線） |
| 自己テストの口 | `/Account/AssertionConsumerService`（**閉じる**。結果を画面に出すだけ） |
| `AuthnRequest` | `NameIDFormat=emailAddress`、`Issuer` ＝ **`http://` ＋ 上流に登録された `client_id`**、**ACS URL は入れない**（上流が登録値から解決する） |
| `IsPassive` | **送らない**（#287 で OIDC の `prompt=none` を外したのと同じ理由） |
| サインイン画面の入力値 | **使わない**（SAML に `login_hint` 相当が無い。#286 の決め事） |

> **上流には、下流の ACS を `redirect_uri_saml` として登録する**こと。
> **1 文字も違ってはならない**（#263 と同じ照合）。
> 雛形は `IdFederation` クライアントに登録済みで、`store/docker-compose.yml` は
> E2E の 3 つの下流（ホスト core / netfx / 下流コンテナ）の分を持っている。

#### アサーションの属性（`AttributeStatement`）で、メアドと利用者名を運ぶ（#286 の段階 4）

**`NameID` だけでは、メアドと利用者名を運べない。**
**段階 4 で、OIDC 側のクレームに 1 対 1 で対応する属性を出すようにした**
（`CommonLibrary/SamlProviders/CmnSamlAttributes.cs`）。

| OIDC | SAML2 の `Name` | `FriendlyName` | `NameFormat` |
|---|---|---|---|
| `email` | `urn:oid:0.9.2342.19200300.100.1.3` | `mail` | uri |
| `preferred_username` | `urn:oid:0.9.2342.19200300.100.1.1` | `uid` | uri |
| `email_verified` | **`email_verified`** | － | **basic** |

**`urn:oid:…` は X.500/LDAP Attribute Profile**（SAML V2.0 の prof-attr-x500）であり、
**他の IdP（Shibboleth / ADFS など）とも合う。**
**`email_verified` に相当する標準の属性は無い**ので、**OIDC の名前をそのまま basic で出す。**

**出す側（IdP）は、この 3 つだけを出す。**
**読む側（SP）は緩い** — **`Name` と `FriendlyName` の両方を鍵にし、別名も見る**
（`email` / `emailAddress` / ADFS の `http://schemas.xmlsoap.org/…/emailaddress` など）。

**読む側の決め方**（`/Account/IDFederationAssertionConsumerService`）。

| | 順序 |
|---|---|
| メアド | **属性（`mail`）** → `emailAddress` の `NameID` |
| 新規作成時の名前 | **属性（`uid`）** → メアドの `@` より前 |
| 検証済みのメアドか | **属性（`email_verified`）** → `emailAddress` の `NameID` は検証済みとして扱う（下記） |
| 連携キー | **`NameID`**（**`Transient` は受けない**。毎回変わる値を鍵にできない。SAML Core 8.3.8） |

> **これで `Persistent`（PPID）の `NameID` を返す上流とも連携できる**（`SA-7.2`）。
> **段階 3 までは、`NameID` がメアドでなければ繋げなかった。**

> **属性を出さない上流とも、従来どおり繋がる**（`emailAddress` の `NameID` に倒れる）。
> **既定の挙動は変わらない。**

#### `NameIDFormat=emailAddress` の `NameID` は、検証済みのメアドとして扱う（#286 の段階 2）

**上流が `email_verified` を言わないときの倒し方**である
（**段階 4 で属性が入ったので、言ってくる上流ではそちらに従う**）。

| | |
|---|---|
| OIDC の `email` | **属性の 1 つ**である。**検証済みかどうかを別に言う必要がある**（`email_verified`） |
| **SAML2 の `NameID`（`emailAddress`）** | **主体そのものの識別子**である（SAML Core 8.3.2）。**上流が署名して「この主体である」と主張している** |

**だから、検証済みとして扱う。**
**そうしないと、既にメアドで登録のある利用者には永久に結び付けられない**
（**実測** : `super_tanaka` が下流にも居るため、`null` で扱った版では
`Rejected linking a SAML2 ID federation login to …` で止まった）。

**緩めたくない配備は `RequireVerifiedEmailForAccountLinking` を `false` にする**
（この判断に関わらず、その設定が優先される）。

> **段階 3 までは、`NameIDFormat` が `emailAddress` でなければ受け付けなかった。**
> **段階 4 では、属性でメアドが分かるなら受け付ける**（上の表）。
> **属性も無く、`NameID` もメアドでなければ、受け付けない**
> （**メアドでない値をメアドとして扱わないため**）。

#### Redirect Binding の `SigAlg` は、実際のアルゴリズム（Open棟梁 #604 の追随）

**Open棟梁 [#604](https://github.com/OpenTouryoProject/OpenTouryo/issues/604) で、
`SigAlg` が実際の署名アルゴリズムになった**（既定の SHA256 なら `rsa-sha256`）。
**受け手も `SigAlg` を見る**ようになったので、この repo も合わせてある。

| | 変更前 | 変更後 |
|---|---|---|
| 出す `SigAlg`（要求・応答とも） | **`rsa-sha1` 固定**（実際の署名は SHA256） | **`rsa-sha256`** |
| **SP の要求を受けるとき**（`CmnEndpoints.VerifySamlRequest`） | `Rsa_SHA256` 固定で検証 | **`SigAlg` でハッシュを選ぶ**（`RSA` を受ける版。SHA256 / 384 / 512） |
| **上流の応答を受けるとき**（`CmnSaml2Response`） | **`SigAlg` が `rsa-sha1` のときだけ検証** | **`SigAlg` でハッシュを選ぶ**（同上） |

> **利用者への影響がある。**
>
> | | |
> |---|---|
> | **旧版の Open棟梁 で署名する SP** | **Redirect Binding の `AuthnRequest` が通らなくなる**（`rsa-sha1` と名乗る SHA256 の署名）。**SP 側で Open棟梁 を更新すること** |
> | **ID 連携の上流** | **上流も #604 以降であること**（Redirect Binding の場合） |
> | POST Binding | **影響なし**（ハッシュは XML の `SignatureMethod` が持つ） |
> | **SHA1 の署名** | **受けない**（`VerifyRedirect` の既定の許可リストは SHA256 / 384 / 512） |

**この repo は `OpenTouryoAssemblies/` の複製を参照している**ので、
**複製を更新した時点で効く**（`1_BuildAll.ps1 -Libs Force`）。

#### 自己テストの `aud` は、その回の `client_id` で確認する（Open棟梁 #603 の追随）

**Open棟梁 [#603](https://github.com/OpenTouryoProject/OpenTouryo/issues/603) で、
設定で判定する `IdToken.Verify` / `ResponseObject.Verify` が、
`JwkSetFilePath` が在る配備（＝この配備）でも `aud` を確認するようになった。**

**自己テストは `OAuth2AndOidcClientID` 以外のクライアントでも回す**ので、
**設定で判定する版では落ちる。**
**そこで、[#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601) の版
（鍵・`iss`・`aud` を渡す）に移した。**

| 渡すもの | 値 |
|---|---|
| 鍵（`jws`） | **null**（自分が出したトークンなので、設定の選び方で引ける） |
| `iss` | **`IssuerId`（自分）** — **`SpRp_Isser` は「相手の Issuer」**であり、下流コンテナでは別の値である |
| `aud` | **その回の `client_id`**（セッション／Cookie に預けてある値） |

> **設定に `OAuth2AndOidcClientIDs` を列挙する案は採らなかった。**
> **クライアントを足すたびに設定も直すことになる**うえ、
> **「どれかのテスト用クライアント宛か」までしか確かめられない。**

#### メタデータ（`/samlmetadata`）から、上流の口と鍵を引く（#291）

| 設定キー | 雛形の値 | |
|---|---|---|
| `IdFederationSaml2MetadataUrl` | `https://localhost:44301/samlmetadata` | **上流のメタデータ**（`EntityDescriptor`）。**空なら従来どおり** |

**引くもの**（引けなければ、従来の設定に倒れる）。

| メタデータ | 倒れ先（設定） |
|---|---|
| `IDPSSODescriptor` ＞ `SingleSignOnService`（HTTP-Redirect）の `Location` | `IdFederationSaml2RequestEndpoint` |
| `KeyDescriptor use="signing"` ＞ `X509Certificate` | `IdFederationSaml2CerFilePath` |

**`entityID` は引かない。** **`IdFederationSaml2IssuerId` と照合する**ために使う。
**一致しなければ、メタデータの値は使わない**
（**設定の URL を差し替えられた配備で、別の相手の口と鍵を信じないため**）。
**自分の ACS（`IdFederationSaml2ResponseEndpoint`）も、設定のまま**である。

> **SAML2 には、メタデータの既知のパスが無い**（OIDC の `/.well-known/…` に当たるものが無い）。
> **だから、OIDC 側（#289）のように口の URL から組み立てる形にはしていない** — **URL を設定で与える。**

> **メタデータは署名されていない**（実測）。**信頼の根拠は TLS と `entityID` の照合だけ**である。
> **署名されたメタデータを検証する形は、まだ無い**（その鍵をどこから得るかを決める必要がある）。

**導線（サインイン画面のボタン）の出し方も変わった**（`Config.CanIdFederationBySaml2`）。

| | |
|---|---|
| **必ず要る** | 自分の ACS（`…ResponseEndpoint`）と、期待する上流の EntityID（`…IssuerId`） |
| **どちらかで揃っていればよい** | **メタデータの URL** ／ **口（`…RequestEndpoint`）と鍵（`…CerFilePath`）の両方** |

**鍵のロールオーバー中は、`KeyDescriptor` が 2 本以上並ぶことがある。**
**全部試す**（#292 の段階 3。**`SAML2` の署名には `kid` に当たるものが無い**ので、選べない）。
**取り直しの下限は 1 分**（OIDC 側の discovery と同じ）。

##### 鍵を引く宛先は「サーバが呼ぶ先」である（#293 の段階 3）

**メタデータ（`IdFederationSaml2MetadataUrl`）と JWK Set（`IdFederationJwkSetUri`）を引くのは、
サーバである。** **ブラウザが行く先（SSO / ACS / `authorize`）とは、分けて考えること。**

| | 誰が呼ぶか | 宛先 |
|---|---|---|
| SSO（`…Saml2RequestEndpoint`）／ ACS ／ `authorize` | **ブラウザ** | **ブラウザから届く URL** |
| **メタデータ ／ JWK Set ／ discovery** | **サーバ** | **サーバから届く宛先**（`token` / `userinfo` と同じ） |

**コンテナに入れた配備で、ここを取り違えていた**（実測 2026/10/13）。
**下流コンテナから `https://localhost:44301/samlmetadata` には届かない**
（公開ポートはホスト側のもので、コンテナの中の待ち受けは 8080 / 8081）。
**ログは `The SAML2 metadata could not be read. (empty response)`** で、
**一巡は通っていた** — **通っていたのは倒れ先（設定の `.cer`）である。**

> **倒れ先が在ると、引けていないことは落ちて教えてくれない。**
> **引けたかどうかはログで確かめる**
> （`The SAML2 metadata was read.` / `The JWK Set was read from the configured URL.`）。

**メタデータが書く SSO の口は、上流の公開 URL である**
（`OAuth2AuthorizationServerEndpointsRootURI` から作る。要求の `Host` では作らない）。
**だから、サーバから届く宛先でメタデータを引いても、ブラウザが行く先は正しい。**

> **discovery の `jwks_uri` も同じ理屈で、上流の公開 URL になる。**
> **discovery は読めても、その先の `jwks_uri` に届かない**ことがある。
> **その配備では `IdFederationJwkSetUri` を直接与える**（#290 の順番で、これが最も先に見られる）。

**例**（`store/docker-compose.yml` の下流コンテナ）。

```
appSettings__IdFederationJwkSetUri=http://upstream:8080/jwkcerts
appSettings__IdFederationSaml2MetadataUrl=http://upstream:8080/samlmetadata
```

#### 鍵の入れ替え（ロールオーバー。#292 の段階 3）

**署名鍵は、いつか替える。** **替えている途中は、新旧 2 本が世の中に在る。**
**出す側は 2 本広告し、受け取る側は 2 本試す** — **どちらも要る。**

##### 出す側（この配備の鍵）

| | 広告する所 | 新旧 2 本を並べる方法 |
|---|---|---|
| **OIDC** | `/jwkcerts`（`JwkSetFilePath`） | **`JwkSet.json` に並べる。** `CommandLineTools/CreateJwkSetJson` は**追記しかしない**ので、**新しい `.cer` で 1 回回せば 2 本になる**（**退役した鍵は手で消す**） |
| **SAML2** | `/samlmetadata` の `KeyDescriptor` | **`PreviousSigningCerFilePaths`**（空白かカンマ区切り）。**`SAML2Bindings.CreateMetadata` は 1 本しか受けない**ので、**出来上がった XML に足している** |

**順番**（どちらの方式でも同じ）。

| 順 | すること | なぜ |
|---|---|---|
| 1 | **新しい証明書を広告に足す**（署名はまだ古い鍵） | **相手のキャッシュに、新しい鍵を先に配る** |
| 2 | 相手のキャッシュが切れるのを待つ | **SAML2 のメタデータも OIDC の JWK Set も、相手がキャッシュする** |
| 3 | **署名鍵を入れ替える**（`RsaPfxFilePath` / `SpRp_RsaCerFilePath`） | ここで初めて、新しい鍵の署名が出る |
| 4 | **古い証明書を広告から外す** | 退役。**`JwkSet.json` は手で消す。** SAML2 は設定から外す |

> **OIDC は `kid` で選べる**（`id_token` のヘッダに入る）。
> **SAML2 は選べない** — **署名に `kid` に当たるものが無い**（`KeyInfo` は任意）。
> **だから SAML2 の受け取り側は、広告されている鍵を順に試す。**

##### (2) の署名鍵は、上流ごとに替えられる（#292 の段階 4-a）

**上流が「この SP の公開鍵はこれ」と指定してくる配備**のために在る。

| | 鍵 |
|---|---|
| 行に **`signing_pfx_file_path`** が在る | **その `.pfx`**（パスワードは `signing_pfx_password`。**空なら共通設定のパスワード**） |
| 空 | **共通設定**（`SpRp_RsaPfxFilePath`）。**従来どおり** |

**「行」は、設定でも user store でもよい**（#292 の段階 4-b）。
**`IdFederationUpstreams` 表に `SigningPfxFilePath` / `SigningPfxPassword` の列が在り、
管理画面（`/IdFederationAdmin`）から入れられる。**
**パスワードは暗号化して保管する**（#297 の対象。`ClientSecret` と同じ）。

**組み立ては `SamlProviders.IdFederationSaml2Request` の 1 か所**である
（**両アプリの `AccountController` に同文で置かない**）。
**鍵が読めなければ、共通設定に倒れる**（**設定の誤りで連携の口を死なせない**。理由はログに残す）。

> **(1)（SPRP → この IdP）の署名鍵は共通設定のまま**である。
> **あちらは「この配備がクライアントとして名乗る鍵」**で、**相手ごとに替える話は出ていない。**

##### 受け取る側（相手の鍵）

| | 引き方 |
|---|---|
| **OIDC** | **`kid` で引く**（`IdFederationJwkSetUri` / discovery の `jwks_uri`）。**JWK Set に 2 本在っても、合う 1 本を選ぶ** |
| **SAML2** | **メタデータの `KeyDescriptor` を順に全部試す** → **引けなければ設定の `.cer`**（最後の受け皿） |

**実測**（2026/10/14）。

| 測ったこと | 結果 |
|---|---|
| 上流の `/jwkcerts` に **RSA 2 本**（新旧） | **OIDC の ID 連携は通る**（`kid` で選べている。`RT-140.*` / `CN-5.*` の 31 件） |
| 上流の `/samlmetadata` に **2 本** | **SAML2 の ID 連携は通る**（`SA-6.6`） |
| **1 本目を「署名に使っていない証明書」にした** | **2 本目で検証して通る**（ログに `The SAML2 response was verified with key #2.`） |

#### なぜ (3) の鍵を `SpRp_RsaCerFilePath` にできないか

**(3)（上流 → 下流の応答）の検証鍵として、`SpRp_RsaCerFilePath` は使えない。**
**このキーは、この配備では「自分の証明書」として読まれている**（**(4) の側**）。

| | `SpRp_RsaCerFilePath` の役 | どの脚か |
|---|---|---|
| SAML2 | **`/samlmetadata` の `KeyDescriptor`**（**自分の証明書を広告する**） | **(4)** |
| OIDC | **`JwkSet.json`（`/jwkcerts`）の素**（`CreateJwkSetJson` が読む） | **(4)** |
| 共通 | **署名検証の控え**（`kid` が引けないとき。8 節） | (3) / (4) |
| クライアント役 | **相手の公開鍵**（Open棟梁 の `SAML2Client.VerifyResponse` が読む先） | **(3)** |

**1 つのキーが、(3) の検証鍵と (4) の広告鍵を兼ねている。**
**上流のものに差し替えると、(4) が壊れる**（**他人の証明書を広告することになる**）。

**だから (3) の鍵は、別のキーで持つ** — `IdFederationSaml2CerFilePath`（SAML2）／
`IdFederationJwkSetUri` ・ `IdFederationOidcDiscoveryUrl` ・ `IdFederationOidcCerFilePath`（OIDC）。

> **検証の本体は `CommonLibrary/SamlProviders/CmnSaml2Response.cs` にある。**
> **`SAML2Client.VerifyResponse` を使わず、`SAML2Bindings` を直に呼ぶ。**
> **以前は「あちらが検証鍵を引数に取らない」ためだったが、
> Open棟梁 #600 で鍵を渡せるようになった。**
> **いまも写しを使っているのは、`Reason`（落ちた理由）を画面と E2E が見ている**ためである。
> **署名検証そのものは `SAML2Bindings.VerifyRedirect` / `VerifyPost`** であり、
> **`AuthnRequest` の検証と同じもの**である。**実装が 2 本になるわけではない。**
>
> **自己テストの SP 役（`SelfTestClient.VerifySaml2Response`）も、同じ本体を使う。**
> **渡す引数が違うだけ**である（**自分の証明書と、自分の `IssuerId`**）。

#### 署名のない `AuthnRequest` は通る

**`jwk_rsa_publickey` を登録していないクライアントの `AuthnRequest` は、署名が無くても通る**
（`SamlProviders/CmnEndpoints.VerifySamlRequest` の「鍵がない場合は、通す」）。

**SAML では `AuthnRequest` の署名は任意**であり、**守りは別のところで効いている。**

| | |
|---|---|
| **返す先は、常に事前登録の `redirect_uri_saml`** | **要求に書かれた `AssertionConsumerServiceURL` は、登録値との照合にしか使わない**（#276）。一致するか、省略されているときだけ通す |
| **不一致なら、登録値へ `Requester`** | **要求の URL へは返さない** |
| **登録が無ければ、応答しない** | **返す先が決まらない**ので、エラー画面を返す（SAML Core 3.2.1） |

**つまり、署名が無くても「他人の ACS へアサーションを飛ばす」ことはできない。**
**署名を必須にしたい配備では、`jwk_rsa_publickey` を登録すること。**

> **メタデータは `WantAuthnRequestsSigned="true"` を固定で出している**（Open棟梁 の雛形）。
> **鍵を登録していない配備では、広告と振る舞いが揃っていない。**
> 測定は `SA-2.1`（広告）と `SA-5.4`（登録した場合に効くこと）。

> **「登録すれば検証される」ことは `SA-6.5` が測っている**（#293 の段階 4）。
> **製品が署名した本物の `AuthnRequest` の、署名だけを 1 バイト変えて送り**、
> **`Requester` で返ることを見る。**
>
> **登録を外すと、このケースは `Success` になって落ちる**（実測。「鍵がない場合は、通す」）。
> **つまり、登録が外れたことにも気付ける。**

---

### WebAuthn の有効・無効 — `FIDOServerMode`（#137）

**net10.0 版だけの設定である。**

| 値 | |
|---|---|
| `webauthn` | **有効**（雛形の既定）。登録は `/Manage/AddWebAuthnData`、認証はサインイン画面の [WebAuthn] |
| `none`（またはキーが無い） | **無効**。画面の導線も出ない |

**net48 版にこのキーは無い。**
**現行版の WebAuthn ライブラリが `netstandard2.0` を支えていない**ためである。
`Fido2` は **2.0.2 を最後に `netstandard2.0` を落としている**（3.0 以降は `net6.0` 以降）。
`WebAuthn.Net` / `Shark.Fido2` / `Rsk.AspNetCore.Fido` も net8.0 以降だけである。

#### 配備したときに注意すること

| | |
|---|---|
| **RPID はホスト名から決まる** | `OAuth2AuthorizationServerEndpointsRootURI` のホストをそのまま使う（`WebAuthnHelper` の constructor）。**資格情報はこの値に紐づく**ので、**ホスト名を変えると登録済みの認証器が使えなくなる** |
| **https が必要** | WebAuthn は安全なコンテキストしか走らない（`localhost` は例外） |
| **セッションに challenge を置く** | 複数インスタンスなら `SessionStoreType` を `mem` 以外にする（#256。置くのは `fido2.CredentialCreateOptions` / `fido2.AssertionOptions`） |
| **保存先は `FIDO2Data` 表** | `UserStoreType` が `mem` ならプロセス内の辞書に入るので、**再起動で消える** |
| **利用者を消すと、資格情報も消す** | `FIDO2Data` は `UserName` で持っている。**DB ストアでは外部キー**（`FK.FIDO2Data.Users_UserName`。`ON DELETE CASCADE`）**が落とす**。**`mem` には外部キーが無い**ので、**GDPR の削除（`/Manage/DeleteGdprPersonalData`）が明示的に消す**（#299） |

---

## 8. 証明書

```json
"RsaPfxFilePath":      "C:/root/files/resource/X509/SHA256RSA_Server.pfx",
"EcdsaPfxFilePath":    "C:/root/files/resource/X509/SHA256ECDSA_Server.pfx",
"SpRp_RsaCerFilePath": "C:/root/files/resource/X509/SHA256RSA_Server.cer",
"SpRp_RsaPfxFilePath": "C:/root/files/resource/X509/SHA256RSA_Client.pfx",
"SpRp_ClientCertPfxFilePath": "C:/root/files/resource/X509/SHA256RSAClientCert.pfx"
```

| キー | 誰の鍵か | 誰が読むか |
|---|---|---|
| `RsaPfx*` / `EcdsaPfx*` / `Ecdsa384Pfx*` / `Ecdsa512Pfx*` | **サーバの秘密鍵**（`*_Server.pfx`） | **サーバだけ。** SAML2 と JWT の署名 |
| `SpRp_RsaCerFilePath` / `SpRp_EcdsaCerFilePath` / `SpRp_Ecdsa384CerFilePath` / `SpRp_Ecdsa512CerFilePath` | **サーバの公開鍵**（`*_Server.cer`） | **サーバとクライアントの両方**（下記） |
| `SpRp_RsaPfx*` / `SpRp_EcdsaPfx*` | **クライアントの秘密鍵**（`*_Client.pfx`） | クライアントだけ。`client_assertion` と Request Object の署名 |
| `SpRp_ClientCertPfx*` | **クライアント証明書** | クライアントだけ。mTLS |

> **`SpRp_` は「クライアント側」という意味ではない。**
> Open棟梁 のクライアント用パラメタの接頭辞（`CmnClientParams.Isser` は `SpRp_Isser` を読む）であり、
> **意味は「相手（OP / IdP）の値」**である
> （[OpenTouryo#602](https://github.com/OpenTouryoProject/OpenTouryo/issues/602) で読み手を確かめた）。

#### 「この配備の値」と「相手の値」の分け方（#290）

**1 つの規則で揃えてある。**

| | 置き場 | 例 |
|---|---|---|
| **この配備の値**（**自分の役でも、相手が自分のときでも読む**） | **共通設定のまま**（`Client-Server共通設定` の節） | `JwkSetUri`（**自分の `/jwkcerts` のパス**）／`SpRp_*CerFilePath`（**この配備の証明書**） |
| **相手（上流 IdP）の値** | **`IdFederation*` のキー**（**相手ごとの値**） | `IdFederationJwkSetUri` / `IdFederationOidcDiscoveryUrl` / `IdFederationOidcCerFilePath` / `IdFederationSaml2*` |

> **以前は「サーバ役の自分の値」を別のキーに分ける案を採っていた**
> （`JwkSetEndpoint` / `RsaCerFilePath` など）。
> **やめた。** **同じ意味のキーが 2 本になるだけ**だったためである。
>
> **`JwkSetUri` も `SpRp_*CerFilePath` も、雛形では `Client-Server共通設定` の節に在る。**
> **「この配備の JWK Set の口」「この配備の証明書」**であり、
> **サーバ役が自分の値として読んでよい。**
>
> **本当に足りなかったのは「上流（相手）の値」**であり、
> **それは `IdFederation*` のキーが持つ**（#286 / #289 / #291 で揃えた）。

**この規則で、相乗りは解けている。**

| 以前の困りごと | いまの形 |
|---|---|
| **上流の証明書に差し替えられない**（`SpRp_RsaCerFilePath` は自分の証明書として読まれる） | **差し替えない。** 上流の証明書は `IdFederationOidcCerFilePath` / `IdFederationSaml2CerFilePath` |
| **上流の JWK Set を取りに行けない**（`JwkSetUri` は相対パスで、`new Uri(...)` に渡せない） | **`IdFederationJwkSetUri`**（または discovery の `jwks_uri`）から引く。**`JwkSetStore` の経路は通らない** |
| **期待する上流の Issuer が 1 つしか無い**（`SpRp_Isser`） | **上流ごとに持てる**（#292 の段階 1。`IdFederationUpstreams` の `issuer`）。**登録が無ければ、従来どおり SAML2 は `IdFederationSaml2IssuerId`、OIDC は `SpRp_Isser`** |

**サーバ側での読み方は 2 つある。**

| | |
|---|---|
| `/jwkcerts` の元 | `CommandLineTools/CreateJwkSetJson` が `.cer` から `JwkSet.json` を作る |
| 署名検証の控え | `CmnAccessToken.VerifyAccessToken` から `SelectJws`。**`kid` が無い / `JwkSet.json` が無い / その `kid` が載っていない**ときに `.cer` へ落ちる |

**alg と鍵の対応は `CommonLibrary/TokenProviders/SigningKeys.cs` の表が 1 か所で持つ**
（`alg` に対して `pfx`（署名）と `cer`（検証・JWK Set）を組で持たせてある。#129 の段階 3 / D-9）。

> **実測（2026/10/15）** : 発行されるトークンは **`kid` を持ち**（**`jku` は持たない**。#302）、
> `JwkSet.json`（RSA 1 本 ＋ EC 3 本）に載っているので、**通常は JWK の経路を通る。**
> **`.cer` は、鍵リングが欠けたときに落ちる先**として在る。
>
> **`jku`（ヘッダに書く JWK Set の URL）は、入れない**（#302 の段階 1。`ANALYSIS-IdP.md` の D-10）。
> **ヘッダに鍵の在り処を書くと、検証する側はその URL を取りに行く** —
> **出どころを発行者が自由に指し示せる**ので、**検証側の SSRF を誘発しうる。**
> **鍵は `kid` ＋ discovery の `jwks_uri` で引く**のが標準の経路である
> （**この製品も Open棟梁 も、検証では `jku` を読んでいない**）。
> **測定は `RT-302.1`**（access_token / id_token / JARM の 3 つを見る）。

> **`typ` は、トークンの種類で違う**（#302 の段階 2。RFC 9068 §2.1）。
>
> | トークン | `typ` |
> |---|---|
> | **access_token** | **`at+jwt`** |
> | id_token / JARM の応答 / Request Object | `JWT` |
>
> **受ける側も期待値を見る** — **`/userinfo` やリソース サーバは `at+jwt` 以外を拒否する**
> （RFC 9068 §4）。**`id_token_hint` は `JWT` を期待する**ので、
> **access_token を渡しても通らない**（取り違えの防止）。
>
> **配備したとき、発行済みの access_token は検証に通らなくなる**（`typ` が `JWT` のため）。
> **有効期限が切れるまでの間だけ**で、**`refresh_token` で取り直せば新しい `typ` になる。**

**絶対パスで書かれている。** リポジトリの `root/files/resource/X509` を、
そのパスへ配置するか、値を書き換える。生成用のバッチが同じフォルダにある。

#### 口ごとのレート制限 — `RateLimitPerClientPermits` / `RateLimitPerIpPermits` / `RateLimitWindowSeconds`（#305 の段階 3）

**段階 2 は「失敗の回数」、ここは「要求の回数」**である（**成否を問わない**）。
**成功する要求を浴びせる形の負荷は、段階 2 では止まらない。**

| 設定 | |
|---|---|
| **`RateLimitPerClientPermits`** | **`client_id` 1 つあたりの上限**（雛形は **120**。**0（未設定）なら制限しない**） |
| **`RateLimitPerIpPermits`** | **送信元アドレス 1 つあたりの上限**（雛形は **600**。同上） |
| **`RateLimitWindowSeconds`** | **数える窓の長さ**（雛形は **60** 秒。未設定も 60） |

**数える単位は「口 × 鍵」**である。

| | |
|---|---|
| **口ごと** | **`/token` の洪水で `/revoke` は止まらない** |
| **鍵は 2 つ** | **`client_id` ごと**（洪水を起こしたクライアントだけを止める）と、**送信元ごと** |
| **両方を数える** | **`client_id` が分かる要求は、送信元の方でも数える** — **`client_id` を毎回変えて上限を避ける**攻撃に、これが効く |
| 断るとき | **`429` ＋ `Retry-After`**（RFC 6585 §4。**本体は返さない**） |

**制限する口**（**ここに無い口は制限しない**）。

| 口 | 設定キー |
|---|---|
| `/token` | `OAuth2TokenEndpoint` |
| `/revoke` | `OAuth2RevokeTokenEndpoint` |
| `/introspect` | `OAuth2IntrospectTokenEndpoint` |
| `/device_authz` | `DeviceAuthZAuthorizeEndpoint` |
| `/device_verify` | `DeviceAuthZVerifyEndpoint` |
| `/ciba_authz` | `CibaAuthorizeEndpoint` |
| `/par` | `AuthRequestPushUri` |
| `/jwkcerts` | `JwkSetUri` |

> **`client_id` は、まず `Authorization: Basic` から読む**（RFC 6749 §2.3.1）。
> **無ければ本体**（`client_secret_post`）**か、クエリから拾う。**
> **どこにも無ければ、送信元アドレスだけで数える。**

> **`429` は OAuth のエラー応答にしていない。**
> **段階 1 の `slow_down` はプロトコルの層の話**（RFC 8628 §3.5）で、
> **こちらは HTTP の層の話**である（`/token` のエラー符号は RFC 6749 §5.2 で閉じている）。

**作りは、両アプリで同じ判断にしてある**（`Extensions/Sts/RateLimitProvider`）。

| | |
|---|---|
| net10.0 | `Startup.Configure` の `app.Use(...)`（**静的ファイルやセッションより前**） |
| net48 | `Global.asax` の `Application_OnBeginRequest` |

> **net10.0 には組み込みのレート制限ミドルウェアが在る**（`Microsoft.AspNetCore.RateLimiting`）**が、使っていない。**
> **net48 には組み込みが無く、別々に作ると振る舞いが分かれる** —
> **E2E は両方に同じテストを流す**ので、**判定は 1 か所に置いた。**

**限界**（**知っておく必要がある**）。

| | |
|---|---|
| **プロセスの中に覚える** | **インスタンスを増やすと、その数だけ緩くなる**（段階 2 は表に持たせたが、**ここは要求ごとに触るので表には置かない**） |
| **固定窓** | **窓の境目では、瞬間的に上限の 2 倍まで通り得る**（滑る窓にはしていない） |
| **プロキシの後ろ** | **見える送信元はプロキシのものになる。** net10.0 版は **`UseForwardedHeaders`**（＋ `ForwardedHeadersKnownProxies`）で元に戻せるが、**net48 版は戻さない。** **プロキシの後ろに置く配備では、プロキシ側で制限する方が確かである** |
| **鍵の粒度は、利用者の数に追随しない** | **同じ `client_id` の下に利用者が多数いる配備では、`RateLimitPerClientPermits` を「その全員分の正常な流量」に合わせる**ことになる — **すると、その `client_id` を騙る相手に対しては、それだけ緩くなる。** **送信元ごとの上限で補う形だが、これも万能ではない** : **public クライアント**（SPA・モバイル）**なら送信元は利用者ごとに分かれる**が、**NAT やキャリア・企業プロキシの背後は束**になる。**confidential クライアント**（サーバサイドの Web アプリ）**は、`/token` を自分のサーバ数本から呼ぶ**ので、**送信元も束になる** — **この場合、どちらの鍵も「利用者ごと」にはならない。** **利用者ごとの総当たりは、段階 2・段階 4 の「失敗の回数」で止める**（次の節） |

> **閾値の決め方は運用の判断である。**
> **ポーリングは `interval` を守っても 1 分に 12 回**（`interval` が 5 秒のとき）なので、
> **雛形の 120 回 / 60 秒は、正しいクライアント 10 本分に当たる。**
> **足りなければ上げる。** **0 にすれば、従来どおり無制限である。**

#### 認証の失敗を数える — `AuthFailureMaxAttempts` / `AuthFailureLockoutSeconds` / `AuthFailureWindowSeconds`（#305 の段階 2・段階 4）

**総当たりを「回数」で止める。**

| 設定 | |
|---|---|
| **`AuthFailureMaxAttempts`** | **連続してこの回数失敗したら断る**（雛形は **5**。**0（未設定）なら数えない** ＝ 従来どおり） |
| **`AuthFailureLockoutSeconds`** | **断る長さ**（雛形は **300** 秒。未設定も 300） |
| **`AuthFailureWindowSeconds`** | **数えた分を覚えている長さ**（雛形は **300** 秒。**未設定は `AuthFailureLockoutSeconds` と同じ**。段階 4） |

| 鍵 | 何の失敗か |
|---|---|
| **`client:<client_id>` ＋ `ip:<送信元>`** | **クライアント認証**（`client_secret` / mTLS） |
| **`device_verify:<利用者>`** | **`user_code` の投入**（RFC 8628 §5.2） |
| **`Users` 表の `AccessFailedCount`** | **利用者のパスワード**（**画面のサインイン**と、**`/token` の `grant_type=password`**。段階 4） |

**置き場は `AuthFailure` 表**（`Extensions/Sts/AuthFailureProvider`。`mem` では辞書）。
**表に持つので、インスタンスを増やしても効く。**
**利用者のパスワードだけは `Users` 表**（ASP.NET Identity の数え）。

| | |
|---|---|
| **成功したら消す** | **連続した失敗だけを数える**（ASP.NET Identity のロックアウトと同じ考え） |
| **断っている間** | **正しい資格情報でも通さない** — それがロックアウトである |
| 応答 | **従来どおり `invalid_client`**（**断っていることは教えない**） |
| 期限が切れたら | **また同じ回数だけ試せる**（回数は 0 に戻す） |
| **間隔を空けた失敗は積まれない** | **最後の失敗から `AuthFailureWindowSeconds` 経つと、数えた分は忘れる**（段階 4） |

##### 数えるのは「クライアント ＋ 送信元」である（段階 4）

**段階 2 は `client_id` だけで数えていた。**
**これは、ロックアウトそのものが妨害の手段になる形だった。**

| | |
|---|---|
| **`client_id` は外から見える** | **authorize の URL に載る**（秘密ではない） |
| **失敗は誰でも起こせる** | **間違った `client_secret` を上限まで送るだけ**でよい |
| **止まるのは全員** | **同じ `client_id` の利用者が多数いる配備では、被害がその人数分になる。** **`/token` だけでなく `/revoke` `/introspect` `/device_authz` も同じクライアント認証を通る**ので、**そのクライアントの口が全部止まる** |

**段階 4 で、送信元を鍵に混ぜた。**
**断るのは失敗を重ねた送信元だけで、正しい秘密を持つ他の送信元は通ったままである**
（`RT-305.7` が、それを測っている）。

> **多数の送信元から分散して試す経路は、ここでは止まらない**（各送信元が上限まで試せる）。
> **その頭を打つのは、口ごとのレート制限である**（段階 3。前の節）。
> **「回数」と「流量」は、別々に要る** — **これが両方を入れた理由である。**

> **プロキシの後ろでは、送信元がプロキシのものになる**ので、**鍵が分かれない**
> （段階 3 の限界と同じ）。**net10.0 版は `UseForwardedHeaders` で元に戻せる。**
>
> **そのときは `ForwardedHeadersKnownProxies` を必ず指定すること。**
> **指定しないと、クライアントが `X-Forwarded-For` を詐称して鍵を変えられる** —
> **送信元ごとの数えも、送信元ごとのレート制限も、意味を失う。**

> **`private_key_jwt` の失敗は数えていない。**
> **署名を当てることはできない**ので、回数で止める意味が無い
> （**数えると、アサーションの `iss` を騙るだけで、そのクライアントの枠を汚せる**）。

##### 行は、期限が切れたら消える（段階 4）

**鍵に送信元が入るので、行の数は「クライアント × 送信元」になる。**
**放っておくと増えるだけなので、2 つ手当てがある。**

| | |
|---|---|
| **登録の無い `client_id` では数えない** | **要求の `client_id` をそのまま鍵にして行を作ると、誰でも表を好きなだけ太らせられる**（登録の有無は `GetClientName` で見る） |
| **期限の切れた行を消す** | **どの行も期限を持つ**ようにした（**断る期限**か、**数えた分の寿命**）。**期限が過ぎた行は意味を持たない**ので、**書き込み 100 回に 1 回、まとめて `DELETE` する**（要求ごとには撃たない） |

##### `/token` の `grant_type=password` も数える（段階 4）

**この口だけ、パスワードの失敗を数えていなかった。**
**`SignInManager` を通らず `VerifyHashedPassword` を直に呼んでいた**ため、
**画面のサインインのロックアウトが効かなかった**（`CmnEndpoints.GrantResourceOwnerCredentials`）。

**段階 4 で、画面と同じ数えに合流させた。**

| | |
|---|---|
| 設定 | **`MaxFailedAccessAttemptsBeforeLockout` / `DefaultAccountLockoutTimeSpanFromSeconds` / `UserLockoutEnabledByDefault`**（**画面と同じ**。新しい設定を増やしていない） |
| 置き場 | **`Users` 表**（`AccessFailedCount` / `LockoutEndDateUtc`） |
| 応答 | **どの場合も `access_denied`** — **「利用者が居ない」「パスワードが違う」「断っている」を区別させない** |

> **別の数えを作らなかったのは、口を変えれば回数が戻る、という抜けを作らないため**である。
> **画面で 3 回間違えて `/token` で 3 回間違えたら、合わせて 6 回**になる。

> **ROPC は雛形の既定で無効**（`EnableResourceOwnerPasswordCredentialsGrantType`）。
> **有効にしている配備にだけ効く話である。**

> **利用者名が見つからないときは数えられない**（鍵が無い）。
> **利用者名を変えながら試す経路は、口ごとのレート制限で頭を打つ**（段階 3）。

> **利用者のロックアウトも、ASP.NET Identity の形のまま「利用者ごと」である** —
> **利用者名を知っていれば、その人を一定時間止められる。**
> **これは画面のサインインが元から持っている性質**で、段階 4 で変えていない
> （`UserLockoutEnabledByDefault` を `false` にすれば、どちらも数えなくなる）。

> **`user_code` は「投入した人」で数える。**
> **間違えた `user_code` では、どの要求を狙ったか分からない**ためである
> （RFC 8628 §5.2 が求めるのは、**投入の制限**である）。

> **既存のデータベースには表が要る**（#305 の段階 2）。
> **`Create_UserStore.sql` を流し直す**か、**表を 1 つ足す。**
>
> ```sql
> -- SQL Server
> CREATE TABLE [AuthFailure](
>     [FailureKey] [nvarchar](256) NOT NULL,
>     [FailedCount] [int] NOT NULL,
>     [LockoutEndAt] [bigint] NULL,
>     CONSTRAINT [PK.AuthFailure] PRIMARY KEY NONCLUSTERED ([FailureKey] ASC)
> )
>
> -- Oracle
> CREATE TABLE "AuthFailure"(
>     "FailureKey" NVARCHAR2(256) NOT NULL,
>     "FailedCount" NUMBER(10) NOT NULL,
>     "LockoutEndAt" NUMBER(19) NULL,
>     CONSTRAINT "PK.AuthFailure" PRIMARY KEY ("FailureKey")
> );
>
> -- PostgreSQL
> CREATE TABLE AuthFailure(
>     FailureKey varchar(256) NOT NULL,
>     FailedCount int NOT NULL,
>     LockoutEndAt bigint NULL,
>     CONSTRAINT PK_AuthFailure PRIMARY KEY (FailureKey)
> );
> ```
>
> **表が無いと、クライアント認証で落ちる**（数える設定のときだけ）。
> **`AuthFailureMaxAttempts` を 0 にすれば、表を読まない。**
>
> **段階 4 で列は変えていない**（鍵が長くなるだけで、`nvarchar(256)` に収まる）。
> **段階 2 の表をそのまま使える。**

> **数える設定では、`/token` 1 回につき表を 2 回触る**
> （**断っているかの `SELECT`** ＋ **成功したときの `DELETE`**）。
> **`AuthFailureMaxAttempts` が 0 のときは、どちらも走らない。**
>
> **失敗したときは、さらに書き込みが 1 回**（`UPDATE`。無ければ `INSERT`）、
> **その 100 回に 1 回だけ、掃除の `DELETE` が 1 回**（段階 4）。
> **掃除は失敗しても認証を落とさない**（次の機会に消せばよい）。

#### ポーリングの間隔 — `EnablePollingSlowDown`（#305 の段階 1）

**Device Authorization Grant と CIBA は、クライアントが `/token` を繰り返し叩く。**
**間隔は `interval` で伝えてある**（`DeviceAuthZPollingIntervalSeconds` /
`CibaPollingIntervalSeconds`。どちらも雛形は **5 秒**）**が、守らなくても何も起きなかった。**

| 値 | 振る舞い |
|---|---|
| **`true`（未設定も同じ）** | **前回から `interval` 未満で来た要求に `slow_down`**（RFC 8628 §3.5 / CIBA §11） |
| `false` | **従来どおり**（`authorization_pending` を返し続ける） |

**判定に使うのは「最後にポーリングされた時刻」だけ**である
（`DeviceAuthZData` / `CibaData` の **`LastPolledAt`**。UNIX 時刻）。

| | |
|---|---|
| **初回** | **`slow_down` にしない**（`LastPolledAt` が無い） |
| **`interval` ちょうど** | **許す**（**ちょうどで断ると、正しいクライアントが詰まる**） |
| **`slow_down` のとき** | **要求は消さない**（まだ承認待ち）。**待ってから叩けば `authorization_pending` に戻る** |
| 置き場 | **表に持つ**ので、**インスタンスを増やしても効く**（プロセス内に覚えると、別のインスタンスへ投げれば抜けられる） |

> **既存のデータベースには列が要る**（#305 の段階 1）。
> **`Create_UserStore.sql` を流し直す**か、**`ALTER` で足す。**
>
> ```sql
> -- SQL Server
> ALTER TABLE [DeviceAuthZData] ADD [LastPolledAt] [bigint] NULL;
> ALTER TABLE [CibaData]        ADD [LastPolledAt] [bigint] NULL;
>
> -- Oracle
> ALTER TABLE "DeviceAuthZData" ADD ("LastPolledAt" NUMBER(19) NULL);
> ALTER TABLE "CibaData"        ADD ("LastPolledAt" NUMBER(19) NULL);
>
> -- PostgreSQL
> ALTER TABLE deviceauthzdata ADD COLUMN lastpolledat bigint NULL;
> ALTER TABLE cibadata        ADD COLUMN lastpolledat bigint NULL;
> ```
>
> **列が無いと、ポーリングの SELECT が落ちる。**

#### `/jwkcerts` のキャッシュ — `JwkSetCacheMaxAgeSeconds`（#303）

**この口は、トークンを検証する相手が必ず読む。**
**内容は鍵を入れ替えるまで変わらない**ので、**持ち回らせてよい。**

| 値 | 応答 |
|---|---|
| **0（または未設定）** | **`Cache-Control: no-store`**（**従来どおり**。毎回取りに来る） |
| 正の秒数（雛形は **300**） | **`Cache-Control: public, max-age=<秒>`** |

**`ETag` は、値に関係なく常に付く**（中身の SHA-256。**同じ中身なら同じ値**）。
**`If-None-Match` が一致すれば `304`** を返し、**本文を送らない。**

**サーバ側でも覚える**（`Extensions/Sts/JwkSetDocument`）。
**ファイルの最終更新時刻と長さだけを見て**、変わっていなければ覚えている分を返す
（**`stat` だけで済ませ、中身は読まない**）。

> **鍵を入れ替えた直後は、`max-age` の間だけ古い鍵を見る相手が居る。**
> **出す側は新旧 2 本を広告する**（#291 / #292 の段階 3）ので、**入れ替えの最中も検証は通る。**
> **`max-age` は、鍵を入れ替える周期より短くすること。**

> **起動時に 1 度だけ読む形にはしていない。** **ロールオーバーに追随できなくなる**ためである。
> **`JwkSet.json` を作り直せば、次の要求で新しい内容が返る**（測定は `RT-303.2`）。

**同梱の証明書は、テスト用の自己署名である。** 本番では使わないこと（パスワードも雛形に書いてある）。

- `SpRp_ClientCertPfxFilePath`（`SHA256RSAClientCert.pfx`）は、**アプリが外向きに呼ぶときの
  HttpClient に必ず載る**（`Extensions/Sts/Helper.cs`）。サーバが要求すれば、これを提示する
- **Subject は、クライアント登録の `tls_client_auth_subject_dn` と一致させること。**
  雛形では `TestClient1` / `TestClient2` の値（`CN=MPAS Test Client`）
- 作り直すバッチは `GenClientCertByOpenSSL.bat`（先頭に `_` の付いたファイルができる。
  確かめてから名前を変えて置き換える）
- **期限切れにしないこと。** 期限切れの証明書を提示すると、要求した相手との TLS がそこで失敗する

### クライアント証明書（mTLS）を受け付ける

**`fapi2` の登録は、mTLS（RFC 8705 の `tls_client_auth`）でしか通らない**（`ANALYSIS-IdP.md` C-7）。
使うには、**サーバ側で、クライアント証明書を要求させる設定が要る。雛形のままでは要求しない**（#226 で実測）。

**アプリは、証明書の Subject と、登録の `tls_client_auth_subject_dn` の一致だけを見る。**
**発行元（チェーン）と失効の検証は、TLS の層（Kestrel / IIS）に任せている。**
したがって、TLS の層で**信頼できる発行元だけを受け付ける**ように設定すること。

| | 設定 | 検証 |
|---|---|---|
| net10.0（Kestrel） | `Kestrel:EndpointDefaults:ClientCertificateMode` を `AllowCertificate`（証明書の無いクライアントも通す）または `RequireCertificate`。`appsettings.json` でも環境変数（`Kestrel__EndpointDefaults__ClientCertificateMode`）でもよい | 既定でチェーンと失効を検証する。自己署名など信頼できない証明書は、TLS の段階で切れる |
| net48（IIS） | サイトの `<access sslFlags="Ssl, SslNegotiateCert" />`（証明書を要求するが、無くても通す） | 信頼できない証明書は、アプリより前で **HTTP 403.16** になる |

- **証明書を要求させる口は、`/token` だけでは足りない。**
  mTLS で発行したトークンは証明書に紐づく（`cnf`）ので、**そのトークンを受ける口でも照合する**（RFC 8705 §3。`ANALYSIS-IdP.md` C-19）。
  照合には証明書の提示が要るため、**`/userinfo` にも同じ設定が要る。**
  紐づいたトークンを `/ciba_result` `/SetDeviceToken` `/2fa_result` にも出すなら、それらにも要る
  （認証デバイスは証明書を使わないので、通常は不要）。
  net48（IIS）は、サイト全体ではなく**口ごとに**掛けること。サイト全体に掛けると、
  サーバが自分自身を呼ぶ経路（FAPI2 の自己テスト）が証明書を求められて止まる（実測）
- **リバース プロキシで TLS を終端する場合、アプリには証明書が届かない。** 今の実装は、プロキシが転送するヘッダ
  （`X-ARR-ClientCert` など）を読まない
- `tls_client_auth_subject_dn` は **JSON の文字列**なので、`\\` は 1 文字の `\` になる。
  照合するのは、.NET が返す `X509Certificate2.Subject` の文字列
- **E2E のテスト専用のフック（`Tests/MtlsTestHook`）は、発行元を問わずに受け付ける。本番の構成で読ませないこと**
  （`test.ps1 -Launch` が、起動したサイトにだけ `DOTNET_STARTUP_HOOKS` で渡す。Development 以外では何もしない）

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
| 認証クッキーの設定 | `App_Start/StartupAuth.cs` | `Startup.cs` の `ConfigureApplicationCookie`（#223） |
| セッションの置き場 | `Web.config` の `sessionState`（既定 `StateServer`） | `SessionStoreType`（`mem` / `sql` / `redis`。#256） |
| WebAuthn | **無し**（設定キーも無い。#137） | `FIDOServerMode`（`none` / `webauthn`。既定 `webauthn`） |
| 転送ヘッダの取り込み | IIS 側（ARR の `<proxy>` など） | `UseForwardedHeaders` / `ForwardedHeadersKnownProxies`（#279） |
| HTTPS へのリダイレクト | IIS 側（URL Rewrite） | `UseHttpsRedirection`（#279） |
| Cookie の `Secure` を全部に付ける | `Web.config` の `<httpCookies requireSSL>` | `CookieSecurePolicy`（#279。`CookiePolicyOptions` は DI 側に一本化） |

**両者は共通ライブラリを使う別アプリである。** 片方にしか無い問題があり得る。

> **実例**: `AuthCookieExpiresFromHours` / `AuthCookieSlidingExpiration` は、
> **net10.0 では長らく読まれていなかった**（#223）。
> 設定は書かれていたが、**誰も使っていないスキームに対する指定**だったため。
> **雛形の値（`336` 時間）が Identity の既定（14 日）と偶然一致していて、表面化しなかった。**
> **「設定ファイルに在る」ことと「効いている」ことは別である。**

---

## 11. 本番へ切り替えるときに見るもの

**雛形の既定は「開発・テストで動く」状態である。** 本番へ出す前に、次を確認する。

> **一覧の目的は、読み落としを減らすこと。** 各キーの意味は雛形のコメントが一次情報。

### 設定

| キー | 雛形の既定 | 本番 | なぜ |
|---|---|---|---|
| `UserStoreType` | `mem` | `sql` / `ora` / `npg` | `mem` は**再起動で消える**。**`mem` のままだと `IsDebug` が常に true になる**（下の注意 1） |
| `IsDebug` | `true` | `false` | テスト利用者の生成、メール / SMS の送信の代替、ログの扱いが変わる |
| `SessionStoreType` | `mem`（#256） | **複数インスタンスなら `redis` / `sql`** | **画面のセッションの置き場**（7 節「セッションの置き場」）。**`mem` は複数インスタンスで共有されない** — ID 連携の `state` / `nonce` / `code_verifier`、管理画面の `access_token`、FIDO2 の challenge が読めず、**途中で失敗する**。**書かなければ `mem`**（既存の配備は従来どおり）。`sql` は `Create_SessionCache.sql` が要る。**`ora` / `npg` 用の実装は標準に無いので `redis`。** **net10.0 版だけ**（net48 版は `Web.config` の `sessionState`） |
| `DataProtectionKeyPath` | `""`（空） | **コンテナでは必須**（#251） | **DataProtection の鍵の置き場。** 空なら `%LOCALAPPDATA%` 配下（**コンテナでは揮発 → 再起動で全員サインアウト**）。**net48 の `machineKey` と同じ役割**だが、**鍵そのものは書かない**（置き場を共有する。鍵は自動生成・自動ローテーション）。**効くのは画面のセッション**（認証 Cookie / AntiForgery / メール確認のリンク）で、**access_token・PPID・refresh_token には影響しない**。**鍵リングは平文の XML**。**#279 で、アプリケーション名を固定した**（`SetApplicationName`） — 既定は**コンテンツ ルートのパスから導かれる**ため、**同じ置き場を見ていても、配備先のパスが違うと復号できない**（コンテナの入れ替えやスケール アウトで全員サインアウト）。**裏返しとして、別の配備と同じ置き場を共有すると Cookie を相互に復号できる**ので、**配備ごとに別の置き場を与えること**（`CookieNamePrefix` / `AuthCookieName` と同じ話）。**net10.0 版だけ** |
| `UseHttpsRedirection` | `""`（空＝呼ばない） | **TLS 終端を前段に置くなら `on`** | **http で来た要求を https へリダイレクトする**（#279。上流 Open棟梁 #549）。**空なら呼ばない**（従来どおり）。**効かせるには転送先のポートが判る必要がある** — `ASPNETCORE_HTTPS_PORT`（**単数形**）か `UseForwardedHeaders` 経由。**判らないと、例外にならずリダイレクトしない**（気付きにくい）。5 節「リバース プロキシや TLS 終端の背後に置く」。**net10.0 版だけ** |
| `CookieSecurePolicy` | `""`（空） | **`always`** | **すべての Cookie に `Secure` を付ける**（#279）。空なら、各 Cookie 自身の宣言に従う（認証まわりは元から `Secure`）。**`always` にすると、平文 HTTP ではサインインできなくなる**ので、開発では空のままにする。**net10.0 版だけ**（net48 版は `Web.config` の `<httpCookies requireSSL>`） |
| `UseForwardedHeaders` | `""`（空＝取り込まない） | **リバース プロキシの背後なら `on`** | **`X-Forwarded-Proto` / `X-Forwarded-For` を取り込む**（#279。上流 Open棟梁 #549）。**取り込まないと、プロキシが https で受けていてもアプリは http だと思う** → `issuer`・リダイレクト先の URI・`Secure` の判定がずれる。**パイプラインの先頭で呼んでいる。** **net10.0 版だけ** |
| `ForwardedHeadersKnownProxies` | `""`（空） | **プロキシの IP を列挙する** | **転送ヘッダを信じるプロキシの IP**（#279。カンマ区切り）。**`UseForwardedHeaders` が `on` のときだけ読む。** 空なら、**送った相手を問わない**（`KnownProxies` / `KnownIPNetworks` を空にしてあるため）。**プロキシを経由せずアプリに直接届く経路があるなら、必ず列挙する。** **net10.0 版だけ** |
| `OAuth2ContainerizatedAuthSvrFqdnAndPort` / `OAuth2ContainerizatedAuthSvrEPRootURI` | `""`（空） | **コンテナ配備で自己テストを使うときだけ** | **サーバが自分自身を呼ぶときの宛先**（#250）。宛先は `OAuth2AuthorizationServerEndpointsRootURI` から組み立てられるが、**コンテナの中からは外向けのホスト名・ポートに届かない**（実測 : コンテナ内から `localhost:44301` は CLOSED、待ち受けは 8080 / 8081）。`Helper.GetContainerizatedAuthZServerUri` が差し替える（**Windows でないときだけ働く**）。`FqdnAndPort` はホスト名とポートだけ、`EPRootURI` はスキームごと差し替える。**HTTPS のままにすると、コンテナの中で証明書を検証できない**ので、`store/` の上流は `EPRootURI` に **HTTP のループバック**を与えている |
| `CookieNamePrefix` | `""`（空） | **同じホストに 2 つ立てるときだけ** | **Cookie の名前に付ける接頭辞**（#255）。**先頭が `.` なら、その後ろに入る**（`.MultiPurposeAuthSite` → `.upstream_MultiPurposeAuthSite`）。**名前を決められるものすべてに掛かる** — 認証・外部ログイン・2FA（Identity の 4 スキーム）、セッション、`auth_time` / `re_auth_at`、TempData。**`max_age` の判定に使う**ので、混ざると**再認証の要否を誤る**（サインインは妨げない）。**名前そのものは `AuthCookieName` と `sessionState:SessionCookieName` で決め、この設定は「どの配備か」を表す**（役割が違う）。**`AuthCookieName` が空でも、枠組みの既定名に接頭辞が付く**（`.probe_AspNetCore.Identity.Application` など。#283。**以前はこの組み合わせだけで 500 になっていた**）。**分けられないのは `SessionTimeOut`（Open棟梁 の定数）だけ**だが、雛形は `FxSessionTimeOutCheck` を `off` にしているため読まれない。**AntiForgery にも掛かる**（#282）。名前は net10.0 版では **DataProtection の識別子から導かれ**、**#279 でそれを固定したので、`DataProtectionKeyPath` を設定した配備同士はパスが違っても同名になる**（**実測 2026/10/08**。[`TESTING.md`](TESTING.md) 1 節）。net48 版は `AntiForgeryConfig.CookieName`。**net48 版のセッション Cookie は ASP.NET のもの**（`system.web/sessionState`）で、これも対象外 |
| `AuthCookieName` | `""`（空） | **同じホストに 2 つ立てるときだけ** | **認証 Cookie の名前**（#250 の段階 4）。空なら既定（net10.0 : `.AspNetCore.Identity.Application` / net48 : `.AspNet.ApplicationCookie`）。**Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、`localhost:44300`（下流）と `localhost:44301`（上流）は **Cookie を共有し、後にサインインした側が相手を蹴り出す。** **パスが違っても解決しない**（仮想ディレクトリ配下と root で同名・別パスの Cookie が 2 つ並ぶ）。**ID フェデレーションは毎回この経路を通る**ので、上流には別名を与えること |
| `UserClaimsMapping` | `{}`（空） | **任意** | **`profile` / `address` で返すクレームの対応付け**（#230）。**空なら何も返らない。** 値の在り処は `UnstructuredData` の中のパスか、`user:UserName` / `user:Email` / `user:PhoneNumber`。**利用者名を RP に渡したいなら `{"preferred_username": "user:UserName"}`**（#151 の段階 1）。**`sub` は利用者を指す識別子なので、そこに載せてはならない**。**ID 連携の下流は、新規に作る利用者名にこれを使う**（#151 の段階 4）。**サンプルは下の「標準クレームを返す」**（#261） |
| `EnableDebugTraceLog` | `true` | `false` | 冗長なトレースを止める（**改名した**。旧 `EnabeDebugTraceLog`。下の 12 節） |
| `TestUserPWD` | `[password of TestUser]` | **空にする** | 空なら、テスト利用者（`super_tanaka@gmail.com` / `tanaka@gmail.com`）を**作らない** |
| `TestUserSuffix` | `""`（空） | **E2E が渡す。手で設定しない** | **テスト利用者の名前に付ける接尾辞**（#260）。空なら `super_tanaka` / `tanaka`。**E2E は 2 つのサイトを同時に立てる**ので、**DB ストアでは同じ利用者の行を書き換え合う。**`test.ps1` がサイトごとに `_core` / `_netfx` を渡して分ける。**初期化済みの DB でも、居なければ作る**ので、接尾辞を変えても DB を作り直さなくてよい |
| `AdministratorUID` / `AdministratorPWD` | `[Please fill in this input item.]` | 実運用の値 | **`IsDebug` に関係なく作られる**（下の注意 2）。既定のまま出さない |
| `IsLockedDownTestEndpoints` | `false` | `true` | **テスト用の口をまとめて閉じる。** 自己テスト画面（`/Home/Saml2OAuth2Starters`）、テスト用のリダイレクト先、`/TestHybridFlow`、`api/Values`（net10.0）。**`/Ping` は閉じない**（下の注意 3） |
| `EnableImplicitGrantType` / `EnableResourceOwnerPasswordCredentialsGrantType` | **`false`**（#220 で変更） | `false` のまま | **OAuth 2.1 で廃止されたフロー。** コードは残してあるので、必要なら `true` に戻せる |
| `RequirePkce` / `RequirePkceS256` | `false` | **任意**（下の注意 5） | **OAuth 2.1 に寄せるための締め金**（#220）。既定は従来どおり緩い。`RequirePkceS256` は Discovery の `code_challenge_methods_supported` にも効く（#228） |
| `RequireVerifiedEmailForAccountLinking` | **`true`**（#140 の段階 1 で追加） | `true` のまま | **外部 ID を既存アカウントに結び付けるとき、上流が `email_verified: true` と言ったメアドだけを鍵にする。** **未設定でも `true`**（他の `Require*` と既定の向きが違う）。`false` にすると従来どおり（上流の言い値で結び付ける）。**Google は `email_verified` を写すようにしたので自動リンクできる。Microsoft Account は示せないので、`/Manage/ManageLogins` での明示的な追加になる** |
| `FacebookAuthentication` / `TwitterAuthentication` | `false` | **触らない** | **サポートを取り下げた**（#249）。**`true` にしても有効にならない**（アプリ側の登録をコメント アウトしてある）。**動かないからではなく、維持コストが便益に見合わないため。** キーを残してあるのは戻せるようにするため（`CommonLibrary/ANALYSIS.md` 12 節） |
| `ServiceDocumentation` | `""`（空） | **任意** | Discovery の `service_documentation`。**空なら出さない**（#228）。文書を公開しているなら、その URL |
| `AuthRequestPushUri` | `/par` | 既定のまま | PAR（RFC 9126）の口（#229）。独自の `/ros`（`RequestObjectRegUri`）とは別。**改名した**（旧 `PushedAuthorizationRequestEndpoint`。下の 12 節） |
| `OAuth2AuthorizationCodeExpireTimeSpanFromSeconds` | `600` | 既定のまま（または短く） | 認可コードの寿命（#188）。RFC 6749 §4.1.2 は 10 分以内を推奨 |
| `RequestObjectExpireTimeSpanFromSeconds` | `300` | 既定のまま（または短く） | `/ros` に預けた Request Object の寿命（#188）。応答の `exp` にも出る |
| `OAuth2RefreshTokenExpireTimeSpanFromDays` | `14` | 運用に合わせる | **#188 で、実際に検証するようになった**（以前は事実上の無期限）。短くすると、既存のトークンが失効する |

> **#188 で `RefreshTokenDictionary` に 2 列を足した**（`FamilyId` / `UsedDate`。3 方言とも）。
> **既存のデータベースには `ALTER` が要る**（移行用のスクリプトは用意していない）。
> 新規に作る場合は `Create_UserStore.sql` のままでよい。詳細は `ANALYSIS-IdP.md` C-5。
| `FcmOutboxDirectory` | `""`（空） | **空のまま** | 設定すると、プッシュ通知を FCM に送らずファイルに書く（テスト用。2 節） |
| `OAuth2ClientsInformation` | **テスト用が 12 件** | 実運用のものだけ残す | `TestClient` `TestClient1`〜`5` `MVC_Sample` `WebForms_Sample` `SPA_Application` `Native_Application` `AuthenticationDevice_Web` `IdFederation` が**登録済みクライアントとして使える**まま |

**net48 / net10.0 で、キー名と既定値は同じ。** 書き方だけ違う（10 節）。

```xml
<!-- app.config -->
<add key="IsDebug" value="false" />
<add key="TestUserPWD" value="" />
```

```json
// appsettings.json
"IsDebug": "false",
"TestUserPWD": "",
```

### 起動したあとの確かめ方

| 見るもの | 期待 |
|---|---|
| `/Home/Saml2OAuth2Starters` | 自己テスト画面ではなく **Index が出る**（`IsLockedDownTestEndpoints`） |
| 雛形のテスト利用者でサインイン | **できない**（`TestUserPWD` が空なら作られていない） |
| `.well-known/openid-configuration` | HTTP 200 で、`issuer` が本番の URL（5 節） |
| `ACCESS` / `OPERATION` ログ | 冗長なトレースが出ていない（`EnableDebugTraceLog`） |

### キーを改名した（`IsLockedDownRedirectEndpoint` → `IsLockedDownTestEndpoints`）

閉じる対象がリダイレクト先だけではなくなったため、名前を実態に合わせた（#219）。

- **旧いキー名も読む。** 新しいキー名が無ければ、旧いキー名を使う
- **旧いキー名だけのときは、起動時に警告する**（下の「起動時の自動確認」）
- **未設定のときは `false`（＝開く）。** だから「改名しただけ」だと、
  既存の設定ファイル（旧キーしか無い）で**本番が黙って開いてしまう。** 互換を残したのはこのため

### 起動時の自動確認

**このチェックリストの読み落としを拾うため、起動時にも確かめている**（`Co/ProductionCheck`。両アプリ）。

- 該当すると、`OPERATION` ログに `[設定の確認] …（CONFIGURATION.md 11 節）` が出る
- **起動は止めない。** 設定を直せない状況で復旧できなくなるため
- **`UserStoreType` が `mem` のときは何も言わない**（開発・テスト専用の構成なので、雑音にしかならない）。
  ただし `AdministratorUID` / `AdministratorPWD` が雛形の値のままのときだけは、ストアによらず言う
- **`RequirePkce` / `RequirePkceS256` の 1 件だけは、性質が違う**（#220）。
  `false` は「開発向けの設定が残っている」ではなく、**従来の OAuth 2.0 のまま**というだけで、
  それ自体は誤りではない。**本番では意図して選ぶべき**なので、選ばれていないことだけを知らせる

**ログに出ていないこと＝設定が正しいこと、ではない。** 確かめているのは上の表のうち、
機械で判る範囲だけ（クライアント登録の中身などは見ていない）。

### 注意（仕様上の落とし穴）

1. **`IsDebug` は `UserStoreType = mem` のとき、設定を無視して常に `true`** を返す
   （`CommonLibrary/Co/Config.cs`）。**`IsDebug=false` と書いても効かない。** 本番は DBMS 前提。
2. **管理者ユーザ（`AdministratorUID`）は、`IsDebug` に関係なく無条件で作られる。**
   テスト利用者だけが `IsDebug` と `TestUserPWD` で閉じられる。
3. **`/Ping` は閉じない。** セッションのタイムアウト防止に使われているため（#219）。
   本番で塞ぐなら、前段（リバース プロキシなど）で行う。
   `/TestHybridFlow` と `api/Values`（net10.0 のみ）は、`IsLockedDownTestEndpoints` で閉じる。
4. **STS 専用モード**（`EnableSignupProcess` / `EnableEditingOfUserAttribute` /
   `EnableAdministrationOfUsersAndRoles` を**全部 false**）にすると、サインアップ・属性の編集・
   ユーザ管理が無効になる。**利用者ストアへの書き込みも止まる**ので、切替の影響が大きい。
5. **PKCE の 2 つのキーは、別のものを締める**（#220。どちらも既定 `false`）。

   | キー | 何を求めるか | どこで弾くか | 有効にすると通らなくなるもの |
   |---|---|---|---|
   | `RequirePkce` | PKCE 自体（`code_challenge`） | 認可エンドポイント（`invalid_request`） | **PKCE を使っていない既存クライアント** |
   | `RequirePkceS256` | 使うなら `S256` に限る | トークン エンドポイント | `plain` を使っているクライアント |

   **両方 `true` が OAuth 2.1 相当。** ただし**クライアントが揃っていないと繋がらなくなる**ので、
   既存の登録を確かめてから切り替える。**Device AuthZ / CIBA は `RequirePkce` の対象外**
   （認可エンドポイントを通らないため）。

   **`RequirePkce` は、クライアント単位でも指定できる**（#221）。
   クライアント登録に `require_pkce` を書くと、**そのクライアントにだけ**必須になる。

   ```json
   "c4309326f39b1e0975fddb4bc93b56a0": {
     "client_secret": "...",
     "redirect_uri_code": "http://localhost:12347/",
     "client_name": "TestClient6",
     "require_pkce": "true"
   }
   ```

   **判定は `RequirePkce`（サーバ全体）との OR。**
   サーバ側が「全クライアント共通の床」、クライアント側は「個別の引き上げ」で、
   **クライアント側から床を下げることはできない。**
   **移行では、締められるクライアントから順に `require_pkce` を立て、
   全部揃ったらサーバの `RequirePkce` を `true` にする**、という順序が取れる。

   > **`oauth2_oidc_mode` を `fapi1` にしても PKCE は必須になるが、そちらは重い。**
   > **ROPC / `client_credentials` / `refresh_token` も巻き添えで塞がる**（実測。#222）。
   > 「PKCE だけ必須にしたい」なら `require_pkce` を使う。

> **設定を変えたら、雛形（`_app.config` / `_appsettings.json`）にも反映する**（1 節）。
> 本番の値そのものは書かない。

---

## 標準クレームを返す（#261）

**`profile` / `address` のクレームは、設定の対応付けで返す**（#230）。
**この実装は氏名・住所の項目を持たない。** 入れ物は `ApplicationUser.UnstructuredData`（JSON）で、
**中身は導入する側が決める**という方針である（`Extensions/Sts/UserClaims.cs`）。

### 入れ物（`UnstructuredData`）

**OIDC Core 5.1 の標準クレームを、そのままのキー名で入れた例。**

```json
{
  "given_name": "Taro",
  "family_name": "Tanaka",
  "nickname": "taro",
  "profile": "https://example.com/taro",
  "picture": "https://example.com/taro.png",
  "website": "https://example.com/",
  "gender": "male",
  "birthdate": "1990-01-23",
  "zoneinfo": "Asia/Tokyo",
  "locale": "ja-JP",
  "updated_at": 1759449600,
  "address": {
    "formatted": "100-0001 1-1 Chiyoda, Chiyoda-ku, Tokyo, JP",
    "street_address": "1-1 Chiyoda, Chiyoda-ku",
    "region": "Tokyo",
    "postal_code": "100-0001",
    "country": "JP"
  }
}
```

**`IsDebug` のときは、2 人目のテスト利用者（`tanaka`）にこれが入る**
（`AccountController.SampleUnstructuredData`）。**E2E が `RT-261.1` で測っている。**

### 対応付け（`UserClaimsMapping`）

**キー名をクレーム名に合わせておけば、対応付けは 1 対 1 になる。**

```json
"UserClaimsMapping": {
  "name":                   "name",
  "family_name":            "family_name",
  "given_name":             "given_name",
  "birthdate":              "birthdate",
  "updated_at":             "updated_at",
  "address.postal_code":    "address.postal_code",
  "address.country":        "address.country",
  "preferred_username":     "user:UserName"
}
```

| 値の書き方 | 意味 |
|---|---|
| `name` | `UnstructuredData` の `name` |
| `address.postal_code` | `UnstructuredData` の `address` の中の `postal_code`（`.` で辿る） |
| `user:UserName` | `ApplicationUser` から直に取る（白名簿は `UserName` / `Email` / `PhoneNumber`） |

**`address.<副フィールド>` は、まとめて 1 つの `address` オブジェクトに組み立てて返す**（OIDC Core 5.1.1）。

### 型は、入れた側の JSON が決める

**`UserClaimsMapping` はクレーム名と在り処だけを持ち、型は持たない。**
**`UnstructuredData` に入れた JSON の型が、そのまま返る**（#261）。

| JSON | 返る型 |
|---|---|
| `"updated_at": 1759449600` | **数値**（OIDC Core 5.1 の NumericDate。これが正しい） |
| `"updated_at": "1759449600"` | 文字列（**引用符付きで返るので、RP が落ちうる**） |

> **以前は、すべて文字列にして返していた**（#261 で直した）。
> **#184 と同じ種類の誤り**である（あちらは JWT のクレーム、こちらは `UnstructuredData` 由来）。

### 管理画面で入れられるのは `usd1` / `usd2` だけ

**`Manage/AddUnstructuredData` の画面は 2 欄しか持たない。**

> **画面で保存すると、それ以外のキーは消える。**
> 画面の ViewModel（`ManageAddUnstructuredDataViewModel`）は `usd1` / `usd2` しか持たないので、
> **読み込みで他のキーが捨てられ、保存で JSON ごと置き換わる**
> （`user.UnstructuredData = JsonConvert.SerializeObject(model)`）。

**標準クレームを運用で入れるなら、画面を足すか、別の経路で `UnstructuredData` を書くことになる。**
**#261 では画面を変えていない**（入れ物の中身は導入する側が決める、という方針を保つため）。

## 12. 改名した設定キー（#236）

**改名しても、旧いキー名を読み続ける。** 配備済みの設定ファイルがあり、
**改名だけで黙って既定値に戻ると危ない**ため（`IsLockedDownTestEndpoints` は、
既定が「開く」なので特に）。

一覧は **`Config.RenamedKeys`** が一次情報で、**起動時に `ProductionCheck` が
「旧いキー名が使われています」と警告する**（`UserStoreType` が `mem` 以外のとき）。

| 旧いキー名 | 新しいキー名 | なぜ | 旧キーも読む |
|---|---|---|---|
| `IsLockedDownRedirectEndpoint` | `IsLockedDownTestEndpoints` | 閉じる対象がリダイレクト先だけではなくなった（#219） | **読む** |
| `EnabeDebugTraceLog` | `EnableDebugTraceLog` | **綴りの誤り**（`Enabe`） | **読む** |
| `IdFederationAuthorizeEndPoint` | `IdFederationAuthorizeEndpoint` | `EndPoint` の `P` を、他のキーに揃えた | **読む** |
| `IdFederationRedirectEndPoint` | `IdFederationRedirectEndpoint` | 同上 | **読む** |
| `IdFederationTokenEndPoint` | `IdFederationTokenEndpoint` | 同上 | **読む** |
| `IdFederationUserInfoEndPoint` | `IdFederationUserInfoEndpoint` | 同上 | **読む** |
| `PushedAuthorizationRequestEndpoint` | `AuthRequestPushUri` | **クライアント側も読む設定**なので、`RequestObjectRegUri` / `JwkSetUri` と同じ形に寄せた。**Open棟梁 側へ移す予定** | **読まない**（#229 で入れたばかりで、配備実績が無い） |

**`IdFederationRedirectEndpoint` の値に含まれる `Account/IDFederationRedirectEndPoint` は、
画面の口（アクション名）なので変えていない。** 変えると、委譲先に登録した `redirect_uri` と
食い違う。

### 揃えていないもの

| 接尾辞 | 例 | 理由 |
|---|---|---|
| `...RootURI` | `OAuth2AuthorizationServerEndpointsRootURI` | **エンドポイントではなく、その根っこ**（種別が違う） |
| `...Uri` | `JwkSetUri` / `RequestObjectRegUri` / `AuthRequestPushUri` | **クライアント側も読む設定**で、**実装が Open棟梁 側**にある（`OAuth2AndOIDCParams`）。この実装だけでは改名できない |
| `...Endpoint` | それ以外 | こちらに揃えた |
