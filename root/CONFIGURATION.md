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
| **動作確認の後** | **自分の RP の折り返し先に書き換える**（クライアント 1 件に `redirect_uri_code` は 1 つ） |

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
| `RsaPfxFilePath` | — | **応答の署名鍵**。メタデータの `KeyDescriptor` に、対応する証明書（`RsaCerFilePath`）が出る |

クライアントの登録（`OAuth2ClientsInformation` または管理画面）側は次の 2 つ。

| 登録項目 | |
|---|---|
| `redirect_uri_saml` | **ACS URL**（`AssertionConsumerServiceURL`） |
| `jwk_rsa_publickey` | **`AuthnRequest` の署名を検証する鍵**（OAuth2 側と共用） |

> `saml_name_id_format` という登録項目が雛形に書かれているが、**実装は読んでいない。**
> **`NameID` の形は、要求の `NameIDPolicy` だけで決まる。**

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
| **利用者を消すと、資格情報も消す** | `FIDO2Data` は `UserName` で持っており、**`Users` への外部キーが無い**。GDPR の削除（`/Manage/DeleteGdprPersonalData`）が明示的に消す |

---

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
