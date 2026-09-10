# ANALYSIS-IdP.md — IdP / STS 実装の適合性分析と近代化ロードマップ

対象: `root/programs/MultiPurposeAuthSiteCore`（＋実装の実体である `../CommonLibrary`） / ブランチ: `develop`
最終更新: 2026-09-07

本書は [`ANALYSIS.md`](ANALYSIS.md) の続編で、**「IdP / STS としてのプロトコル実装がどこまで出来ていて、
最新の仕様・慣行に対して何が足りないか」** だけを扱う。
ディレクトリ構成・ビルド手順・net48 版との差は [`ANALYSIS.md`](ANALYSIS.md) を参照。

**重要: 指摘の多くは `../CommonLibrary` に在る＝net48 版（`../MultiPurposeAuthSite`）にも同じ症状が出る。**
各項目に **[Core]** / **[Lib]**（＝両系統に影響）を付けた。

プロジェクト・ポリシーは リポジトリ ルートの `AGENTS.md` に定義済み。
→ **エージェントは git 操作を行わない。**

**凡例:** 対応済みの項目は、見出しに **✅ 修正済み（#Issue 番号）** を付ける。
**分析が誤りだった項目は ⚠️ 誤検出（#Issue 番号）** を付け、
**なぜ見誤ったかを残す**（消さない。同じ誤りを繰り返さないため）。
本書は分析の記録であると同時に、**対応状況の一覧**でもある。

---

## 0. 全体の所見

現状は **「OAuth 2.0（RFC 6749）＋ OIDC Core ＋ FAPI1/2・CIBA・Device の実験的実装」** であり、
プロトコルの守備範囲は広い。一方で、

- **エンドポイントの応答形式（`expires_in` / `error` / JSON 型）が仕様から外れている**箇所があり、
  **市販の RP ライブラリや適合性テストを通せる状態にない。**
- **異常系がほぼ全て未実装**で、不正入力が `NullReferenceException` → HTTP 500 になる。
- **有効期限（code / refresh_token / request object）が一切検証されていない。**
- 2020 年前後で更新が止まっており、**PAR / DPoP / RP-Initiated Logout / DCR / OAuth 2.1** が未対応。

「最新の IdP に近づける」うえでの最短経路は、**新機能の追加ではなく、
まず A・B（応答形式と異常系）を直して適合性テストが回る土台を作ること**である。

**対応状況:** **フェーズ 0 は完了**（A-1 / A-3・A-4 / A-9 / B-1〜B-7 / C-14）。B-7（#199）は、後から E2E テストで見つかったもの。
**フェーズ 1 は A-6 / A-8 が完了**し、A-7 は #196（テスト整備後）、A-10 は #189 の残りに紐づく。
セキュリティは C-1（#193）/ C-2（#194）/ C-16（#191）と A-5（#186）が完了。
A-2 は誤検出だった。次はフェーズ 1（仕様どおりのエラー応答）。
nonce まわりは C-14（#190）＋ C-16（#191）で仕様どおりに揃った。
見出しの **✅ 修正済み** / **⚠️ 誤検出** で個別に追える（7 節も参照）。

---

## 1. 実装済みの機能（棚卸し）

| 分類 | 仕様 | 実装 | 備考 |
|---|---|---|---|
| 認可 | Authorization Code | ✓ | `AccountController.OAuth2Authorize` |
| | Implicit | ✓ | `Config.EnableImplicitGrantType` |
| | Hybrid | ✓ | `code id_token` / `code token` / `code id_token token` |
| | ROPC | ✓ | `Config.EnableResourceOwnerPasswordCredentialsGrantType` |
| | Client Credentials | ✓ | |
| | JWT Bearer Token Flow (RFC 7523) | ✓ | `assertion` |
| | Device Authorization Grant (RFC 8628) | ✓ | `/device_authz` `/device_verify` |
| | CIBA (FAPI-CIBA) | ✓ | poll モードのみ。FCM プッシュ連携 |
| | Refresh Token | ✓ | ローテーションあり |
| トークン | JWS 署名 access_token / id_token（RS256 / ES256） | ✓ | |
| | JWE 暗号化 id_token（FAPI2） | ✓ | RSA-OAEP + AES-GCM |
| | PPID（`subject_types`: `public` / `pairwise` / `uname`） | ✓ | `Util/PPIDExtension` |
| | mTLS Sender-Constrained（`cnf.x5t#S256`） | ✓ | `/token` のみ |
| エンドポイント | `/token` `/userinfo` `/revoke` `/introspect` `/jwkcerts` | ✓ | |
| | `.well-known/openid-configuration` | ✓ | 不足あり（3 節） |
| | `/ros`（Request Object 登録） | ✓ | **PAR ではない独自仕様** |
| | `samlmetadata` / SAML2 IdP | ✓ | |
| 拡張 | PKCE (RFC 7636) | ✓ | `plain` / `S256` |
| | JARM（`query.jwt` / `fragment.jwt` / `form_post.jwt`） | ✓ | |
| | Request Object（`request_uri`） | ✓ | |
| | ID フェデレーション（他 IdP への委譲） | ✓ | |
| | 2FA（SMS / Email / TOTP / プッシュ承認） | ✓ | |

**未実装**は 5 節にまとめた。

---

## 2. A. 応答形式の不適合（RP・適合性テストが通らない）

> このグループは**外から見える振る舞いが仕様と違う**もの。修正の費用対効果が最も高い。

### A-1. `expires_in` が常に `0` になる **[Lib][Core]** — **✅ 修正済み（#182）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnEndpoints.cs
ret.Add(OAuth2AndOIDCConst.expires_in,
        Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString());
```

`TimeSpan.Seconds` は **「秒の端数成分」**であり、`TimeSpan.TotalSeconds` ではない。
`OAuth2AccessTokenExpireTimeSpanFromMinutes` は `TimeSpan.FromMinutes(n)` なので
**秒成分は必ず 0**。したがって **全てのトークン応答が `"expires_in": "0"`** を返している。

仕様に従う RP は「発行と同時に期限切れ」と解釈するため、即座に再取得ループに入るか失敗する。

該当は `.Seconds` を使っている **33 箇所**。

| 場所 | 件数 |
|---|---|
| `CommonLibrary/TokenProviders/CmnEndpoints.cs:2152` | 1 |
| `MultiPurposeAuthSiteCore/.../AccountController.cs`（Implicit / Hybrid の各 response_mode） | 16 |
| `MultiPurposeAuthSite/.../AccountController.cs`（net48 版・同上） | 16 |

**修正:** `.Seconds` → `.TotalSeconds`（`(int)` にキャストして整数化）。
併せて `expires_in` は RFC 6749 §5.1 で**数値**なので、応答の型も見直す（A-3 と同根）。

### A-2. ~~`nonce` が無いと `id_token` が発行されない~~ **[Lib]** — **⚠️ 誤検出（#183）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnIdToken.cs
if (tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.nonce)
    && tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.scopes))
```

> **この指摘は誤りだった。** 条件だけを見て「`nonce` が無ければ `id_token` を打ち切る」と判断したが、
> **呼び出し元を辿っていなかった。**
> `Helper.AddClaim`（`Extensions/Sts/Helper.cs`）は **`nonce` 未指定時に `state` を代入して
> 無条件に nonce クレームを追加する**。トークンを発行する 6 経路
> （code / implicit / hybrid / ROPC / client_credentials / JWT bearer）はすべてここを通るため、
> payload には **常に** `nonce` キーが存在し、上の条件は**常に真**だった。
> → **`nonce` 無しでも `id_token` は返っていた。**
>
> #183 のコミットは、**可読性のため**「常に真の条件を外した簡素化」として残してある
> （挙動は変わらない）。
> **注意: コミット メッセージは `fixed #183` だが、不具合修正ではない。**
> git log だけを見ると誤読するので、経緯は #183 のコメントを参照すること。
>
> **本当の問題は fallback の側にある。** → **C-16（#191）**

当初の記述（誤り）は次のとおり。
`nonce` は **Authorization Code フローでは OPTIONAL**（OIDC Core §3.1.2.1）。
本実装は access_token の payload に `nonce` クレームが無いと id_token 生成を打ち切る、と読んだ。
`nonce` 必須チェックが `ValidateAuthZReqParam` 側でコメント アウトされていた点は事実で、
**#190 で implicit / hybrid のみ必須に戻した。** C-14 参照。

**対応:** 判定条件から `nonce` を外し、`scope` に `openid` が含まれるかだけで判断するようにした
（#183）。挙動は変わらないが、条件と実態が一致した。

### A-3. JWT の `exp` / `nbf` / `iat` が文字列 **[Lib]** — **✅ 修正済み（#184）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnAccessToken.cs、CmnIdToken.cs
tokenClaimSet.Add(OAuth2AndOIDCConst.exp, expiresUtc.ToUnixTimeSeconds().ToString());
```

RFC 7519 §2 の **NumericDate は JSON の数値**。`"exp": "1789..."` は仕様違反で、
`System.IdentityModel.Tokens.Jwt` や `jose` 系の検証器は型エラーで弾く。
自前の `CmnJwtToken.VerifyExp(string)` が文字列前提になっているため、
**自分自身では検証が通ってしまい、外部 RP だけが落ちる**という気付きにくい形になっている。

**修正:** `.ToString()` を外して `long` を代入した。

**検証側も併せて直した。** `CmnJwtToken.VerifyExp` は Open棟梁側に
**`string` 引数のオーバーロードしか無い**（実測）ため、`(string)` キャストのままだと
数値になった `exp` で `InvalidCastException` になる。`.ToString()` を通す形に変えてある。
`CmnAccessToken.AddClaims` の `exp` / `nbf` / `iat` も同様
（`Claim` の値は `string` なので変換が要る）。この書き方なら、
**文字列で発行済みの古いトークンもそのまま検証を通る。**

> **残っている同種の箇所:** JARM の Response Object（`CmnResponseObject.Create`）も
> `exp` を文字列で入れている。ただし引数が `Dictionary<string, string>` なので、
> 直すにはシグネチャ変更と両アプリの呼び出し側 12 箇所の修正を伴う。**本 Issue の範囲外**とした。

### A-4. `email_verified` / `phone_number_verified` が文字列 **[Lib][Core]** — **✅ 修正済み（#184）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnAccessToken.cs
//         MultiPurposeAuthSiteCore/.../OAuth2EndpointController.cs（net48 版も同じ）
tokenClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed.ToString());
```

`bool.ToString()` は `"True"` / `"False"`（先頭大文字）。
OIDC Core §5.1 は **boolean** と定めている。JSON 的にも `"True"` は真偽値ではない。

**修正:** `.ToString()` を外した。access_token / id_token と `/userinfo` の計 4 箇所。

### A-5. OIDC のとき `redirect_uri` が code に紐付かない（条件が反転している） **[Lib][Core]** — **✅ 修正済み（#186）**

```csharp
// CommonLibrary/TokenProviders/AuthorizationCodeProvider.cs:83-87
if (!scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
{
    // OIDCの場合は、redirect_uriを保存しない。   ← コメントと条件が食い違っている
    temp.Add(OAuth2AndOIDCConst.redirect_uri, queryString[OAuth2AndOIDCConst.redirect_uri]);
}
```

ファイル冒頭の更新履歴には **「2020/07/24 OIDCではredirect_uriは必須。」** とあるのに、
実際には **OIDC のときだけ `redirect_uri` を保存していない**。
保存されていないと `CheckClientIdAndRedirectUri` は
「認可リクエスト時、指定無し」として**無条件に成功**する。

→ **OIDC フローでは `/token` の `redirect_uri` が検証されない。**
RFC 6749 §4.1.3 / OIDC Core §3.1.3.1 が要求する照合が効いていない。

**対応（#186）:** 条件を外し、認可リクエストの `redirect_uri` を常に code に紐付けるようにした。

**サーバだけ直すと自己テストが壊れる**点が要だった。
`HomeController.SaveOAuth2Params` に

```csharp
if (!isOidc) { /* OIDCはTokenリクエストにredirect_uriを指定しない。 */ }
```

という分岐があり、**クライアント側も送らない実装**になっていた。
このコメントは仕様の誤解で、**OIDC Core §3.1.3.1 は Token リクエストの `redirect_uri` を
REQUIRED としている**（RFC 6749 §4.1.3 の「認可リクエストに含めた場合は必須」より厳しい）。
両アプリの分岐を外し、意味を失った `isOidc` 引数も廃止した（呼び出し 14 箇所 × 2 アプリ）。

Device AuthZ / CIBA は空の `NameValueCollection` を渡すので `redirect_uri` は null のままとなり、
`CheckClientIdAndRedirectUri` の「認可リクエスト時、指定無し」経路に入る。影響しない。

> **残っている穴（#197）:** `request_uri`（Request Object / JAR）の経路では、
> `redirect_uri` が **JWT の中**にあって `queryString` には無いため、**紐付けが効かない。**
> `CreateCodeInAuthZNRes` に実効値を渡す形にする必要がある。
>
> E2E テストで実測した（2026/09/09, net10.0）。**推測ではない。**
>
> ```
> 誤った redirect_uri: HTTP 200 / keys=[access_token, expires_in, id_token, ...] / error=-
> ```
>
> PKCE の `code_challenge` も同じ理由で拾えていないが、**向きは逆**で、
> 記録されないため `code_verifier` を送ると `invalid_client` になる（素通りではなく拒否）。
> 安全側だが、`request_uri` ＋ PKCE のパブリック クライアントは機能しない。
>
> 再現するテストが `root/programs/Tests/E2ETests/Tests/RequestObjectTests.cs` にある
> （`Skip` を外すと落ちる）。

### A-6. 認可エンドポイントのエラー応答が独自形式 **[Core]** — **✅ 修正済み（#187）**

```csharp
// MultiPurposeAuthSiteCore/.../AccountController.cs:2848, 2977
return new RedirectResult(valid_redirect_uri +
    string.Format("?err={0}&errDescription={1}", err, errDescription));
```

RFC 6749 §4.1.2.1 が要求するのは `error` / `error_description`、
さらに **リクエストに `state` があれば `state` を返すこと**。
現状は名前が `err` / `errDescription` で `state` も返さないため、RP はエラーを解釈できない。

加えて次の 3 つも同じ行にある。

- `redirect_uri` が既にクエリを持つ場合でも無条件に `?` を付ける（URL が壊れる）
- `err` / `errDescription` を URL エンコードしていない
- `err` は事実上いつも `server_error`（A-8 参照）

**対応（#187）:** `CmnEndpoints.BuildRedirectUrl` を新設し、**両アプリの 36 箇所**を置き換えた。

- パラメタ名を `error` / `error_description` にし、**`state` は要求にあった場合のみ返す**（RFC 6749 §4.1.2）
- 既にクエリ文字列を持つ `redirect_uri` でも壊れないよう、区切りを `?` と `&` で切り替える
- **値を必ず URL エンコードする。** `state` はクライアントが自由に決められるため、
  生で連結するとリダイレクト先 URL にパラメタを注入できた（**C-6 の解消**）

実機で確認済み。`state="a&b=c d"` が分割されずに復元されること、
`state` を送らなければ応答にも入らないこと、`client_id` / `response_type` が不正なときは
**リダイレクトせずエラー画面**になること（RFC 6749 §4.1.2.1）を確かめた。

> **`?` と `&` の切り替えは、コードの読みでしか確認できていない。**
> 登録済みクライアントの `redirect_uri` にクエリ文字列を持つものが無く、
> `CheckRedirectUri` は完全一致を要求するため、実機で試せなかった。単体テスト向き。

### A-7. エラーの HTTP ステータスが 200 **[Core]** — **未対応（#196）**

`/token` `/userinfo` `/revoke` `/introspect` はいずれも
`Dictionary<string,string>` を返すだけなので、**エラーでも HTTP 200** になる。
RFC 6749 §5.2 は **400（`invalid_client` は 401）**、
OIDC Core §5.3.3 の UserInfo は **401 ＋ `WWW-Authenticate`** を求める。

**修正:** `IActionResult` に変えて `BadRequest(...)` / `Unauthorized(...)` を返す。
**net48 版（`ApiController` / `HttpResponseMessage`）とは書き方が違うので、両系統で別実装になる。**

> **#187 から #196 に分離した。** 戻り値の型変更を伴い両系統で実装が分かれること、
> **HTTP ステータスはクライアントの期待そのもの**でテスト整備後に着手したいことが理由。
> `/revoke` は RFC 7009 §2.2 により**エラーでも 200 が正**（例外）である点に注意。

### A-8. 認可エラーのコードが全て `server_error` **[Lib]** — **✅ 修正済み（#187）**

```csharp
// CommonLibrary/TokenProviders/CmnEndpoints.cs:378-380
err = "server_error";
...
//err = "server_error";   ← 個別のエラー コードは全てコメント アウト
```

`ValidateAuthZReqParam` / `CheckRedirectUri` は、client_id 不正・response_type 不正・
redirect_uri 不一致・scope 不正のいずれでも `server_error` を返す。
本来は `invalid_request` / `unauthorized_client` / `unsupported_response_type` /
`invalid_scope` / `access_denied` を返し分ける必要がある。

`/token` 側も `"not_supported"`（未登録の値。正しくは `unsupported_grant_type`）や
未知の grant_type に `invalid_grant`（正しくは `unsupported_grant_type`）を使っている。

**対応（#187）:** `OAuth2AndOIDCConst` に標準コードが揃っていたので、それを使って返し分けた。

| 失敗の内容 | 返すコード |
|---|---|
| `client_id` 未設定 | `invalid_request` |
| `client_id` 不正 | `unauthorized_client` |
| `response_type` 空 | `invalid_request` |
| `response_type` 不明 / グラント種別が無効 | `unsupported_response_type` |
| OIDC が無効なのに `scope=openid` | `invalid_scope` |
| OIDC で `redirect_uri` 欠落 / `redirect_uri` 不一致・未登録 | `invalid_request` |
| Grant\* の `"not_supported"` | `unsupported_grant_type` |

> **未知の `grant_type` に `invalid_grant` を返している件は、まだ直していない**
> （`OAuth2EndpointController` 側。正しくは `unsupported_grant_type`）。#196 で扱う。

### A-9. discovery のキー名に末尾スペース **[Lib]** — **✅ 修正済み（#189 の一部）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnEndpoints.cs
OpenIDConfig.Add("backchannel_token_delivery_modes_supported ", ...)
//                                                          ↑
```

CIBA クライアントはこのキーを見つけられない。

**対応:** 末尾スペースを除去した。併せて `OpenIDConfig.Add` する **32 個のキーを全数確認**し、
**前後に空白のあるキーは他に無い**ことを確かめてある。
このキーを読んでいるコードはリポジトリ内に無い（外部の CIBA クライアントだけが読む）。

> **#189 はこの 1 件だけ対応済みで、他の項目（A-10）は未対応のまま。**

### A-10. discovery のその他の不整合 **[Lib]**

| 現状 | あるべき姿 |
|---|---|
| `device_authorization_endpoint` が無い | RFC 8628 §4。`/device_authz` を公開しているのに広告していない |
| `grant_types_supported` に device_code が無い | `Config.EnableDeviceAuthZGrantType` が discovery から参照されていない |
| `mutual_tls_sender_constrained_access_tokens: "true"` | RFC 8705 §3.3 の正式名は `tls_client_certificate_bound_access_tokens`、値は boolean |
| `backchannel_user_code_parameter_supported: "false"` | boolean |
| `backchannel_authentication_request_signing_alg_values_supported: "ES256"` | 配列 |
| `id_token_encryption_alg_values_supported` のみ | `..._enc_values_supported` も対で必要 |
| `code_challenge_methods_supported` に `plain` | OAuth 2.1 / FAPI は `S256` のみ |
| `subject_types_supported` に `uname` | 登録済みの値は `public` / `pairwise` のみ（独自拡張であることを明示するか外す） |
| `request_object_endpoint`（独自名） | PAR にするなら `pushed_authorization_request_endpoint` |
| `service_documentation: "・・・"` | プレースホルダのまま |
| `end_session_endpoint` / `registration_endpoint` が無い | 5 節（未実装のため） |
| `authorization_response_iss_parameter_supported` が無い | RFC 9207（未実装のため） |
| JARM の `authorization_signing_alg_values_supported` が無い | JARM を広告しているのに alg を出していない |

---

## 3. B. 異常系で落ちる（HTTP 500 になる）

> いずれも**外部から容易に到達できる**。適合性テストは異常系を大量に投げるため、
> ここを直さないとテスト自体が完走しない。
>
> **#185 で 6 件とも対応済み。** 着手前に到達性を 1 件ずつ確認した結果、
> **B-3 は資格情報なしで到達する**ことが分かった
> （`grant_type=authorization_code` ＋ 任意の `code` ＋ `code_verifier`、`client_secret` なし
> → `ReceiveChallenge` で NRE）。この経路が最も深刻だった。
>
> **B-7 は、後から E2E テストの拡張仕様（EX-4.5）で見つかり、#199 で対応した。**

### B-1. `kid` の無い JWT で `NullReferenceException` **[Lib]** — **✅ 修正済み（#185）**

```csharp
// CommonLibrary/TokenProviders/CmnAccessToken.cs:487, 546
JWS jws = null;
...
if (header.Keys.Any(s => s == JwtConst.kid))   // ← kid が無ければ jws は null のまま
{ ... }

if (jws.Verify(jwt))                            // ← ここで NRE
```

`Authorization: Bearer <kid の無い JWT>` を `/userinfo` `/introspect` `/revoke`
`/SetDeviceToken` `/ciba_result` のいずれかに投げるだけで HTTP 500 になる。

**修正:** `jws == null` を「検証失敗」として扱う。

### B-2. `/token` の異常系で `err` が null **[Core]** — **✅ 修正済み（#185）**

```csharp
// MultiPurposeAuthSiteCore/.../OAuth2EndpointController.cs:166-167
Dictionary<string, string> ret = null;
Dictionary<string, string> err = null;      // ← 初期化されない
...
default:
    err.Add(OAuth2AndOIDCConst.error, ...);  // ← NRE
```

**未知の `grant_type`**、**`grant_type` 無し**、**フォーム データ無し** の 3 経路で NRE。
（`Grant*` が呼ばれる経路だけ `out err` で代入されるため、成功時と検証失敗時は通る。）

**修正:** `err = new Dictionary<string, string>();` で初期化する。net48 版も同型。

### B-3. 使用済み・不正な `code` で `NullReferenceException` **[Lib]** — **✅ 修正済み（#185）**

```csharp
// CommonLibrary/TokenProviders/AuthorizationCodeProvider.cs:Receive()
JObject jobj = (JObject)JsonConvert.DeserializeObject(value);   // value = "" → null
return CheckClientIdAndRedirectUri(client_id, redirect_uri, jobj); // → jobj[...] で NRE
```

さらに `CheckClientIdAndRedirectUri` が `""` を返した場合（client_id 不一致）も、
`GrantAuthorizationCodeCredentials` は空文字列チェックをせずに
`CmnAccessToken.ProtectFromPayload("")` を呼ぶため、そこでも NRE になる。

→ **code の再利用・改ざんが `invalid_grant` ではなく HTTP 500。**
`GetAccessTokenPayload` も同型（`temp["access_token_payload"]`）。

### B-4. 他クライアントの refresh_token で未処理例外 **[Lib]** — **✅ 修正済み（#185）**

```csharp
// CommonLibrary/TokenProviders/CmnEndpoints.cs（Grant*Credentials 共通）
if (client_id != aud) { throw new Exception("[client_id != aud]"); }
```

クライアント A が B の refresh_token を提示すると、`throw` がそのまま上がって HTTP 500。
**チェック自体は正しい**ので、`invalid_grant` を返す形に変えるだけでよい。

### B-5. 存在しない `request_uri` で `NullReferenceException` **[Core]** — **✅ 修正済み（#185）**

`AccountController.OAuth2Authorize`（GET / POST 両方）と
`OAuth2EndpointController.CibaAuthorizeAsync` は、
`RequestObjectProvider.Get()` の戻り値を null チェックせずに `JObject` として添字アクセスする。

### B-6. 応答が空になる経路 **[Lib]** — **✅ 修正済み（#185）**

`GrantRefreshTokenCredentials` は、`RefreshTokenProvider.Receive` が空を返したとき
（＝ローテーション済み・存在しない refresh_token）に `err` を設定せず `false` を返す。
→ `/token` が **`{}` を HTTP 200 で返す**。`invalid_grant` を返すべき。

### B-7. 使用済み・不正な `device_code` で `KeyNotFoundException` **[Lib]** — **✅ 修正済み（#199）**

E2E テストの拡張仕様（EX-4.5）で見つかった。

`DeviceAuthZProvider.ReceiveTokenReq` が、`ConcurrentDictionary` を**索引子で**読んでいた。
トークンを渡した時点でレコードは削除されるため、
**同じ `device_code` で 2 回目を送ると、必ず例外（HTTP 500）になる。**
発行していない `device_code` も同じ行を通る。

```csharp
// 修正前: CommonLibrary/Extensions/Sts/DeviceAuthZProvider.cs
temp = DeviceAuthZProvider.DeviceAuthZData[deviceCode];
```

トークンは出ないので、権限の漏れは無い。

**対応（#199）:**

- `ReceiveTokenReq` は `TryGetValue` で読み、無ければ `not_found` として扱う。
  `null` のキーも `ConcurrentDictionary` は例外にするので、先に弾く
- `ReceiveResult`（`/device_verify`）も同じ読み方をしていたので `TryGetValue` にした
  （キーを列挙した後に、トークン要求側が削除すると同じ例外になる）
- `GrantDeviceAuthZ` は、仕様外の状態（`not_found` / `irregularity_data`）を
  **enum 名のまま `error` に入れていた**のをやめ、`invalid_grant` で返す。
  `access_denied` / `expired_token` は RFC 8628 §3.5 の値なので、そのまま返す
- `device_code` を送らない要求は `invalid_request`

E2E テスト: `EX-4.5`（使用済み）/ `EX-4.7`（発行していない・送らない）。

---

## 4. C. セキュリティ上の弱点

### C-1. `/device_authz` にクライアント認証が無い **[Core][Lib]** — **✅ 修正済み（#193）**

```csharp
// MultiPurposeAuthSiteCore/.../OAuth2EndpointController.cs:706
public Dictionary<string, string> DeviceAuthZAuthorize(IFormCollection formData)
```

`client_id` / `client_secret` を読み出しているが、**`ClientAuthentication` を呼んでいない。**
`GetClientName(client_id)` の戻り値も使っていない。
その結果、**未登録の client_id でも、認証情報が無くても、`device_code` / `user_code` が発行される。**

RFC 8628 §3.1 は「クライアントの識別」を要求し、コンフィデンシャル クライアントには
トークン エンドポイントと同等の認証を求める。

**`/token`（device_code グラント）側にも認証が無い。**
`CmnEndpoints.GrantDeviceAuthZ` は**認証ブロックが丸ごとコメント アウトされている**
（`// 認証は無し（Client認証のclient_idとToken類のaudをチェック`）。
呼び出し側もこのグラントに限って `client_secret` / `assertion` / クライアント証明書を渡していない。
唯一のチェック `if (client_id != aud)` は、`aud` が**攻撃者の指定した `client_id`** から
作られた code に由来するため常に一致し、**機能していない**
（#185 で `throw` は `invalid_grant` 応答に変えたが、判定自体は素通りのまま）。

→ **資格情報を持たない第三者が、公開情報である `client_id` だけでフローを最後まで通せる。**

**対応（#193）:** `CmnEndpoints.DeviceAuthZClientAuthentication` を新設し、
`/device_authz`（両アプリ）と `GrantDeviceAuthZ` の双方から呼ぶようにした。

| クライアント | 扱い |
|---|---|
| 未登録の `client_id` | **拒否**（`invalid_client`） |
| コンフィデンシャル（`client_secret` 登録済み、または x509 提示） | **認証必須**。`ClientAuthentication` に委譲 |
| パブリック（`client_secret` 未登録） | `client_id` の確認のみ（RFC 8628 は公開クライアントを許す） |

**パブリックを一律で弾かないのが要点。** 実測では、登録済み 10 クライアントのうち
`oauth2_oidc_mode: device` の `ae5a1798…`（TestClient3）**だけが `client_secret` を持たない**。
一律に認証必須にすると、同梱の自己テストが動かなくなる。

`device_code` と `client_id` の紐付けは、`AuthorizationCodeProvider.Receive(code, client_id, "")` が
`aud` を照合することで既に効いている（#185 で `invalid_grant` を返すようになった）。

併せて次も直した。

- `formData == null` のときの `error` / `error_description` が空文字列だったのを設定
- `verification_uri` がパスだけだったのを絶対 URI に（RFC 8628 §3.2）
- 使われていなかった `string name = GetClientName(client_id);` を削除

> **未対応:** `GrantDeviceAuthZ` は `refresh_token` を生成しているが
> `CreateAccessTokenResponse(access_token, "", "")` と空を渡すため応答に載らない。
> 「返す」か「作らない」かは挙動の判断を伴うので別途。

現状は user_code の無制限発行が可能で、ユーザに `user_code` を入力させるフィッシングや、
`DeviceAuthZData` テーブルの肥大化に使える。

### C-2. `/revoke` `/introspect` がトークンの所有者を確認しない **[Core][Lib]** — **✅ 修正済み（#194）**

呼び出し元のクライアント認証は行うが、**そのクライアントとトークンの `aud` を突き合わせていない。**
`VerifyAccessToken` も `aud` が「登録済みの何らかのクライアント」であることしか見ない。

→ **登録済みクライアントであれば、他クライアントのトークンを introspect / revoke できる。**
RFC 7009 §2.1 / RFC 7662 §2.1 はいずれも所有者確認を要求している。

併せて、`/revoke` `/introspect` は **mTLS クライアント認証が無効化されている**
（`X509Certificate2 x509 = null; // Request.GetClientCertificate();`）ため、
`tls_client_auth` のクライアントはこの 2 つを使えない。`/token` とは非対称。
**これは .NET (Core) 版だけの問題**で、net48 版は `Request.GetClientCertificate()` を読んでいた。

**対応（#194）:** `CmnEndpoints.CheckTokenOwner`（access_token / ClaimsIdentity 用）と
`CheckRefreshTokenOwner`（refresh_token / payload 用）を新設し、
両アプリの `/revoke`・`/introspect` から呼ぶようにした。併せて Core 側の mTLS を有効化。

| エンドポイント | 所有者が違う場合 |
|---|---|
| `/revoke` | `invalid_grant` を返す（RFC 7009 §2.1 が検証を要求） |
| `/introspect` | **`{"active": false}` を返す**（RFC 7662 §2.2 / §5。エラーにするとトークンの存否を漏らす） |

`/introspect` の `active` が **`"true"` という文字列**だったのも真偽値に直した
（A-3 / A-4 と同じ defect だが #184 では未列挙だった分）。

### C-3. `prompt=none` が同意画面を無条件にスキップする **[Core]**

```csharp
// MultiPurposeAuthSiteCore/.../AccountController.cs:2764
if (isAuth || prompt.ToLower() == "none")   // 認可画面をスキップ
```

OIDC Core §3.1.2.1 の `prompt=none` は
**「UI を一切出すな。出す必要があるなら `login_required` / `consent_required` /
`interaction_required` をエラーとして返せ」** という意味。
本実装は「同意画面を出さずに code を発行する」動作なので、
**セッションさえ生きていれば、どのクライアントも無音で認可を取得できる。**

そもそも**同意の記録（consent grant）を保存していない**ため、
「以前に同意済みか」を判定する土台が無いのが根本原因（D-6）。

`prompt=login` / `select_account` / `consent` は未処理。

### C-4. 認可コードに有効期限が無い **[Lib]**

`AuthenticationCodeDictionary` に `CreatedDate` を書いているが、**どこからも読んでいない。**
`Receive` は経過時間を見ずに payload を返す。
RFC 6749 §4.1.2 は「短命であること（推奨 10 分以内）」を求めている。

Memory Provider の `ConcurrentDictionary` も未使用の code を回収しないため、
**メモリ リークになる**（DBMS 側も行が残り続ける）。

### C-5. refresh_token に有効期限も再利用検知も無い **[Lib]**

- `Config.OAuth2RefreshTokenExpireTimeSpanFromDays`（既定 14 日）は
  **`Co/Config.cs` の定義以外どこからも参照されていない。** → 事実上の無期限。
- ローテーション（使用時に削除）は行っているが、
  **ローテーション済みトークンを再提示されても検知・失効（family revocation）をしない。**
  OAuth 2.0 Security BCP §4.14 が求める挙動。
- `permittedLevel` を `ClientMode.normal` にハードコードしているため、
  **FAPI クライアントがリフレッシュすると保証レベルが落ちる。**

### C-6. `state` を URL エンコードせずに連結している **[Core]**

```csharp
// MultiPurposeAuthSiteCore/.../AccountController.cs:3017, 3035 ほか
string.Format("?code={0}&state={1}", code, state)
```

`state` はクライアント（＝攻撃者が用意しうる RP）が自由に決められる値であり、
`&` を含めればリダイレクト URL にパラメタを注入できる。
`?` の無条件付与（A-6 と同じ）と併せて、リダイレクト URL の組み立てを一箇所に集約すべき。

### C-7. PKCE の扱いが OAuth 2.1 と噛み合わない **[Lib]**

```csharp
// CommonLibrary/TokenProviders/CmnEndpoints.cs:1010-1050
if (code_verifier 無し && assertion 無し)      → クライアント認証
else if (code_verifier 有り && client_secret 無し) → PKCE のみで認証成立
else if (code_verifier 有り && client_secret 有り) → 【空実装】
```

3 つの問題がある。

1. **`code_verifier` と `client_secret` を両方送るとどのフローにも入らず、必ず `invalid_client` になる。**
   OAuth 2.1 / 最近の RP ライブラリは**コンフィデンシャル クライアントでも常に PKCE を付ける**ため、
   **現代的なクライアントほど繋がらない。**
2. **`plain` を受理している**（`CmnEndpoints.cs:1022`）。`plain` は保護にならず、
   OAuth 2.1 / FAPI は `S256` のみを許す。
3. **`S256` を使ったという理由だけで `permittedLevel` を `fapi1` に格上げしている**（`:1030` 付近）。
   PKCE のメソッドは「クライアント認証の強度」ではないので、権限判定と分離すべき。

さらに、**認可エンドポイント側で `code_challenge` を必須化していない**ため、
PKCE 無しの認可コード フローがそのまま通る。

### C-8. トークンの `alg` ヘッダで検証器を選んでいる **[Lib]**

`VerifyAccessToken` は `header[JwtConst.alg]` を読んで `JWS_ES256_X509` / `JWS_RS256_X509` を選ぶ。
サーバ側で**期待する alg を固定していない**ため、アルゴリズム混同の温床になる。
（`kid` が JWK Set に当たる経路では JWK 側の `alg` を使っており、そちらは妥当。）

**修正:** 自分が発行するトークンは自分の署名鍵と alg で検証する形に固定する。

### C-9. CORS が全エンドポイントで `AllowAnyOrigin` **[Core]**

```csharp
// Startup.cs:Configure
app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
```

`OAuth2EndpointController` の `[EnableCors]`（ポリシー名なし）はこのインライン ポリシーに解決される。
`/token` `/revoke` `/introspect` まで任意オリジンから叩ける。
`AllowCredentials` は付いていないので Cookie は飛ばないが、
**任意のサイトの JS がユーザのブラウザからトークン エンドポイントを直接呼べる**状態ではある。

CORS を開くべきなのは `/userinfo` と `.well-known` 程度で、
`/token` は SPA の PKCE 用に**必要なオリジンだけ**許可するのが定石。

なお CORS の設定が **3 重**になっている（`AddCors` の名前付きポリシー `AllowAllOrigins`、
`UseCors` のインライン、`[EnableCors]` の既定ポリシー）。整理対象。

### C-10. `redirect_uri` の比較が大文字小文字を無視 **[Lib]**

```csharp
// CommonLibrary/TokenProviders/CmnEndpoints.cs:717
if (redirect_uri.ToLower() == preRegisteredUri.ToLower())
```

RFC 6749 §3.1.2.3 / OIDC Core §3.1.2.1 は **単純文字列比較（大文字小文字を区別）** を求める。
URI のパス・クエリは大文字小文字を区別するため、緩めた分だけ一致範囲が広がる。

また `CheckRedirectUri` には
**「`Config.OAuth2ClientEndpointsRootURI + OAuth2AuthorizationCodeGrantClient_Manage` は
どの client_id でも無条件に許可」** という自己テスト用の抜け道がある。
`Config.IsLockedDownRedirectEndpoint` の対象外なので、**本番で閉じられない。**

### C-11. Request Object（`/ros`）に有効期限もワンタイム性も無い **[Core][Lib]**

- 署名検証は行っている（`RequestObject.Verify` / `VerifyCiba`）。
- しかし `RequestObjectProvider` は `CreatedDate` を書くだけで**読まない**。
- `/ros` の応答が返す `exp` は **空文字列**（`exp = ""`）。
- 認可エンドポイントで消費した後も **`Delete` が呼ばれない**（`Delete` メソッドは在るが未使用）。

コード中のコメント「存続期間は短く、好ましくは一回限」がそのまま未実装項目になっている。

### C-12. Cookie 認証の有効期限が 2 分にハードコード **[Core]**

```csharp
// Startup.cs:401
options.ExpireTimeSpan = new TimeSpan(0, 2, 0);
options.SlidingExpiration = true;
```

`Config.AuthCookieExpiresFromHours` / `AuthCookieSlidingExpiration` は
**net48 版（`App_Start/StartupAuth.cs:194,196`）でしか使われていない。**
Core 側は設定を無視して 2 分固定。SlidingExpiration があるので操作中は延びるが、
**2 分放置するとサインアウトする**。設定の意味が失われている。

### C-13. DataProtection の鍵が永続化されていない **[Core]**

`services.AddDataProtection().PersistKeysTo***()` を呼んでいない。
既定では鍵はローカル プロファイル（コンテナでは揮発）に置かれるため、

- **再起動で認証 Cookie と AntiForgery トークンが全て無効になる**
- **複数インスタンスで動かすとインスタンス間で Cookie が通らない**

`AddDistributedMemoryCache`（[`ANALYSIS.md`](ANALYSIS.md) 4.3 節）と併せて、
**現状はスケールアウトできない構成**である。

### C-14. `nonce` が implicit / hybrid でも必須になっていない **[Lib]** — **✅ 修正済み（#190）**

```csharp
// 修正前: CommonLibrary/TokenProviders/CmnEndpoints.cs
// nonceパラメタ 必須 → 任意
//if (string.IsNullOrEmpty(nonce)) { ... return false; }
```

OIDC Core §3.2.2.1（implicit）/ §3.3.2.11（hybrid）は `nonce` を REQUIRED としている。
A-2 と表裏の関係にあり、**「nonce を必須にする」か「nonce 無しでも id_token を出す」かを
どちらかに寄せないと整合しない。** 仕様どおりなら**両方**（code は任意・implicit/hybrid は必須）。

**#190 で対応。** `response_type` が implicit / hybrid のときだけ `nonce` を必須にし、
無ければ `invalid_request` を返すようにした（Authorization Code フローは OPTIONAL のまま）。
このブロックは `scope=openid` の内側に在るため、**単純にコメントを外すと
Authorization Code フローまで必須になってしまう**点が要だった。

### C-15. `response_type` の照合が文字列完全一致 **[Lib]**

`response_type` は**順不同の空白区切り集合**（OAuth 2.0 Multiple Response Types §3）。
現状は `response_type.ToLower() == "code id_token"` のような完全一致なので、
`id_token code` と書く RP を弾く。

### C-16. 送られていない `nonce` を `state` から捏造している **[Lib]** — **✅ 修正済み（#191）**

```csharp
// 修正前: CommonLibrary/Extensions/Sts/Helper.cs  AddClaim()
if (string.IsNullOrEmpty(nonce))
{
    if (state == null) state = ""; // null対策
    identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnNonceClaim, state));  // ← state を nonce にする
}
```

**クライアントが `nonce` を送っていないとき、`state` の値を `nonce` クレームとして埋め込む。**
トークンを発行する 6 経路（code / implicit / hybrid / ROPC / client_credentials / JWT bearer）は
すべてここを通るため、**access_token と id_token の両方**に影響する。

問題は 3 つ。

1. **RP が送っていない `nonce` が id_token に入る。** OIDC Core §3.1.3.7 は
   「id_token に `nonce` があれば検証せよ」としており、`nonce` を送っていない RP が
   厳密に実装していると検証に失敗する。
2. **`nonce` のリプレイ防止が黙って無効化される。** 認可サーバが値を作っているので、
   `nonce` は「クライアントが生成した一度きりの値」ではなくなる。
3. **`state` がトークンに混入する。** `state` は RP 側の不透明な値であり、
   署名済みトークンに載って転送・保存されるべきものではない。

C-14（#190）で Implicit / Hybrid は `nonce` 必須にしたので弾けるようになったが、
**Authorization Code フローでは `nonce` は OPTIONAL のため、この捏造が残る。**

**修正の注意:** fallback を外すと `nonce` キーが存在しなくなるため、
`CmnAccessToken.AddClaims` の

```csharp
Helper.AddClaim(identity, (string)tokenClaimSet[...aud], "", scopes, null,
                (string)tokenClaimSet[OAuth2AndOIDCConst.nonce]);
```

が **`KeyNotFoundException`** になる。`TryGetValue` などに変える必要がある。

**対応（#191）:** fallback を外し、`nonce` の指定があるときだけクレームを作るようにした。
`AddClaims` は `TryGetValue` に変更。併せて、**使い道が無くなった `Helper.AddClaim` の
`state` 引数を削除**した（呼び出し 7 箇所）。残すと同じ実装に戻りやすいため。
自己テスト用クライアント（`HomeController`）は常に `nonce` を送るので影響しない。

> A-2（#183）を誤検出と判断する過程で見つかった。**A-2 の「真の問題」はこちら。**
> #183 は close 済み。

---

## 5. D. 最新の IdP として不足している機能

| # | 仕様 | 状況 | 影響 |
|---|---|---|---|
| D-1 | **RP-Initiated Logout / Front-Channel / Back-Channel Logout / Session Management** | **未実装**（`end_session` の実装も discovery も無し） | RP からのログアウト連携ができない。SSO の解除手段が無い |
| D-2 | **PAR（RFC 9126）** | 独自の `/ros` のみ。`request_uri` の払い出しは在るが、クライアント認証・`expires_in`・ワンタイム性が無い | FAPI 2.0 Security Profile は PAR を必須としている |
| D-3 | **DPoP（RFC 9449）** | 未実装 | Sender-Constrained は mTLS のみ。パブリック クライアント（SPA / ネイティブ）を縛れない |
| D-4 | **Dynamic Client Registration（RFC 7591 / 7592）** | 未実装。クライアントは `appsettings.json` の `OAuth2ClientsInformation` に手書き | クライアント追加に再デプロイが要る。運用でスケールしない |
| D-5 | **`iss` 認可応答パラメタ（RFC 9207）** | 未実装 | Mix-Up 攻撃への対策が RP 側任せ |
| D-6 | **同意（consent）の永続化** | 未実装。毎回同意画面を出すか、`prompt=none` で丸ごとスキップするかの二択 | C-3 の根本原因。UX と安全性の両方に効く |
| D-7 | `profile` / `address` スコープのクレーム | **空実装**（`// ・・・`）。`name` `given_name` `family_name` 等を返さない | `scopes_supported` に載っているのに何も返らない |
| D-8 | クライアントあたり複数 `redirect_uri` | 不可（`redirect_uri_code` / `redirect_uri_token` の 1 本ずつ） | 開発／本番の共存、複数プラットフォーム対応ができない |
| D-9 | 署名鍵のローテーション運用 | JWK Set への追記はできる（`CreateJwkSetJson`）が、**発行側は `Config.RsaPfxFilePath` の 1 本を固定参照** | 無停止での鍵交換ができない |
| D-10 | **`typ: at+jwt`（RFC 9068）** | 未設定。加えて access_token のヘッダに `jku` を入れている | トークン取り違え（token confusion）対策が無い。`jku` は検証側に SSRF を誘発しうるので通常は付けない |
| D-11 | 応答の `scope` | `/token` の応答に `scope` を返していない | 要求と付与が違う場合に RP が判別できない |
| D-12 | **OAuth 2.1 への整合** | Implicit / ROPC が既定で有効（`_appsettings.json` は全て `true`）、PKCE 任意、`plain` 可 | 最新プロファイルとは逆方向 |
| D-13 | レート制限 / ブルートフォース対策 | 未実装（`/token` `/device_authz` `/ciba_authz` とも無制限） | user_code・client_secret への総当たりが可能 |
| D-14 | **適合性テスト** | 仕組みが無い | OpenID Foundation Conformance Suite を回せば A・B の大半は自動で検出できる |

---

## 6. E. 実装・運用の品質

| # | 内容 |
|---|---|
| E-1 | `Startup.cs` 方式のまま。.NET 6 以降の Minimal Hosting（`WebApplication.CreateBuilder`）へ寄せると、`Program.cs` の `IWebHost` / `IHost` のコメント アウト群も整理できる |
| E-2 | `AddDistributedMemoryCache()` / DataProtection 未永続化（C-13）でスケールアウト不可 |
| E-3 | CORS が 3 重定義（C-9） |
| E-4 | `Views/_ViewImports.cshtml` と `Views/Manage/ManageTwoFactorAuthenticator.cshtml` が Shift_JIS（[`ANALYSIS.md`](ANALYSIS.md) 10 節） |
| E-5 | `log4net` 3.2.0 に既知の脆弱性（[`ANALYSIS.md`](ANALYSIS.md) 9.1 節） |
| E-6 | 認可画面（`Views/Account/OAuth2Authorize.cshtml`）に **Deny ボタンが無い**。ユーザは拒否できず、`access_denied` を返す経路も無い。scope も生の識別子をそのまま表示している |
| E-7 | `/jwkcerts` は毎回ファイルを読む（キャッシュ・`Cache-Control` なし） |
| E-8 | `AccountController.cs` 4402 行 / `ManageController.cs` 3262 行。STS 部分（`#region STS` 以下 約 1800 行）を別 Controller へ切り出すと、以降の改修が安全になる |

---

## 7. 近代化ロードマップ（提案）

**Contributing.ja.md の方針（バグ／エンハンス 1 件ごとに feature ブランチと "プルリクエスト"）に合わせ、
1 フェーズ内でも項目ごとに分ける前提で並べた。**

### フェーズ 0 — 「RP が繋がる」状態にする（小さく確実）

| 順 | 項目 | 規模 | 影響範囲 |
|---|---|---|---|
| 1 | ✅ **A-1 `expires_in`（`.Seconds` → `.TotalSeconds`）** #182 | 33 行 | Lib ＋ 両アプリ |
| 2 | ⚠️ **A-2 は誤検出だった** #183（変更は簡素化として保持） | 1 行 | Lib |
| 3 | ✅ **A-3 / A-4 JSON の型（`exp`/`nbf`/`iat`/`*_verified`）** #184 | 検証側含め 20 行前後 | Lib ＋ 両アプリ |
| 4 | ✅ **B-1 〜 B-6 異常系の NRE と未処理例外** #185 | 82 行 | Lib ＋ 両アプリ |
| 5 | ✅ **A-9 discovery の末尾スペース** #189 の一部 | 1 行 | Lib |
| 6 | ✅ **C-14 implicit / hybrid で `nonce` を必須化** #190 | 15 行 | Lib |
| 7 | ✅ **B-7 使用済み・不正な `device_code` の未処理例外** #199 | 39 行 | Lib |

> 6 は本来フェーズ 2（セキュリティ）の項目だが、**2 と表裏の関係**にあり、
> 片方だけ直すと「nonce 無しの implicit / hybrid が nonce クレームの無い id_token を得る」
> という中途半端な状態になるため、続けて実施した。
>
> このフェーズだけで、**OIDC の Basic / Config プロファイルの適合性テストが通る見込みが立つ。**
> 逆にここを飛ばすと、以降の機能追加をテストで裏付けられない。

### フェーズ 1 — 仕様どおりのエラー応答

| 項目 |
|---|
| ✅ **A-6 認可エラーを `error` / `error_description` / `state` に。URL 組み立てを共通化（C-6 も同時に解消）** #187 |
| ✅ **A-8 エラー コードの返し分け（`server_error` 一辺倒をやめる）** #187 |
| A-7 エラーの HTTP ステータス（400 / 401） → **#196 に分離。テスト整備後** |
| A-10 discovery の項目整備 → **#189 の残り 13 項目** |

### フェーズ 2 — セキュリティの底上げ

| 項目 |
|---|
| C-1 `/device_authz` のクライアント認証 |
| C-2 `/revoke` `/introspect` の所有者確認、mTLS の有効化 |
| C-4 / C-5 / C-11 有効期限の実装（code / refresh_token / request object）＋ ワンタイム化 ＋ 再利用検知 |
| C-8 検証アルゴリズムの固定 |
| C-9 CORS をエンドポイント単位に |
| C-10 `redirect_uri` の厳密比較、テスト用抜け道のロックダウン対象化 |
| C-12 / C-13 Cookie 有効期限の設定反映、DataProtection の永続化 |

### フェーズ 3 — OAuth 2.1 / FAPI 2.0 への整合

| 項目 |
|---|
| C-7 PKCE：`code_verifier` ＋ `client_secret` の同時送信を正式サポート、`plain` 廃止、権限判定と分離 |
| C-3 / D-6 同意の永続化と `prompt` の正しい処理（`login_required` / `consent_required`） |
| D-2 `/ros` を PAR（RFC 9126）へ寄せる |
| D-5 `iss` 認可応答パラメタ |
| D-10 `typ: at+jwt`、`jku` の除去 |
| D-12 Implicit / ROPC を既定 無効に（`_appsettings.json`）。**下位互換の方針上、廃止ではなく既定値の変更＋ obsolete 期間** |

### フェーズ 4 — 機能の追加

| 項目 |
|---|
| D-1 RP-Initiated Logout（＋ Front-Channel / Back-Channel） |
| D-3 DPoP |
| D-4 Dynamic Client Registration |
| D-7 `profile` / `address` クレーム |
| D-8 複数 `redirect_uri` |
| D-9 鍵ローテーション |
| D-13 レート制限 |

### フェーズ 5 — 土台

| 項目 |
|---|
| D-14 適合性テスト（OpenID Foundation Conformance Suite）を回す手順の整備 |
| E-1 Minimal Hosting への移行 |
| E-8 `AccountController` からの STS 部分の切り出し |

---

## 8. 作業時の注意（このリポジトリ固有）

- **指摘の多くは `../CommonLibrary` に在るため、直すと net48 版にも効く。**
  逆に言えば、**net48 版の回帰確認をせずにマージできない。**
  `../MultiPurposeAuthSite/ANALYSIS.md` 9 節のとおり、net48 は **Debug 構成でのみ**ビルドできる。
- **`Config` にプロパティを足したら `_appsettings.json` と `_app.config` の両方**に既定値を足す。
  実ファイル（`appsettings.json` / `app.config`）は `.gitignore` 対象で秘密情報を含むため、
  **中身を報告・Issue・コミット メッセージに転記しない。**
- **エンドポイントを足したら、net48 側の `App_Start/WebApiConfig.cs` / `RouteConfig.cs` にも登録が要る。**
- ヘッダ コメントの更新履歴に 1 行追記する（Contributing.ja.md）。
- **1 つの "プルリクエスト" に複数のタスクを混ぜない。** 本書のロードマップは
  そのまま Issue の単位になるよう項目を切ってある。
