# ANALYSIS-IdP.md — IdP / STS 実装の適合性分析と近代化ロードマップ

対象: `root/programs` の IdP / STS 実装
（`CommonLibrary` ＋ `MultiPurposeAuthSiteCore`（net10.0）＋ `MultiPurposeAuthSite`（net48）） / ブランチ: `develop`
最終更新: 2026-09-30

本書は各 `ANALYSIS.md` の続編で、**「IdP / STS としてのプロトコル実装がどこまで出来ていて、
最新の仕様・慣行に対して何が足りないか」** だけを扱う。

ディレクトリ構成・ビルド手順・両系統の差は、各プロジェクトの分析を参照。

- [`CommonLibrary/ANALYSIS.md`](CommonLibrary/ANALYSIS.md) … **実装の実体**（両系統が使う）
- [`MultiPurposeAuthSiteCore/ANALYSIS.md`](MultiPurposeAuthSiteCore/ANALYSIS.md) … net10.0 版
- [`MultiPurposeAuthSite/ANALYSIS.md`](MultiPurposeAuthSite/ANALYSIS.md) … net48 版

**重要: 指摘の多くは `CommonLibrary` に在る＝net48 版（`MultiPurposeAuthSite`）にも同じ症状が出る。**
各項目に **[Core]** / **[Lib]**（＝両系統に影響）を付けた。

プロジェクト・ポリシーは リポジトリ ルートの `AGENTS.md` に定義済み。
→ **エージェントは git 操作を行わない。**

**凡例:** 対応済みの項目は、見出しに **✅ 修正済み（#Issue 番号）** を付ける。
**分析が誤りだった項目は ⚠️ 誤検出（#Issue 番号）** を付け、
**なぜ見誤ったかを残す**（消さない。同じ誤りを繰り返さないため）。
本書は分析の記録であると同時に、**対応状況の一覧**でもある。

---

## 0. 全体の所見

> **以下の箇条書きは、この分析を起こした時点の所見**である（**直した分も、そのまま残してある**）。
> **いま何が残っているかは、次の「対応状況」と 5 / 6 節の表が一次情報**である。

当時の状況は **「OAuth 2.0（RFC 6749）＋ OIDC Core ＋ FAPI1/2・CIBA・Device の実験的実装」** であり、
プロトコルの守備範囲は広い。一方で、

- **エンドポイントの応答形式（`expires_in` / `error` / JSON 型）が仕様から外れている**箇所があり、
  **市販の RP ライブラリや適合性テストを通せる状態にない。**
- **異常系がほぼ全て未実装**で、不正入力が `NullReferenceException` → HTTP 500 になる。
- **有効期限（code / refresh_token / request object）が一切検証されていない。**
- 2020 年前後で更新が止まっており、**PAR / DPoP / RP-Initiated Logout / DCR / OAuth 2.1** が未対応。

「最新の IdP に近づける」うえでの最短経路は、**新機能の追加ではなく、
まず A・B（応答形式と異常系）を直して適合性テストが回る土台を作ること**である。

### 対応状況（2026/10/29 時点）

| グループ | |
|---|---|
| **A. 応答形式** | **全件 ✅**（A-2 は**誤検出**。A-3 の残り（JARM）は #201、A-5 の `request_uri` 経路は #197、A-10 の残り（#189 の 9〜14）は **#228 で決着**。A-15〜A-17 は `CmnEndpoints.*.cs` のレビューで見つかり #294） |
| **B. 異常系の 500** | **全件 ✅**（#185。B-7 は後から E2E で見つかり #199。B-9 はレビューで見つかり #294。B-10 は E2E の拡充で見つかり #294。B-11 / B-12 は `CmnEndpoints.*.cs` のレビューで見つかり #294） |
| **C. セキュリティ** | **全件 ✅**（nonce まわりは C-14（#190）＋ C-16（#191）で仕様どおりに揃った。**C-40〜C-46 は `CmnEndpoints.*.cs` のレビューで見つかり #294**。**C-47 / C-48 は `ManageController.*.cs` のレビューで、C-49 は 2 回目、C-50 / C-51 は 3 回目のレビューで見つかり #294**。**C-52 / C-53 は `CmnUserStore.*.cs` のレビューで、C-54 は 2 回目のレビューで見つかり #294**。**C-55 は `OAuth2EndpointController.*.cs` のレビューで見つかり #294**。**C-40 は「方法を明示した登録」で閉じ、空の登録は従来どおり**） |
| **D. 機能不足** | **1 件 残り** : **D-14**（適合性テスト）。**D-3（DPoP）は ✅ #311**（段階 1〜4）、**D-4（DCR）は ✅ #307 / #308 / #309**（段階 1〜6 ＋ 発行者の台帳 ＋ `jwks_uri`） |
| **E. 品質** | **7 件 残り** : **E-1**（Minimal Hosting）／**E-8**（Controller の切り出し）／**E-13**（refresh_token の失効で access_token も）／**E-14**（ROPC の失敗の数えを原子的に）／**E-15**（クライアント認証の方法を 1 要求に 1 つへ）／**E-16**（CIBA の送れなかった要求の後始末）／**E-17**（`user_code` の大文字小文字）。**E-6 は「同意画面の scope が生の識別子のまま」だけが残る** |

**7 節のフェーズ 0 〜 3 は完了**（D-10 は #302 で解けた）。
**残っているものは フェーズ 4・5（機能の追加と土台）に寄っている。**

**起票時の箇条書きとの対応。**

| 起票時の指摘 | いま |
|---|---|
| 応答形式（`expires_in` / `error` / JSON 型）が仕様から外れている | **✅ A で片付いた**（#182 / #184 / #187 / #196 / #200 / #201） |
| 異常系がほぼ全て未実装で 500 になる | **✅ B で片付いた**（#185 / #199） |
| 有効期限が一切検証されていない | **✅ C-4 / C-5 / C-11**（#188 / #229） |
| **PAR / DPoP / RP-Initiated Logout / DCR / OAuth 2.1** が未対応 | **PAR は ✅ #229**、**RP-Initiated Logout は ✅ #232**（**Front / Back-Channel Logout も ✅ #310**。**Session Management だけは見送り**）、**OAuth 2.1 は ✅ #220**。**DPoP も ✅ #311**（D-3。**段階 1〜4**）。**DCR も ✅ #307 / #308 / #309**（D-4。**登録・管理・クライアント認証の方法（RFC 7591 / 7592）＋ `software_statement` の発行者の台帳 ＋ `jwks_uri`**）。**この 5 つは、どれも残っていない** |

**見出しの ✅ 修正済み / ⚠️ 誤検出 で個別に追える**（7 節も参照）。

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
| | PPID（`subject_types`: `public` / `pairwise`） | ✓ | `Util/PPIDExtension`。**既定は `public`**（#151 の段階 4。独自値は段階 5 で廃止） |
| | mTLS Sender-Constrained（`cnf.x5t#S256`） | ✓ | 発行（`/token`）と照合（`/userinfo` ほか）。C-19 |
| エンドポイント | `/token` `/userinfo` `/revoke` `/introspect` `/jwkcerts` | ✓ | |
| | `/end_session`（RP-Initiated Logout） | ✓ | #232。**`sid` は `id_token` に出る**（#310 の段階 1。**RP ごとに別の値**。伝える先は `SessionClient` の表）。**サインアウトすると、登録が在る RP へ `logout_token` を POST する**（#310 の段階 2）。**`frontchannel_logout_uri` の登録が在れば、`iframe` の画面も返す**（#310 の段階 3）。**どちらも Discovery で広告している** |
| | `/register`（Dynamic Client Registration） | ✓ | #307 の段階 1。**既定は無効**（`EnableDynamicClientRegistration`）。**専用 scope（`client_registration`）のアクセス トークンで叩く** |
| | `/register/{client_id}`（Client Configuration） | ✓ | #307 の段階 2（RFC 7592 の `GET` / `PUT` / `DELETE`）。**`registration_access_token` で叩く**（登録の応答で 1 回だけ返る） |
| | `.well-known/openid-configuration` | ✓ | 不足あり（3 節） |
| | `/ros`（Request Object 登録） | ✓ | **PAR ではない独自仕様** |
| | `samlmetadata` / SAML2 IdP | ✓ | |
| 拡張 | PKCE (RFC 7636) | ✓ | `plain` / `S256` |
| | JARM（`query.jwt` / `fragment.jwt` / `form_post.jwt`） | ✓ | |
| | Request Object（`request_uri`） | ✓ | |
| | ID フェデレーション（他 IdP への委譲） | ✓ | **認可コード ＋ PKCE(S256) ＋ `client_secret_post`**（#140 の段階 3）。連携キーは `(iss, sub)`、`iss` は RFC 9207 でも照合、**`aud` も照合**（C-24 / #286 の段階 5）。**SAML2 でも委譲できる**（#286。`SA-6.*`）。**上流の SSO の口と署名証明書は、上流のメタデータから引く**（#291。**引けなければ設定**）。**上流の `id_token` の検証鍵は、上流の discovery（`jwks_uri`）から `kid` で引く**（#289 の段階 2）。**引けなければ設定の `.cer`**（段階 1。`IdFederationOidcCerFilePath`）。**メアド・利用者名・`email_verified` は、アサーションの属性で運ぶ**（#286 の段階 4。`SA-7.*`）。**上流は n 件**（#292 の段階 1・2。**設定 ＋ user store**。**管理画面は `/IdFederationAdmin`**。D-15）。**(2) の署名鍵は上流ごとに替えられる**（#292 の段階 4-a・4-b）。**目視・E2E とも実施済み**（上流は `Container/E2E/` のコンテナ。`RT-140.4` 〜 `RT-140.7`。#250 の段階 4〜5。`TESTING.md` 5 節） |
| | 2FA（SMS / Email / TOTP / プッシュ承認） | ✓ | プッシュ承認（`MobileApp`）は #213（net10.0）/ #216（net48） |

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

> **残っていた同種の箇所 — ✅ 修正済み（#201）:** JARM の Response Object（`CmnResponseObject.Create`）も
> `exp` を文字列で入れていた（E2E テスト EX-6.4 で実測）。
>
> ```csharp
> // 修正前: CommonLibrary/TokenProviders/CmnResponseObject.cs
> responseDictionary.Add(OAuth2AndOIDCConst.exp, expiresUtc.Value.ToUnixTimeSeconds().ToString());
> ```
>
> 当時は「引数が `Dictionary<string, string>` なので、シグネチャ変更と両アプリの呼び出し側の修正を伴う」
> として範囲外にした。#201 では、**関数の中で `Dictionary<string, object>` に写してから `exp` を数値で入れる**形にし、
> シグネチャも呼び出し側も変えずに直した。
> 検証側（Open棟梁 の `ResponseObject.Verify`）は `(string)` で読むが、JSON の数値も文字列として読めるので、変更は要らない。

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

> **残っていた穴 — ✅ 修正済み（#197）:** `request_uri`（Request Object / JAR）の経路では、
> `redirect_uri` が **JWT の中**にあって `queryString` には無いため、**紐付けが効かなかった。**
>
> E2E テストで実測した（2026/09/09, net10.0）。**推測ではない。**
>
> ```
> 誤った redirect_uri: HTTP 200 / keys=[access_token, expires_in, id_token, ...] / error=-
> ```
>
> PKCE の `code_challenge` も同じ理由で拾えていなかったが、**向きは逆**で、
> 記録されないため `code_verifier` を送ると `invalid_client` になっていた（素通りではなく拒否）。
> 安全側だが、`request_uri` ＋ PKCE のパブリック クライアントは機能しなかった。
>
> ```csharp
> // 修正前: CommonLibrary/TokenProviders/AuthorizationCodeProvider.cs（Create）
> temp.Add(OAuth2AndOIDCConst.redirect_uri,          queryString[OAuth2AndOIDCConst.redirect_uri]);
> temp.Add(OAuth2AndOIDCConst.code_challenge,        queryString[OAuth2AndOIDCConst.code_challenge]);
> temp.Add(OAuth2AndOIDCConst.code_challenge_method, queryString[OAuth2AndOIDCConst.code_challenge_method]);
> ```
>
> **対応（#197）:** 当時は「`CreateCodeInAuthZNRes` に実効値を渡す形にする」としたが、
> 呼び出し側（両アプリの Controller）を変えずに済むよう、
> **`AuthorizationCodeProvider.Create` の中で値の出どころを決める**形にした。
> クエリ文字列に `request_uri` があれば Request Object を読み、その中の 3 つの値だけを使う（RFC 9101 §5）。
> `request_uri` が無い、または Request Object が見つからないときは、従来どおりクエリ文字列から読む
> （見つからないときの扱いは Controller と揃えた）。
> 認可コード フローと Hybrid フローの両方がこの関数を通るので、1 か所で両方に効く。
>
> Request Object は Controller でも読んでいるが、`RequestObjectProvider.Get` は消費しない（C-11）ので読み直せる。
> **ワンタイム化（C-11。#188 の段階 2）は、読む回数を減らすのではなく、
> 認可応答を作り終えた時点で消すことで実現した**（`CmnEndpoints.ConsumeRequestObject`）。
>
> E2E テスト（`root/programs/Tests/E2ETests/Tests/RequestObjectTests.cs`）:
> `RT-197.5`（誤った `redirect_uri` → `invalid_grant`）/
> `RT-197.6`（正しい検証子で通り、誤った検証子は拒否）。net48 / net10.0 の両方で確認した。

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

### A-7. エラーの HTTP ステータスが 200 **[Core]** — **✅ 修正済み（#196）**

`/token` `/userinfo` `/revoke` `/introspect` はいずれも
`Dictionary<string,string>` を返すだけなので、**エラーでも HTTP 200** になる。
RFC 6749 §5.2 は **400（`invalid_client` は 401）**、
OIDC Core §5.3.3 の UserInfo は **401 ＋ `WWW-Authenticate`** を求める。

**修正方針:** 戻り値を `IActionResult`（net10.0）/ `IHttpActionResult`（net48）に変え、エラーを 400 / 401 で返す。
**両系統で書き方が違うので、別実装になる。** エンドポイントごとに分けて進める。

> **#187 から #196 に分離した。** 戻り値の型変更を伴い両系統で実装が分かれること、
> **HTTP ステータスはクライアントの期待そのもの**でテスト整備後に着手したいことが理由。
> `/revoke` は、成功と無効なトークンの場合に 200 を返す（RFC 7009 §2.2。#200 で対応済み）。
> `invalid_client` などのエラーは、他と同じく 400 / 401 になる。

**対応（#196 の 1 つ目 : `/token`）:**

- エラーは 400、`invalid_client` は 401（RFC 6749 §5.2）。401 には `WWW-Authenticate: Basic realm="token"` を付ける
  （Authorization ヘッダで認証を試みたクライアントには必須）
- 判定は `CmnEndpoints.GetErrorStatusCode` に置き、両アプリで共用する（残りのエンドポイントでも使う）
- 本文（`error` / `error_description` の JSON）は変えていない。成功は 200 のまま
- **net48 版だけの落とし穴:** OWIN の Cookie 認証が、**401 の応答をログイン画面への 302 に書き換えていた。**
  `StartupAuth` の `OnApplyRedirect` で、Web API（`WebApiConfig` に登録したルートと、`[Route]` の属性ルート）を
  書き換えの対象から外した。対象は登録済みのルートから判定し、別の一覧は持たない（§8）。
  画面の遷移は、従来どおりログイン画面へリダイレクトする
- E2E テスト : `RT-196.1`（フォームでの認証失敗 → 401）/ `RT-196.2`（Basic 認証の失敗 → 401 と `WWW-Authenticate`）/
  `RT-196.3`（その他のエラー → 400）/ `RT-196.4`（成功は 200 のまま）

> **net48 版の既知の問題（Open棟梁 側）:** 401 の `WWW-Authenticate` に、`somescheme somechallenge` という仮の値が付け足される。
> Open棟梁 の `MyBaseAsyncApiController.ChallengeAsync` が、雛形のまま残った `ResultWithChallenge` を無条件に使っているため。
> 先頭の `Basic realm="token"` は正しく付くので、動作には支障が無い。

**対応（#196 の 2 つ目 : `/userinfo`）:** RFC 6750 §3（OIDC Core §5.3.3 が参照）に合わせた。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| Bearer トークンが無い（ヘッダ無し、または Basic など他の方式） | 200 ＋ `invalid_request` | **401 ＋ `WWW-Authenticate: Bearer realm="userinfo"`、本文なし** |
| 無効なトークン（JWT でない・改竄・失効・期限切れ） | 200 ＋ `invalid_request` | **401 ＋ `WWW-Authenticate: Bearer realm="userinfo", error="invalid_token", …`、本文は `invalid_token`** |
| 有効なトークン | 200 ＋ ユーザ情報 | 変更なし |

- **本文も変えた。** 無効なトークンの `error` は `invalid_request` から `invalid_token` に
  （`invalid_request` は RFC 6750 §3.1 で 400 に当たるコードで、401 と食い違うため）。
  トークンが無い要求には、エラー情報を返さない（§3.1 : 認証情報の無い要求にはエラー コードを含めない）
- 判定（`invalid_token` は 401）と `WWW-Authenticate` の組み立ては `CmnEndpoints` に置き、両アプリで共用する
  （`GetErrorStatusCode` / `GetBearerChallengeParameter`）。`invalid_token` は Open棟梁 の定数に無いので `CmnEndpoints` で定義した
- 同梱のクライアント（Open棟梁 の `OAuth2AndOIDCClient.GetUserInfoAsync`）は、ステータスを見ずに本文を読むので影響しない
- E2E テスト : `RT-196.5`（トークン無し・Basic 方式 → 401、エラー コードなし）/
  `RT-196.6`（JWT でない・改竄・失効 → 401 と `invalid_token`）/ `RT-196.7`（成功は 200 のまま）

**対応（#196 の 3 つ目 : `/revoke`）:** RFC 7009 §2.2.1（エラーは RFC 6749 §5.2 のとおり）に合わせた。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| 成功、無効なトークン（RFC 7009 §2.2） | 200 | 変更なし |
| クライアント認証の失敗（`invalid_client`） | 200 | **401 ＋ `WWW-Authenticate: Basic realm="revoke"`** |
| `token` の欠落（`invalid_request`）、他のクライアントのトークン（`invalid_grant`） | 200 | **400** |

- 本文（`error` / `error_description` の JSON）は変えていない
- `/token` のエラー応答（400 / 401 と `WWW-Authenticate: Basic`）を作る関数を、両アプリとも `/token` の region から
  クラス末尾の共通の region に移し、`/revoke` と共用する（`realm` だけを変える）
- E2E テスト : `RT-196.8`（フォーム・Basic での認証の失敗 → 401）/
  `RT-196.9`（`token` なし・他のクライアントのトークン → 400）/ `RT-196.10`（Authorization ヘッダでの成功は 200 のまま）。
  フォームでの成功と、無効なトークンの 200 は `EX-2.1` / `EX-2.5` が見ている

**対応（#196 の 4 つ目 : `/introspect`）:** RFC 7662 §2.3（認証の失敗は RFC 6749 §5.2 のとおり 401）に合わせた。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| 問い合わせへの答え（`active=true`、および無効・他クライアントのトークンの `active=false`） | 200 | 変更なし（RFC 7662 §2.2 : `active=false` もエラーではない） |
| クライアント認証の失敗・資格情報なし（`invalid_client`） | 200 | **401 ＋ `WWW-Authenticate: Basic realm="introspect"`** |
| `token` の欠落（`invalid_request`） | 200 | **400** |

- 本文（`error` / `error_description` の JSON）は変えていない
- エラー応答は、`/token`・`/revoke` と共用の関数（クラス末尾の共通の region）で作る
- E2E テスト : `RT-196.11`（フォーム・Basic・資格情報なし → 401）/ `RT-196.12`（`token` なし → 400）/
  `RT-196.13`（`active=true` も `active=false` も 200）

**対応（#196 の 5 つ目 : `/device_authz`）:** RFC 8628 §3.1（クライアント認証はトークン エンドポイントと同じ）に合わせ、
エラーを RFC 6749 §5.2 のとおりに返す。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| 成功（`device_code` / `user_code` を発行） | 200 | 変更なし |
| 登録されていない `client_id`、コンフィデンシャル クライアントの認証の失敗（`invalid_client`） | 200 | **401 ＋ `WWW-Authenticate: Basic realm="device_authz"`** |
| フォームデータなし（`invalid_request`） | 200 | **400** |

- 本文（`error` / `error_description` の JSON）は変えていない
- エラー応答は、`/token`・`/revoke`・`/introspect` と共用の関数で作る
- E2E テスト : `RT-196.14`（登録されていない `client_id`・Basic での認証の失敗 → 401）/ `RT-196.15`（成功は 200 のまま）。
  フォームデータなし（400）は、空のフォームでは `client_id` なし（401）の経路に入るため、E2E では測っていない
- `expires_in` / `interval` が文字列で返る点（`EX-4.1` で観測）は、HTTP ステータスの範囲外なので扱っていない

**対応（#196 の 6 つ目 : `/ciba_authz`）:** CIBA Core §13（エラー コードごとに HTTP ステータスを定める）に合わせた。
**エラー コードも直した。** 以前は、空文字列や `server_error` のまま返る経路があった。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| 成功（`auth_req_id` を発行） | 200 | 変更なし（ユーザへプッシュ通知を FCM で送るので、E2E では測っていない） |
| `request_uri` が無い・存在しない | 200 ＋ `invalid_request` | **400** ＋ `invalid_request` |
| `scope` に `openid` が無い | 200 ＋ `error` が空 | **400** ＋ `invalid_scope` |
| `exp` / `nbf` の範囲外、必須のクレームの欠落 | 200 ＋ 空 / `server_error` | **400** ＋ `invalid_request` |
| `login_hint` のユーザが見つからない | 200 ＋ 空 | **400** ＋ `unknown_user_id` |
| 登録されていないクライアント（`iss`） | 200 ＋ 空 | **401** ＋ `invalid_client` |
| **ユーザの端末（認証デバイス）が未登録** | **500 ＋ JSON でない本文**（#210） | **400** ＋ `access_denied` |
| **プッシュ通知（FCM）の送信に失敗** | **500 ＋ JSON でない本文**（#210） | **400** ＋ `server_error` |

- **クライアント認証を求めるようにした**（**#234 の段階 3**）。CIBA Core §7.1 は
  **この口でのクライアント認証を MUST** としており（FAPI-CIBA は `private_key_jwt` を要求）、
  **`ClientAuthentication` を呼んでいないのは、この口だけだった**（`/token`・`/device_authz` は呼んでいた）。
  以前は署名付きの要求（ES256）だけでクライアントを識別していた。

  受け付ける方式は `/token`・`/par` と同じ（`client_secret_basic` / `client_secret_post` /
  `private_key_jwt` / `tls_client_auth`）。**401 には `WWW-Authenticate` を付ける**ようにした
  （HTTP 認証を行うようになったため。RFC 6749 §5.2。以前は `realm` に `null` を渡していた）。

  **認証しただけでは足りない。** CIBA Core §7.1.1 は `iss` を「クライアントの `client_id`」と定めており、
  **認証したクライアントと要求の `iss` の一致**も確かめる（`VerifyCibaRequestIssuer`）。
  でないと、**自分の資格情報で認証して、他人の要求を代わりに送れる**
  （要求の署名は、その他人の鍵で正しく検証できてしまう）。`RT-234.4` / `RT-234.5`

  **同梱の自己テストも、これに合わせて移した。** `/ros` に預けて `request_uri` を渡す形をやめ、
  **`request` を直接送り、資格情報を添える**（`Helper.CibaAuthZRequestAsync` のオーバーロード）。
  Open棟梁 の `OAuth2AndOIDCClient.CibaAuthZRequestAsync(Uri, string)` は
  資格情報を渡す引数が無いため使わず、`/chage_to_user` などと同じく自前で組み立てている（OpenTouryo #592）
- **`aud` を検証するようにした**（**#234 の段階 1**）。CIBA Core §7.1.1 は
  **`aud` に OP の Issuer Identifier を入れること**を MUST としている（`Config.IssuerId` ＝
  Discovery の `issuer`、トークンの `iss`、認可応答の `iss` と同じ値）。
  見ないと、**別の認可サーバ宛てに作られた要求**を、同じクライアントの鍵が登録されていれば受け付けてしまう。

  **直す前は、呼び出し側の 2 つとも仕様と違う値を入れていた。**

  | | `aud` に入れていた値 |
  |---|---|
  | 同梱の自己テスト（`HomeController`） | `/ciba_authz` の**エンドポイント URL** |
  | E2E | サイトの **base URL** |

  どちらも Issuer Identifier に直した。E2E は **Discovery の `issuer` を読んで使う**
  （`IdPClient.IssuerAsync`）ので、設定を変えても追随する（`RT-234.1` / `RT-234.2`）
- **`jti` で使い切りにした**（**#234 の段階 2**）。以前は未検証（`//string jti = "";`）で、
  **同じ要求 JWT を `exp` まで何度でも送り直せた**（`request_uri` の経路も、`/ros` に預け直せば同じ）。
  `/ciba_authz` はクライアント認証をしない（段階 3 で入れる）ので、
  要求を手に入れた者が、利用者に通知を繰り返し送れてしまう。

  **記録先は Request Object のストアを使い回す**（キーに `ciba:` を付ける）。
  #188 の有効期限と掃除がそのまま効き、**表を増やさない**（DDL を 3 方言とも変えなくてよい）。

  **キーは固定長にしてある**（`ciba:` ＋ `jti` の SHA-256 の先頭 16 バイトを Base64URL ＝ 27 文字。**#243**）。
  当初は `ciba:jti:` ＋ `jti` をそのまま繋いでおり、**記録先の `Urn`（38 文字）に入らず、
  DB ストアでは書き込みが失敗して HTTP 500 になっていた**
  （`mem` は辞書なので桁の制限が無く、`RT-234.3` では現れなかった）。
  **`jti` はクライアントが決める値で長さの上限が無い**ため、桁を広げるだけでは足りない。
  **元の `jti` は値として残す**ので、再送の調査はできる（`RT-243.1`）。
  **保持はそのストアの有効期限まで**（既定 300 秒）なので、要求の `exp` をそれより長くすると、
  記録が消えた後は同じ `jti` を受け付ける。厳密な排他はしていない（同時到着は防がない）。
  検証は `jti` を確かめた時点で行うので、**利用者が見つからずに終わった要求でも `jti` は消費される**（`RT-234.3`）
- **要求の受け取り方は 2 つある**（#233。`CmnEndpoints.ReceiveCibaRequest`）。

  | | 送り方 | 位置付け |
  |---|---|---|
  | `request` | 署名付き JWT を、そのままフォームで POST | **CIBA Core §7.1.1。標準の送り方**（#233 で追加） |
  | `request_uri` | `/ros` に預け、その参照を POST | **CIBA Core に無い独自拡張。** 後方互換で残す |

  **両方あれば `request` を使う。** 署名の検証は同じ（登録済みの `jwk_ecdsa_publickey`）で、
  検証を通った中身を `ValidateCibaAuthZReqParam` に渡す流れも変わらない。
  `request` の経路では**預けたものが無いので、使用後に消す対象も無い**（`request_uri` のときだけ `Delete` する）
- 未登録のクライアントや必須のクレームの欠落は、`request_uri`（`/ros` に登録）の経路では
  登録の時点で先に断られるので、`/ciba_authz` では起きにくかった。
  **`request` の経路では `/ciba_authz` が最初の関門になる**ので、ここの判定が実際に効く
- `unknown_user_id` は Open棟梁 の定数に無いので `CmnEndpoints` で定義した。
  クレームの欠落は、Open棟梁 の `CmnJwtToken.CheckClaims` が返す `server_error` を、`invalid_request` に読み替える（`GetCibaClaim`）
- E2E テスト : `RT-196.16`（`request_uri` なし・存在しない → 400）/
  `RT-196.17`（`openid` なし・`nbf` が未来・`exp` が過去 → 400 と CIBA のコード）/
  `RT-196.18`（ユーザ不明 → 400 と `unknown_user_id`）。要求は、テスト基盤に足した ES256 の署名で組み立てる

**対応（#210 : 端末未登録・送信失敗）:** 上の表の下 2 行。**#196 の対応では、この 2 つが残っていた。**
`FcmService.SendAsync` の呼び出しに `try` / `catch` が無く、例外がそのまま外に出て HTTP 500 になっていた
（開発モードでは例外の平文、それ以外では HTML のエラー画面。どちらも JSON ではない）。

- **端末の有無は、送る前に確かめる**（`CibaProvider.Create` よりも前）。保留中のレコードを作らずに返す
- ユーザ自体は見つかっているので、`unknown_user_id` ではなく `access_denied` を返す
- 送信の失敗（資格情報の誤り、宛先の拒否、通信障害など）は `server_error`。
  **こちらは `Create` の後なので、レコードは期限（`CibaExpireTimeSpanFromSeconds`、既定 600 秒）まで残る**
- **原因は `ACCESS` ログに残す**（`Logging.MyDebugLogForEx`）。
  例外を受け止めると、それまで `OnException` が書いていた内容（何が起きたか）が失われるため。
  あとから足した（A-7-2 / #214 と同じ考え方。両アプリ）
- E2E テスト : `RT-210.1`（端末未登録 → 400 と `access_denied`）。
  **送信そのものの失敗は E2E では測れない。** `test.ps1 -Launch` は送信箱を使い、`FcmService` は宛先を検証せずファイルに書くため
- テストの `login_hint` には `tanaka@example.com` を使う。
  テスト ユーザ（`super_tanaka@example.com`）は `EX-8` が端末を登録するので、「端末が無い」状態を作れない

**対応（#196 の 7 つ目 : `/ciba_result`・`/SetDeviceToken`）:** 認証デバイス（`authentication_device`）が呼ぶ 2 つの口。

| 要求 | 修正前 | 修正後 |
|---|---|---|
| 成功 | 200 ＋ `"OK"` | 変更なし |
| Bearer トークンが無い | 200 ＋ `"NG"` | **401 ＋ `WWW-Authenticate: Bearer realm="…"`**、本文 `"NG"` |
| 無効なトークン、ユーザの無いトークン | 200 ＋ `"NG"` | **401 ＋ `WWW-Authenticate: Bearer …, error="invalid_token"`**、本文 `"NG"` |
| パラメタの不備（`device_token`・`auth_req_id` なし、`result` が真偽値でない） | 200 ＋ `"NG"` | **400**、本文 `"NG"` |

- **本文（`"OK"` / `"NG"`）は変えていない。** 認証デバイスは、ステータスと本文の `"OK"` を見ているので、アプリの修正は要らない
- **E2E テストでは、認証デバイスとプッシュ通知を置き換える。**
  サーバは、構成の `FcmOutboxDirectory` が設定されていれば FCM に送らず、そのディレクトリにファイルとして書く（送信箱）。
  設定するのは `test.ps1 -Launch`（環境変数）だけで、本番では空のまま。
  テストは送信箱を読み、認証デバイスと同じ要求（`/SetDeviceToken`・`/ciba_result`）を送る。
  これで、これまで測れなかった CIBA の成功経路（`EX-8.1` 許可 → トークン、`EX-8.2` 拒否 → `access_denied`）を測れる
- E2E テスト : `RT-196.19`（`/SetDeviceToken` の 400 / 401）/ `RT-196.20`（`/ciba_result` の 400 / 401）

> **別の問題（#196 の範囲外。調査の途中で見つけ、別に報告した）:**
> - `/ciba_result`（と `CibaProvider.ReceiveResult`）が、`auth_req_id` の宛先ユーザを確かめていなかった
>   → **✅ 修正済み。** `CibaData` に承認する利用者（`Users.Id`）を記録し、
>   返答時に **`auth_req_id` と利用者の両方**で照合する。要求が無い場合と自分宛てでない場合は
>   同じ応答（400 ＋ `"NG"`）で返す（存在を推測させないため）。
>   あわせて、メモリのストアの 2 つの取り違えも直した。
>   **（a）`ReceiveResult` が `auth_req_id` を見ず、保留中の全要求へ結果を書き込んでいた**（E2E : `EX-8.3`）。
>   **（b）`ReceiveTokenReq` が、一致したものとは別の保留要求を削除しうる状態だった**（ループ変数の取り残し）。
>   E2E : `EX-8.3` / `EX-8.4`（別の利用者は承認できない。#212 で Skip を解消）
> - `TwoFactorAuthPushResult` は、ルートだけが登録され、両アプリともアクションが無かった → **✅ 削除済み（#203）**。その後、**プッシュでの 2FA 承認そのものを `/2fa_result` として実装した**（#213 : net10.0 / #216 : net48）
> - `Authorization: Bearer`（方式だけで値が無い）で HTTP 500 になる
>   （Open棟梁 の `AuthenticationHeader.GetCredentials` が `temp[1]` を確かめずに読む）
>   → Open棟梁 の #586。`RT-196.5` で観測している

### A-7-2. 2FA のコード送信で、送信の失敗が処理されない例外になる **[Core][netfx]** — **✅ 修正済み（#214）**

**`/ciba_authz` と同じ形の不具合が、画面側（`/Account/SendCode`）にも残っていた。**
送信（メール / SMS / プッシュ）を `try` / `catch` 無しで呼んでいたため、
**DNS の一時障害で `FirebaseMessagingException` がそのまま外に出て、原因の分からないエラー画面**になった
（#205 の確認中に実際に発生。`ACCESS` ログに `Account,SendCode(OnException)` として残っていた）。

| 状況 | 修正前 | 修正後 |
|---|---|---|
| 送信に成功 | コードの入力画面へ | 変更なし |
| **送信に失敗（通信障害、資格情報の誤りなど）** | **処理されない例外 → エラー画面** | **コードの送信画面に戻し、失敗を表示**（別の送信先を選び直せる） |
| 入力の検証に失敗、または送信が false | **`View()` にモデルを渡さず `NullReferenceException`** | 同上（モデルを作り直して再表示） |

- **例外は握り潰さず、`Logging.MyDebugLogForEx` で `ACCESS` ログに残す。**
  受け止めると、これまで `OnException` が書いていた原因が失われるため
- 表示のために `SendCode.cshtml` に `ValidationSummary` を足した（他の画面と同じ形。**無いと `ModelState` のエラーが出ない**）
- 一覧を作る処理は `CreateSendCodeViewModelAsync` にまとめ、初期表示と再表示で共用する
- **net48 版も同じ形だったので、あわせて直した**（`SendTwoFactorCodeAsync` がメール / SMS を送るため、同様に失敗しうる）
- **E2E では測れない。** テストは 2FA を有効にしておらず、送信箱（`FcmOutboxDirectory`）は失敗しない

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

**対応（#187 の残り。2026-09-17）: エラーの「返し方」も直した。**

コードは返し分けられていたが、**`response_type` の誤りは `redirect_uri` を確かめる前に弾いていた**ため、
`valid_redirect_uri` が空のまま呼び出し元に戻り、**リダイレクトではなくエラー画面（HTTP 200）**になっていた。
RP からは何が起きたのか分からない。

- **判定の順序とエラー コードは変えていない。** `ValidateAuthZReqParam` をラッパにし、
  **失敗して返し先が決まっていないときだけ**、返してよい `redirect_uri` を決める（`ResolveErrorRedirectUri`）
- **返してよいかは「このクライアントに登録された URI か」で決める**（RFC 6749 4.1.2.1）。
  `response_type` が不明だと種別ごとの登録（`redirect_uri_code` / `redirect_uri_token`）を引けないので、両方と突き合わせる。
  一致しなければ空を返し、**画面で知らせる**（検証していない URI へは飛ばさない＝オープン リダイレクタにしない）
- **成功したときの宛先には使わない。** 成功経路の `valid_redirect_uri` は元のまま
- `client_id` が不正なときは、そもそも登録を引けないので画面のまま（`RT-187.5`）
- E2E テスト : **`RT-187.4` の `Skip` を解消**（両ターゲットで `unsupported_response_type` がリダイレクトで返る）。
  `RT-187.3` の観測も「リダイレクトして `error=unsupported_response_type`」に変わった

### A-8-2. トークン応答にキャッシュ制御のヘッダが無い **[Core][netfx]** — **✅ 修正済み（#218 の 1 つ目）**

RFC 6749 §5.1（成功）/ §5.2（エラー）は、**`Cache-Control: no-store` と `Pragma: no-cache` を MUST**
としている。トークンを中間のキャッシュやブラウザの履歴に残さないため。

**両系統とも、どこにも設定していなかった**（`no-store` で全文検索して 0 件）。
E2E の `TC-3.2` は測っていたが、**観測にとどめて「別途 Issue」と書いたまま放置されていた**（#218）。

- **アクションの入口で付ける**（`OAuth2EndpointController.OAuth2Token`）。
  **成功・エラーのどちらの経路でも返す**ため、出口ごとに書かない
- net10.0 は `Response.Headers` に直接入れて `no-store`。
  **net48 は `System.Web` の `Response.Cache`**（`SetCacheability(NoCache)` ＋ `SetNoStore()`）を使う。
  ヘッダを直接書くと ASP.NET のキャッシュ モジュールに上書きされうるため。
  結果、net48 は `Cache-Control: no-store, no-cache` になる（RFC が求めるのは `no-store` が在ること）
- E2E テスト : **`TC-3.2` を観測から検証に格上げ**（両ターゲットで成立）。
  値は完全一致で見ず、`no-store` / `no-cache` を含むかで判定する
- **`/token` のほか、資格情報・属性を返す口にも付けた**（`/introspect`・`/userinfo`・
  `/device_authz`（`device_code`）・`/ciba_authz`（`auth_req_id`）。#218 の案 C）。
  **RFC が MUST としているのは `/token` だけ**だが、キャッシュに残ると困る性質は同じ。
  E2E テスト : `RT-218.1`（4 口 × 2 ヘッダを、両ターゲットで確認）

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

> **#189 のうち、この 1 件を先に対応した。残りは A-10。**

### A-10. discovery のその他の不整合 **[Lib]** — **✅ 誤りと未広告は修正済み（#189 の 2〜8）**

**Discovery は RP が最初に読む唯一の入口である。** 誤りは「読めない」「型で落ちる」に直結し、
広告していない項目は「実装しているのに使えない」と判断される。

**修正したもの（#189 の 2〜8）**

| # | 修正前 | 修正後 | E2E |
|---|---|---|---|
| 2 | `mutual_tls_sender_constrained_access_tokens: "true"`（草案の名前・文字列） | `tls_client_certificate_bound_access_tokens: true`（RFC 8705 §3.3） | `RT-189.3` |
| 3 | `backchannel_user_code_parameter_supported: "false"` | `false`（boolean） | `RT-189.2` |
| 4 | `backchannel_authentication_request_signing_alg_values_supported: "ES256"` | `["ES256"]`（配列） | `RT-189.2` |
| 5 | `id_token_encryption_alg_values_supported` のみ | `..._enc_values_supported: ["A256GCM"]` を対で追加（実装は `JWE_RsaOaepAesGcm`） | `RT-189.4` |
| 6 | `device_authorization_endpoint` が無い | 追加（RFC 8628 §4） | `RT-189.1` |
| 7 | `grant_types_supported` に device_code が無い | `Config.EnableDeviceAuthZGrantType` を見て追加 | `RT-189.1` |
| 8 | JARM の alg が無い | `authorization_signing_alg_values_supported: ["RS256"]`（実装は `CmnResponseObject` の JWS(RS256)） | `RT-189.4` |

> **`"false"` は危い。** 多くの実装で**真**として読まれるので、
> 「user_code に対応していない」が「対応している」に反転する。

**#228（仕様方針の判断を伴うもの。#189 の 9〜14）で決めたこと**

| # | 決定 | 理由 | E2E |
|---|---|---|---|
| 9 | **設定に合わせて広告する**。`RequirePkceS256` が `true` なら `["S256"]`、既定（`false`）なら `["plain","S256"]` | 広告と実装を一致させる。**既定の挙動は変えない。** `RequirePkceS256` はサーバ全体の設定なので、要求者によらず 1 つに決まる（クライアント単位の `require_pkce` は「必須にするか」で別の話。Discovery にクライアント別の項目は無い） | `RT-189.5` |
| 12 | **設定値にする**（`ServiceDocumentation`。既定は空、空なら出さない） | 任意の項目なので、嘘のプレースホルダ（`"・・・"`）を配らない | `RT-189.5` |
| 10 | **変えない**（#151 に委ねる） → **✅ #151 の段階 4〜5 で解決** | 独自値は**登録の既定であり、実際の振る舞い**（`sub` に利用者名）だった。広告だけ直すと、実際の `sub` とズレる。**段階 4 で既定を `public` に変え、段階 5 で独自値を廃止した**ので、**いまの広告は `public` / `pairwise` の 2 つ**＝実装どおりである | `RT-151.1` / `RT-151.2` |
| 11 | **変えない**（D-2＝#229 に委ねる） | `request_object_endpoint` は FAPI1 の Request Object（JAR）の置き場所を示す独自拡張。**名前だけ PAR に寄せると、中身が PAR でないのに PAR と読まれる** | — |
| 13 | **別 Issue（#230）**（`profile` / `address` のクレームは未実装。D-7） | 広告だけ足すと嘘になる | — |
| 14 | **別 Issue**（`end_session` は D-1＝#232、`iss` は D-5＝#231。`registration` は D-4 で、**#307 の段階 1 で広告するようになった**。**管理は段階 2**） | いずれも未実装。とくに `iss`（RFC 9207）は認可応答に値を足す実装が要る | — |

> **`request_object_endpoint`（`/ros`）と PAR（RFC 9126）の差**（D-2）。
> `/ros` は Request Object の署名だけで受け付け、応答の `exp` は空文字、`request_uri` は使い切りにしていない。
> PAR は**クライアント認証**（トークン エンドポイントと同じ）、**`expires_in` 必須**、**一回限り**を求める。

### A-11. `/revoke` `/introspect` がヒントを必須にし、無効なトークンをエラーにする **[Core][Lib]** — **✅ 修正済み（#200）**

E2E テストの拡張仕様（EX-2 / EX-3）で見つかった。

| # | エンドポイント | 修正前 | RFC |
|---|---|---|---|
| 1 | `/revoke` | `token_type_hint` が無いと `invalid_request`。失効しない | ヒントは任意。見つからなければ全種類を探す（RFC 7009 §2.1） |
| 2 | `/revoke` | 無効なトークンに `invalid_request` | 200 で成功扱い（RFC 7009 §2.2） |
| 3 | `/introspect` | 無効なトークンに `invalid_request` | `{"active": false}`（RFC 7662 §2.2） |
| 4 | `/introspect` | refresh_token の問い合わせが、実行ごとに `active=true` / `invalid_request` に揺れる | `active=true` |
| 5 | `/revoke` | 成功が net10.0 は HTTP 204、net48 は HTTP 200（本文 `null`） | 200（RFC 7009 §2.2） |

4 の原因は、refresh_token を**有効期限が現在時刻の** access_token に作り直してから検証していたこと。
`CmnJwtToken.VerifyExp` は秒単位の `exp >= now` なので、作ってから検証するまでに秒をまたぐと失効扱いになる。

```csharp
// 修正前: MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/OAuth2EndpointController.cs（net48 版も同じ）
token = Token.CmnAccessToken.ProtectFromPayload(
    "", tokenPayload, DateTimeOffset.Now,
    null, OAuth2AndOIDCEnum.ClientMode.normal, out string aud, out string sub);
```

**対応（#200）:** クライアント認証より後の本体を、両アプリの Controller から
`CmnEndpoints.RevokeToken` / `IntrospectToken` に移した。
両アプリに同じコードが 2 本ずつあったため、片方だけ直す事故を防ぐ。Controller にはクライアント認証だけを残した。

- `token_type_hint` は探す順番の手掛かりにする。ヒントの種類で見つからなければ、他の種類も探す
- どの種類でも見つからなければ、`/revoke` は成功（空の JSON、HTTP 200）、`/introspect` は `{"active": false}`
- 他のクライアントのトークンの扱い（#194）は変えていない
- refresh_token の問い合わせでは、作り直す access_token の期限を、検証の間は持つ長さにした。
  その一時的なトークンの `exp` / `nbf` / `iat` / `jti` は refresh_token 自身の値ではないので、返さない
- `token` が無い要求は `invalid_request`（以前は `token_type_hint` だけでも先へ進んでいた）

E2E テスト: `EX-2.4` / `EX-2.5` / `EX-2.6`（ヒントの取り違え）/ `EX-3.2` / `EX-3.4` / `EX-3.7`（同）。

**対応（#218 の 2 つ目）: `/introspect` の `token_type`。**

「見つかった種類」（`access_token` / `refresh_token`）を入れていたが、
RFC 7662 §2.2 の `token_type` は **RFC 6749 §5.1 の型**（`bearer` など）を指す。

- **アクセス トークンには `bearer`** を返す。値はトークン応答（`CreateAccessTokenResponse`）と揃える
- **リフレッシュ トークンには付けない。** §5.1 の型が無いため（RFC 7662 §2.2 の `token_type` は OPTIONAL）
- E2E テスト : `EX-3.7` を**観測から検証に格上げ**（`bearer` が返る。大小文字は問わない）。
  `EX-3.2`（リフレッシュ トークン）には「返らない」ことを観測として残した

> **残っている点:**
> エラー応答の HTTP ステータス（400 / 401）は #196 で対応した（`/revoke`・`/introspect` とも）。
> メタデータは Claim の値をそのまま入れているため、`exp` / `iat` なども文字列で返る。

### A-12. `max_age` を超えたときに、再認証もエラー応答もせず、空のエラー画面になる **[Core][netfx]** — **✅ 修正済み（#247）**

```csharp
// AccountController.OAuth2Authorize（両アプリに同文）
if (this.CheckAuthTime(max_age)) {
    if (Token.CmnEndpoints.ValidateAuthZReqParam(...)) { ... }
    else { /* 不正なRequest */ }
}
else
{
    // 不正なRequest        ← ここに何も無い
}

// ここまで来たらエラー。
if (!string.IsNullOrEmpty(valid_redirect_uri)) { /* redirect_uri へ error を返す */ }
else { ViewData["Err"] = err; return View("Error"); }   ← err は空のまま
```

`CheckAuthTime` は、次のいずれでも `false` を返す。

- `auth_time` の Cookie が無い
- 前回の認証からの経過が `max_age` を超えている
- **`max_age` が数値でない**

`false` になると `ValidateAuthZReqParam` を通らないため **`valid_redirect_uri` が空**で、
**`err` も空のまま**「ここまで来たらエラー」に落ちる。
結果は **文面の無いエラー画面**である（#246 の自己テストで `max_age=60` を選んで実測）。

**仕様が求めているもの。**

| 状況 | あるべき応答 | 根拠 |
|---|---|---|
| `max_age` を超えている | **利用者を再認証する**（サインインさせ、`auth_time` を更新して続ける） | OIDC Core §3.1.2.1（`max_age`）／§2（`auth_time`） |
| 再認証が必要だが `prompt=none` | `redirect_uri` へ **`login_required`** | OIDC Core §3.1.2.6 |
| **そもそも未サインイン**だが `prompt=none` | `redirect_uri` へ **`login_required`**（**UI を出さない**） | OIDC Core §3.1.2.1 / §3.1.2.6 |
| `max_age` が数値でない | `redirect_uri` へ **`invalid_request`** | RFC 6749 §4.1.2.1 |

いずれも**エラー画面ではなく、`redirect_uri` へ返す**のが仕様である（A-6 と同じ筋）。

**同族の項目:** `prompt` の処理そのものは C-3、同意の永続化は D-6。
`auth_time` は `AddAuthTimeClaim` で ID トークンに入れており、**読み書きの土台はある。**

**対応（#247）。**

- **検証の順序を入れ替えた。** 先に `ValidateAuthZReqParam` を通し、`redirect_uri` を確定させてから
  `max_age` を見る。**これでエラーを RP へ返せる**
- 判定を `CommonLibrary`（`CmnEndpoints.CheckAuthTime`）へ移し、**bool から 3 値**にした
  （`Ok` / `InvalidMaxAge` / `NeedsReAuthentication`）。**bool では区別できなかった**のが原因
- `NeedsReAuthentication` のとき : `prompt=none` なら **`login_required`**、
  そうでなければ**サインアウトして同じ URL に戻す**（＝再認証）
- `InvalidMaxAge`（数値でない・負）は **`invalid_request`**
- **経過は「秒」で比べる（切り捨て）。これが要だった。**
  `auth_time` も `max_age` も秒単位なので、**秒未満の差を超過とみなさない。**
  小数のまま比べると、**再認証した直後でも「0.3 秒 > 0 秒」で超過**となり、
  `max_age=0` では何度でも再認証を求めることになる
- **繰り返しを防ぐ印**（`re_auth_at` の Cookie。10 分）は、**収束しない場合の保険**として残す。
  通ったら消す
- E2E : `RT-247.1`（再認証へ送る・**繰り返さない**・自己テストの 2 つのボタン）/
  `RT-247.2`（`login_required`）/ `RT-247.3`（`invalid_request`）。
  **テストはサインインから 1 秒以上ずらして測る**（速すぎると同じ秒に入り、超過にならない）

**対応（#254）— 未サインインの場合。**

**#247 が扱ったのは「セッションは在るが古い」場合だけだった。**
**「セッションが無い」場合は、`[Authorize]` が認可エンドポイントのコードに入る前に
サインイン画面へ飛ばしており、`prompt` を見る機会が無かった。**

- **認可エンドポイント（GET）を `[AllowAnonymous]` にし、未認証のときの扱いを自分で決める。**
  `prompt=none` なら **`login_required`**、そうでなければ
  **`ChallengeResult`（net48 は `HttpUnauthorizedResult`）**＝ `[Authorize]` と同じ動き
- **判定は `ValidateAuthZReqParam` より後に置く。**
  **`redirect_uri` を照合する前に RP へ返すと、オープン リダイレクトになる**
- E2E : `RT-247.4`（未サインイン ＋ `prompt=none` → `redirect_uri` へ `login_required`）

> **ここに 3 回作り直した跡がある。** 記録として残す。
> **(1) 印の新しさ（300 秒）だけを見る** → 手の操作が 5 分を超えると古い印と見なし、**二度サインイン**。
> **(2) 「数秒前の認証なら通す」猶予** → `max_age=0` の意味が消える（仕様に反する）ので取り消し。
> **(3) 印 ＋ 印より後に認証** → ブラウザではまだ二度。
> **(4) 経過を秒単位で比較** → 印に依存せず成立（採用）。
> **秒単位の値（`auth_time`）を小数で比べたことが、症状の根**だった。

> **副産物。** net10.0 版の「別のアカウントでログイン」（同意画面の `submit.Login`）は、
> `HttpContext.SignOutAsync()`（スキーム指定なし）で**サインアウトできていなかった**。
> このサイトが使うのは `Identity.Application` で、既定のスキームでは消えない。
> **`SignInManager.SignOutAsync()` に直した**（net48 版はスキームを指定していたため無症状）。

---

### A-13. `refresh_token` で更新すると、登録種別のクレーム（`fapi`）が消える **[Lib]** — **✅ 修正済み（#245）**

```csharp
// CmnEndpoints.GrantRefreshTokenCredentials
if (CmnEndpoints.CheckClientMode(client_id, Flow.RefreshToken, proof,
        out OAuth2AndOIDCEnum.ClientMode _,      // ← 登録種別を捨てていた
        out jwkString, out err))
...
string access_token = CmnAccessToken.ProtectFromPayload(
    client_id, tokenPayload, …, x509,
    OAuth2AndOIDCEnum.ClientMode.normal,          // ← 固定
    out string aud, out string sub);
```

**認可コードで得たトークンには `fapi` クレームが載るのに、更新すると消えていた。**
`fapi` で判断するリソース サーバは、**更新の前後で違うトークンを受け取る**
（`cnf` は残るので、証明書との紐づけは保たれる）。

**#239 の段階 3 で `refresh_token` を fapi1 / fapi2 に開くまでは、normal しか通らなかったので無害だった。**
開いたときの取り残しである。

**対応（#245 の段階 1）。** `CheckClientMode` が既に返している登録種別を受け取り、
`ProtectFromPayload` に渡す（隣の認可コードの経路と同じ形）。
**E2E : `FA-6.5`（mTLS）/ `RT-239.5`（private_key_jwt）** が、更新後も `fapi` が載ることを検証する。

> **見つけ方に意味がある。** #245 の段階 1 で
> **`ClientModePolicy` の表の 16 行に E2E を突き合わせ、空いていた 1 行
> （`refresh_token × mTLS`）を埋めた**ところで出た。
> **網羅の穴と実装の穴が同じ場所にあった。**

### A-14. `subject_types=pairwise` のクライアントに、`sub` 以外を返せていなかった **[Lib]** — **✅ 修正済み（#140 の段階 2）**

**PPID（pairwise の `sub`）が salted hash で、一方向だった。**

```
sub = BASE64URL( SHA-256( client_id + user_id + salt ) )
```

**OP 自身も戻せないため、`PPIDExtension.GetUserFromSub` が `pairwise` で `null` を返していた**
（コード中のコメントは「取りようが無いので...。」）。その結果 —

| 口 | `pairwise` のときの挙動 |
|---|---|
| `/userinfo` | **`sub` だけを返し、`profile` / `email` / `address` のクレームが空**（`user != null` の中だけで詰めているため） |
| `ciba_result` | **401 / `invalid_token`** |
| `SetDeviceToken` | 利用者を引けない |
| オペレーション ログ | 利用者名が **`PPID: …`** のままで読めない |
| `id_token_hint` からの利用者特定（#232） | 成立しない |

**つまり `pairwise` は、選べるが機能しない状態だった。**

**対応（#140 の段階 2）。** **PPID を「OP だけが戻せる暗号化」に変えた。**

- **pairwise に求められるのは「OP 以外が戻せないこと」**であり、**一方向であることではない。**
  **OP だけが鍵を持つ暗号化は、その条件を満たす**
- **決定的**でなければならない（RP は `sub` を利用者の主キーとして保存するため、
  同じ利用者・同じクライアントなら常に同じ値）。**鍵と IV を秘密と `client_id` から導出**して実現
- **クライアントごとに変わる**（`client_id` を鍵材料に入れている）
- 実装は `Util/PPIDExtension`（AES-CBC）。**対応表（新しいテーブル）を作らずに済む**ので、
  **DDL の 3 方言と、既存データベースへの移行が要らない**
- E2E テスト : **`RT-140.2`**（`pairwise` でも `/userinfo` がクレームを返す）、
  **`RT-140.3`**（毎回同じ値になり、クライアントが違えば違う値になる）。
  **`subject_types=pairwise` のクライアント（`TestClient_5`）は種データが作る**（#264）

> **制約 : 秘密（`SaltParameter`）を替えると、発行済みの PPID が全部変わる。**
> **RP は `sub` を主キーとして保存している**ので、**RP 側では全員が別人になる。**
>
> **これは以前の salted hash でも同じ**で、この変更で悪化してはいない。
> **効くのは漏洩時である。** 秘密を替えなければならないのに、替えると RP が壊れる。
>
> **✅ この宿題は #151 の段階 2 で片付いた。**
> **発行した `sub` を対応表（`SubjectIdentifier`）に記録する**ようにしたので、
> **秘密を替えても、発行済みの値は動かない**（表から引くため）。詳細は下記。

### A-15. トークン エンドポイントと照会・広告に、取りこぼしが残っていた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**`CmnEndpoints.*.cs`（分割した後）のレビューで見つけた。** どれも「動くが、返すべきものを返していない」形である。

| 口 | 修正前 | 修正後 |
|---|---|---|
| **Device グラントの `/token`** | **refresh_token を作って保存するだけで、応答に入れていなかった**（使われない行が溜まる） | **返す**（device の登録には、従来どおり発行しない） |
| **`client_registration` 専用トークンの `expires_in`** | **配備ぜんたいの期限（既定 360 分）を返していた**（実際の期限は既定 300 秒） | **実際に付けた期限を返す**（`CreateAccessTokenResponse` の `expiresIn`） |
| **`/introspect` の `cnf`** | **DPoP の `jkt` を返していなかった**（mTLS の `x5t#S256` だけ。`urn:oauth:` の絞り込みで落ちていた） | **`cnf` を 1 つのオブジェクトにまとめ、`jkt` も入れる**（RFC 9449 §6.2） |
| **CIBA の `/token`** | **`client_assertion` を読まなかった**（`/ciba_authz` は読む。FAPI-CIBA は private_key_jwt か mTLS を求める） | **`ClientAuthentication` の、どの方式でも受ける版を使う** |
| **CIBA の知らない `auth_req_id`** | **内部の状態名（`not_found` / `irregularity_data`）を `error` に入れていた** | **`invalid_grant`**（Device グラントは #199 で直してあった） |
| **JWT Bearer が無効のとき** | **`error` を入れずに返していた** | **`unsupported_grant_type`** |
| **Discovery** | **revoke / introspect の認証方法を、秘密の 2 つしか広告していなかった**（#239 から 4 つとも通る）。**`request_object_signing_alg_values_supported` を値で直に書いていた** | **`TokenEndpointAuthMethods` / `RequestObjectSigningAlgs` から作る** |

**E2E** : **`RT-294.41`**（Device の refresh_token）、**`RT-307.5`**（`expires_in`）、**`RT-294.42`**（`cnf.jkt`）、
**`RT-294.43`**（CIBA を private_key_jwt で通す）、**`RT-294.44`**（`invalid_grant`）、**`RT-294.49`**（Discovery）。

### A-16. 標準のクライアントが通らない・同意の後で失敗する経路が残っていた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**`CmnEndpoints.*.cs` の 2 回目のレビューで見つけた。**

| | 修正前 | 修正後 |
|---|---|---|
| **N1 : PKCE と private_key_jwt / mTLS の併用** | **`code_verifier` が在ると `client_assertion` と証明書を見ず、PKCE だけで認証した** → **証明が PKCE になり、fapi2（FAPI 2.0 は PKCE と鍵か証明書の両方を求める）が通らなかった**。`RequirePkce` を有効にすると、鍵・証明書のクライアントは全く通らなかった | **まず資格情報で認証し、PKCE は別に検証する**（証明は PrivateKeyJwt / Mtls） |
| **N3 : `response_type=id_token`** | **Implicit を閉じても検査を通り、同意の後で `server_error`** | **`unsupported_response_type`**（Implicit の経路として扱う） |
| **N4 : `client_assertion` の `aud`** | **トークン エンドポイントの URL だけ**（FAPI 2.0 は issuer も受けることを求める）。**配列は上流が例外を投げて 500** | **issuer も受ける。** **配列は 500 にせず `invalid_client`**（上流の `JwtAssertion.Verify` が文字列として読むため、受けるには上流の対応が要る） |
| **N5 : poll の CIBA** | **`client_notification_token`（ping / push のときだけ REQUIRED）と `binding_message`（OPTIONAL）を必須にしていた** | **省略できる**（`/ros` は前者の有無で CIBA を見分けるので、`request_uri` の経路では在ることになる） |
| **N6 : Device グラントの登録種別** | **`device` を固定で書いていた**（normal の登録のトークンも `device` を名乗った） | **登録された種別で書く**（#220 と同じ） |
| **登録の `grant_types` と Implicit / Hybrid** | **認可エンドポイントで見ず、同意の後で `server_error`** | **認可エンドポイントで発行する経路（`implicit`）は、同意の前に `unauthorized_client`**。**code は従来どおり `/token` で見る**（#307 の段階 1 の決め。`RT-307.7`） |
| **Discovery** | **CIBA を、`EnableCibaGrantType` を見ずに広告していた。** `token_endpoint_auth_signing_alg_values_supported` を値で直に書いていた | **開けた配備だけ広告する。** **一覧から作る。** **`token_endpoint_auth_methods_supported` に `none` を足し、revoke / introspect の一覧からは除いた**（認証を要する口のため） |

**E2E** : **`RT-294.51`**（N1）、**`RT-314.4`**（N3。`-NoImplicit`）、**`RT-294.54`**（N4）、**`RT-294.56`**（N5）、**`RT-294.41`**（N6）、**`RT-294.55`**（grant_types）、**`RT-294.49`**（Discovery）。

### A-17. 合わない `code_verifier` を `invalid_client` で返していた **[Lib]** — **✅ 修正済み（#294）**

**`GrantAuthorizationCodeCredentials` は、PKCE の検証に落ちると、クライアント認証の失敗と同じ `invalid_client` を返していた。**
**RFC 7636 §4.6 は `invalid_grant` とする。** **クライアントは「資格情報が違う」のか「`code_verifier` が違う」のかを区別できなかった。**
（PKCE だけの経路は以前から、資格情報との併用は A-16 の N1 で広げた経路が、どちらもそうなっていた）

**PKCE の検証に落ちたことを別に持ち、`invalid_grant` で返す**ようにした。**資格情報の誤りは、従来どおり `invalid_client`。**

**E2E** : **`RT-294.58`**（PKCE だけ・`client_secret` ＋ PKCE とも `invalid_grant`、秘密が違えば `invalid_client`）、**`RT-294.51`**（private_key_jwt ＋ PKCE でも `invalid_grant`）。

### `sub` の対応表（`SubjectIdentifier`）**[Lib]** — **✅ 実装（#151 の段階 2）**

**`sub` が「導出」から「データ」になった。**

```
以前 : sub = f(subject_types, client_id, user_id, salt)   ← 式を変えると値が変わる
いま : sub = 表から引く。無ければ作って入れる              ← 式を変えても既存の値は動かない
```

**RP は `sub` を利用者の主キーとして保存する。**
値が変わると **RP 側では全員が別人になる**ので、そこを切り離した。

| 表 | `SubjectIdentifier` |
|---|---|
| 主キー | **`(Sector, UserId)`** |
| 逆引き | **`(Sector, Sub)` に一意索引**（同じ Sector で 2 人が同じ `sub` を持ってはいけない） |
| 後始末 | **外部キー（`ON DELETE CASCADE`）**。`mem` は `SubjectIdProvider.DeleteByUserId` |

- **`pairwise` 専用ではない。** `uname` / `public` の `sub` も入れる
  （そうしないと、`subject_types` の既定値の変更を無害にできない）
- **`Sector` は、いまは `client_id`。** `sector_identifier_uri`（OIDC Core §8.1）に対応したら
  その解決結果が入る。**列の意味は「Sector Identifier」**なので、**対応しても既存行は有効**である。
  変えるのは `PPIDExtension.GetSector` の 1 箇所だけ
- **引く順** … **まず表**（設定に関わらず引ける）→ 無ければ `subject_types` で引く
  （表を入れる前に発行した `sub` のため）

**これで解ける問題。**

| | |
|---|---|
| **#151** | **`subject_types` の既定を変えても、既存の RP が壊れない** |
| **D-9-2** | **PPID の秘密を、漏洩時に替えられる** |

### `subject_types` の既定を `public` に **[Lib]** — **✅ 実施（#151 の段階 4）**

**既定を `uname`（独自値）から `public` に変えた。**

**`uname` を落としたい理由は「独自値だから」より「`sub` に利用者名が入るから」である。**
以前は「利用者名＝メアド」だったので、**`sub` としてメアドが全ての RP に渡っていた。**
**`sub` は「その RP の中で利用者を指す識別子」**であって、表示用の属性ではない。

| 変えたところ | |
|---|---|
| `Helper.GetSubjectTypes` | **登録に `subject_types` が無いときの戻り値**（2 箇所。構成ファイルと画面登録） |
| `CmnEndpoints`（Discovery） | `subject_types_supported` の**並びを `public` 先頭**に（**`uname` は残す**） |
| `ManageAddSaml2OAuth2DataViewModel` | **選択肢の先頭を `public`** に（＝ 画面の既定）。`uname` に `(deprecated)` を付けた |
| 雛形（`app.config` / `appsettings.json`） | `TestClient` の `"subject_types": "uname"` を**消した**（＝ 既定に従う） |
| `AccountController`（ID 連携） | **新規作成の利用者名を `preferred_username` から取る**（下記） |

**既存の `sub` は動かない。** 段階 2 の対応表が効くため（上記）。
**効くのは、まだ `sub` を発行していない（クライアント × 利用者）だけ**である。

> **ID 連携の下流で、利用者名の出所が変わった。**
> **以前は上流の `sub` を利用者名として使っていた**（`uname` だったから成り立っていた）。
> **既定が `public` になると `sub` は利用者 ID** なので、
> **`preferred_username` → メアドの `@` より前**の順にした。
> **`sub` は見ない**（**下位互換は維持しないと決めてある**ので、`uname` の上流は考慮しない）。
> **結び付ける鍵はメアド**なので、**どちらになっても同じ利用者に結び付く。**

**踏んだ不具合が 2 つある。どちらも「`sub` が利用者名である」ことに依存していた。**

| | |
|---|---|
| **CIBA / Device AuthZ が HTTP 500** | **認可コードの `identity.Name` に `sub` を入れていた。** `identity.Name` は**利用者名として**扱われる（`CmnAccessToken` が、そこから改めて `sub` を作る）。`uname` では同じ値だったので成り立っていた。**利用者名を入れるように直した** |
| `Helper.GetClientIdByName` が NRE | **クライアント名でも利用者名でもない値**（`sub`）を渡されると `FindByName` が null を返し、**`user.ClientID` で落ちていた**（B 群と同じ性質）。**見つからなければ `""` を返す**ようにした |

**測り方には注意が要る。** `RT-151.1` / `RT-151.2` は**新しい `client_id`**（`TestClient_6` / `TestClient_7`）で測る。
**使い回した `client_id` では、対応表から以前の値が返る**ので、既定の変更が見えない
（`root/TESTING.md` 5 節）。

### 独自値 `uname` の廃止 **[Lib]** — **✅ 実施（#151 の段階 5）**

**`subject_types` は `public` と `pairwise` の 2 つ**（どちらも OIDC Core §8 の登録値）になった。

| 消したところ | |
|---|---|
| `PPIDExtension` | **`GetSubForOIDC` / `GetUserFromSub` の 3 分岐を 2 分岐に**（`pairwise` 以外は `public`） |
| `CmnEndpoints`（Discovery） | `subject_types_supported` を **2 つ**に |
| `ManageAddSaml2OAuth2DataViewModel` | 選択肢を **2 つ**に |
| 雛形（`app.config` / `appsettings.json`） | 選択肢の説明から独自値を削除 |
| `ManageController`（両アプリ） | **`AddEmail`（GET/POST）と `RemoveEmail` を削除**（段階 3 で引退させたもの）。状態メッセージの列挙体と対応付けも削除 |
| ビュー | **`Views/Manage/AddEmail.cshtml` を削除**（net48 は `.csproj` の `Content` も） |
| リソース | `ManageViews` の 5 件（`AddEmail*` / `IndexEmailAddActionLink` / `IndexEmailRemoveButton`）と `ManageController` の 3 件（`AddEmail*` / `RemoveEmailSuccess`）を削除 |

> **設定に独自値が残っていても、エラーにはしない。**
> **`pairwise` 以外は `public` として扱う**ので、`public` と同じ振る舞いになる
> （**下位互換は維持しないと決めてある**ため、値の読み替えや警告は入れない）。
>
> **コードとコメントから独自値の名前を落とした**（履歴は MD 側に残す）。

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

### B-8. JWT でない値で HTTP 500 になっていた **[Lib]** — **✅ 修正済み（#241）**

**公開鍵は payload の `iss` で引く**ので、**署名検証の前に payload を読む**ことになる。
そこに外から来た壊れた値を渡されると、処理されない例外で **HTTP 500**（JSON でない本文）になっていた。

| 場所 | 壊れ方 |
|---|---|
| `/ros`（`RegisterRequestObject`） | `Split('.')[1]` が IndexOutOfRange / Base64URL の復号で FormatException / `JObject` が null |
| `client_assertion` の検証（`ClientAuthentication`） | 同上 ＋ **`iss` が無いと辞書の参照で例外** |
| 公開鍵の復号（両方） | **空かどうかを確かめる前に復号**していたため、**未登録のクライアント**で NullReferenceException |

**`client_assertion` は #238 / #239 で受け口が増えていた**ので
（`/token` の各グラント・`/par`・`/ciba_authz`・`/revoke`・`/introspect`）、
**どの口からでも 500 に落とせる**状態だった。**実測で 5 パターンすべて 500**（両アプリ）。

**対応 :** 解析を 1 か所にまとめた。

| | 内容 |
|---|---|
| `CmnEndpoints.TryReadJwtPayload` | JWT でなければ **null**（例外にしない）。**`JObject` で読む**（`Dictionary<string, string>` だと入れ子のクレームで失敗する） |
| `CmnEndpoints.DecodeRegisteredJwk` | 登録値が空・壊れていれば **空文字**（復号は空でないと確かめた後） |

`/ros` は **400**、`client_assertion` は**アサーション無しとして扱い 401（`invalid_client`）**。
後者は、`client_assertion_type` が誤りのときと同じ扱い（#238）。

**先に書いた 2 箇所は、もともと落としていた**（`ReceiveCibaRequest` は `try`/`catch` で 400、
`PushedAuthorizationRequest` は payload を自分で読まない）。**未対処だったのは古い 2 箇所**である。

E2E : `RT-241.1`（`/ros`）/ `RT-241.2`（`client_assertion`）/ `RT-241.3`（`iss` 無し・未登録）

### B-9. 利用者が引けないメアド検証・パスワード リセットで HTTP 500 になっていた **[Core][NetFx]** — **✅ 修正済み（#294）**

**メールのリンク（`/Account/EmailConfirmation`・`/Account/ResetPassword`）は、利用者が消えた後にも踏まれる**（古いメール・書き換えた URL）。
**`AccountController.SignUp`（両版）は、`FindByIdAsync` で引けなかった利用者（null）を、そのまま Identity に渡していた。**

| 口 | 修正前 |
|---|---|
| `EmailConfirmation`（GET。約款を出さない配備） | `ConfirmEmailAsync(null, …)` が例外 |
| `EmailConfirmation`（POST。約款に同意） | 同上 |
| `ResetPassword`（GET） | `user.Id` で `NullReferenceException` |
| `ResetPassword`（POST） | `ResetPasswordAsync(null, …)` が例外 |

**4 か所とも、利用者が居なければエラー画面を返す**ようにした。

**E2E** : **`RT-294.6`**（4 か所とも 200 のエラー画面）。

### B-10. 自己テストの受け口が、始めていない要求の JARM で HTTP 500 になっていた **[Core][NetFx]** — **✅ 修正済み（#294）**

**自己テストの受け口**（`OAuth2AuthorizationCodeGrantClient`・`OAuth2ImplicitGrantClient`。`AccountController.SelfTest` の両版）は、
**JARM（`response`）を、その回の `client_id`（Session・Cookie に置いたもの）を `aud` にして検証する。**
**自己テストを始めていない要求では `client_id` が空で、`ResponseObject.Verify` が `ArgumentNullException('aud')` を投げた。**

| | 修正前 |
|---|---|
| net10.0 版 | **HTTP 500** |
| net48 版 | **HTTP 302**（例外の処理へ回された） |

**`client_id` が無い・検証が例外を投げるときは「検証できない」として扱い、エラー画面を返す**ようにした（`VerifyTestResponseObject`。2 か所 × 両版）。
**例外の中身は、記録に残す。** **検証できない応答の値を使わないのは、以前のとおり**（#294 の B7）。

> **E2E の拡充（カバレッジで通っていない所を叩いた）で見つかった。** 自己テストの口は `IsLockedDownTestEndpoints` で閉じられる、テスト用の口である。

**E2E** : **`RT-294.39`**（両版。2 つの受け口とも 200 のエラー画面）。

### B-11. 外から来た値・登録の値を確かめずに読み、HTTP 500 になっていた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**#241 で他の口は直してあったが、次は取り残されていた**（`CmnEndpoints.*.cs` のレビューで見つけた）。

| 口 | 500 になった入力 |
|---|---|
| **JWT Bearer グラント**（`GrantJwtBearerTokenCredentials`） | **JWT でない assertion**（`Split('.')[1]`）、**`iss` が文字列でない**（`Dictionary<string, string>` への逆直列化）、**登録の無い鍵**（null の復号） |
| **scope を省いたトークン要求**（client_credentials / password / JWT Bearer） | **null の `Split`**（scope は OPTIONAL。RFC 6749 §4.3.2 / §4.4.2） |
| **CIBA の `request`**（`ReceiveCibaRequest`） | **payload がオブジェクトでない・`iss` が文字列でない JWT**（Base64URL の復号だけを守っていた） |
| **CIBA の `/ciba_authz` を private_key_jwt で** | **フォームに `client_id` が無い**ので、**空の `client_id` で code を作ろうとした**（両版の Controller） |
| **PAR の `request`・fapi2 の登録・`/ros` の `iss`** | **登録の鍵の列が NULL・壊れている**、**`iss` が文字列でない**（読んで直した。E2E では作れない） |

**外から来た JWT のクレームは `StringClaimOf` で読み、登録の鍵は `DecodeRegisteredJwk` で読む**ようにそろえた。
**CIBA の Controller は、`client_id` を要求の `iss`（認証したクライアントと照合済み）から取る。**
**JWT Bearer は、ヘッダの alg が受ける集合（`JwtBearerSigningAlgs`。RS256）にあることも見る**
（`JwtAssertion.Verify` は JWK の `kty` で検証器を選び、名乗りを見ない）。

**E2E** : **`RT-294.45`**（JWT Bearer）、**`RT-294.46`**（scope の省略）、**`RT-294.47`**（CIBA の `request`）、**`RT-294.43`**（private_key_jwt の `/ciba_authz`）。

### B-12. scope を省いた認可要求と、配列の `aud` の assertion で HTTP 500 になっていた **[Lib]** — **✅ 修正済み（#294）**

| 口 | 500 になった入力 |
|---|---|
| **認可エンドポイント**（`ValidateAuthZReqParam`） | **scope を省いた要求**（null の `Split`。scope は RFC 6749 §3.3 で省略できる） |
| **`client_assertion` / JWT Bearer の `assertion`** | **`aud` が配列**（上流の `JwtAssertion.Verify` が文字列として読み、例外を投げた） |

**scope は空として扱い、assertion の検証は例外を失敗として扱う**（`TryVerifyAssertion`）ようにした。

**E2E** : **`RT-294.53`**（scope の省略）、**`RT-294.54`**（配列の `aud`）。

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
`client_mode: device` の `ae5a1798…`（TestClient3）**だけが `client_secret` を持たない**。
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

> その後、#200 で `/revoke`・`/introspect` の本体を `CmnEndpoints.RevokeToken` / `IntrospectToken` に移したので、
> この 2 つは現在、その中からだけ呼ぶ private 関数になっている。

| エンドポイント | 所有者が違う場合 |
|---|---|
| `/revoke` | `invalid_grant` を返す（RFC 7009 §2.1 が検証を要求） |
| `/introspect` | **`{"active": false}` を返す**（RFC 7662 §2.2 / §5。エラーにするとトークンの存否を漏らす） |

`/introspect` の `active` が **`"true"` という文字列**だったのも真偽値に直した
（A-3 / A-4 と同じ defect だが #184 では未列挙だった分）。

### C-3. `prompt=none` が同意画面を無条件にスキップする **[Lib][Core][NetFx]** — **✅ 修正済み（#272）**

> **`[Core]` と書いていたが、誤り。** **同じコードが net48 版にもある。**
> 判定を `CommonLibrary` へ寄せたので、いまは `[Lib]` でもある。

```csharp
// 直す前（両アプリに同じコードがあった）
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

**段階 1 は片付いた（#272）** — **`prompt` の照合を集合に寄せた。**

**同じ要求の中で、照合規則が 2 つ混在していた。**

| 書き方 | 問題 |
|---|---|
| `prompt.ToLower().Contains("none")`（#247 / #254 で入れた側） | **部分文字列**なので、**`prompt=nonexistent` でも `none` 扱い** |
| `prompt.ToLower() == "none"`（同意スキップの側） | **完全一致**なので、**`prompt=none login` で `none` 扱いにならない** |

その結果、**`prompt=none login` は「`login_required` の判定では none 扱い、
同意画面の判定では none でない」**という状態になっていた。

- **`CmnEndpoints.SplitPrompt` / `HasPrompt` / `CheckPrompt` に寄せた**
  （#267 の `NormalizeResponseType` と同じ流儀。**大文字小文字の寛容さも残す**）
- **`none` の併記は `invalid_request`**（§3.1.2.1 :
  「If this parameter contains none with any other value, an error is returned.」）。
  **これを入れないと、集合に揃えたことで振る舞いが悪くなる** —
  以前は同意画面を出していたが、**同意を飛ばして code を発行する**ことになる
- **判定は `redirect_uri` を確かめた後**（`ValidateAuthZReqParamCore`）。
  **でないとエラーを RP へ返せない**（#187 / #247 と同じ理由）
- **PAR（`/par`）にも掛かる**（RFC 9126 §2.1 が「認可エンドポイントと同じ検証」を求めるため）
- **E2E** : **`RT-272.1`**（`none` の併記で `invalid_request`）/
  **`RT-272.2`**（`none` 単体は従来どおり）/
  **`RT-272.3`**（`nonexistent` を `none` 扱いにしない。**同意画面で止まるか**で見る）。
  **旧挙動に戻すと `RT-272.1` と `RT-272.3` が落ちることを確かめてある**

**段階 2（同意の永続化。D-6）も片付いた（#272）** — **`ConsentGrant` 表を持った。**

| 状況 | いまの振る舞い |
|---|---|
| 要求 scope が記録の部分集合 | **同意画面を飛ばす** |
| 記録が無い ＋ `prompt=none` | **`consent_required`**（§3.1.2.6）。**これが C-3 そのもの** |
| 記録が無い | 同意画面を出し、**許可で記録する**（scope は足し込む） |
| `prompt=consent` | **記録が在っても出す** |
| `prompt=select_account` | **出す**（画面に「別のアカウントでログイン」が在る） |
| `prompt=login` | **再認証する**（`max_age` の再認証と同じ経路。印で繰り返しを防ぐ） |

- **置き場** : `ConsentGrant`（`UserId` / `ClientID` の PK、`Scopes`、`CreatedDate`、`UpdatedDate`）。
  **DDL 3 方言**。**`Users.Id` への FK（`ON DELETE CASCADE`）**なので、
  **利用者を消せば同意も消える**
- **粒度は（利用者, クライアント）で 1 行**。**scope は集合として足し込む**
  （並びは辞書順に正規化して持つ。**"openid email" と "email openid" を別物にしない**）
- **管理画面から取り消せる**（`/Manage/ConsentGrants`）。
  **記録するなら、取り消せなければならない**。
  **発行済みのトークンは失効しない**（そちらは `/revoke`。RFC 7009）
- **設定キーは置いていない。** **常に仕様どおり**である
  （「記録が無いときは従来どおり通す」逃げ道を作らないという判断）
- **E2E** : `RT-272.4`（記録が無ければ `consent_required`）/
  `RT-272.5`（`prompt=consent`）/ `RT-272.6`（拒否 → `access_denied`）/
  `RT-272.7`（管理画面からの取り消し）
- **自己テスト画面も直した。** **OIDC のボタンが `prompt=none` を固定で付けていた**ので、
  **記録が無い配備では初回に必ず `consent_required`** になる。
  **固定を外した**ので、**初回だけ同意画面を通る**（2 回目以降は記録が効いて飛ぶ）。
  `prompt` を試したいときは**画面の選択**で指定する（#246 の項目 3）
- **E2E（続き）** : `RT-272.8`（**`prompt=login`**。再認証を求め、
  **印（`re_auth_at`）で繰り返しにならない**ことまで見る）/
  `RT-272.9`（**`prompt=select_account`**。同意画面を出し、
  **その画面に「別のアカウントでログイン」が在る**ことを見る）
- **測っていないもの** : **アカウントの一覧から選ぶ仕組み**。
  **この実装は 1 利用者ずつのサインインしか持たない**ので、
  `select_account` は**同意画面を出すところまで**である
  （**`account_selection_required` を返す道もあった**が、切り替えの口が画面に在るので、画面を出す方を選んだ）

**あわせて E-6（認可画面の Deny ボタン）も入れた。**
**同意を記録するなら、拒否もできなければ筋が通らない。**
**拒否は記録しない**（「拒否した」を覚えて次回以降自動で断ると、
**利用者が気を変えられなくなる**）。

> **Implicit の経路には同意画面が無い（以前から）。**
> 同意の判定を入れたのは **`response_type=code` の経路だけ**である。
> **Implicit は既定で無効**（#220）で、OAuth 2.1 でも廃止されているため。

### C-4. 認可コードに有効期限が無い **[Lib]** — **✅ 修正済み（#188）**

**直す前。** `AuthenticationCodeDictionary` に `CreatedDate` を書いているが、
**どこからも読んでいなかった。** `Receive` は経過時間を見ずに payload を返していた。
RFC 6749 §4.1.2 は「短命であること（推奨 10 分以内）」を求めている。

Memory Provider の `ConcurrentDictionary` も未使用の code を回収しないため、
**メモリ リークになっていた**（DBMS 側も行が残り続けた）。

**直し方**（`AuthorizationCodeProvider`。コミット `b7fd215`）。

```csharp
private static DateTime ExpireLimit
{
    get { return DateTime.Now - Config.OAuth2AuthorizationCodeExpireTimeSpanFromSeconds; }
}
```

- **`Receive` が経過時間を見る**（`entry.CreatedDate < ExpireLimit` なら返さない）
- **DBMS 側は `WHERE [Key] = @Key AND [CreatedDate] > @Limit`** で、期限切れを引かない
- **回収も入れた。** `mem` は辞書を掃き、DBMS は `DELETE ... WHERE [CreatedDate] <= @Limit`
  （`sqlserver` / `oracle` / `pstgrs` の 3 方言）
- **期限は設定で決まる**（`OAuth2AuthorizationCodeExpireTimeSpanFromSeconds`。既定 600 秒）
- **E2E** : **`RT-188`**（`test.ps1 -ShortLifetimes` で寿命を縮めて測る。`TESTING.md` 5 節）
- **利用者への影響** : **無し**（既定の 600 秒は RFC の推奨内。**それより長く待つ RP が在れば影響する**）

### C-5. refresh_token に有効期限も再利用検知も無い **[Lib]** — **✅ 修正済み（#188）**

**有効期限は、#188 の段階 1 で実際に検証するようにした**（`RT-188`）。
認可コード（新しい設定キー。既定 600 秒）・Request Object（同。既定 300 秒）・
refresh_token（既存の `OAuth2RefreshTokenExpireTimeSpanFromDays`。既定 14 日）の 3 つで、
**期限切れは「無いもの」と同じ扱い**（存在しない code / token と同じ経路に合流する）。

- メモリ ストアは作成時刻を持っていなかったので、値と作成時刻の組に変えた
- DBMS は `CreatedDate` を書くだけで読んでいなかったので、**SELECT の条件に入れた**（3 方言とも）
- **期限切れは、参照した時点で消す**（メモリ ストア。DBMS は使用時の DELETE で消える）
- `/ros` の応答の `exp`（以前は空文字）に、期限を入れるようにした

**再利用の検知と、一族ごとの失効（#188 の段階 3）**

以前は「使ったら行を消す」方式だったので、**使用済みだったのか、元から無いのかを区別できなかった。**
いまは消さずに印を付け、**使用済みが再び提示されたら、その一族をまとめて失効させる。**

| 列（`RefreshTokenDictionary`。3 方言とも追加） | 意味 |
|---|---|
| `FamilyId` | **1 回の認可から派生した refresh_token のまとまり**（GUID）。最初の発行で作り、更新では引き継ぐ |
| `UsedDate` | 使った時刻。NULL なら未使用 |

**例**（`c93a…` が一族の識別子）

| 時点 | 行 |
|---|---|
| 認可コードを交換 | `RT1`（`c93a…` / 未使用） |
| RT1 で更新 | `RT1`（使用済み）、`RT2`（`c93a…` / 未使用） |
| RT2 で更新 | `RT1`（済）、`RT2`（済）、`RT3`（`c93a…` / 未使用） |
| **RT1 が再び提示された** | **`c93a…` の行をすべて削除**（RT3 も使えなくなる） |

認可をやり直せば、別の `FamilyId` になる。**別の一族は影響を受けない。**

**なぜ正規の側も失効させるのか。** 漏れたトークンと正規のトークンを、サーバは見分けられない。
OAuth 2.0 Security BCP §4.14.2 は、この場合に一族の失効を挙げている。

**明示的な失効（`/revoke`）も一族ごと**にした。RFC 7009 §2.1 が、refresh_token を失効させるときは
**同じ認可グラントに基づくトークンも無効にすべき**としているため。
漏れたトークンを失効させたのに、そこから派生した新しいトークンが生き残るのは、利用者の意図と違う。

- `introspect`（`Refer`）は、**使用済み・期限切れを「無い」と同じ扱い**にする（`active: true` を返さない）
- E2E テスト : **`EX-1.2`**（再利用すると、正規の新しい方も使えなくなる）、**`EX-1.4`**（失効も一族ごと）
- **DDL を変えた。** 既存のデータベースには `ALTER` が要る（移行用のスクリプトは用意していない）

**期限切れの行の掃除（#188 の案 4）**

参照時にも期限切れは消えるが、**一度も参照されない行は残る**
（Issue が指摘していた「未消費の code がメモリに残り続ける」がこれ）。
そこで **書き込み（`Create`）のついでに、10 分に 1 回だけ、期限切れの行をまとめて消す。**
3 つのストア（認可コード / refresh_token / Request Object）とも同じ作りで、
メモリ ストアと DBMS の両方に効く。

- **常駐の仕組み（バッチ・タイマ）を増やしていない。** net48 / net10.0 で同じコードにするため
- **消す条件は「作成時刻が期限より古い」だけ。**
  使用済みの refresh_token は、**期限までは消さない**（消すと、再利用の検知ができなくなる）
- 間隔（10 分）は定数。設定値にはしていない
- **E2E では測っていない**（内部の掃除で、外から観測できないため）

- `Config.OAuth2RefreshTokenExpireTimeSpanFromDays`（既定 14 日）は
  **`Co/Config.cs` の定義以外どこからも参照されていない。** → 事実上の無期限。
- ローテーション（使用時に削除）は行っているが、
  **ローテーション済みトークンを再提示されても検知・失効（family revocation）をしない。**
  OAuth 2.0 Security BCP §4.14 が求める挙動。
- 有効期限は #188 で検証するようにした（上記）。以下は**再利用検知と、経路の制限**の話
- `refresh_token` の経路は、**証明によらず `normal` の登録にしか許されていない**
  （`ClientModePolicy` の表。#224）。**`normal` 以外の登録には、`refresh_token` を発行しない**
  （#224 の段階 2。以前は発行していたが、使えなかった。`FA-1.2` / `FA-3.1`。C-7）。

### C-6. `state` を URL エンコードせずに連結している **[Core]** — **✅ 修正済み（#187）**

**直す前。**

```csharp
// MultiPurposeAuthSiteCore/.../AccountController.cs:3017, 3035 ほか
string.Format("?code={0}&state={1}", code, state)
```

`state` はクライアント（＝攻撃者が用意しうる RP）が自由に決められる値であり、
`&` を含めればリダイレクト URL にパラメタを注入できた。

**直し方。** **リダイレクト URL の組み立てを 1 か所に集約した**
（`CmnEndpoints.BuildRedirectUrl`。A-6 と同じ #187）。

- **値は必ず URL エンコードする**
- **区切りを `?` と `&` で切り替える**（既にクエリ文字列を持つ `redirect_uri` でも壊れない。A-6）
- **値が空のパラメタは付けない。** `state` は**要求に含まれたときだけ**返す（RFC 6749 §4.1.2）
- **認可応答は、成功も失敗も全てここを通る**（`BuildRedirectUrl` の呼び出し元は両アプリで多数）

> **`"&state=" + state` の連結は、まだ 2 か所に残っている**
> （両アプリの `AccountController` の ID 連携。
> **`ManageController` の `GetOAuth2Token` は、管理画面のトークン取得ごと削除された**）。
> **こちらは「この実装が RP として送る認可要求」で、`state` は自分で作っている**
> （`GetPassword.Generate(32, 0)` / `(10, 0)`。**記号を入れない**）。
> **C-6 が問題にしていた「クライアントから来た値を、そのまま応答に連結する」経路ではない。**

### C-7. PKCE の扱いが OAuth 2.1 と噛み合わない **[Lib]** — **✅ 修正済み（#220 / #221 / #224）**

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
   **格上げの影響は権限判定だけでは終わらない。** `CmnAccessToken.ProtectFromPayload` は
   `permittedLevel` を見て**アクセス トークンに `fapi` クレームを書く**ため、
   **`normal` 登録のクライアントでも、`S256` の PKCE を使えば `fapi: fapi1` を名乗るトークンになる。**
   （この repo の中では誰もこのクレームを読んでいない。効くのは、これを信頼する RS がある場合。）

さらに、**認可エンドポイント側で `code_challenge` を必須化していない**ため、
PKCE 無しの認可コード フローがそのまま通る。

> **もう 1 つ、逆向きの穴が残っていた。** `code_challenge` を送った認可から出たコードでも、
> **`code_verifier` を省けば PKCE の検証を通らずに交換できた**（**C-22**。#245 の段階 2 で修正）。
> **ここで直した 3 点は、いずれも「クライアントが送ってきたもの」の扱いで、
> 「認可要求の側から必須性を決める」向きは見ていなかった。**

**対応（#220 の 1 つ目）: 上の 1 と 2。**

- **1（同時送信）: 直した。** 空実装だった分岐を実装し、
  **クライアント認証（`client_secret`）と PKCE の検証を、別々に行って両方を求める**。
  PKCE は当初「`client_secret` を持てないクライアントの代わり」だったが、
  いまは**種別によらない標準的な防壁**で、`client_secret` と併用される
- **2（`plain`）: 設定で拒否できるようにした**（`RequirePkceS256`）。
  **既定は `false`（従来どおり受理）。** 下位互換のため
- 検証は `VerifyPkce` にまとめ、パブリック クライアントの経路と共用する（同じ判定が 2 箇所に散らない）
- E2E テスト : **`RT-220.1`**（`client_secret` ＋ `code_verifier` でトークンが返る／
  **誤った `code_verifier` では発行しない**）、**`RT-220.2`**（`plain` は既定で受理）

**対応（#220 の残件）: `code_challenge` の必須化。**

- **設定で必須にできるようにした**（`RequirePkce`）。**既定は `false`（従来どおり任意）。**
  有効にすると、**認可エンドポイント**で `invalid_request` になる
  （`ValidateAuthZReqParam`。エラーは #187 の仕組みで RP へリダイレクトで返る）
- 対象は **`code` を発行する `response_type`**（`code` / `code id_token` / `code token` /
  `code id_token token`）。**Device AuthZ / CIBA は認可エンドポイントを通らないので掛からない**
- 値の出どころは `request_uri`（JAR / PAR）が在ればその中、無ければクエリ文字列。
  `AuthorizationCodeProvider.GetAuthorizationRequestParams` と同じ決め方（#197）
- **`RequirePkce` と `RequirePkceS256` は別物。** 前者は PKCE 自体を求め、後者は使うなら `S256` に限る
- E2E テスト : **`RT-220.3`**（既定では `code_challenge` 無しでも認可コードが返る）

**対応（#221）: クライアント単位の PKCE 必須化。**

- **サーバ全体の設定だけでは、全クライアントが揃うまで有効にできない。**
  クライアント登録に **`require_pkce`** を足し、**締められるものから順に締められる**ようにした
- 判定は **`Config.RequirePkce || Helper.GetClientRequirePkce(client_id)` の OR**。
  サーバ側が「床」、クライアント側は「個別の引き上げ」で、**床は下げられない**
- 設定ファイル（`OAuth2ClientsInformation`）と、管理画面の登録（`saml2OAuth2Data`）の両方に対応
- **保存済みの登録に項目が無くても `false`** になるので、従来どおりの動作が続く
  （`oauth2_oidc_mode` の改名案が抱えていた「静かに緩む」問題は起きない）
- E2E テスト : **`RT-221.1`**（`require_pkce` のクライアントは PKCE 無しを拒否し、付ければ通る）、
  **`RT-221.2`**（他のクライアントには波及しない）

**対応（#220 の残件）: 3（`permittedLevel` の分離）。**

**2 つの意味が 1 つの変数に混ざっていたので、値を分けた。**

| | 意味 | 決まり方 | 使い道 |
|---|---|---|---|
| `permittedLevel`（#224 の段階 1 で表に置き換えた。下記） | **その経路が、どこまでの登録種別を通すか** | クライアント認証の強度（`client_secret` / x509 / assertion / PKCE の `S256`） | 継続の可否の判定 |
| `clientMode` | **そのクライアントが、何として登録されているか** | クライアント登録 | **トークンのクレーム** |

- `CheckClientMode` に `out clientMode` を足し、**登録された種別を呼び出し元へ返す**
- `ProtectFromPayload` へ渡す値を、`permittedLevel` から **`clientMode` に変えた**（2 箇所）。
  これで **`normal` 登録のクライアントは、`S256` を使っても `fapi` を名乗らない**
- **格上げ（`S256` → `fapi1`）そのものは残す。** 外すと `fapi1` で登録された
  クライアントが PKCE で通らなくなる。**格上げは「経路が認める上限」の話**なので、
  そこに置いてあるのは正しい（#224 の段階 1 で、表の「認可コード × PKCE の `S256`」の行になった）
- **`device` 登録のクライアント**（LIR で PKCE を使う経路）は、これまで `fapi: fapi1` を
  名乗っていたが、**`device` クレームに変わる。** 登録どおりの名乗りになる
- E2E テスト : **`RT-220.4`**（`normal` 登録のクライアントが `S256` で取ったトークンに
  `fapi` クレームが載らない）

> 他の `ProtectFromPayload` の呼び出し（Implicit / Device AuthZ / CIBA / `/ros`）は、
> もともと `permittedLevel` ではなく**固定値**（`normal` / `device` / `fapi_ciba`）を
> 渡しているので、影響を受けない。

**判定側（`CheckClientMode`）の設計（#222 で現状を固定し、#224 で表に置き換えた）。**

E2E で現状を固定した（`Tests/Fapi/`。`FA-1`〜`FA-3`）。**実測は次のとおり。**

| 登録（`client_mode`） | 認可コード ＋ `client_secret` | 認可コード ＋ PKCE `S256` | ROPC | `client_credentials` | `refresh_token` |
|---|---|---|---|---|---|
| `normal`（対照） | 通る | 通る | 通る | 通る | 通る |
| **`fapi1`** | 拒否 | **通る** | 拒否 | 拒否 | **拒否** |
| **`fapi2`** | 拒否 | **拒否** | 拒否 | 拒否 | （到達せず） |
| **`device`** | （`client_secret` 無し） | **通る** | — | — | （`client_secret` 無しで不可） |

拒否はいずれも `unsupported_grant_type`（#224 の段階 2 で `unauthorized_client` に改めた）。
**`fapi2` は x509（mTLS）でしか通らない**ので、平文の経路は全滅する（設計どおり）。
**`fapi1` の `refresh_token` は、段階 2 で発行しないようにした**（下記）。

**#224 の段階 0 で、未測定だったマスを埋めた**（E2E : `FA-1.3` / `FA-1.4` / `FA-4.1`）。

| 登録 | 経路 | 結果 |
|---|---|---|
| fapi1 | 認可コード ＋ `client_secret` ＋ PKCE `S256`（併用） | 拒否（`unsupported_grant_type`）。併用の経路は、PKCE を検証だけに使い、`client_secret` の認証として扱うため。**段階 2 で「設計どおり」と判断**（D） |
| fapi1 | Hybrid（`code id_token`） | 拒否。**ただし `error=access_denied` のリダイレクトで返る**（`/token` 側は `unsupported_grant_type`。経路でエラー コードがそろっていない）。**段階 2 で、要求の検証時に `unauthorized_client` を返すよう改めた**（B / C） |
| fapi1 / fapi2 / fapi_ciba | Device AuthZ グラント | **修正前は client_secret だけで発行していた**（C-18）。修正後は `unauthorized_client` |
| normal | CIBA | 拒否（`unsupported_grant_type`）。**ただしトークンの段階で。** 開始（`/ciba_authz`）は登録種別を見ないので、**利用者にプッシュ通知が届き、承認させた後で**拒否になる（`FA-5.1`）。**段階 2 で、開始の時点で `unauthorized_client` を返すよう改めた**（B / C）。測るために、TestClient4 を写して登録種別だけ normal にした `TestClient4_2` を、**種データが作る**（公開鍵ごと写すので署名検証を通る。設定ファイルは変えない。#264） |


**設計上の問題が 3 つある。**

1. **順序として扱っているが、順序ではない。** `device` / `fapi_ciba` は水準ではなく**種別**。
   実際 `CheckClientMode` は、`permittedLevel > fapi2` のとき
   「以下」ではなく「**一致**」に判定を切り替えている
2. **例外がハードコードされている。** `clientMode = device` かつ `permittedLevel = fapi1`
   （＝ PKCE の `S256`）のときだけ通す、という LIR 用の措置がある（`FA-3.1` が、この経路を固定している）
3. **巻き添えが大きい。** `fapi1` にすると PKCE 以外の経路も塞がる。とくに
   **`refresh_token` は、発行されるのに使えない**（`FA-1.2`。RP から見ると
   「受け取ったのに必ず失敗する資格情報」）

**あるべき形**は 1 次元の水準ではなく、
**「この要求が何を証明したか」の集合**と**「このクライアントが何を要求するか」の集合**の照合。
ただし **`ClientMode` の列挙は Open棟梁側**（別リポジトリ）に在り、認証・認可の中心でもあるため、
**#222 では着手しない**（別 Issue : #224）。上の E2E は、そのときに**壊していないことを確かめる土台**である。

**#224 の段階 1 : 大小比較を表に置き換えた（振る舞いは変えていない）。**

- `CommonLibrary/TokenProviders/ClientModePolicy.cs` を新設。
  **「経路 × その要求で何を証明したか」→ 通す登録種別**の表で引く。表に無い組み合わせは拒否
- 上の問題 1・2 は、表の形そのもので解消した（`device` / `fapi_ciba` は「以下」ではなく、行ごとに列挙する。
  LIR 用の例外は「認可コード × PKCE の `S256`」の行に `device` を含めるだけになった）。
  **問題 3（`refresh_token` など）は、表の行を書き換える段階 2 で扱う**
- **以前の判定と全マスで一致することを確かめた**（経路 9 × 証明 7 × 登録の文字列 9。
  未知の文字列・空も含む。以前のコードで生じない組み合わせ（認可コード × 証明なし）を除く）。
  **E2E で守られていない行がある** : 認可コードの **private_key_jwt**。
  **mTLS の行は #226 で E2E を張った**（`FA-6`。net10.0 版は既定で、net48 版は準備のうえ `-NetFxMtls` で。**両方とも実測済み**）
- **既知のどれにも当たらない登録値（空・書き間違い）は、`fapi2` として扱う**（以前のまま。段階 2 の候補）
- 変わったのは、拒否したときの `error_description` の文面だけ
  （`This client (<種別>) is not allowed to use this flow.`。エラー コードは `unsupported_grant_type` のまま）

**#224 の段階 2 : 振る舞いを変えた。** 項目ごとに判断した結果は次のとおり。

| | 項目 | 以前 | 段階 2 | E2E |
|---|---|---|---|---|
| A | 使えない `refresh_token` | `fapi1` / `device` の登録にも発行し、使うと拒否 | **登録種別で `refresh_token` の経路を使えないなら、発行しない** | `FA-1.2` / `FA-3.1` |
| B | 拒否の時点 | 認可エンドポイント（Implicit / Hybrid）はログイン・同意の後、CIBA はプッシュ通知・承認の後で拒否 | **要求を検証する時点で断る**（認可エンドポイントは `redirect_uri` を確かめた直後。`/ciba_authz` は `iss` を確かめた直後） | `FA-1.4` / `FA-5.1` |
| C | エラー コード | `/token` は `unsupported_grant_type`、Hybrid は `access_denied`、Device AuthZ は `unauthorized_client` | **`unauthorized_client` に揃えた**（RFC 6749 §4.1.2.1 / §4.2.2.1 / §5.2、CIBA Core §13） | `FA-1.1` ほか |
| D | `fapi1` で `client_secret` と PKCE の併用 | 拒否 | **変えない**（FAPI 1.0 Advanced は `client_secret` を認めない。設計どおり） | `FA-1.3` |
| E | 既知でない登録値（書き間違い・空） | `fapi2` とみなす | **不正な登録として拒否する**（「一番厳しい種別」に倒す作りは、種別が増えると意味が変わる）。`client_mode` を書いていない登録は従来どおり `normal` | `FA-5.2` / **`FA-6.3`**（以前との違いが出るのは mTLS の経路だけ。#226） |
| F | mTLS で認証したクライアントの refresh / ROPC / client_credentials | `normal` の登録のみ | **見送り**（表は変えていない。mTLS の E2E は #226 で張ったので、変えるときは `FA-6` に足して測れる） | — |

- **B の早い判定は「その経路を、何かの証明で使えるか」**（`ClientModePolicy.MayUse`）で見る。
  認可エンドポイントの時点では、トークン エンドポイントでの証明（`client_secret` / PKCE など）がまだ分からないため。
  **最終の判定は従来どおり、トークンを出す時点の表**（`IsAllowed`）
- **利用者への影響**
  - RP から見えるエラー コードが変わる（`unsupported_grant_type` / `access_denied` → `unauthorized_client`）。
    **登録どおりに使っている RP には影響しない**（もともと拒否される要求だけが対象）
  - `fapi1` / `device` の登録のクライアントには、`refresh_token` が返らなくなる（もともと使えなかった）
  - `client_mode` に既知でない値を書いた登録は、全経路で拒否される（以前も、mTLS 以外はほぼ拒否されていた）

### 署名アルゴリズムの対照表（#129 の段階 0）

**どの口で、どの `alg` が実際に通るか。** 広告（Discovery）と実装を突き合わせたもの。
**#129（384 / 512 への拡張）を検討するときの出発点**として置く。

| 口 | Discovery の広告 | **実際に通る** | 決めているもの |
|---|---|---|---|
| `/token`（`client_assertion`。`private_key_jwt`） | `token_endpoint_auth_signing_alg_values_supported: ["RS256","ES256"]` | **RS256 / ES256**（#129 の段階 2 で ES256 を足した） | `CmnEndpoints.ClientAuthentication` が、**登録された RSA → ECDSA の公開鍵を順に試す**（`JwtAssertion.Verify` が JWK の `kty` で分岐する）。**クライアントが登録した鍵の種類で決まる。登録 `token_endpoint_auth_signing_alg` で片方に絞れる**（#262） |
| `id_token` | `id_token_signing_alg_values_supported` : **`RS*` / `PS*` / `ES*` の 9 つ** | **左の 9 つ**（段階 2 で RS384 / RS512、段階 3 で ES384 / ES512、段階 4 で PS256 / PS384 / PS512 を足した） | **クライアントの登録 `id_token_signed_response_alg` で決まる**（既定は RS256。#129 の段階 2）。`client_mode=fapi_ciba` は ES256 固定 |
| access_token | （広告しない） | 同上（9 つ） | 同上（`id_token` と同じ alg になる） |
| Request Object（`/ros` / `/par`） | `request_object_signing_alg_values_supported: ["RS256"]` | **RS256 固定** | `RequestObject.Verify`。**登録 `request_object_signing_alg` で絞れる**が、受ける集合が 1 つなので結果は変わらない（#262） |
| CIBA の `request` | `backchannel_authentication_request_signing_alg_values_supported: ["ES256"]` | **ES256 固定** | `RequestObject.VerifyCiba` |
| 認可応答（JARM） | `authorization_signing_alg_values_supported: ["RS256"]` | RS256 固定 | `CmnResponseObject` |

**広告と実装は一致している**（#189 / A-10 で整えた）。

**`PS256` は、段階 0 の時点ではどこにも無かった。**
**Open棟梁 に `JWS_PS*` が存在しなかった**ためである。
**FAPI 1.0 Advanced / FAPI-CIBA は `PS256` または `ES256` を求める**ので、
**上流の対応が要った** → **✅ 上流に入った**
（[OpenTouryo#596](https://github.com/OpenTouryoProject/OpenTouryo/issues/596)。
**この実装も段階 4 で `PS256` / `PS384` / `PS512` を発行するようにした**。下記）。

> **コード中の記述が実装と食い違っていた。**
> CIBA の広告のあたりに **「RequestObjectの署名は、ES256 と PS256のみ許可」** と書かれていたが、
> **`PS256` は通らない。** #129 の段階 0 で、記述を実装に合わせた。

**拡張するときに効く事実**（#129 の段階 0 で調べたもの）。

- **Open棟梁 には `RS256/384/512` と `ES256/384/512` が既に在る**（`_Param` / `_X509` の両方）。
  **待ちの状態は解消している**
- **`client_assertion` の ES256 は、✅ 対応した**（#129 の段階 2）。
  `JwtAssertion.Verify` が **JWK の `kty` を見て RSA / EC を選ぶ**ので、
  **MPAS が RSA 鍵しか渡していないだけ**だった。
  **登録された RSA → ECDSA の公開鍵を順に試す**ようにし、広告も `["RS256","ES256"]` にした。
  **アサーションの `alg` ヘッダでは選ばない**（C-8 と同じ轍を踏まないため）。
  E2E テスト : **`RT-129.1`**（ES256 で通る／RS256 の対照／Discovery の広告）
- **ES384 / ES512 は鍵の差し替えを伴う**（JWA で `ES256`→P-256、`ES384`→P-384、`ES512`→P-521。
  曲線が alg に紐づく）。**RS384 / RS512 は同じ RSA 鍵のままダイジェストだけ変えられる**。
  **✅ 対応した（#129 の段階 3）。** **鍵はリポジトリに在った**（`SHA384ECDSA.pfx` / `SHA521ECDSA.pfx`）
- **登録（クライアント）側の alg の項目**は、**`id_token_signed_response_alg` を ✅ 足した**（#129 の段階 2。下記）。
  **検証する側**（`request_object_signing_alg` / `token_endpoint_auth_signing_alg`）も
  **✅ 足した**（#262。**書かなければ絞らない**。受ける alg を広げるのは別の話）

### 署名アルゴリズムを登録で選べるようにした（#129 の段階 2）

**`RS384` / `RS512` を足し、クライアントの登録 `id_token_signed_response_alg` で選べるようにした。**
**段階 0 の対照表で「登録側に alg の項目が無い」と書いた箇所**が、ここで埋まる。

| | |
|---|---|
| 発行する alg | **`RS256` / `RS384` / `RS512` / `ES256`**（`CmnAccessToken.SupportedAlgs`） |
| 選び方 | **クライアントの登録 `id_token_signed_response_alg`**。**書かなければ `RS256`**（＝ 従来どおり） |
| 効く範囲 | **access_token と id_token の両方**（2 つは同じ alg になる） |
| 既知でない値 | **入口で拒否する**（`CheckClientMode` → `unauthorized_client`。#224 と同じ方針） |

**鍵は増えない。** `RS256` / `RS384` / `RS512` は**同じ RSA の鍵**で、**ダイジェストだけが違う。**
**`kid` は鍵から作る**（RFC 7638 : kty / n / e）ので**3 つで同じ値**になり、
**RP は `jwkcerts` の同じ鍵でそのまま検証できる**（どのダイジェストかはヘッダの `alg` が伝える）。

**一覧は 1 か所に寄せた**（`CmnAccessToken.SupportedAlgs`）。
**発行（`SelectJwsForSigning`）・検証（`SelectJws`）・広告（Discovery）が同じ一覧を見る**ので、
**増やしても食い違わない。**

> **id_token は、渡さないと既定に落ちる。**
> `CmnIdToken.ChangeToIdTokenFromAccessToken` の `alg` は**既定が `RS256`** で、
> **`/token` の呼び出し側が、ヘッダから読んだ `alg` を渡していなかった。**
> **access_token だけ `RS512`、id_token は `RS256`** という状態になり、**`RT-129.3` で見つかった。**
> **既定値のある引数は、渡し忘れても動く。** 測らないと分からない。

- **CIBA は `ES256` のまま**（FAPI-CIBA が `PS256` / `ES256` を求めるため、登録値で上書きしない）
- **JARM（`authorization_signing_alg_values_supported`）も `RS256` のまま**
- **検証する側の登録項目**（`request_object_signing_alg` / `token_endpoint_auth_signing_alg`）は
  **#262 で ✅ 足した**（**狭める側だけ**。受ける alg を広げるのは上流の対応が要る）
- **E2E** : **`RT-129.3`**（`RS512` で署名され、`jwkcerts` の同じ鍵で検証でき、`kid` が `RS256` と同じ。
  **自分の検証経路＝C-8 で固定した集合も、これを受ける**）／
  **`RT-129.4`**（Discovery が `RS256 RS384 RS512 ES256` を、**この順で**広告する）
- **`ES384` / `ES512` は段階 3**（鍵の差し替えを伴う）。
  **`PS256` は段階 4**（上流の対応が要った。[OpenTouryo#596](https://github.com/OpenTouryoProject/OpenTouryo/issues/596)。✅ 対応済み）
- **利用者への影響** : **無し。** **書かなければ `RS256`** で、**既存の登録は従来どおり**である

### ES384 / ES512 と、鍵の表（#129 の段階 3 / D-9）

**`ES384` / `ES512` を足し、alg → 鍵の対応を 1 か所に寄せた。**

| | |
|---|---|
| 発行する alg | **6 つ**（`RS256` / `RS384` / `RS512` / `ES256` / `ES384` / `ES512`） |
| 鍵 | **4 本**（RSA 1 本 ＋ EC 3 本）。**RSA は 3 つの alg で共有**し、**EC は曲線が alg に紐づく** |
| 表の場所 | **`CommonLibrary/TokenProviders/SigningKeys.cs`** |
| 表を見る側 | **発行**（`SelectJwsForSigning`）・**検証**（`SelectJws` / `SelectJwsFromCertificate`）・**広告**（Discovery）・**`jwkcerts` の生成**（`CreateJwkSetJson`） |

**鍵は新しく作っていない。** `root/files/resource/X509/` に **`SHA384ECDSA.pfx`（P-384）** と
**`SHA521ECDSA.pfx`（P-521）** が在った（`GenECDsaCertByOpenSSL.bat` が作ったもの）。
**設定キーを足して、表から引くようにしただけ**である。

#### D-9「発行側が 1 本を固定参照」の実体は、対応が散っていたこと

**鍵の入れ替えそのものは、もともと回る形になっていた**（`JwkSet.json` は追記式で、
検証は `kid` で引く）。**無停止の入れ替えを妨げていたのは、alg → 鍵の対応が 3 箇所に散っていたこと**である。

| 散っていた場所 | 何が起きうるか |
|---|---|
| 発行（`CmnAccessToken`） | |
| 証明書での検証（`CmnAccessToken`） | **署名した鍵と、検証に落ちる鍵が食い違う** |
| `jwkcerts` の生成（`CreateJwkSetJson` が **RSA と ES256 を決め打ち**） | **載っていない鍵で署名する**（RP は検証できない） |

**`CreateJwkSetJson` が `SigningKeys` の表を回すようにした。**
**ツールは、その 1 ファイルだけをソース参照する**（`Compile Include` の `Link`。
CommonLibrary ごと参照すると、コンソール ツールに DB ドライバまで付いてくる）。
＝ **アプリが署名に使う鍵が、そのまま `jwkcerts` に載る。**

**入れ替えの手順は `CONFIGURATION.md`** に書いた（**先に載せ、キャッシュを待ち、切り替え、後で外す**）。

#### `kty` だけでは足りなかった（`crv` まで突き合わせる）

**`ES256` / `ES384` / `ES512` は、どれも `kty=EC`** である。
`IsSameKeyType` は **`kty` だけを見ていた**ので、
**P-256 の鍵で `ES512` のトークンを受けうる形**だった。**`crv` まで突き合わせるようにした。**

**実害は出ていない。** 段階 2 まで `ES384` / `ES512` は**受ける集合に無かった**ので、
**alg の固定（C-8）で先に弾かれていた。**
**発行し始めるのと同じ段階で入れた**のが、この修正である。
E2E : **`RT-129.5`**（`ES384` のトークンの alg を `ES512` に書き換えると受けない）。

#### 上流（Open棟梁）の不具合を踏んだ — **✅ 上流で修正済み（[OpenTouryo#595](https://github.com/OpenTouryoProject/OpenTouryo/issues/595)）**

**`JWS_ES384_Param` / `JWS_ES512_Param` が、Windows では検証できなかった。**

`DigitalSignECDsaCng(ECParameters, bool)` が**ダイジェストを受け取っていなかった**ため、
検証が `ECDsaCng.VerifyData(data, sign)` ＝ **`ECDsaCng.HashAlgorithm` の既定（SHA-256）**になっていた。
**`ES256` だけ、たまたま合っていた。**

**実測（Open棟梁 の DLL を直に叩いて確認したもの）**

| alg | `JWS_ES*_X509`（証明書） | `JWS_ES*_Param`（JWK）<br>2026/10/02（修正前） | `JWS_ES*_Param`（JWK）<br>2026/10/03（修正後） |
|---|---|---|---|
| `ES256` | ○ | ○ | ○ |
| `ES384` | ○ | **×** | **○** |
| `ES512` | ○ | **×** | **○** |

（修正後は **net48 / net10.0 の両方**で確認した。`DigitalSignECDsaCng` に
ダイジェストを渡す引数が増え、`JWS_ES*_Param` がそれを渡すようになっている。
**`JWS_ES*_Param` の引数は変わっていない**ので、呼ぶ側は元のままで良い。）

`_X509` は `DigitalSignECDsaX509(path, password, hashAlgorithmName)` に**ダイジェストを渡していた。**
Linux の経路（`DigitalSignECDsaOpenSsl(param, SHA384.Create())`）も渡していた。
**Windows（Cng）の経路だけが渡していなかった。**

**`kid` で JWK を引く経路が、この `_Param` である。**
＝ **鍵の入れ替え（D-9）で要る経路**なので、避けて通れなかった。

| | |
|---|---|
| **修正前** | `SigningKeys` の中に `EcdsaJwkVerifier`（`JWS_ECDSA` の派生）を置いて回避していた |
| **修正後** | **回避の派生 class は外し、上流の `JWS_ES*_Param` をそのまま使う** |

> **これは「受けられない」不具合**（false negative）であって、**通してしまう類ではなかった。**
> SHA-256 で検証されるのは**P-384 / P-521 の鍵で SHA-256 の署名を作れたときだけ**で、
> この実装は **alg と鍵を対応させている**ので、そういう署名は発行しない。

> **上流のアセンブリを入れ替えたら、アプリの出力も作り直すこと。**
> **`bin_locked_*` のような「名前を変えて残した出力」が、参照の解決で先に当たる。**
> 詳細 → [`BUILDING.md`](../BUILDING.md) 3 節

- **E2E** : **`RT-129.5`**（`ES384` / `ES512` で署名され、`jwkcerts` の曲線の合う鍵で検証でき、
  `kid` が曲線ごとに違い、曲線が食い違うトークンは受けない）／
  **`RT-129.6`**（**Discovery が広告する alg すべてに、`jwkcerts` の鍵が在る**）
- **利用者への影響** : **無し。** **書かなければ `RS256`** で、**既存の登録は従来どおり**である
- **残り** : **`PS256` は段階 4**（下記で ✅ 対応した）。
  **検証する側の登録項目**（`request_object_signing_alg` / `token_endpoint_auth_signing_alg`）は **#262 で対応済み**

### PS256 / PS384 / PS512（RSASSA-PSS）（#129 の段階 4）

**FAPI 1.0 Advanced / FAPI-CIBA は、ID Token の署名に `PS256` または `ES256` を求める。**
段階 3 までは `ES256` しか選べなかった（上流に `JWS_PS*` が無かった）。

| | |
|---|---|
| 発行する alg | **9 つ**（`RS*` 3 ＋ `PS*` 3 ＋ `ES*` 3） |
| 鍵 | **4 本のまま。** **`PS*` は `RS*` と同じ RSA の 1 本**で、**パディングだけが違う** |
| `kid` | **`RS256` と同じ値**（RFC 7638 は kty / n / e から作る）。＝ **`jwkcerts` に鍵を足す必要が無い** |
| 広告の並び | **`RS*` → `PS*` → `ES*`**（鍵ごとに固まる。**順序に仕様上の意味は無い**） |

**実装はほぼ表への 3 行である**（#129 の段階 3 で `SigningKeys` に寄せてあるため）。
`CreateJwsFromPfx` / `CreateJwsFromCer` / `CreateJwsFromJwk` に `JWS_PS*` の分岐を足し、
**設定キーは `RS*` と同じものを指す。**

> **`jwkcerts` の JWK の `alg` は `RS256` のまま**である。
> RSA の鍵 1 本に対して JWK は 1 件なので、**6 つの alg を書き分けられない。**
> **これでよい** —— RFC 7517 の `alg` は「用途」で任意であり、
> **この実装は `kty`（と EC では `crv`）で照合する**（`IsSameKeyType`）。

#### `kty` が同じなので、`PS*` は「3 つ目の関門」で落ちる

**`RS256` のトークンの alg を `PS256` に書き換えると、鍵の照合は通ってしまう**
（どちらも `kty=RSA` で、`kid` も同じ鍵を指す）。
**落ちるのは署名の検証**である（PKCS #1 v1.5 の署名を RSASSA-PSS として検証するため）。

| 関門 | 書き換えた alg | 落ちるところ |
|---|---|---|
| 1 | `HS256` / `HS384` / `none` | **`SupportedAlgs` に無い**（即、拒否） |
| 2 | `ES256` / `ES384` / `ES512` | **`kty` が違う**（RSA ≠ EC） |
| 3 | `PS256` / `PS384` / `PS512` | **`kty` は同じ。署名が合わない** |

**実測で 3 つとも拒否することを確かめている**（`RT-129.2`）。

- **E2E** : **`RT-129.7`**（`PS256` / `PS384` / `PS512` で署名され、
  **`kid` が `RS256` と同じ**で、**`jwkcerts` の RSA 公開鍵で RSASSA-PSS として検証でき**、
  `/userinfo` が受ける）／**`RT-129.2` の (4)**（パディングが違えば受けない）
- **CIBA は `ES256` のまま**（登録値で上書きしない）。**JARM も `RS256` のまま**
- **利用者への影響** : **無し。** **書かなければ `RS256`** で、**既存の登録は従来どおり**である。
  **`jwkcerts` も変わらない**（鍵を足していないため、RP 側の作業も無い）
- **残り** : 無し。**検証する側の登録項目**（`request_object_signing_alg` /
  `token_endpoint_auth_signing_alg`）は **#262 で対応済み**（#129 は段階 4 で完了）

### 検証する側の alg をクライアント単位で登録できるようにした（#262）

**#129 で足したのは「発行する側」だけ**だった（`id_token_signed_response_alg`）。
**「受ける側」の登録項目が無く、広告との非対称が残っていた。**

| | 広告（Discovery） | 登録（クライアント） |
|---|---|---|
| `client_assertion` | `token_endpoint_auth_signing_alg_values_supported` | **無かった → ✅ 足した** |
| Request Object | `request_object_signing_alg_values_supported` | **無かった → ✅ 足した** |

**効くのは `client_assertion` である。**
`ClientAuthentication` は**登録された RSA → ECDSA の公開鍵を順に試す**ため、
**両方の鍵を登録したクライアントは `RS256` でも `ES256` でも認証が通っていた**。
**登録で片方に絞れる**ようにした（OIDC Registration 1.0 §2 / FAPI 1.0 Advanced §8.6）。

| 登録 | 振る舞い |
|---|---|
| 書かない | **両方通る**（従来どおり） |
| `RS256` | **`ES256` のアサーションは通らない** |
| **受ける集合の外**（例 : `PS256`） | **通らない**（不正な登録として拒否。#224 と同じ方針） |

**`request_object_signing_alg` は、いま書ける値が 1 つだけ**である。
**受ける側が `RS256` 固定**（上流の `RequestObject.Verify` が `JWS_RS256_Param` 決め打ち）なので、
**絞っても結果は変わらない。** **それでも項目を用意したのは、広告との非対称を先に解消しておくため**で、
**受ける alg が増えた時点で、値を書けるようになるだけ**になる。
**受ける alg を広げるのは「広げる側」の話**で、#262 では扱っていない（上流の対応が要る）。

**CIBA の `request` は対象外**である。**`ES256` 固定**で、
**仕様でも別の登録項目**（`backchannel_authentication_request_signing_alg`）になっている。

**受ける集合は 1 か所が持つ**（`CmnEndpoints.TokenEndpointAuthSigningAlgs` /
`CmnEndpoints.RequestObjectSigningAlgs`）。**広告・登録値の検証・画面の選択肢が、同じものを見る**
（発行する側が `SigningKeys` の表 1 か所を見るのと同じ考え方。#129 の段階 3）。

- **絞る口は 3 つ** : `ClientAuthentication`（`client_assertion`）／
  `/ros` の FAPI2-CC（`RequestObject.Verify`）／`request` パラメタ（JAR）
- **E2E** : **`RT-262.1`**（`token_endpoint_auth_signing_alg=RS256` のクライアントは、
  **`RS256` は通り、`ES256` は通らない**。**絞っていないクライアントは `ES256` でも通る**）／
  **`RT-129.1`**（絞らなければ両方通る＝従来どおり）
- **画面でも選べる**（`AddSaml2OAuth2Data`。**先頭が「絞らない」**）
- **利用者への影響** : **無し。** **書かなければ絞らない**ので、**既存の登録は従来どおり**である

### C-8. トークンの `alg` ヘッダで検証器を選んでいる **[Lib]** — **✅ 修正済み（#129 の段階 1）**

`VerifyAccessToken` は `header[JwtConst.alg]` を読んで `JWS_ES256_X509` / `JWS_RS256_X509` を選んでいた。
サーバ側で**期待する alg を固定していない**ため、アルゴリズム混同の温床になる。
（`kid` が JWK Set に当たる経路では JWK 側の `alg` を使っており、そちらは妥当だった。）

**直し方**（`CmnAccessToken.SelectJws`）。

| | |
|---|---|
| **受ける alg を固定した** | **この認可サーバが発行するものだけ**（**`SigningKeys` の表**。段階 1 では `RS256` / `ES256`、**段階 2 で `RS384` / `RS512`、段階 3 で `ES384` / `ES512`、段階 4 で `PS*` を足した**）。**それ以外は即、検証失敗**（`none` / `HS256` / `HS384` …） |
| **鍵を alg に対応させた** | **以前は、`kid` を引けないときに必ず RSA を選んでいた**ので、**ES256 で発行したトークンが検証できなかった** |
| **JWK とヘッダの食い違いを拒む** | `kid` で引いた JWK の `alg` が**ヘッダの `alg` と違えば受けない**（どちらを信じるかという話にしない） |

**以前も偽造はできなかった。** 署名は**自分の公開鍵**で確かめており、
知らない alg は RS256 として扱われて**署名不一致で落ちていた**。
**問題は「サーバが期待する alg を決めていなかった」こと**で、
**alg の選択肢を増やす段階（#129 の段階 2 以降）の前に決めておく必要があった。**

- **`kid` を引けないときに証明書へ落とす動きは、従来どおり**残した
  （`JwkSet.json` を置いていない配備でも、自分の鍵で検証できる）
- **E2E** : `RT-129.2`（`HS256` / `HS384` / `none` に書き換えたトークンを拒む。
  **関門は 3 つ**で、**発行しない alg**は即、拒否し、
  **発行する alg でも鍵（`kty` / `crv`）が合わなければ拒否**し、
  **鍵まで合っても署名が合わなければ拒否する**（`PS*` はここで落ちる））。
  **署名と `kid` はそのまま**にして**ヘッダの `alg` だけ**を書き換えるので、**alg の判定そのもの**を測れる
  （`TC-6.4` はヘッダを丸ごと作り替えるため、`kid` が消えて alg の判定まで届かない）
- **受ける集合を増やすときは、`RT-129.2` の一覧も直す**（黙って広がらないようにするため）

### C-9. CORS が全エンドポイントで `AllowAnyOrigin` **[Core]** — **✅ 修正済み（#265）**

**直す前。**

```csharp
// Startup.cs:Configure
app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
```

`OAuth2EndpointController` の `[EnableCors]`（ポリシー名なし）がこのインライン ポリシーに解決され、
**`/token` `/revoke` `/introspect` まで任意オリジンから叩けた**（実測）。
`AllowCredentials` は付いていないので Cookie は飛ばないが、
**任意のサイトの JS が、利用者のブラウザからトークン エンドポイントを直接呼べる**状態だった。

**直し方。** **既定のポリシーを置かず、口ごとに属性で選ぶ**ようにした。

| 口 | 方針 |
|---|---|
| `.well-known/openid-configuration` / `jwkcerts` / `samlmetadata` | **常に全開**（公開情報。`MpasPublicDocs`） |
| `/userinfo` / `/token` / `/SetDeviceToken` / `/ciba_result` / `/2fa_result` | **許すオリジンだけ**（`MpasBrowserApi`） |
| `/revoke` / `/introspect` / `/device_authz` / `/ciba_authz` / `/par` / `/ros` | **CORS を付けない** |

**許すオリジンは、登録から導く**（`CmnEndpoints.GetCorsAllowedOrigins`）。

**構成ファイルの public クライアント（`client_secret` を持たないもの）の `redirect_uri_*`** を
記号を解決してから `http` / `https` のオリジンだけ集める。
**SPA の `redirect_uri` は、必ずその SPA のオリジン上にある**ので、
**登録を足せば、CORS の設定を別に書かなくてよい。**
**Keycloak の Web origins の既定値 `+`（Valid Redirect URIs のオリジンを使う）と、
Entra ID の SPA プラットフォームと同じ考え方**である。
**追加分は `CorsAllowedOrigins`**（空でよい。導出で拾えないものを足す口）。

- **`AllowCredentials` は、どちらのポリシーにも付けない。**
  **Cookie で通る口をこの範囲に入れない**ため（入れると、他オリジンの JS から資格情報で呼べる）
- **画面登録（`saml2OAuth2Data`）も導出に含める**（#266）。
  全件を読む口を足し、**クライアント単位の登録項目 `web_origins`** を持たせた
  （**#270 で専用列に切り出したので、いまは `Saml2OAuth2DataProvider.GetAllUris`**。
  **JSON を全部読んで逆直列化するのをやめ、URI 関連の列だけを読む**）
  （**空なら `redirect_uri_*` から導出**。Keycloak の Web origins / Auth0 の `web_origins` に相当）。
  **許可オリジンはキャッシュしていた**（60 秒 ＋ 登録の保存で破棄）が、
  **✅ やめた（#271）**。**毎回作るので、登録の変更が即座に効く。**
  **捨てられない経路が 2 つあった** — 複数インスタンスの他のインスタンスと、
  **利用者の削除（`UsersAdmin`）で登録が FK で消える場合**。
  **#270 で読む量が URI 関連の 6 列だけになった**ので、キャッシュを置く理由が消えた
  （**重くなったときは `IDistributedCache`。#256 で使えるようになっている**）
- **3 重定義（E-3）も片付いた。** `AllowAllOrigins` は**自己テスト用の口だけ**が使う
  （`ValuesController` / `TestHybridFlow`。どちらも `IsLockedDownTestEndpoints` で経路ごと閉じる）
- **E2E** : **`RT-265.1`**（公開情報は全開／ブラウザから叩く口は導出したオリジンだけ／
  `/revoke` `/introspect` には付かない／`Allow-Credentials` を付けない）。**両系統に流す。**
  **旧挙動に戻すと落ちることを確かめてある**（`/revoke` が `*` を返す）
- **利用者への影響** : **挙動が変わる。**
  **任意オリジンから `/token` を叩いている SPA は、登録から導出されるか
  `CorsAllowedOrigins` に書かれていないと動かなくなる。**
  **`.well-known` / `jwkcerts` は従来どおり。**
  **サーバサイドの Web RP とネイティブ / モバイルは影響なし**（CORS はブラウザの仕組み）

> **net48 版も、同じ方針に揃えてある。**
> **仕組みは違う**（あちらは Web API の `[EnableCors]` ＝ `ICorsPolicyProvider` の属性）が、
> **外から見た振る舞いは同じ**である。**`RT-265.1` を両系統に流して固定している。**

### C-10. `redirect_uri` の比較が大文字小文字を無視 **[Lib]** — **✅ 修正済み（#263）**

**2 つの論点が同居していた。起票先を分けた。**

| | 論点 | 行き先 |
|---|---|---|
| 1 | **照合が大文字小文字を無視**（下記） | **✅ 修正済み（#263）** |
| 2 | **自己テスト用の抜け道**（下記） | **✅ 修正済み** |

#### 1. 照合が大文字小文字を無視（#263）— **✅ 修正済み**

```csharp
// 直す前（CommonLibrary/TokenProviders/CmnEndpoints.cs）
if (redirect_uri.ToLower() == preRegisteredUri.ToLower())
```

RFC 6749 §3.1.2.3 / OIDC Core §3.1.2.1 は **単純文字列比較（大文字小文字を区別）** を求める。
URI のパス・クエリは大文字小文字を区別するため、緩めた分だけ一致範囲が広がっていた。

**直し方**（`CmnEndpoints.CheckRedirectUri`）。

```csharp
if (string.Equals(redirect_uri, preRegisteredUri, StringComparison.Ordinal))
```

**URI 全体を比べる。** スキームとホストは RFC 3986 では大文字小文字を区別しないが、
**RFC 6749 §3.1.2.3 が指しているのは RFC 3986 §6.2.1（Simple String Comparison）**で、
**正規化しない比較**を求めているため、そこも揃っていなければ通さない。

**`post_logout_redirect_uri` の方は、#232 の時点から単純文字列比較だった**
（`StringComparison.Ordinal`。仕様が exactly match と書いているため）。
**`redirect_uri` だけが揃っていなかったので、揃えた。**

- **E2E** : **`RT-245.4`**（パスの大文字小文字だけが違う `redirect_uri` では、
  **認可コードを発行せず、その URI へリダイレクトもしない**）。
  **Skip を外した。** それまでは**実測で認可コードが発行されていた**（2026/09/29）
- **`/token` 側は元から完全一致だった**（`AuthorizationCodeProvider.CheckClientIdAndRedirectUri`）。
  **認可の入口だけが緩かった**ため、**コードは発行され、交換まで通っていた**
- **利用者への影響** : **挙動が変わる。**
  **登録と大文字小文字が違う `redirect_uri` を送っている RP は、認可に失敗するようになる。**
  **登録どおりに送っている RP には影響しない。** 設定キーの増減・DDL の変更は無し

#### 2. 自己テスト用の抜け道 — **✅ 修正済み**

`CheckRedirectUri` には
**「`Config.OAuth2ClientEndpointsRootURI + OAuth2AuthorizationCodeGrantClient_Manage` は
どの client_id でも無条件に許可」** という自己テスト用の抜け道があった。
`Config.IsLockedDownTestEndpoints` の対象外で、**本番で閉じられなかった。**

**宛先は配備自身の設定から組み立てる固定値**で、攻撃者が選べるわけではないため、
**深刻度は低いと評価していた。** 問題と見ていたのは**本番で閉じられないこと**である。

**直し方。** **特別扱いを無くした。**

| | |
|---|---|
| 足したもの | **`Const.TestSelfCodeManage`（`test_self_code_manage`）** — `GetRedirectUriFromConstr` が、管理画面の折り返し先に解決する |
| 消したもの | **「この URL なら登録を確かめずに通す」分岐**（`CheckRedirectUri`）。**例外は無くなった** |
| 画面 | **新規登録の `redirect_uri_code` の既定**を、この記号にした（両アプリの `Manage/AddSaml2OAuth2Data`） |

**管理画面の「トークンを取る」（`GetOAuth2Token`）は、利用者自身のクライアント登録で認可を要求する。**
**その折り返し先を登録値として表せるようにした**ので、**通常の照合に載り、分岐が要らなくなった。**

> **管理画面の「トークンを取る」は、その後に削除された。**
> **この画面は、管理画面からオンライン決済の WebAPI（`/ChageToUser`）を呼ぶためのもの**で、
> **決済そのものを落としたので、要らなくなった**（下の「オンライン決済サービスの取り下げ」）。
>
> **分岐を消したこと（この項の本体）は、そのまま効いている。**
> **記号 `test_self_code_manage` も落とし、新規登録の既定は `test_self_code` に戻した。**
>
> **`RT-C10.1` は残してある。** 測る中身を**「他のクライアントに登録されている URI は使えない」**
> に建て直した（**消した分岐が許していたのは、この形**である）。
> **`TC-1.3`（誰にも登録されていない URI）とは別の形**なので、両方要る。

- **E2E** : **`RT-C10.1`**（**登録していないクライアントは、この折り返し先では認可コードを得られない。
  登録しているクライアントは得られる**）。
  **分岐を戻して、両系統で落ちることを確かめてある**（戻すと `TestClient` がコードを得る）
- **`IsLockedDownTestEndpoints` に足していない。** **分岐そのものを消した**ので、
  ロックダウンの有無に関わらず迂回できない
- **利用者への影響** : **挙動が変わる。**
  **管理画面の「トークンを取る」は、`redirect_uri_code` にこの記号が登録されている必要がある。**
  **既存の登録では通らなくなる**（`invalid_request`）ので、画面で登録し直す。
  **新規登録は既定でこの値**になっており、**動作確認の後に自分の RP の折り返し先へ書き換える**使い方

> **クライアント 1 件に `redirect_uri_code` は 1 つ**なので、
> **本物の RP として使っている登録では、このボタンは使えない。**
> **自己テストのための便宜であり、そこは割り切っている。**

### C-11. Request Object（`/ros`）に有効期限もワンタイム性も無い **[Core][Lib]** — **✅ 修正済み（#188 / #229）**

> **#229 で、RFC 9126 の口（`/par`）を別に設けた。**
> `/ros` は**クライアント認証をしない**（署名だけ）ので、登録済みの鍵さえあれば誰でも預けられる。
> `/par` は**トークン エンドポイントと同じクライアント認証**を求める。**新しい RP は `/par` を使う。**
>
> **`/ros` は残す。** 一時は廃止を見込んでいたが、**RFC 9101（JAR）§5.2.1 が、この形を認めている。**
>
> > The client stores the Request Object resource either locally or remotely at a URI the
> > authorization server can access. **Such a facility may be provided by the authorization server** …
> > For example, **the authorization server may provide a URL to which the client POSTs the
> > Request Object and obtains the Request URI.**
>
> ただし **RFC 9101 は中身を何も規定していない**（認証方法も応答形式も）。
> したがって `/ros` は**相互運用できる口ではなく、この IdP の任意機能**である。
> FAPI 2.0 Security Profile は PAR を必須としているので、**本命は `/par`** という関係は変わらない。
>
> 廃止しないのであれば、**両アプリに二重に書かれたままにする理由も無い。**
> **✅ #235 で `CmnEndpoints.RegisterRequestObject` に集約した**（`/par` と CIBA の受け取りに続いて）。
> **振る舞いは変えていない**（署名だけを確かめ、クライアント認証はしない）。
> Controller に残るのは、本文の読み方（net48 は同期、net10.0 は非同期）と応答の包み方だけ。
>
> **CIBA での `request_uri` は、これとは別の話。**
> `/ciba_authz` が `request_uri` を受けるのは **CIBA Core に無い独自拡張**で（§7.1.1 は `request` で直接送る形。
> **初期のドラフトには `request_uri` があったが、最終版にも FAPI-CIBA にも無い**）、
> **#233 で `request` を直接受け取れるようにした**（`RT-233`）。
> `request_uri` の受け口は後方互換で残しているが、**こちらは将来外す。**
> （同梱の自己テストを `request` に移すには、Open棟梁 #592 の対応が要る）

修正前は、署名検証は行っていた（`RequestObject.Verify` / `VerifyCiba`）ものの、

- `RequestObjectProvider` は `CreatedDate` を書くだけで**読まなかった**
- `/ros` の応答が返す `exp` は **空文字列**（`exp = ""`）だった
- 認可エンドポイントで消費した後も **`Delete` が呼ばれなかった**（メソッドは在るが未使用）

コード中のコメント「存続期間は短く、好ましくは一回限」が、そのまま未実装項目になっていた。

**対応（#188 の段階 1・2）:**

| | 修正後 | E2E |
|---|---|---|
| 有効期限 | `Config.RequestObjectExpireTimeSpanFromSeconds`（既定 300 秒）で判定。`/ros` の応答の `exp` にも出す | `RT-188.3` |
| ワンタイム | **認可応答を作り終えた時点で消す**（`CmnEndpoints.ConsumeRequestObject`）。CIBA は `/ciba_authz` で消す | `RT-188.4` |

> **消す場所が要点だった。** 1 回の認可の中で、同じ `request_uri` を複数回読む
> （Controller の同意画面 → `AuthorizationCodeProvider.Create`）。
> **最初の読み取りで消すと、その認可自体が壊れる。**
> 読む回数を 1 回にまとめるのではなく、**応答を作り終えた時点で消す**ことで、
> 「2 回目の認可要求には使えない」を実現した。

### C-12. Cookie 認証の有効期限が 2 分にハードコード **[Core]** — **✅ 修正済み（#223）**

**直す前。** net10.0 版は 2 分固定だった。

```csharp
options.ExpireTimeSpan = new TimeSpan(0, 2, 0);
options.SlidingExpiration = true;
```

`Config.AuthCookieExpiresFromHours` / `AuthCookieSlidingExpiration` は
**net48 版（`App_Start/StartupAuth.cs:227,229`）でしか使われていなかった。**
Core 側は設定を無視して 2 分固定で、`SlidingExpiration` があるので操作中は延びるが、
**2 分放置するとサインアウトしていた**。設定の意味が失われていた。

**直し方**（`Startup.ConfigureServices`。コミット `2af1915`）。
**`ConfigureApplicationCookie` の中で、net48 と同じ設定キーを読む**ようにした。

```csharp
services.ConfigureApplicationCookie(options =>
    {
        // **net48 と同じ設定キーで揃える**（App_Start/StartupAuth.cs）。
        options.ExpireTimeSpan = Config.AuthCookieExpiresFromHours;
        options.SlidingExpiration = Config.AuthCookieSlidingExpiration;
```

**置き場所が本題だった。** 以前は `authenticationBuilder.AddCookie(options => ...)` に書いていたが、
**それはスキーム `Cookies` の設定で、サインインには使われていなかった**
（`AddIdentity` が既定を `Identity.Application` にするため）。
**`LoginPath` も含めて、書いた設定が 1 つも効いていなかった。**
`ConfigureApplicationCookie` は `Identity.Application` を設定するので、**ここに書いたことが効く。**

- **設定キーは両系統の雛形にあり、値も同じ**（`AuthCookieExpiresFromHours` = 336 時間 /
  `AuthCookieSlidingExpiration` = true）
- **`new TimeSpan(0, 2, 0)` は、どちらのアプリにも残っていない**
- **利用者への影響** : **設定が効くようになった。**
  **既定の雛形では 2 分から 336 時間（14 日）に伸びる**ので、**net48 版と揃う**

### C-13. DataProtection の鍵が永続化されていない **[Core]** — **✅ 修正済み（#251）**

> **対応（#251）。** **設定キー `DataProtectionKeyPath` を足し、
> 指定されていれば `PersistKeysToFileSystem` で鍵リングをそこに置く**ようにした
> （`Startup.ConfigureServices`）。**未設定なら従来どおり**（下位互換）。
>
> - **net48 の `machineKey` と同じ役割**だが、**鍵そのものは設定に書かない。**
>   **鍵は自動生成・自動ローテーションされ、共有するのは「置き場」**である
> - **効くのは「画面のセッション」** … 認証 Cookie / AntiForgery /
>   メール確認・パスワード リセットのリンク（`DataProtectorTokenProvider`）。
>   **access_token・id_token（JWS）／ PPID（`SaltParameter` から導出）／
>   認可コード・refresh_token（サーバ側のストア）には影響しない**
> - **鍵リングは平文の XML。** 置き場の保護は運用側の責任
>   （`ProtectKeysWithCertificate` は任意とした）
> - **実測** : キーを指定して起動すると、**その場所に `key-….xml` が書かれる**ことを確認した
> - **有効にした配備では、有効にした時点で 1 度だけ全員がサインアウトする**（鍵の置き場が変わるため）。
>   **以降は再起動に耐える**
>
> **`AddDistributedMemoryCache`（E-2）も ✅ 片付いた**（#256）。
> **`SessionStoreType` で `sql` / `redis` を選べる。**
> **DataProtection の鍵とセッションは別物**で、**両方そろって初めてスケールアウトできる。**

`services.AddDataProtection().PersistKeysTo***()` を呼んでいない。
既定では鍵はローカル プロファイル（コンテナでは揮発）に置かれるため、

- **再起動で認証 Cookie と AntiForgery トークンが全て無効になる**
- **複数インスタンスで動かすとインスタンス間で Cookie が通らない**

`AddDistributedMemoryCache`（[`MultiPurposeAuthSiteCore/ANALYSIS.md`](MultiPurposeAuthSiteCore/ANALYSIS.md) 4.3 節）と併せて、
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

### C-15. `response_type` の照合が文字列完全一致 **[Lib]** — **✅ 修正済み（#267）**

`response_type` は**順不同の空白区切り集合**（OAuth 2.0 Multiple Response Types §3。
**並びは意味を持たない**）。
**直す前は `response_type.ToLower() == "code id_token"` のような完全一致**で、
**`id_token code` と書く RP を `unsupported_response_type` で弾いていた。**

**扱いが混ざっていた。** **フローの判定は既に集合として見ていた**
（`GetFlowOfResponseType` が `Split(' ')` ＋ `Any`）のに、
**要求の検証・`redirect_uri` の選択・応答の振り分けが完全一致**だった。

**直し方。** **正規化を 1 か所に作り、入口で 1 回だけ掛ける。**

```csharp
// CmnEndpoints
public static string NormalizeResponseType(string response_type)
//   空白で分け、空を捨て、重複を除き、辞書順に並べて、空白 1 個で繋ぐ
```

**辞書順が、そのまま `OAuth2AndOIDCConst` の並びになる**（`code` < `id_token` < `token`）ので、
**定数側を変えなくてよい。**

| | |
|---|---|
| 掛ける場所 | **`ValidateAuthZReqParam` の入口**（`CheckRedirectUri` より前） |
| 渡し方 | **`ref string response_type`。** 呼び出し元の変数も正規化された値になるので、**この後ろの完全一致の照合は、そのままで正しくなる** |
| `ref` にした理由 | **呼び出し元を取りこぼさないため。** コンパイラが全ての呼び出し元（両アプリの `AccountController` ×2、`/par`）に `ref` を書かせる |
| 直していない場所 | `GetFlowOfResponseType` と `CmnEndpoints.cs:810`（**既に集合として見ている**） |

**`/par` は、正規化した値を payload に書き戻す**（預けた Request Object は `/authorize` で読み直すため）。

- **大文字小文字の扱いは変えていない。**
  **仕様では値は case-sensitive** だが、**以前から `ToLower()` していて `CODE` も通っていた。**
  **弾く範囲が変わるだけ**なので寛容さを残した（`Contributing.ja.md` の下位互換の方針）。
  #263 で `redirect_uri` を厳密にしたのは、**仕様が単純文字列比較を明示し、
  かつ照合の緩さが安全性に効く**ためで、性質が違う
- **E2E** : **`RT-267.1`**（`code id_token` / `id_token token` / `code token` /
  `code id_token token` の 4 組について、**並べ替えても同じ応答になる**）。
  **正規化を外すと、両系統で `unsupported_response_type` になって落ちることを確かめてある**
- **利用者への影響** : **通る範囲が広がるだけ。**
  **いま通っている `response_type` は、すべてそのまま通る。** Discovery の広告も変えていない

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

### C-17. 要求したスコープがそのまま発行される **[Lib]** — **✅ 修正済み（#198）**

基本テストケース（TC-1.4）で見つかった。

クライアントが要求した `scope` を、**そのままトークンに載せていた。**
Discovery の `scopes_supported` にも無い任意の文字列（`admin` `superuser` など）が、認可サーバの署名付きで発行された。

```
要求: roles userid auth admin superuser whatever → 発行: roles, userid, auth, admin, superuser, whatever
```

RFC 6749 §3.3 は「発行するスコープは要求と異なってよい」とし、**発行するスコープを認可サーバが決める**ことを前提にしている。

直すには 2 段階が要る。

1. **認可サーバが扱わないスコープを発行しない**（`scopes_supported` の範囲に収める）
2. **クライアントごとに、要求してよいスコープを制限する**（登録情報に、そのための項目が無い）

**対応（#198 の前半）:**

- `Helper.GetScopesSupported()` を新設し、Discovery の `scopes_supported` もこれを使うようにした（一覧を 1 か所に）
- `Helper.FilterSupportedScopes()` で、一覧に無いスコープを外してから Claim にする。
  発行の 6 経路（認可コード / Implicit / Hybrid / password / client_credentials / JWT bearer）が対象。
  device と CIBA は認可コードの経路を通る。拒否（`invalid_scope`）ではなく外す（RFC 6749 §3.3 が認める）
- 発行済みのトークンを読む経路（`CmnAccessToken.AddClaims`）は変えていない
- `/token` の応答に `scope` を返すようにした。発行したスコープが要求と異なる場合は必須（RFC 6749 §5.1）

**対応（#198 の後半）:**

- クライアントの登録（`OAuth2ClientsInformation`）に、任意の項目 `scope` を設けた。
  RFC 7591 §2 の client metadata と同じく、要求してよいスコープをスペース区切りで並べる
- 発行するスコープは「要求した」かつ「`scopes_supported` にある」かつ「登録の `scope` にある」もの
- **`scope` の登録が無いクライアントは制限しない**（`scopes_supported` の範囲だけ）。既存の登録を壊さないため
- 空文字列を登録すると、どのスコープも許さない
- 管理画面で登録したクライアント（saml2OAuth2Data）には、まだこの項目が無いので制限しない
- 動作確認用に、雛形へ `TestClient5`（`scope = openid profile email`）を追加した

E2E テスト: `TC-1.4`（認可コード）/ `RT-198.1`（client_credentials）/ `RT-198.2`（password）/
`RT-198.3`・`RT-198.4`（登録の `scope` による制限。client_credentials / 認可コード）。

**対応（#218 の 3 つ目）: JWT Bearer（RFC 7523）が、トークン要求の `scope` を見ていなかった。**

`GrantJwtBearerTokenCredentials` は **assertion の中の `scope` だけ**を読んでいた。
`scope` は RFC 7521 §4.1 / RFC 7523 §2.1 で**トークン要求のパラメタ**として定義されており、
**仕様どおり送るクライアントの指定が、黙って無視されていた。**

- **要求に `scope` があれば、それを使う。** 無ければ、これまでどおり assertion の値を使う
  （要求に `scope` を付けていない利用者を壊さないため）
- どちらも `FilterSupportedScopes` を通す（#198 の絞り込みは維持）
- E2E テスト : **`EX-7.5`**（送らないと `profile email`、`scope=email` を送ると `email` だけ。両ターゲットで実測）

> **残っている点:** Implicit / Hybrid の応答（フラグメント）には、まだ `scope` を返していない
> （RFC 6749 §4.2.2 は、要求と異なるなら必須）。

### C-18. Device AuthZ グラントが登録種別を判定していなかった **[Lib]** — **✅ 修正済み（#224）**

#224 の段階 0（未測定の経路を測る）で見つかった。

他のグラント（認可コード / refresh / ROPC / client_credentials / JWT Bearer / CIBA）は
`CheckClientMode` で登録種別（`client_mode`）を判定しているが、
**`GrantDeviceAuthZ` だけが呼んでいなかった。** 行っていたのはクライアント認証
（`DeviceAuthZClientAuthentication`）だけで、**client_secret が合えば、どの登録種別でもトークンを出していた。**

| 登録種別 | 修正前 | 修正後 |
|---|---|---|
| device / normal | 発行 | 発行（従来どおり） |
| **fapi1 / fapi2 / fapi_ciba** | **client_secret だけで発行** | **`unauthorized_client`（400）** |

**`fapi1` / `fapi2` / `fapi_ciba` の登録は、より強いクライアント認証を求めている**
（PKCE / private_key_jwt / mTLS）。この経路では、それを満たさずにトークンが出ていた。
x509 を渡していなかったので、`fapi2` でも**証明書に束縛されないトークン**になっていた。

**対応:**

- `CmnEndpoints.IsDeviceAuthZAllowed` を新設し、**`normal` と `device` の登録にだけ許す**
- **開始**（両アプリの `/device_authz`）で判定する … 利用者が `user_code` を承認した後で失敗させないため
- **トークン発行**（`GrantDeviceAuthZ`）でも判定する … 二重の防御
- エラーは `unauthorized_client`（RFC 6749 §5.2「認証済みのクライアントに許されていないグラント」）
- E2E テスト : **`FA-4.1`**（fapi1 / fapi2 / fapi_ciba は開始で拒否、normal / device は従来どおり）。
  **トークン発行側の判定は、開始側で弾かれるため到達できず、単独では測っていない**

> **#224 の段階 1 で、この判定も表（`ClientModePolicy`）の「Device AuthZ」の行に取り込んだ。**
> 許す種別（`normal` / `device`）は変えていない。段階 2 で、他の経路のエラー コードも `unauthorized_client` に揃えた。

### C-19. mTLS のトークンの紐づけ（`cnf`）が、形式違いで、照合もしていなかった **[Lib/Core/Net48]** — **✅ 修正済み**

#226（mTLS の E2E）の作業中に見つけた。**2 点あり、どちらも sender-constrained（RFC 8705）の要件を満たしていなかった。**

| | 修正前 | 修正後 |
|---|---|---|
| `cnf` の値 | キーは `x5t#S256` だが、**値は証明書の SHA-1 サムプリント（16 進 40 文字）**。キーの `#S256` / `#S512` も**証明書の署名アルゴリズム**で選んでいた | **証明書（DER）の SHA-256 を BASE64URL**（RFC 8705 §3.1）。キーは常に `x5t#S256` |
| `/userinfo` | **`cnf` を見ていない。** 証明書に紐づくトークンを、**証明書なしで受け付けていた** | 提示された証明書と照合し、合わなければ `invalid_token`（401） |

**紐づけは、トークンが漏えいした場合の防御である。** 照合していなければ、その防御は働かない。
RFC 8705 §3 は、保護されたリソースが照合することを求めている。
また、RFC のとおりに照合する外部のリソース サーバとは、値の形式が違うため紐づけが一致しない。

**対応:**

- `CmnAccessToken` に `VerifyCertificateBinding`（`cnf` と提示された証明書の照合）を新設
- 両アプリの `/userinfo` で照合する。**`cnf` の無いトークンは、これまでどおり bearer として扱う**
- 認証デバイス向けの口（`/ciba_result` `/SetDeviceToken` `/2fa_result`）でも、同じ照合を通す
  - **これらを叩く認証デバイス（`AuthenticationDevice_Web`）はパブリック クライアント**で、証明書を提示しない。
    そのトークンに `cnf` は載らないので、**既定の構成では振る舞いが変わらない**
  - それでも通すのは、**`cnf` を持つトークンを、この口に持ち込めてしまう**ため。
    とくに `/ciba_result` は CIBA の要求を「許可」する口で、CIBA のトークンは
    RP が mTLS で取れば `cnf` を持つ（`cnf` が載るのは、認可コード / `refresh_token` / CIBA の 3 経路）
  - **紐づいたトークンをこれらの口にも出す配置では、サーバ側で証明書を要求させる設定が要る**（`CONFIGURATION.md` 8 節）
- E2E テスト : **`FA-6.4`**（`cnf` の値が RFC の形式であること、同じ証明書なら 200、
  証明書なし・別の証明書なら `invalid_token`（401））

> **`/revoke` `/introspect` は、クライアント認証として証明書を見る口**（C-2）であり、
> ここで言う「保護されたリソース」ではない。

### C-20. `private_key_jwt` が、仕様と違う名前でしか通らなかった **[Lib][Core][NetFx]** — **✅ 修正済み（#238）**

**RFC 7523 §2.2 が定めるのは `client_assertion`**（＋ `client_assertion_type`）。
`assertion` は **JWT Bearer グラント**（§2.1）のパラメタで、別物である。

この実装は **3 つの口（`/token`・`/par`・`/ciba_authz`）で `assertion` を読んでいた**ため、
**仕様に従うクライアントは `private_key_jwt` で認証できなかった。**

**両方を受けるようにした**（`CmnEndpoints.GetClientAssertion`）。
`client_assertion` を優先し、無ければ `assertion` も読む
（Open棟梁 の既存のクライアントが `assertion` を送るため。OpenTouryo #592）。
`client_assertion_type` が来ていれば、値が RFC 7523 の URN であることを確かめる
（違えば「アサーション無し」として扱い、`invalid_client` になる）。

**同時に、`ClientModePolicy` の穴も塞いだ。**

| 経路 × 証明 | 通していた登録種別 | 修正後 |
|---|---|---|
| 認可コード × `private_key_jwt` | normal / fapi1 / device | **＋ fapi2** |

**FAPI 2.0 はクライアント認証を MTLS か `private_key_jwt` に限っている**のに、
`fapi2` は `client_secret` も通らないため、**mTLS を使えない fapi2 クライアントはトークンを取れなかった。**
表の該当行には「（E2E なし）」と書いてあり、**測っていなかったから残っていた**（#224 で引き継いだもの）。

**E2E に `private_key_jwt` の認証が無かったことが、両方の原因**である（`RT-238.1`〜`.4` で塞いだ）。

**受ける場所も限られていた**（#239 の段階 1・2 で広げた）。

| 口 / グラント | 修正前 | 修正後 |
|---|---|---|
| `/token` の `authorization_code` | 通る（#238） | 通る |
| `/token` の `refresh_token` / ROPC / `client_credentials` | **引数にアサーションが無い** | **通る**（`RT-239.1`） |
| `/revoke` / `/introspect` | **`client_assertion` を読んでいない** | **通る**（`RT-239.2` / `.3`） |

仕様は「**トークン エンドポイントと同じクライアント認証**」を求めている
（RFC 6749 §6 / RFC 7009 §2.1 / RFC 7662 §2.1）。
**失効できないと、漏れたトークンを止める手段が無い**ので、`/revoke` は特に効く。

**どの方式で来ても受ける入口**を作った（`CmnEndpoints.ClientAuthentication` の 3 つ目の版）。
アサーションのときは **`client_id` をアサーションの `iss` から得る**ので、
認証の後で client_id を使う処理（トークンとの紐付け、失効）も、そのまま正しく動く。

**`refresh_token` を `fapi1` / `fapi2` にも開いた**（#239 の段階 3）。

| 経路 × 証明 | 修正前 | 修正後 |
|---|---|---|
| `refresh_token` × `private_key_jwt` | normal | **＋ fapi1 / fapi2**（`RT-239.5`） |
| `refresh_token` × mTLS | normal | **＋ fapi1 / fapi2** |
| `refresh_token` × `client_secret` ほか | normal | normal（**変えない**） |

**`client_secret` では開かない。** FAPI は秘密ベースの認証を認めないので、
認可コードの行と同じ扱いにした。

**発行の側にも効く。** `MayUse` が false だと **refresh_token を発行しない**作りなので（#224 の段階 2）、
以前は **fapi1 / fapi2 は refresh_token を受け取れず**、
アクセス トークンが切れるたびに認可からやり直していた。

**表の並び順が意味を持つ。** `IsAllowed` は最初に当たった行を使うので、
**`Proof.Any` の行より前に、証明を限る行を置く**（`refresh_token` は 3 行になった）。

`client_credentials` / ROPC は `normal` のまま。**FAPI の対象外**で、ROPC は OAuth 2.1 で廃止（#220）。

これは「要否」の話ではない（要否は登録がコンフィデンシャルかで決まる。RFC 6749 §3.2.1）。
**方式の側の取りこぼし**を塞いだもの。

### C-21. Basic の資格情報を復号せずに照合していた **[Lib][Core][NetFx]** — **✅ 修正済み（#237）**

**RFC 6749 §2.3.1 は、`client_id` と `client_secret` を
`application/x-www-form-urlencoded` で符号化してから `:` で繋ぎ、Base64 にする**ことを求めている
（Appendix B に例がある）。受け側は、**復号してから照合する**必要がある。

この実装は復号していなかったため、**仕様に従うクライアントは、記号を含む秘密では認証できなかった。**

| 秘密に含まれる文字 | 符号化すると | 復号しないと |
|---|---|---|
| `+` | `%2B` | 一致しない（素朴に復号すると**空白**になる文字でもある） |
| `/` `=` `%` | `%2F` `%3D` `%25` | 一致しない |
| `:` | `%3A` | 一致しない（**符号化しない `:` は、Open棟梁 が最初の `:` で分ける**。RFC 7617 §2。OpenTouryo#643。下の注） |

**秘密は base64 で生成されるのが普通**なので、`+` `/` `=` は現実に現れる。
つまり**仕様どおりに送る相手ほど繋がらない**状態だった。

**復号後と復号前の両方と照合する**ようにした（`CmnEndpoints.GetBasicCredentials`）。
復号後で認証できなければ、復号前の値で扱う。
**符号化しないクライアントは配備済み**（Open棟梁 の従来のクライアントを含む）なので、
復号だけを入れると、そちらが繋がらなくなる。

**英数字だけの秘密では、符号化しても同じ文字列になる**。
このため**既存の E2E では現れず**（雛形の秘密は base64url の英数字）、
**記号を含む秘密のクライアントを用意して測る**ようにした
（`RT-237.1`〜`.4`。**種データで作る**。#264。もとの仕組みは #224）。

送り側（Open棟梁 の `CreateBasicAuthenticationHeaderValue`）は OpenTouryo #592 で符号化するようになった。
**送り側だけを直すと、受け側が復号しない認可サーバに繋がらなくなる**ため、
受け側の対応（この項）と対になっている。

`:` を含む秘密は、**符号化しなくても通る。** **Open棟梁 は最初の `:` で分ける**
（RFC 7617 §2。`:` を含められないのは user-id の側だけ。OpenTouryo#643）。
**以前は 3 つに割れて読めず「符号化したときだけ通る」だった**（`RT-237.3`）。

**復号前の値での照合（OpenTouryo#634 の H-3）は、Open棟梁 4.0 で既定ではやめる**（OpenTouryo#645）。
**記号（`+` など）を含む秘密を符号化せずに送るクライアントは、4.0 で繋がらなくなる**
（`RT-237.2` と `RT-237.4` の (2) が落ちる。`:` だけの `RT-237.3` は変わらない）。

これも C-20 と同じく**相互接続性の話**で、弱点を塞いだものではない。
Basic を受ける **6 つの口**（`/token`・`/revoke`・`/introspect`・`/device_authz`・`/ciba_authz`・`/par`）が、
**両アプリとも同じ入口を通る**ようにしたので、口ごとに直し忘れる形にはしていない。

### C-22. `code_challenge` を送った認可コードが、`code_verifier` 無しで交換できた **[Lib]** — **✅ 修正済み（#245）**

**RFC 7636 §4.6 は、認可要求に `code_challenge` が在ったなら、
トークン要求の `code_verifier` を検証することを求めている。**
無ければ発行してはならない（`invalid_grant`）。

**判定が、要求の側から見て行われていた。**
`CmnEndpoints.GrantAuthorizationCodeCredentials` の認証の分岐は
**「クライアントが何を送ってきたか」**で選ばれる。

| クライアントが送ったもの | 選ばれる分岐 | PKCE の検証 |
|---|---|---|
| `client_secret`（`code_verifier` 無し） | クライアント認証 | **呼ばれない** |
| `code_verifier` のみ | パブリック クライアント | `VerifyPkce` |
| `client_secret` ＋ `code_verifier` | 併用（#220） | `VerifyPkce` |
| `client_assertion`（`code_verifier` 無し） | クライアント認証 | **呼ばれない** |

**`code_verifier` を送らなければ、`VerifyPkce` を通らずに済む。**
`code` に紐づく `code_challenge` を見ていないため、**PKCE を付けた要求から出たコードでも、
クライアント認証だけで交換できた**（両アプリ。`CommonLibrary` なので実装は 1 つ）。

**C-7（#220 / #221 / #224）は、これとは別の 3 点**（同時送信・`plain`・権限判定との分離）を直したもので、
**「認可要求の側から必須性を決める」向きは含まれていなかった。**

**影響の範囲は、秘密・鍵・証明書を持つクライアントに限られる。**
**パブリック クライアント（`client_secret` 未登録）では成立しない。**
`ClientAuthentication` は `client_secret` も証明書も無ければ通らないので、
**`code_verifier` を省くと、認証そのものが失敗する**
（実測 2026/09/29、両系統 : **HTTP 401 / `invalid_client`**。`RT-245.3` の手順 4）。
**PKCE 以外に交換の手段が無い**ためである。

したがって、失われていたのは**多層防御の 1 枚**である。
**コードが漏れ、かつクライアントの資格情報も知られている**ときに、
**PKCE が最後の砦にならなかった**（コード横取り・注入に対して、OAuth 2.1 が PKCE に期待する役割）。
`require_pkce`（#221）で認可要求に `code_challenge` を必須化していた場合も、
**交換の側が緩かったため、その必須化は貫徹していなかった。**

**対応（#245 の段階 2）。** 認証の分岐の**後ろ**で、**コードに紐づく `code_challenge` の有無**を見て、
在れば `code_verifier` を必須にする（`CmnEndpoints.UsedPkce`）。
**`ReceiveChallenge` はコードを消さない**ので、交換の前に引いても後続の `Receive` に影響しない。

- **逆向き**（`code_challenge` 無しで `code_verifier` だけ送る）は、**従来から `VerifyPkce` が拒否する**
- **エラーは `invalid_grant`**（RFC 7636 §4.6）。クライアント認証自体は通っているため、`invalid_client` では意味がずれる
- **正当な経路は 1 つも塞がらない。** `code_challenge` を付ける自己テストの起点は
  **PKCE の 4 つと FAPI1 PKCE だけ**で、いずれも交換時に `code_verifier` を送る（実測で確認）
- E2E テスト : **`RT-245.3`**（欠落は `invalid_grant`。**正しい `code_verifier` なら通る**対照つき）

**`require_pkce`（#221）と合わせて初めて意味を持つ。**
`require_pkce` は**認可要求に `code_challenge` を必須化**し、この項は**そのコードの交換に
`code_verifier` を必須化**する。**片方だけでは、PKCE は素通りできた。**

### C-23. 外部 IdP の `email` を検証済みか確かめずにアカウントの突き合わせに使っていた **[Core][NetFx]** — **✅ 修正済み（#140 の段階 1）**

**外部 ID を既存のローカル アカウントに結び付けるとき、鍵になるのは `email` だった**
（`Config.RequireUniqueEmail` が true のとき `uid = email`）。
**上流が「検証した」と言っているかを確かめていなかった。**

| 経路 | 上流 | ロックダウンで閉じるか |
|---|---|---|
| **`ExternalLoginCallback`** | Microsoft / Google / Facebook / Twitter（SDK 経由） | **閉じない（常に有効）** |
| `IDFederationRedirectEndPoint` | 明示設定した 1 社（汎用認証サイト） | 閉じる |

**「連携キー」と「初回の突き合わせ」は別の話である。**

| | 何をするか | 何を使うか |
|---|---|---|
| 連携キー | 上流の人とローカルの人を**恒久的に対応づける**（`UserLogins`） | 上流の識別子（`sub` / `userid`） |
| **初回の突き合わせ** | リンクが無いとき、**既存アカウントに結ぶか**を決める | **ここでメアドを使っていた** |

**識別子（`public` / `pairwise`）の話ではない。** 受け取った識別子はそのまま保存すればよく、
**PPID を戻す必要も無い**（戻す必要があるのは発行した側だけ。#140 の論点 2 ＝ 段階 2）。

**対応（#140 の段階 1）。** 判定を `CommonLibrary` に置いた（**`Extensions.Sts.AccountLink`**）。

| 判定 | 動作 |
|---|---|
| メアドが鍵でない（`RequireUniqueEmail` が false） | **対象外。** 鍵は上流の識別子で、メアドは一致の確認にしか使っていない |
| メアドが鍵 ＋ 上流が `email_verified: true` | 結び付ける |
| メアドが鍵 ＋ **上流が言っていない / false** | **結び付けない。** 画面に理由を出し、`/Manage/ManageLogins` での明示的な追加へ誘導する |

- **新規に作るアカウントの `EmailConfirmed` も、言い値では true にしない**
  （以前は無条件に true。未検証のメアドが「確認済み」としてローカルに定着していた）
- 設定は **`RequireVerifiedEmailForAccountLinking`**。**未設定でも true（安全側）。**
  他の `Require*` と既定の向きが違うのは、**下位互換のために穴を開けたままにしない**ため
- **上流が汎用認証サイトなら `email_verified` は取れる**（`user.EmailConfirmed`。A-4 / #184 で真偽値に直してある）
- **Google は `email_verified` をクレームに写すようにした**（`Startup` / `StartupAuth`。#140 の段階 1）。
  **Google は実際にメアドを検証しているのに、既定ではクレームにしていなかった**ため、
  **検証している相手を拒否し続ける**ことになっていた
  （net10.0 は `ClaimActions.MapJsonKey`、net48 は `GoogleOAuth2AuthenticationProvider.OnAuthenticated`）
- **他の 3 つには足していない。** 判断材料が無いので、**拒否が正しい**

> **キーの綴りが、両アプリで違った**（#140 の段階 1 で踏んだ）。
>
> | | userinfo の口 | メアド検証のキー |
> |---|---|---|
> | net10.0（`AddGoogle`） | OIDC の `oauth2/v3/userinfo` | **`email_verified`** |
> | net48（Owin の `GoogleOAuth2`） | Google 独自の `oauth2/v2/userinfo` | **`verified_email`** |
>
> **net10.0 だけ通って net48 が通らない**症状になり、切り分けに 3 往復かかった。
> **net48 は両方の綴りを見る**ようにしてある。
>
> **教訓**。**同じ「Google」でも、ライブラリが叩く口が違えばキーが違う。**
> 症状が片系統だけに出たら、**まず「両アプリで同じ物を見ているか」を疑う。**
> **クレームが見つからないときは、実際のキー名をログに出す**（値は出さない）。
> 推測で直すより速い。

| プロバイダ | `email_verified` | 既存アカウントへの自動リンク |
|---|---|---|
| **Google** | **写すようにした** | **結び付く**（検証済みのときだけ） |
| Microsoft Account | Graph の `/me` に相当するクレームが無い | **結び付かない** |
| Facebook | `verified` は**アカウント**の検証で、メアドの検証ではない | **結び付かない** |
| Twitter | **メアド自体が返らない**のが普通 | **結び付かない** |

**結び付かない場合の代替は、ローカルでサインインしてから `/Manage/ManageLogins` で追加すること。**

**アカウント リンクに未検証のメアドを使わないのは OIDC の定石**であり、この実装に固有の事情ではない。

**検証（実測 2026/09/30。net48 / net10.0 の両方）。**

| 見たこと | 結果 |
|---|---|
| **拒否する側** : クレームを写す前に、既存アカウントと同じメアドで Google ログイン | **結び付かない**（両系統） |
| 画面の理由（`ViewBag.Reason`） | **出た**（日本語リソースも解決された。両系統） |
| **結び付く側** : クレームを写した後に、同じ手順 | **結び付いてサインインできた**（両系統） |
| ビルド | 両系統で エラー 0 / 警告 0 |
| 既存の E2E | 410 成功 / 失敗 0 / Skip 3（退行なし） |

**両方の分岐を、両系統で実機で確かめた。**

**外部ログインの経路は E2E で駆動できない**（4 プロバイダへのサインインが要る）ため、
**この判定は目視で確かめている。回帰は E2E で守られていない。**

>
> **ID フェデレーション経路なら E2E で測る目算がある**（設定がもともと
> 「別の汎用認証サイトを上流にする」前提で、`IdFederation` クライアントも雛形に登録済み。
> `-Launch` は既に 2 サイト立てている）。**上流に `EmailConfirmed = false` の利用者を置けば、
> 拒否側も測れる。** #140 の段階 2 で同じ土台が要るので、そこでまとめて作る。

### C-24. ID 連携で受け取る `id_token` の `aud` を確認していなかった **[Core][NetFx]** — **✅ 修正済み（#286 の段階 5）**

**`IdToken.Verify` は、この配備では `aud` を見ない。**

```csharp
// OpenTouryo : IdToken.Verify（iss と exp を確認した後）
if (string.IsNullOrEmpty(OAuth2AndOIDCParams.JwkSetFilePath))
{
    // Client側 : aud == ClientID か、ClientIDs に含まれるかを確認する
}
else
{
    // AuthZ側（検証用カバレッジ
    // OAuth2 AuthZバージョンの実装で成功   ← aud を確認せずに true
}
```

**「自分は認可サーバか」（`JwkSetFilePath` の有無）で分岐している**ため、
**この配備はクライアント役の経路でも認可サーバ側の枝に入る**
（`JwkSetFilePath` は認可サーバとして必要な設定である）。
**残るのは `iss`（`SpRp_Isser`）と `exp` だけ**だった。

**鍵の選び方（`CmnJwtToken.Verify`）と同じ分岐である**
（Open棟梁 [#601](https://github.com/OpenTouryoProject/OpenTouryo/issues/601)）。

**悪用できる経路ではなかった。** `id_token` は**上流の token エンドポイントから直接受け取る**もので
（TLS ＋ クライアント認証の back-channel。`code` と交換する）、**利用者が差し込める値ではない。**
**それでも、確認が 1 つ抜けていた。**

| | ID 連携（OIDC） |
|---|---|
| `state` | 照合していた（セッション） |
| `nonce` | 照合していた（セッション） |
| PKCE（`code_verifier`） | 送っていた（#140 の段階 3） |
| 認可応答の `iss`（RFC 9207） | 照合していた（#140 の段階 3 ＝ E-11） |
| `id_token` の `iss` / `exp` | `IdToken.Verify` が見ていた |
| **`id_token` の `aud`** | **見ていなかった** |

**SAML2 の ID 連携は `Audience` を照合している**（`CmnSaml2Response` の `expectedAcsUrl`。#276）。
**OIDC 側だけが抜けていた。**

**対応（#286 の段階 5）。** **判定を `CommonLibrary` に置き**（**`Extensions.Sts.IdTokenAudience`**）、
**両アプリの `IDFederationRedirectEndPoint` で、`IdToken.Verify` の直後に確認する。**

| | |
|---|---|
| 期待値 | **`OAuth2AndOIDCParams.ClientID`**（**開始処理が `client_id` に使った値**と同じもの） |
| `aud` の形 | **文字列でも配列でもよい**（RFC 7519 4.1.3 / OIDC Core 2）。**配列なら、その中に在ればよい** |
| 無い / 空 | **通さない**（`aud` は OIDC Core が必須としているクレームである） |
| `azp` | **見ない。** **上流に 1 つのクライアントとして登録される**ので、`aud` が自分を含むことだけを確認する |
| 失敗したとき | **エラー画面**。**ログは既存の形に 1 項目足した**（`aud matched`。#253） |

**Open棟梁 側の変更は要らない。** **`IdToken.Verify` が `out JObject` でペイロードを返す**ので、
**呼び出し側で確認できる。**

> **その後、ライブラリ側でも確認されるようになった**
> （[OpenTouryo#603](https://github.com/OpenTouryoProject/OpenTouryo/issues/603)。
> **設定で判定する版も、`aud` が `OAuth2AndOidcClientID` / `OAuth2AndOidcClientIDs` を含むことを見る**）。
> **この項の確認は残してある** — **「その回のクライアント宛か」を厳密に見ており**
> （ライブラリ側は「設定のどれかのクライアント宛か」）、
> **落ちた理由がログの 1 行で分かる**（`aud matched`）ためである。

**検証（実測 2026/10/12。net48 / net10.0 の両方）。**

| 見たこと | 結果 |
|---|---|
| ビルド | 両系統で エラー 0 / 警告 0 |
| 既存の E2E（通し） | **583 成功 / 失敗 0 / Skip 2**（退行なし。**上流は `aud` を正しく入れている**） |
| **歯抜け** : 期待値を別の値に差し替えて流す | **`RT-140.4` / `RT-140.5` が両系統で落ちた**（`RT-140.6` / `RT-140.7` は通ったまま） |
| そのときのログ | `(verified: True, nonce matched: True, aud matched: False)` — **落ちた理由が 1 行で分かる** |

**歯抜けは、期待値の差し替えで測っている。**
**上流に「別の宛先の `id_token`」を出させる口が無い**ため
（`aud` は上流が `client_id` から決める）、**E2E の常設ケースは足していない。**

---

### C-25. mTLS で、登録が空のときに空の Subject DN が一致していた **[Lib]** — **✅ 修正済み（#305 の段階 4）**

**クライアント認証の mTLS の分岐が、登録値を確かめずに突き合わせていた。**

```csharp
// 修正前
if (x509.Subject == Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id))
```

**`GetTlsClientAuthSubjectDn` は、登録が見つからなければ `""` を返す**
（`tls_client_auth_subject_dn` を登録していないクライアントと、未登録の `client_id` が該当する）。
**`X509Certificate2.Subject` は、Subject DN が空の証明書では `""` になる**
（RFC 5280 は `subjectAltName` が在る場合に空の Subject を認めている）。

**両方が `""` で一致し、クライアント認証が通った。**

| | |
|---|---|
| **`client_secret` 側は起きない** | **前段に `!string.IsNullOrEmpty(client_secret)` が在る**（空の秘密では、この分岐に入らない） |
| **通った後** | `/revoke` / `/introspect` は**互換版の入口**で `CheckClientMode` を通らないため、**クライアント認証だけで決まる**。`/token` は `ClientModePolicy` の `Flow.ClientCredentials` × `Proof.Any` → `normal` に当たる |

**発火の前提**（**雛形の配備では成立しない**）。

| | |
|---|---|
| **サーバがクライアント証明書を要求する設定になっていること** | **雛形のままでは要求しない**（#226 で実測。`CONFIGURATION.md` 7 節） |
| TLS 層がその証明書を受け付けること | 信頼の設定次第 |
| 対象の `client_id` に Subject DN が登録されていないこと | **`fapi2` 以外は通常登録していない** |

**登録が空なら通さないようにした。**

```csharp
// 修正後
string registeredDn = Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id);

if (!string.IsNullOrEmpty(registeredDn)
    && x509.Subject == registeredDn)
```

**E2E の常設ケースは足していない。**
**空の Subject DN を持つ証明書を、TLS 層に受け付けさせる仕掛けが要る**ためである
（`Tests/MtlsTestHook` は**発行元を問わずに受け付ける**が、**証明書そのものは用意が要る**）。
**C-24 と同じく、ここは読み取りで見つけたものである。**

> **段階 4 の本題（送信元を鍵に混ぜる）で `ClientAuthentication` を読み直したときに気付いた。**
> **`AuthFailureProvider.Record` を「登録されているクライアントのときだけ」に絞る**作業で、
> **登録の有無を見る必要が出たため、同じ関数の照合も見直した。**


### C-26. 独自 scope の `userid` が、`pairwise` のクライアントにも全体で共通の利用者 Id を渡していた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**`userid` scope を要求すると、`user.Id` がそのまま `userid` クレームとして載っていた**
（access_token は `CmnAccessToken`、/userinfo は両版の `OAuth2EndpointController`）。

**`pairwise` のクライアントには、`sub` を PPID（クライアントごとに違う値。A-14）で返している。**
**ところが `userid` は、どのクライアントにも同じ値を返す。**
**そのため、PPID が防いでいる「クライアントをまたいだ利用者の突き合わせ」を、`userid` で打ち消せた。**

| | |
|---|---|
| **クライアントごとの scope の登録（C-17。#198）** | **登録が在れば、その範囲に絞られる。** **登録が無ければ制限しない**ので、既定では出ていた |
| **`public` のクライアント** | **`sub` が `user.Id` そのもの**なので、`userid` は**同じ値の重複**でしかない |
| **MPAS の中で読む所** | **無い。** ID 連携の旧い鍵（`userid`）からの移行で読んでいた枝は、**上流へ `userid` を要求しない**（#140 の段階 3）ので通らず、先に削除した |

**`userid` を scope ごと廃止した。**

- **Discovery** : `scopes_supported`（`Helper.GetScopesSupported`）と `claims_supported`（`CmnEndpoints`）から外した
- **発行** : access_token（`CmnAccessToken`）と /userinfo（両版）で `userid` を載せる分岐を消した
- **`auth` scope の絞り込み**（`Helper.FilterClaimAtAuth`）で `userid` を残す分岐も消した
- **要求されても、宣言外の scope として外される**（C-17 と同じ扱い。エラーにはしない）
- **自己テストの要求**（`Const.StandardScopes`）からも外した。**使うのが自己テストだけなので、名前も `SelfTestScopes` にした**
- **下位互換は取らない。** `userid` を使っていた RP は、**`sub` を使う**（`public` なら同じ値。`pairwise` なら、それが意図どおりの値である）

**E2E** : **`RT-198.1`** の期待値から `userid` を外した（**要求には残してある** ＝ **宣言外として外されることを測る**）。
**`RT-307.25`** の「上限の外の scope」の候補からも外した（`scopes_supported` に在る値から選ぶため）。
**原本の `scopes_supported` の期待値**が変わった（`TESTCASES.md`）。

> **`Const` の整理（#294）で `StandardScopes` の中身を確かめたときに気付いた。**
> **`roles` は残した** — **自前の資源サーバ（Web API）で使う可能性を考えて**である。
> **ロールそのものは access_token に載らない**（`scopes` には scope 名だけが載る）ので、使うなら /userinfo から取る。

### C-27. 独自 scope の `auth` で、どのクライアントも同意画面を飛ばせた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**`auth` は MPAS 独自の scope** で、**付けると同意画面を出さずに code を返す**（認証だけに使う。発行は `auth` と `openid` に絞る）。

**`AccountController.OAuth2Authorize`（両版）が、要求された scope をそのまま見ていた。**
**登録の scope の絞り（C-17。#198）は、その後の発行で掛かる**ので、判定には効いていなかった。
**そのため、登録に `auth` が無いクライアントでも、要求に付けるだけで同意画面を飛ばせた。**
**同意を求めるかを、要求する側が決めていた**ことになる（#272 の同意の記録とも無関係に飛ぶ）。

| | |
|---|---|
| **渡るもの** | **`sub` など認証の結果だけ**（属性は `FilterClaimAtAuth` で落ちる） |
| **それでも問題になる理由** | **利用者が同意していないクライアントに、誰がサインインしたかが伝わる**（`prompt=none` なら画面も出ない） |
| **大文字小文字** | **小文字にしてから比べていた**ので、`AUTH` でも飛ばせた（scope は case-sensitive。RFC 6749 §3.3） |

**`client_registration`（#307 の段階 1）と同じく、倒し方を逆にした** — **登録に明記したクライアントにだけ出す。**
**同意画面を飛ばしてよいかは、登録を管理する人が決める**（Keycloak の「Consent Required」、Auth0 の first-party の同意の省略と同じ考え方）。

- **判定** : `Helper.FilterSupportedScopes(scopes, client_id)` を通した後に `auth` が残るかで見る（両版の `OAuth2Authorize`）。**小文字化をやめた**
- **発行** : `FilterSupportedScopes` が、`auth` を**登録に明記していなければ外す**（`client_registration` と同じ枝）
- **動的登録** : `auth` を登録しようとすると `invalid_client_metadata` で断る（**自分で付けさせない**）
- **下位互換** : **`auth` で同意画面を飛ばしていたクライアントは、登録の `scope` に `auth` を足す**。足さなければ初回に同意画面が出る（**`prompt=none` だけで動くなら、初回は `consent_required`**）。CONFIGURATION.md 4 節

**E2E** : **`RT-294.1`〜`.3`**（登録に無ければ飛ばさない／明記すれば飛ばす／`AUTH` は別物）。
**`RT-198.1`** の期待値から `auth` を外した（**`MVC_Sample` は登録に scope が無い**ので、外れるのが正しい）。
**`RT-307.4`** に「`auth` も動的登録では付けられない」を足した。
**種データに `TestClient_29`**（登録の scope に `openid auth`）を足した。

> **`ConsentProvider` を読み直したときに、同意の判定の手前で `auth` が素通りしていることに気付いた。**

### C-28. メアドの確認待ちの利用者を、他人が登録し直してパスワードを差し替えられた **[Core][NetFx]** — **✅ 修正済み（#294）**

**サインアップ（`AccountController.Register`。両版）は、作成に失敗すると、同じメアドの利用者を探し、**
**メアドの確認が済んでいなければ（外部ログインも無ければ）、その利用者を消して、送られてきたパスワードで作り直していた。**

```csharp
// 修正前: MultiPurposeAuthSiteCore/Controllers/AccountController.SignUp.cs（net48 版も同じ）
ApplicationUser oldUser = await UserManager.FindByEmailAsync(email);
// … oldUser が確認待ちなら
result = await UserManager.DeleteAsync(oldUser);
result = await UserManager.CreateAsync(user, model.Password);
this.SendConfirmEmail(user);
```

| | |
|---|---|
| **起きること** | **本人が登録してから確認のリンクを踏むまでの間に、他人が同じメアドで登録し直すと、パスワードが差し替わる。** **確認のメールは本人に届く**ので、**本人が踏むと、差し替えたパスワードのまま確認済みになる** |
| **失敗の理由を見ていなかった** | **パスワードの規則違反・利用者名の重複でも、古い利用者を消していた。** **作り直しも同じ理由で失敗するので、利用者が消えるだけで終わった** |
| **作り直した利用者** | **ロール（`User` / `Admin`）が付かず、`signed up` のログも出なかった** |

**作り直しをやめた。** **確認待ちの利用者が既に在れば、その利用者に確認のメールを送り直すだけにする**（**画面は成功のときと同じ**）。
**パスワードは変わらない**（忘れていれば、パスワードの失念から戻せる。確認前でもリセットできる）。
**確認済み・外部ログイン済みの利用者は、従来どおり作成が重複で失敗する。**

**E2E** : **`RT-294.4`**（同じメアドで別の利用者名で登録し直しても、元の利用者が残り、新しい利用者は作られない）。

### C-29. パスワードの失念の画面で、メアドが登録されているかが分かった **[Core][NetFx]** — **✅ 修正済み（#294）**

**`AccountController.ForgotPassword`（POST。両版）のコメントには「ユーザーが存在しないことを（UI経由で）公開しない」と書いてあった**が、
**居なければ入力画面を出し直し、居れば確認画面（`ForgotPasswordConfirmation`）を出していた。**
**画面の違いで、メアドが登録されているかが分かった。**

**どちらも確認画面を返す**ようにした（**メールは居るときだけ送る**）。

**E2E** : **`RT-294.5`**（居ないメアドでも、居るメアドと同じ確認画面になる）。

### C-30. パスワード リセットの画面が、code を確かめずに利用者のメアドを出していた **[Core][NetFx]** — **✅ 修正済み（#294）**

**`AccountController.ResetPassword`（GET。両版）は、`userId` で利用者を引き、code を見ずに、そのメアドを画面に出していた。**
**`userId` が分かれば、code が何でもメアドが読めた**（`userId` は GUID で、既定の `sub` は利用者名なので、外から知るのは難しい）。

**code を確かめてから画面を出す**ようにした（`VerifyUserTokenAsync`。**合わなければエラー画面**）。

**E2E** : **`RT-294.7`**（code が合わなければエラー画面で、メアドが出ない）。

### C-31. メアド検証・パスワード リセットのメールを、他人の受信箱へ何度でも送らせられた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**サインアップ・パスワードの失念は、利用者名かメアドが分かれば、誰でも何度でも押せる。** **押すたびにメールが飛んだ。**
**口ごとのレート制限（#305 の段階 3）は送信元ごとに数える**ので、**宛先が 1 つでも、送信元を変えれば止まらない。**

**宛先（利用者）ごとに数える `Extensions/Sts/MailThrottle` を足した。**
**同じ利用者・同じ用途のメールは、`MailResendIntervalSeconds` 秒に 1 通まで**（雛形は 60。**0（未設定）なら絞らない**）。
**断っても画面は変えない**（**送ったかどうかを画面から分からせない**）。CONFIGURATION.md の「メールの送り過ぎ」。

**E2E では測れない**（送ったかどうかを画面に出さない作りのため）。

### C-32. WebAuthn のサインインで、ロックアウトが効いていなかった（UTC と現地時刻を比べていた） **[Core]** — **✅ 修正済み（#294）**

**WebAuthn のサインイン（`AccountController.Login` の `webauthn_signin`。net10.0 版だけ）は、ロックアウトを自前で判定していた。**

```csharp
// 修正前: MultiPurposeAuthSiteCore/Controllers/AccountController.SignIn.cs
if (user.LockoutEndDateUtc != null
    && DateTime.Now <= user.LockoutEndDateUtc)
{
    signInStatus = AspNetId.SignInResult.LockedOut;
}
```

**`LockoutEndDateUtc` は UTC の値**（`CmnUserStore.SetLockoutEndDate` が `DateTimeOffset.DateTime` を入れる）**なのに、`DateTime.Now`（現地時刻）と比べていた。**
**日本時間（UTC+9）のサーバでは、9 時間より短いロックアウトが、この経路では効かなかった**
（パスワードの失敗でロックされた利用者が、WebAuthn でならすぐにサインインできた）。
**資格情報の持ち主が引けないときは `null` のまま参照していた**（例外は `catch` で受けるので、500 にはならない）。

**判定を `UserManager.IsLockedOutAsync` に任せた**（パスワードの経路と同じ判定になる）。**持ち主が引けなければ `Failed`。**

**E2E では測れていない**（net10.0 版で WebAuthn を有効にして回す E2E が無い）。

### C-33. 確認待ちの利用者には、パスワードを確かめる前に確認のメールを送り、違う文言を返していた **[Core][NetFx]** — **✅ 修正済み（#294）**

**サインイン（`AccountController.Login` の `normal_signin`。両版）は、メアドの確認が済んでいない利用者を見つけると、**
**パスワードを確かめる前に確認のメールを送り、「メアドを確認して下さい」の文言（`Login_emailconfirm`）を返していた。**

| | |
|---|---|
| **見分けられる** | **利用者名かメアドが分かれば、パスワード無しで「確認待ちのアカウントが在る」ことが分かった**（居なければ `Login_Error`） |
| **送らせられる** | **押すたびに、その利用者へ確認のメールが飛んだ**（C-31 と同じ形） |
| **数えていない** | **この枝では、パスワードの失敗を数えていなかった**（ロックアウトに掛からない） |

**パスワードが合ったときだけメールを送り、`Login_emailconfirm` を返す**ようにした。
**合わなければ、利用者が居ないときと同じ `Login_Error`**（**ロックアウトが有効なら、失敗を数える**）。
**ロックアウト中なら、ロックアウトの画面**（`PasswordSignInAsync` と同じ扱い）。

**E2E では測れていない**（確認待ちの利用者でサインインするテストが無い）。

### C-34. TOTP・回復コードでサインインしたとき、セッションを初期化していなかった **[Core]** — **✅ 修正済み（#294）**

**サインインが成り立った後は、`InitSessionAfterlogin` でセッションを初期化する**
（パスワード・コードの 2FA・プッシュ承認・WebAuthn・ID 連携）。**TOTP（認証アプリ）と回復コードの 2 か所だけ、呼んでいなかった**（net10.0 版。net48 版に TOTP は無い）。

| 抜けていたもの | 起きること |
|---|---|
| **セッション ID の切り替え** | **サインインの前後で、同じセッション ID のまま**（セッションの固定化への対策が効かない） |
| **`auth_time` の Cookie** | **`auth_time` が分からない**ので、`DateTimeOffset.MinValue` で埋まる（`max_age` を付けた認可要求は「古すぎる」になる） |
| **OP のセッションの Cookie**（#310） | **`sid` が出ず、Front / Back-Channel Logout の伝え先とつながらない** |

**ほかに、同じ 2 か所に次の穴があった**（どれも net10.0 版）。

- **1 回間違えると、戻り先を失った**（再表示で `ViewData["ReturnUrl"]` を渡さず、認可要求の続きに戻れない）
- **ロックアウトが 404**（`RedirectToAction("Lockout")`。`Lockout` はアクションではなく画面）
- **2FA の途中でなくても、画面が開いた**（確かめるコードがコメントアウトされていた）

**成功したら `InitSessionAfterlogin` を呼び、サインインをログに残す**ようにした。**ほかの 3 つも直した。**

**E2E** : **`RT-294.8`〜`.11`**（TOTP・回復コードでサインインすると `auth_time` と OP のセッションの Cookie が書かれる／1 回間違えても戻り先へ戻る／2FA の途中でなければエラー画面／ロックアウトの画面になる）。
**認証アプリの役は、テストが RFC 6238 で計算して務める。**

> **回復コードの E2E を足したところで、`CmnUserStore.UpdateTotpToken` の不具合も見つかった。**
> **`case EnumUserStoreType.Memory:` に `break` が無く、DB の枝へ落ちていた**ので、**mem ストアでは回復コードを使うと 500 になった。**

### C-35. 2FA のプッシュ承認を待つスクリプトが、`ReturnUrl` を符号化せずに埋め込んでいた **[Core][NetFx]** — **✅ 修正済み（#294）**

**コードの入力画面（`Views/Account/VerifyCode.cshtml`。両版）は、手段が MobileApp のとき、**
**承認を待つスクリプト（`TwoFactorPushStatus` へのポーリング）を出す**（#213 / #216）。
**そのスクリプトが、`ReturnUrl` を JavaScript の文字列リテラルへ、符号化せずに埋め込んでいた。**

```javascript
// 修正前: MultiPurposeAuthSiteCore/Views/Account/VerifyCode.cshtml（net48 版も同じ）
+ '?returnUrl=' + encodeURIComponent('@Html.Raw(Model.ReturnUrl)')
```

**`ReturnUrl` は要求から来る値**（サインイン画面の URL から `SendCode` → `VerifyCode` へ引き継がれる）**で、**
**`Html.Raw` は HTML の符号化も外す**ので、**値によってはスクリプトとして解釈され得た**（反射型のスクリプト注入）。

**JavaScript の文字列として符号化して埋め込む**ようにした
（net10.0 版は `Json.Serialize`、net48 版は `HttpUtility.JavaScriptStringEncode(…, true)`。**どちらも `<` `>` `&` `'` を逃がす**）。
**あわせて、「ブラウザを記憶」のチェックボックスを、問い合わせのたびに読む**ようにした（読み込んだ時点の値に固定されていた）。

**E2E では測れていない**（プッシュ承認の画面は、認証デバイスを登録した利用者でないと出ない）。

> **`TwoFactor.cs` のレビューの指摘 6（`rememberMe` を渡す）で、同じ行を直すときに気付いた。**

### C-36. メールの送信に失敗すると、プロセスが落ちえた（`async void`） **[Core][NetFx]** — **✅ 修正済み（#294）**

**メアド検証・パスワード リセット・完了の通知のメールは、`AccountController.Helper`（両版）の 4 つのメソッドで送る。**
**どれも `async void` で、呼ぶ側（サインイン・サインアップ・パスワードの失念とリセット）は待っていなかった。**

```csharp
// 修正前: MultiPurposeAuthSiteCore/Controllers/AccountController.Helper.cs（net48 版も同じ形）
private async void SendConfirmEmail(ApplicationUser user)
{
    code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
    callbackUrl = this.Url.Action(..., protocol: HttpContext.Request.Scheme);
    await EmailSender.SendAsync(user.Email, subject, ...);
}
```

**本番（`IsDebug=false`）では、`CmnEmail.SendAsync` が `SmtpClient.Send` を同期で呼ぶ。**
**SMTP の失敗**（サーバの停止・資格情報の誤り・宛先の拒否）**は例外になり、`async void` では呼ぶ側へ戻らない。**

| | 起きること |
|---|---|
| **net10.0 版** | **同期コンテキストが無いので、スレッドプールの処理されない例外になり、プロセスが終了する** |
| **net48 版** | **要求の完了と競合し、処理されない例外になる** |
| **両版** | **トークンの生成が非同期のとき**（DB ストア）、**要求が終わった後に `HttpContext` / `Url` を触る** |

**サインアップとパスワードの失念は、認証なしで誰でも押せる。**
**SMTP が落ちている間は、押すだけで IdP を止められた**（可用性。2FA のコード送信は #214 で直していたが、こちらは残っていた）。

**送信を要求から切り離した**（`SendMailInBackground`）。

- **トークンと URL は、要求の中で作り終える**（呼ぶ側は `await` する。`HttpContext` / `UserManager` を後から触らない）
- **送信だけを別のタスクで行い、失敗は受け止めて記録する**（OPERATION ログに「could not be sent」。利用者の id と例外の型だけ）
- **応答の時間が、送ったかどうかで変わらない**（C-29 の「存在を明かさない」と両立する）
- **送れなかった分は、`MailThrottle` の間隔に数えない**（C-31。`Release`）
- **net48 版は `EmailService` を直接使う**（`UserManager` は要求の後に破棄されるので、`UserManager.SendEmailAsync` は使わない）

**E2E** : **`RT-294.14`**（両版）。**`IsDebug` のとき、宛先が `@e2e-mail-failure.invalid` なら `CmnEmail` が送信を例外にする**
（`CmnEmail.FailureDomainForTest`。RFC 2606 の `.invalid`。**本番では効かない**）。
**そのメアドでサインアップとパスワードの失念を通し、画面が普段どおりで、その後もサイトが応えることを見る。**

> **`AccountController.Helper.cs` のレビューで気付いた。** 完了メールは、文面のファイルが無いと空のメールを送っていたので、それも止めた（送らずに記録する）。

### C-37. `/device_verify` の承認が、AntiForgery トークンを検証していなかった **[Core][NetFx]** — **✅ 修正済み（#294）**

**Device Authorization Grant の利用者の画面（`AccountController.DeviceAuthZVerify` の POST。両版）は、**
**画面にトークンを埋めていたが、アクションに `[ValidateAntiForgeryToken]` が無く、検証していなかった。**

**認証まわりの Cookie は `SameSite=None` で出している**（CONFIGURATION.md の「https で動かすこと」）ので、
**別のサイトから送られた POST にも Cookie が付く。**
**サインインしている利用者のブラウザから、本人が意図しない `user_code` の承認を送らせることができた**
（承認すると、その `user_code` の機器に、利用者の権限でトークンが出る。RFC 8628 §5.4 が挙げる類いの攻撃）。

**属性を付けた**（画面は既にトークンを送っているので、正しい利用には影響しない）。

**E2E** : **`RT-294.15`**（トークン無しの POST では承認されず、機器は `authorization_pending` のまま）。

### C-38. Implicit と Hybrid は、同意を確かめずにトークンを発行していた **[Core][NetFx]** — **✅ 修正済み（#294）**

**同意の判定**（`ConsentProvider.HasConsent`・`prompt=consent` / `none`・同意画面）**は、`OAuth2Authorize`（GET。両版）の**
**`response_type=code` の分岐の中にしか無かった。**
**Implicit と Hybrid の分岐は、サインインしていれば、同意の記録が無くてもそのままトークンを発行した。**

| | |
|---|---|
| **C-3（#272）との関係** | **「同意していなければ `prompt=none` は `consent_required`」が、この 2 つには効いていなかった** |
| **影響の範囲** | **Implicit は既定で無効**（#220）だが、**Hybrid は無効にできない**（#314） |

**同意の判定を、3 つのフローで共通にした**（同意の記録が無ければ同意画面、`prompt=none` なら `consent_required`）。
**同意画面の「許可」（POST）も、`response_type` に応じて発行する**ようにした（以前は code しか返さなかった）。

**E2E** : **`RT-294.16`**（同意の記録が無い Hybrid は、`prompt=none` で `consent_required`、無ければ同意画面）。

### C-39. `auth_time` と再認証の印を、署名の無い Cookie で持っていた **[Lib][Core][NetFx]** — **✅ 修正済み（#294）**

**`max_age` の判定（`CmnEndpoints.CheckAuthTime`）と、id_token / access_token に出す `auth_time` は、平文の Cookie（`auth_time`）から読んでいた。**
**`prompt=login` / `max_age` の繰り返しを止める「再認証の印」（`re_auth_at`）も、平文の Cookie が有るか無いかしか見ていなかった。**

```csharp
// 修正前: MultiPurposeAuthSiteCore/Controllers/AccountController.SignIn.cs（net48 版・ManageController も同じ形）
Response.Cookies.Set(Config.AuthTimeCookieName,
    FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);
```

| | 起きること |
|---|---|
| **ブラウザ側で書き換えられる** | **`max_age` / `prompt=login` が求める再認証を飛ばし、偽の `auth_time` を RP に保証した** |
| **印がどの要求にも効いた** | **再認証の途中でやめると印が残り、後で別の RP が送ってきた `prompt=login` が、再認証なしで通った** |
| **壊れた値** | **`DateTime.Parse` が例外を出し、500 になった** |

**どちらの Cookie も、改ざんできない形で包む**ようにした（`Extensions/Sts/AuthTimeCookie`。
**net10.0 : DataProtection**（#251 で鍵を永続化）／**net48 : `MachineKey.Protect`**）。**開けない値は、無いものとして扱う。**
**再認証の印は、それを求めた認可要求に結び付けた**（クエリから作る指紋。**別の要求の `prompt=login` には効かない**）。

> **更新した直後は、平文の古い Cookie が開けない**ので、「認証時刻が分からない」として扱う
> （`max_age` を付けた要求なら、一度だけ再認証になる）。

**E2E** : **`RT-294.17`**（`auth_time` を平文に書き換えても `max_age` の再認証は飛ばせない）、
**`RT-294.18`**（印を平文で置いても `prompt=login` の再認証は飛ばせない）、
**`RT-272.8`**（再認証の後は同じ要求で戻るとコードが返り、別の要求の `prompt=login` はまた再認証になる）。

> **`AccountController.Authorize.cs` のレビューで気付いた**（C-37〜C-39）。**同じレビューで、次も直した。**
> **JARM の `aud` / `exp` / `iss`**（Implicit が入れていなかった。JARM §2.1）、**使えない `response_mode` で `error` が空のまま返る**、
> **Request Object と違う `client_id` を確かめずに上書き**（RFC 9126 §4）、**同意画面のボタンが無い POST**。
> **応答の組み立ては 1 か所にまとめ、認可エンドポイントの本文は両版で同じにした**（E2E : `RT-294.19`〜`.22`）。

### C-40. コンフィデンシャル クライアントの code を、`code_verifier` だけで引き換えられた **[Lib]** — **✅ 修正済み（#294。方法を明示した登録で閉じる）**

**`CmnEndpoints.GrantAuthorizationCodeCredentials`** は、**`code_verifier` が在り `client_secret` が無い要求を、PKCE だけで認証が済んだものとして扱っていた。**
この分岐は **`ClientAuthentication` も `AllowsAuthMethod` も呼ばない。**
`ClientModePolicy` の表は「認可コード × PKCE S256 → normal / fapi1 / device」を通すので、
**`client_secret`（や鍵）を登録したクライアントの code も、この分岐で引き換えられた**
（RFC 6749 §4.1.3 は、コンフィデンシャル クライアントの認証を MUST としている）。

**対応 : PKCE だけで引き換えられるのは、`token_endpoint_auth_method` が空か `none` の登録だけにした**（`MayUsePkceOnly`）。

| 登録 | `code_verifier` だけ |
|---|---|
| **`none`**（パブリックの明示。#294 で受けるようにした） | **通す** |
| **空**（明示しない） | **通す**（**従来どおり**） |
| **それ以外**（認証の方法を明示した） | **通さない**（`invalid_client`） |

**空を通すのは、既定の挙動を変えないため**である。**雛形の SPA / ネイティブ アプリのクライアントは、秘密を持ったまま PKCE だけで引き換えている**
（E2E の `FA-1.1` や `PkceTests` も同じ）。**閉じたいクライアントは、方法を明示する**（`CONFIGURATION.md`）。

> **残り : 方法が空の登録は、秘密を持っていても PKCE だけで通る。**
> **雛形の SPA / ネイティブから秘密を外し `none` を登録すれば、既定でも閉じられる**（雛形と E2E の書き換えを伴う）。

**同じ分岐に、逆向きの不具合も在った**（`code_verifier` が在ると `client_assertion` と証明書を見なかった）。A-16 の N1。

**E2E** : **`RT-294.52`**（方法を明示した登録は PKCE だけでは `invalid_client`、`none` は PKCE だけで通り、秘密では通らない）、
**`FA-2.1`**（fapi2 の PKCE だけの拒否が `unauthorized_client` から `invalid_client` に変わった）。

### C-41. PAR に預けた Request Object の `client_id` を、認証したクライアントと照合していなかった **[Lib]** — **✅ 修正済み（#294）**

**`CmnEndpoints.PushedAuthorizationRequest`** は、`request`（JAR）で預けるとき、**`iss` が認証したクライアントであることは確かめていた**が、
**中の `client_id` は確かめていなかった。** その後の検証（`ValidateAuthZReqParam`）と保存は、**中の `client_id` で行っていた**ので、
**別のクライアントの名義で、PAR に預けた要求を作れた**（RFC 9126 §2.1 / RFC 9101 §6.3）。

**中の `client_id` が認証したクライアントと違えば `invalid_request_object`、無ければ認証したクライアントで埋める**（フォームの経路と同じ）ようにした。

**E2E** : **`RT-294.57`**。

### C-42. 他のクライアントが出した refresh_token を、消費してから断っていた **[Lib]** — **✅ 修正済み（#294）**

**`GrantRefreshTokenCredentials` は、`RefreshTokenProvider.Receive`（消費・ローテーション）の後で、`aud`（発行先）を見ていた。**
**他のクライアントが出しただけで使用済みになり、持ち主が次に使うと「使用済みの再提示」と見なされ、一族ごと失効した**（#188 の段階 3）。

**消費する前に、`Refer`（読むだけ）で発行先を照合する**ようにした。**使用済み・存在しないものは、従来どおり後の `Receive` が断る。**

**E2E** : **`RT-294.48`**（他のクライアントが出すと `invalid_grant`、持ち主はその後も更新できる）。

### C-43. Basic の資格情報の照合で、失敗を 2 回数えていた **[Lib]** — **✅ 修正済み（#294）**

**`CmnEndpoints.GetBasicCredentials`** は、復号の前後どちらを使うかを決める照合に **`ClientAuthentication` を渡していた。**
**あちらは失敗を数え、成功で数えた分を消す**（#305 の段階 2）ので、**記号を含む値で 1 回間違えると、2 回と数えられていた**
（**この後に呼び出し側が、もう一度認証する**）。**remarks には「副作用は無い」と書いてあった。**

**照合は数えない `MatchesClientSecret` にした。** **方法（`token_endpoint_auth_method`）とロックアウトは、その後の本番の認証で見る。**

> **E2E では測っていない**（上限の手前の数を外から読めない）。**読んで直した。**

### C-44. client_credentials / JWT Bearer のトークンが、クライアントと同じ名前の利用者に結び付いていた **[Lib]** — **✅ 修正済み（#294）**

**`GrantClientCredentials` / `GrantJwtBearerTokenCredentials` は、トークンの主体にクライアント名（`ClientName`）を渡し、**
**`PPIDExtension.GetSubForOIDC` がその名前で利用者を引いていた。** **居れば、その利用者の `sub` になった。**

**`ClientName` はラベルである。** 動的登録・管理画面の登録では**登録の時点の所有者の利用者名**が入り、**名前を付け替えても追従しない**（#307 の段階 5-a の決め）。
そのため、**付け替えた後に同じ名前を取った別の利用者に、クライアントのトークンが結び付いた**（`/userinfo` やリソース サーバは、その利用者として扱う）。
**構成ファイルのクライアント名**（`MVC_Sample` など）**と同じ名前で利用者が登録された場合も**同じである。

**利用者名を渡さないようにした**（**`sub` は常にクライアント名**）。**client_credentials は資源所有者の居ないトークン**である（RFC 6749 §4.4）。
**動的登録の client_credentials 経路**（#307 の段階 5-b）は、**所有者を `OwnerUserId` / `owner` 属性から引く**ので、影響しない。

**E2E** : **`RT-294.50`**（同じ名前の利用者を作っても、`sub` はクライアント名で、`/userinfo` はその利用者のメアドを返さない）。

### C-45. 秘密の照合と利用者の有無で、応答の時間に差が出ていた **[Lib]** — **✅ 修正済み（#294）**

| | 修正前 | 修正後 |
|---|---|---|
| **`client_secret` の照合** | `==`（**最初に食い違った所で止まる**） | **全部を比べてから答える**（`FixedTimeEquals`。net48 に `CryptographicOperations` が無いので自前） |
| **ROPC で利用者が居ない** | **パスワードを照合せずに返す**（ストレッチの分だけ速い） | **誰のものでもないハッシュと照合してから返す**（`VerifyDummyPassword`。応答の文面は以前から揃っている。TC-4.2） |

> **E2E では測っていない**（時間の差は環境で揺れる）。**読んで直した。**

### C-46. `/ros` に預けた Request Object の `client_id` を、署名したクライアントと照合していなかった **[Lib]** — **✅ 修正済み（#294）**

**C-41（PAR）と同じ形が、`/ros`（`RegisterRequestObject`）にも残っていた。** **署名（`iss`）だけを確かめ、中の `client_id` は確かめていなかった**ので、
**自分の鍵で署名した Request Object を、別のクライアントの名義で預けられた**（`/authorize` は、要求の `client_id` と Request Object の `client_id` だけを突き合わせる）。

**中の `client_id` が `iss` と違えば預からない（400）、無ければ `iss` で埋める**ようにした（PAR と同じ扱い。RFC 9101 §6.3）。

**E2E** : **`RT-294.59`**。

> **`CmnEndpoints.*.cs` の 2 回目のレビュー（C-40〜C-45・A-16・B-12）で、判断して見送ったもの。**
> **`client_assertion` / JWT Bearer の `assertion` の `jti` による使い切り**（RFC 7523 §3 は MAY）、
> **パブリック クライアントの PAR**（RFC 9126 §2 は認める）、**Hybrid の `code token` の `nonce` を任意にする**（OIDC Core §3.3.2.1 は OPTIONAL。#190 で必須にした）。
> **設計の変更が要るものは E-13 / E-14 に残した。**

### C-47. 利用者名を変えても、WebAuthn の資格情報が元の名前に残っていた **[Lib][Core]** — **✅ 修正済み（#294）**

**WebAuthn の資格情報は、利用者名で持っている**（`FIDO2Data.UserName` と、`StoredCredential.UserId`（利用者名の UTF-8））。
**サインインは、資格情報から利用者名を引き、その名前で利用者を引く**（`AccountController.SignIn` → `FIDO.DataProvider.GetUserByCredential` → `FindByNameAsync`）。

**`ManageController.ChangeUserName` と `UsersAdminController.Edit`（net10.0 版）は、利用者名を変えても資格情報を移していなかった。**

| | 起きること |
|---|---|
| **本人** | **変えた後は、自分の資格情報でサインインできない** |
| **元の名前** | **資格情報が元の名前に残る**（その名前の利用者が後で作られると、その利用者に結び付く） |

**利用者名を変えるときに、資格情報も新しい名前へ移す**ようにした（`FIDO.DataProvider.RenameUser`。**`UserHandle` は変えない** —
認証器が持っている値であり、サインインで照合する）。**管理画面で利用者を消すときも、資格情報を消す**ようにした（GDPR の削除は以前から消していた）。
**表の形は変えていない**（利用者の id で持ち直すことはしない）。

**E2E** : **`RT-294.62`**（種データの利用者の名前を変えると、資格情報が付いて来て、作り直された元の名前の利用者には 0 件）。

### C-48. 管理画面で外部ログインを結び付けると、ブラウザ記憶(2FA)を発行していた **[NetFx]** — **✅ 修正済み（#294）**

**`ManageController.ExternalLoginCallback`（net48 版）は、外部ログインを結び付けた後の再サインインで `rememberBrowser: true` を渡していた。**
**結び付けただけで、そのブラウザでは以後 2FA が求められなくなった。**
**再サインイン（`ReSignInAsync`）の同じ不具合は 2026/09/17 に直していた**（net48 版 `ANALYSIS.md`）が、**ここは残っていた。**

**`rememberBrowser: false` にした。** net10.0 版は、同じ引数を渡していない。

> **E2E では測っていない**（外部ログインの上流が要る）。**読んで直した。**

> **`ManageController.*.cs` のレビューで気付いた**（C-47 / C-48）。**同じレビューで、次も直した**（両版。TOTP は net10.0 版だけ）。
>
> | | 以前の振る舞い | 直した形 |
> |---|---|---|
> | **メアドの変更** | **変わったかを利用者名と比べていた**（#151 の名残）。同じメアドも、他の利用者のメアドも、**何も言わずに出し直した** | **いまのメアドと比べる**。同じなら文言、**他の利用者のメアドなら送らずに確認の画面**（使われているかを分からせない）（`RT-294.61`） |
> | **利用者名・メアドの変更のパスワードの確認** | **サインインそのもの**（`PasswordSignInAsync`）で確かめたので、**2FA を有効にした利用者は必ず失敗**。パスワードの無い利用者は通せず、**間違えても文言が無い** | **サインインしない確認**（ロックアウトは数える）。パスワードが無ければ、先に設定するよう文言を出す |
> | **外部ログインの結び付け**（`ExternalLoginCallback`） | **name / email が無いと 500**、**利用者名と照合**（利用者名がメアドと違うと結び付けられない）、**クレームがたまる**、**他の利用者に結び付いた外部ログインなら、その利用者のクレームを書き換えて成功のように戻る** | **`AccountController` に揃えた**（email は必須・name は任意、メアドで照合、`ReplaceClaimAsync`、他の利用者なら `AccountConflictInSocialLogin`） |
> | **未登録の provider**（`ExternalLogin`） | **500**（net10.0 版） | **外部ログインの管理画面へ戻す**（両版） |
> | **外部ログインの解除**（`RemoveLogin`） | **最後のサインインの手段も消せた**（画面がボタンを隠すだけ）。**消せなくてもクレームを消した** | **パスワードが無く外部ログインが 1 つなら断る**。クレームは消せてから消す |
> | **メールの送信** | **`async void`**（C-36 と同じ）。**続けて送れた**。**文面が無いと空のメール** | **`SendMailInBackground`**、**`MailThrottle`**（メアドの変更・電話番号の SMS）、**文面が無ければ送らない** |
> | **TOTP の登録** | **画面を開いただけで鍵を保存**（管理画面は登録済みと出し、サインインの手段にも出た）。**`CanEdit2FA` で閉じていなかった**。**鍵のリセットで SecurityStamp を変えなかった** | **コードを確かめてから保存**（`RT-294.60`）し、2FA も有効にする。**2FA の設定で閉じる**。**リセットで SecurityStamp を更新** |
> | **利用者の削除**（`CmnUserStore.Delete`） | **mem では同意が残った**。**持っていたクライアントへの、他の利用者の同意が残った**（DB でも） | **どちらも消す**（`ConsentProvider.DeleteByUser` / `RevokeByClient`） |
>
> **パスワードの確認は、既定の配備では行わない**（`RequirePasswordInEditingUserNameAndEmail`）ので、**E2E では測っていない。**
> **外部ログインの結び付けと解除も、上流が要るので測っていない**（読んで直した）。

### C-49. 管理画面でサインインし直すだけで、`auth_time` を「いま」にしていた **[NetFx][Core]** — **✅ 修正済み（#294）**

**`ManageController.ReSignInAsync`（両版）は、サインインし直すたびに `auth_time` の Cookie を現在時刻で書いていた。**
**この Cookie は、`max_age` の判定（`CmnEndpoints.CheckAuthTime`）と、id_token の `auth_time` に使われる。**

**`ReSignInAsync` を呼ぶ操作の多くは、資格情報を確かめていない**（2FA の有効化・無効化、電話番号の削除、非構造化データ・クライアント登録の保存と削除、
外部ログインの解除、TOTP の鍵のリセットなど）。**そのため、認証していないのに `auth_time` が新しくなり、RP が `max_age` で求めた再認証が行われないまま通っていた**
（OIDC Core §2 の `auth_time` は「利用者が認証した時刻」）。

**`ReSignInAsync` は `auth_time` を書かない**ようにし、**書くのは資格情報を確かめた所だけ**にした（`WriteAuthTime`。**パスワードの再確認・パスワードの変更・外部ログインの結び付け**）。
**`AccountController.Authorize` の注**（「サインインし直した時に書く」）も直した。

**E2E** : **`RT-294.63`**（パスワードを確かめた直後は `max_age=2` で先へ進み、2FA の有効化（サインインし直すだけ）の直後は再認証を求める。両版）。

> **`ManageController.*.cs` の 2 回目のレビューで気付いた**（C-49）。**同じレビューで、次も直した**（両版。TOTP は net10.0 版だけ）。
>
> | | 以前の振る舞い | 直した形 |
> |---|---|---|
> | **2FA の無効化・電話番号の削除・外部ログインの解除** | **セッションだけで行えた** | **パスワードを確かめる**（`VerifyPasswordAsync`。**パスワードの無い利用者は、先に設定するよう文言を出す**）（`RT-294.64`） |
> | **TOTP の未確定の鍵**（TempData） | **利用者に結び付いていなかった**（TempData の Cookie はサインアウトでは消えず、**同じブラウザで後からサインインした利用者に、前の利用者が見た鍵を出していた**） | **利用者の id と組にして置き、合うときだけ使う**（`RT-294.65`） |
> | **メアドの変更** | **SecurityStamp を更新しなかった**（変更前のメアドに送ったパスワード リセットのリンクや、ほかのセッションが使えた）。**完了の通知は新しいメアドだけ** | **SecurityStamp を更新し、完了の通知を変更前のメアドにも送る** |
> | **メール・SMS の間隔**（`MailThrottle`） | **利用者ごとに数えた**（打ち間違いを直して送り直しても、正しい宛先へ届かない） | **管理画面のメアドの変更・電話番号の追加は、宛先ごとに数える**（`TryAcquireForDestination`。ログには宛先を書かない） |
> | **SMS の送信の失敗** | **500**（間隔も使い切った） | **記録して、間隔に数えない**（メールと同じ） |
> | **利用者名・メアドの更新の失敗** | **mem ストアでは、失敗した値が利用者に残った**（引いた利用者がそのまま保存の実体）。利用者名の失敗は理由を出さなかった | **元の値に戻す**。利用者名は理由（重複など）を出して再表示 |
> | **クレームの入れ替え**（`ReplaceClaimAsync`。Account と Manage） | **種類だけで消した**（ほかのプロバイダのクレームまで消えた） | **同じ発行元の分だけ消す** |
> | **外部ログインの結び付けの戻り** | **始めた利用者と照合していなかった**（net48 は入れるだけ、net10.0 は入れてもいなかった）。**外部ログインの Cookie が残った** | **利用者の id で照合し、Cookie を捨てる** |
> | **クライアント登録の作成**（管理画面） | **既に在る `client_id` だと、mem は何もせず「成功」、DB は 500** | **文言を出して再表示**（構成ファイルのクライアントとも重ねない） |
> | **再サインイン** | **「アカウント記憶」を外していた**（`isPersistent: false` 固定） | **いまのサインインの値を引き継ぐ** |
> | **GDPR の削除**（net10.0 版） | **WebAuthn の資格情報を先に消した**（利用者の削除に失敗すると、資格情報だけが無くなる） | **利用者を消せてから消す** |
>
> **E2E で測っていない**もの : 電話番号の削除・外部ログインの解除のパスワード（SMS・上流が要る。**同じ補助を通るので、2FA の無効化で代表させた**）、
> メアドの変更の通知と SecurityStamp、宛先ごとの間隔、SMS の失敗、mem での値の戻し、クレームの入れ替え、結び付けの照合、`client_id` の重複、アカウント記憶（**読んで直した**）。

### C-50. 認証アプリの登録画面が、登録済みの鍵を何度でも出していた **[Core]** — **✅ 修正済み（#294）**

**`ManageController.EnableTwoFactorAuthenticator`（GET）は、鍵が保存済みなら、その鍵を共有鍵と QR コードとして画面に出していた**（`LoadSharedKeyAndQrCodeUriAsync`）。
**保存済みかどうかで画面を閉じていなかった**（管理画面に導線は無いが、URL を開けば出た）。**セッションさえあれば、認証アプリと同じコードを作れた。**

**登録済みなら、登録画面は出さずに `ManageTwoFactorAuthenticator` へ戻す**ようにした（POST も同じ）。**出すのは保存する前の鍵だけ**で、**登録し直すときはリセットを通す。**

**E2E** : **`RT-294.66`**。

### C-51. サインインの手段を足す操作と、2FA を弱める操作が、セッションだけで通っていた **[NetFx][Core]** — **✅ 修正済み（#294）**

**C-49 の後に、2FA の無効化・電話番号の削除・外部ログインの解除にはパスワードの再確認を入れた**が、**同じ理由で次も危うかった。**

| 操作 | セッションだけで起きたこと | 直した形 |
|---|---|---|
| **パスキーの登録**（`AddWebAuthnData`。net10.0） | **それだけでサインインできる資格情報を足せた** | **段階 0 でパスワードを確かめる**（段階 1 は、段階 0 で Session に置いた options が無いと通らない）（`RT-294.69`） |
| **回復コードの再発行**（net10.0） | **それだけで 2FA を通れるコードが画面に出た** | **パスワードを確かめる**（`RT-294.67`） |
| **認証アプリのリセット**（net10.0） | **2FA の手段を外せた** | **パスワードを確かめる**（`RT-294.67`） |
| **電話番号の追加** | **自分の電話番号を 2FA の手段として足せた** | **パスワードを確かめてから、検証コードを作る**（`VerifyPhoneNumber` はそのコードが無いと通らない） |
| **メアドの変更** | **既定の設定（`RequirePasswordInEditingUserNameAndEmail` が false）では確かめず**、**変えた後にパスワード リセットで乗っ取れた** | **設定によらず確かめる**（利用者名の変更は、従来どおり設定に従う）（`RT-294.68`） |

**パスワードを持たない利用者（外部ログインだけ）は、先にパスワードを設定してもらう**（C-49 の後の再確認と同じ）。

> **E2E で測っていない**もの : **電話番号の追加**（SMS が要る。**同じ補助（`CheckPasswordForEditingAsync`）を通る**）。**読んで直した。**

### C-52. net10.0 版の mem ストアで、外したロールが外れていなかった **[Core]** — **✅ 修正済み（#294）**

**Identity Core は、正規化した名前（大文字）をストアに渡す。**
**`CmnUserStore.RemoveFromRole` の mem の分岐は、それを `Name` と突き合わせていた**ので、**ロールが見つからず、何もせずに成功を返していた。**
**`UserManager.RemoveFromRolesAsync` の事前の `IsInRole` は通る**（大文字にそろえて比べる）ので、**管理画面は「編集できた」と出し、ロールは残った。**
**SystemAdmin を外しても、管理画面を開けたままだった。**

**付ける方（`AddToRole`）は #257 で `NormalizedName` に直してあったが、外す方が漏れていた。** net48 版（正規化しない）と DB ストア（`NormalizedName` 列と突き合わせる）は正しかった。
**mem は本番の構成ではない**が、**雛形の既定（`appsettings.json`）は mem である。**

**`NormalizedName` と突き合わせる**ようにした（net10.0 の mem）。

**E2E** : **`RT-294.70`**（**直す前の実装で、net10.0 版が落ちることを確かめた**）。**`RT-257.9` は「付ける」しか測っていなかった。**

### C-53. SQL Server では、外部ログインの `sub` / NameID を大文字小文字を区別せずに照合していた **[NetFx][Core]** — **✅ 修正済み（#294）**

**`CmnUserStore.Find`（外部ログインで利用者を引く）は、`ProviderKey` を SQL の `=` で比べていた。**
**比べ方は DB の照合順序に従い、スキーマは照合順序を指定していないので、SQL Server の既定（大文字小文字を区別しない）になる。**
**上流が大文字小文字だけが違う `sub` / NameID を別の人に振ると、同じローカルの利用者に結び付いた**（mem / ora / npg は区別していた）。

**結び付けた値を読み直して、C# の側で Ordinal に比べ直す**ようにした（`LoginProvider` も同じ）。**スキーマは変えていない。**

> **E2E では測っていない**（E2E は mem ストアで回すため）。**読んで直した。**
>
> **同じレビューで直した不具合**（セキュリティ以外）:
>
> | 場所 | 以前 | いま |
> |---|---|---|
> | **利用者の一覧**（`Users`） | **読み取りに失敗すると 500**。mem は検索条件と件数を無視していた | **空の一覧を返す**。mem も DB と同じく絞る |
> | **ロールの一覧**（`GetRoles`） | **失敗すると null を返し、`IsInRole` が落ちた** | **空の一覧を返す** |
> | **クレームの削除** | **DB は値を見ずに型ごと消し、mem は参照で比べていた** | **型・値・発行元で消す**（両方） |
> | **外部ログイン・クレーム・トークンの一覧** | **DB では、渡された利用者の一覧を更新せず**、トークンは読むたびに重なった | **mem と同じく一覧も揃える** |
> | **回復コード** | **コードが 0 件のとき、空のコードが一致した**（画面の `[Required]` が止めていた） | **ストアでも断る** |
> | **ロックアウトの終了日時** | **`.DateTime` で保存**（UTC 以外を渡されるとずれる） | **`.UtcDateTime`** |
> | **利用者の削除** | **持っていたクライアントへの同意を、削除の前に消していた**。メアド変更の確認待ちが残った | **削除できてから消す**。確認待ちも消す |
> | **`UpdateRoles`** | **呼ばれておらず、トランザクションも確定しない実装だった** | **削除した** |

### C-54. 利用者を消しても、パスワードを変えても、refresh_token で access_token を取り続けられた **[NetFx][Core]** — **✅ 修正済み（#294）**

**`RefreshTokenDictionary` には利用者の列も外部キーも無く**、利用者を消しても行が残った（mem でも DB でも）。
**`CmnEndpoints.GrantRefreshTokenCredentials` は、預けた payload から access_token を作り直すだけで、利用者を確かめていなかった**
（ローテーションで新しい refresh_token も出し続けた）。**パスワードを変えても（SecurityStamp が変わっても）、同じだった。**

**更新のときに、`sub` から利用者を引き、SecurityStamp を照合する**ようにした（`CheckUserOfRefreshToken`）。

| 断る場合 | 見分け方 |
|---|---|
| **利用者が消された** | **`sub` から利用者を引けない**（sub の対応表は、利用者と一緒に消える） |
| **SecurityStamp が変わった**（パスワードの変更・リセットなど） | **発行のときに預けたハッシュと合わない**（`BindUserOfRefreshToken`） |

- **預けるのは SecurityStamp の SHA-256**（値そのものは預けない）。**access_token と照会の応答には載せない**（外してから使う）。
- **照会（`/introspect`）も、更新で断られるものは `active=false`** にした。
- **消費（`Receive`）の後で断る**ので、新しいものは出ず、**一族はそこで終わる。**
- **この確認を入れる前に発行した refresh_token**（ハッシュが無い）は、**利用者が居るかだけを見る**（次の更新でハッシュが入る）。
- **STS 専用モードでは見ない**（`FindById` が毎回作り直す試験用の利用者で、SecurityStamp が定まらない）。
- **DDL は変えていない。** **発行済みの access_token は、期限まで残る**（短命なので許容した）。

**E2E** : **`RT-294.71`**（消した利用者）・**`RT-294.72`**（パスワードの変更。照会も見る）。**確認を外した実装で、両版とも落ちることを確かめた。**

> **同じレビューで直した不具合**（セキュリティ以外）:
>
> | 場所 | 以前 | いま |
> |---|---|---|
> | **関連情報の読み込み**（`CmnStore.SelectChildTablesOfUser`） | **Oracle で値の無いクレームを読むと例外になり**、**後に読む外部ログインと TOTP のトークンが読み込まれなかった** | **NULL を空文字で受ける** |
> | **TOTP のトークンの追加** | **DB に入れる前に一覧へ足していた** | **入れた後で足す** |
> | **外部ログインを外す**（SQL Server） | **大文字小文字だけが違う組も消えた** | **`COLLATE Latin1_General_BIN2` で比べる**（足す側の PK は照合順序に従うので、そこは DDL が要る） |
> | **ロールの一覧**（DB） | **渡された利用者の一覧を更新しなかった** | **揃える** |
> | **net48 の mem** | **利用者名・メアドを大文字小文字を区別して引いた** | **区別しない**（SQL Server の既定に揃える） |
>
> **回復コードを同時に使うと 2 回使える**件は、**#316（楽観排他）に含めた**。

### C-55. 認証デバイス用の口が、どの RP に発行したアクセス トークンでも通っていた **[NetFx][Core]** — **✅ 修正済み（#294）**

**`/SetDeviceToken`・`/ciba_result`・`/2fa_result`（`OAuth2EndpointController`）は、
トークンの署名・縛り（証明書・DPoP）と、`sub` から利用者を引けることだけを見ていた。**
**発行先のクライアント（`aud`）もスコープも見ていなかった。**
**認証デバイス（`AuthenticationDevice_Web`）は `openid email` で取ったトークンを使う**ので、
**利用者が同意したどの RP のトークンでも、同じ口を叩けた。**

| 口 | RP のトークンで、できてしまったこと |
|---|---|
| `/SetDeviceToken` | **利用者の端末の登録（FCM の宛先）を差し替える**（以後の CIBA・2FA のプッシュが、差し替えた先に届く） |
| `/ciba_result` | **利用者宛ての CIBA の要求を「許可」する** |
| `/2fa_result` | **2FA のプッシュ承認を記録する**（コードの照合は要る） |

**設定 `AuthenticationDeviceClientIds` に挙げたクライアントに発行したトークンだけを受ける**ようにした
（**未設定・空なら、同梱の `AuthenticationDevice_Web` の client_id**。`CONFIGURATION.md` 4 節）。**aud の無いトークンも断る。**

**E2E** : **`RT-294.73`**（**判定を外した実装で、net10.0 版が落ちることを確かめた**）。
**認証デバイスの役をする既存のテスト**（`EX-8.x`・`RT-196.20`・`RT-213.1`・`RT-294.40`）は、
**認証デバイスのクライアントでトークンを取る**ようにした（`Flows.RunAuthenticationDeviceFlowAsync`）。

> **同じレビューで直した不具合**（セキュリティ以外）:
>
> | 場所 | 以前 | いま |
> |---|---|---|
> | **`/token` の `grant_type`** | **無い・未知のどちらも `invalid_grant`**。大文字の値も `ToLower` で通した | **無ければ `invalid_request`、未知なら `unsupported_grant_type`**（RFC 6749 §5.2）。**大文字小文字まで比べる**（`RT-294.74`） |
> | **`/device_authz`・`/ciba_authz` の応答** | **`expires_in` / `interval` が文字列** | **JSON の数値**（RFC 8628 §3.2 / CIBA Core 7.3。`RT-294.75` / `.76`） |
> | **CIBA の `requested_expiry`** | **検証も上限も無く**、読めない値は 0（作った瞬間に期限切れ） | **正の整数でなければ `invalid_request`**、**`CibaExpireTimeSpanFromSeconds` で頭を打つ**（`RT-294.76`） |
> | **デバイス認可のクライアント認証** | **`client_assertion` を読まず**、`private_key_jwt` のクライアントは使えなかった（動的登録も断っていた） | **`/device_authz` と `/token` の両方で受ける**。動的登録も断らない（`RT-294.77`） |
> | **`/revoke`・`/introspect`** | **`token` の有無を先に見て**、認証していない要求にも 400 | **認証を先に行い、失敗は 401**（`RT-294.78`） |
> | **`/ros` の失敗** | 本文の無い 400 | **`invalid_request_object` の JSON** |
> | **`/par` の重複したパラメタ** | **カンマでつないだ 1 つの値として受けた** | **`invalid_request` で断る**（RFC 6749 §3.1 / RFC 9126 §2.1。`RT-294.79`。最後のレビューで追加） |
> | **`/userinfo` のメソッド** | **GET だけ**（OIDC Core 5.3.1 は GET と POST の両方を MUST） | **POST も受ける**（トークンはどちらも Authorization ヘッダ。`RT-294.80`。3 回目のレビューで追加） |
> | **`/userinfo` と `openid` の無いトークン** | **client_credentials のトークンなどにも、200 で `sub` を返した** | **403 / `insufficient_scope`**（OIDC Core 5.3 / RFC 6750 §3.1。`RT-294.80`）。**自己テストの OAuth2 の経路（`SelfTestScopes`）では、結果画面の UserInfo が 403 を示す**（OIDC の経路は従来どおり） |
> | **`/jwkcerts` の `If-None-Match`** | 弱い ETag（`W/"…"`。net10.0）と `*` を一致とみなさなかった | **一致とみなす**（RFC 9110 §13.1.2） |
> | **`/userinfo`** | **aud の無いトークンで NullReferenceException**。`claims` の何もしないループ | **利用者を引かずに `sub` だけ返す**。ループは消した |

### C-56. 自己テストの口の 1 つを、本番で閉じられなかった。自己テストの ROPC が管理者のトークンを配っていた **[NetFx][Core]** — **✅ 修正済み（#294）**

**自己テスト（`HomeController`）は `IsLockedDownTestEndpoints` で閉じる設計**だが、**閉じ方と中身に 2 つの抜けがあった。**

| 場所 | 以前 | いま |
|---|---|---|
| **`/Home/DeviceAuthZResponse`**（ポーリング） | **`IsLockedDownTestEndpoints` を見ていなかった**（`Saml2OAuth2Starters` は見ていた）。**本番で閉じても、この口だけは匿名で使え**、**サーバに自分の `/token` を問い合わせさせられた**。**間隔は画面（hidden）の `interval` に従った**ので、**外から短くできた** | **閉じる**。**間隔は設定値（`DeviceAuthZPollingIntervalSeconds`）より短くしない**（`SelfTestClient.RunDeviceAuthZPollingAsync`。`RT-294.82`） |
| **自己テストの ROPC** | **管理者（`AdministratorUID` / `AdministratorPWD`）でトークンを取り、画面に出した。** **この POST は匿名で受ける**ので、**自己テストの口が開いている間は、ログインしていない人にも管理者のトークンを見せていた** | **テスト利用者（`tanaka`）で取る**。**`TestUserPWD` が無ければ取らずに理由を出す**（`RT-294.83`） |

**どちらも `IsLockedDownTestEndpoints` を `true` にした配備には当たらない**（ROPC の件）か、**当たっても問い合わせ先は自分の `/token` だけ**（ポーリングの件）である。
**自己テストを開けたまま公開する配備**（雛形の既定は `false`。テストのスタブも既定で開けている）が対象になる。

> **同じレビューで直した不具合**（セキュリティ以外）:
>
> | 場所 | 以前 | いま |
> |---|---|---|
> | **自己テストの POST 2 つ** | 画面は AntiForgery トークンを出していたが、**確かめていなかった** | **`[ValidateAntiForgeryToken]`**（`RT-294.81`） |
> | **FAPI2（`/ros`）の開始** | **預けられないと `Redirect(null)` の例外で 500** | **理由を出して再表示** |
> | **「ログイン・ユーザの Client」** | **消された利用者・登録の無い利用者で 500**（NRE / `Session.SetString(null)`） | **理由を出して再表示** |
> | **SPA 向けの PKCE** | **`response_mode` を後から足した**ので、画面で選ぶと 2 つ載った（RFC 6749 §3.1） | **`fragment` で置き換える**（`RT-294.84`） |
> | **開始の URL** | **画面から来る値（`prompt`・`max_age`・`response_mode`）と `scope` などを符号化せずに連結**（`&` で別のパラメタを差し込めた） | **URL 符号化する**（`RT-294.85`） |
> | **ROPC・Client Credentials・JWT Bearer の結果** | **応答を JSON と決めて読み**、そうでなければ 500 | **読めなければ access_token を空にして、応答をそのまま出す** |

---

## 5. D. 最新の IdP として不足している機能

| # | 仕様 | 状況 | 影響 |
|---|---|---|---|
| D-1 | **RP-Initiated Logout** | **✅ 実装済み**（#232）。`/end_session` を新設（GET / POST の両方・`id_token_hint` の検証・`post_logout_redirect_uri` の完全一致・確認画面）。Discovery に `end_session_endpoint`（`RT-232`） | RP から SSO を解除できる |
| D-1-2 | Front-Channel / Back-Channel Logout / Session Management | **✅ 実装済み**（#310。**段階 1・2・3**） — **段階 1** : **`sid` を `id_token` に出し**（**RP ごとに別の値**。`pairwise` の `sub` を分けた意味を消さないため）、**セッション × クライアントの台帳**（`SessionClient`）を持つようにした。**段階 2** : **サインアウトで、登録が在る RP へ `logout_token` を POST する**（**`backchannel_logout_uri` の登録を足した**。**要求の経路では待たない**）。**`backchannel_logout_supported` / `backchannel_logout_session_supported` を広告**（`RT-310.4`〜`.6`）。**段階 3** : **`frontchannel_logout_uri` の登録が在る相手を `iframe` に並べた画面を返す**（**`iss` と `sid` を付ける**）。**`frontchannel_logout_supported` / `frontchannel_logout_session_supported` を広告**（`RT-310.7`〜`.9`）。**Session Management（`check_session_iframe`）は見送る**（third-party cookie を読む仕組みで、現代のブラウザでは効かなくなりつつある） | **両方の伝え方が入った** — **受け口を持てる RP にはサーバから、持てない RP にはブラウザから伝わる。** **届いたかどうかは Front-Channel では分からない**（仕様の限界。**Back-Channel と補い合う**） |
| D-2 | **PAR（RFC 9126）** | **✅ 実装済み**（#229）。`/par` を新設（フォーム＋クライアント認証＋`expires_in`）。`/ros` は **RFC 9101 §5.2.1 の任意機能**として残す（`RT-229`） | FAPI 2.0 Security Profile は PAR を必須としている |
| D-3 | **DPoP（RFC 9449）** | **✅ 実装済み（#311。段階 1〜4）** — **`/token` で証明（`DPoP` ヘッダ）を受け、`cnf.jkt` で発行する**（**7 つのグラント全部**）。**`token_type` は `DPoP`**、**`dpop_signing_alg_values_supported` を広告**。**証明が無ければ従来どおり `bearer`**（`RT-311.*`）。**段階 2** : **保護されたリソースで照合する**（`Authorization: DPoP …` ＋ `ath` ＋ `cnf.jkt`。**トークンを受け取る口はすべて同じ判定を通る**）。**段階 3** : **一度使った証明を、二度と通さない**（`DPoPProof` の台帳。**鍵の指紋（`jkt`）と `jti` を組にして記録する** — **`jti` だけでは、クライアントが互いを塞げる**。**記録は検証の最後**。`RT-311.8` / `RT-311.9`）。**段階 4** : **縛りを前と後ろへ広げた**（**認可要求の `dpop_jkt` で `code` を縛り**、**`refresh_token` も同じ鍵に縛る**。`RT-311.10` / `RT-311.11`）＋ **チャレンジを `DPoP` にし**（`algs` 付き。`RT-311.12`）、**`nonce` を要求できるようにした**（`use_dpop_nonce` ＋ `DPoP-Nonce`。**既定は要求しない**。`RT-311.13` / `RT-311.14`） | **パブリック クライアントのトークンを、持ち主に縛れるようになった**（**漏えいしても、鍵が無ければ使えない**）。**縛りは `code` から `refresh_token` まで続き**、**証明の使い回しも断る。** **FAPI 2.0 の Sender-Constrained を、mTLS 以外でも満たせる**（**DPoP のみなら `private_key_jwt` と組み合わせる**。#307 の段階 3） |
| D-4 | **Dynamic Client Registration（RFC 7591 / 7592）** | **✅ 実装済み（#307 の段階 1 〜 6 ＋ #308 ＋ #309）。** **登録（RFC 7591）** : **`registration_endpoint` を新設**（`POST`。既定は無効で、`EnableDynamicClientRegistration` で開ける）。**認可は ROPC で取る専用 scope（`client_registration`）のアクセス トークン**で、**scope も有効期限も絞られる。****所有者はトークンの `sub` の利用者**（**段階 5-a で 1 利用者 n クライアントになった**。下）。**RFC 7591 §2 のメタデータを `Saml2OAuth2Data` の 11 列として持ち**、**`scope` / `grant_types` / `response_types` は実際に効かせる**（空なら絞らない）。**Discovery に `registration_endpoint`**。**管理（RFC 7592）** : **`registration_client_uri`（`…/register/{client_id}`）の `GET` / `PUT`（全置換）/ `DELETE`（`204`）**。**鍵は `registration_access_token`**（**登録の応答で 1 回だけ返し、ハッシュで保管する**。**回さない**）。**`GET` / `PUT` では `client_secret` を返さない**。**`DELETE` は同意も落とす**（**利用者の行は触らない**。**それでも登録し直せる** — **段階 1 〜 4 は `Users.ClientID` を一意制約のため空にできず**、**段階 5-a-1 でその列ごと落ちた**。下）。`RT-307.1` 〜 `.13` | **クライアントを CI / IaC から作り、読み・直し・消せるようになった**（再デプロイも画面も要らない）。**クライアント認証の方法（段階 3）** : **`token_endpoint_auth_method` を 1 列として持ち**、**4 つとも動的登録から設定できる**（`jwks` は **RSA 1 本 ＋ EC 1 本**として列に入れ、`tls_client_auth_subject_dn` と `token_endpoint_auth_signing_alg` も受ける）。**登録された方法は認証でも効く** — **明示が無ければ `client_secret_basic` / `client_secret_post` だけ**で、**鍵や DN を登録しただけでは、その方法では通らない**（`CmnEndpoints.AllowsAuthMethod`）。**材料の無い登録は断る**（`private_key_jwt` に `jwks` 無し・`tls_client_auth` に DN 無し・**`device_code` × `private_key_jwt`**）。**`client_secret` は方法に関わらず発行する**（秘密しか使えない口が在るため）。`RT-307.14` 〜 `.17`。**署名付きの主張（段階 4）** : **`software_statement`（RFC 7591 §2.3）を検証して受ける。** **信頼する発行者は設定で持つ**（`SoftwareStatementIssuers`。**`iss` ＋ `.cer` ＋ `alg`**）。**鍵は「発行者ごと」で、クライアントごとではない** — **1 つのソフトウェアに 1 枚配られ、その全ての配置が同じものを提示する**（§2 の `software_id`）ため、**登録が何件になっても検証鍵は発行者 1 件につき 1 つ**である。**主張した値は本文（plain JSON）に勝つ**（§2.3 は MUST。**食い違っても断らず、上書きした項目の名前をログに残す**）。**壊れていれば `invalid_software_statement`、信頼していない発行者なら `unapproved_software_statement`**（**1 件も設定していない配備は常に後者 ＝ 従来どおり**）。**`exp` / `aud` は在るときだけ効かせる。** **statement は保管せず、応答にも返さない**（§3.2.1 で任意）ので、**この段階で列は増えていない。** **`RequireSoftwareStatement` で必須にできる**（**`POST` と `PUT` の両方に効く** — **`PUT` に効かせないと、statement を省いて主張された値を書き換えられる**）。**statement は 2 つの専用トークンを置き換えない** — **あれは認可、これは内容の保証**であり、**statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**（**RFC 7591 §1.2 の「AT を要らない開いた登録口」は採らない**）。`RT-307.18` 〜 `.21`。**1 利用者 n クライアント（段階 5-a-1）** : **所有者の置き場所を `Users.ClientID`（利用者の行の 1 枠。NOT NULL ＋ 一意索引）から `Saml2OAuth2Data.OwnerUserId`（登録の行ごと。`Users.Id` を指す）へ移した。** **1 対 n にするには、結び付きを「n の側」に持たせる**ためである。**外部キーも張り替えた**（`OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`）。**`Users.ClientID` は列ごと落とし**、**`ApplicationUser.ClientID` のプロパティも落とした**（**残して未使用にすると、DDL と食い違う**）。**上限は設けていない**（**条件分岐を増やさない**という決め。**洪水はレート制限で受ける**）。**あわせて 2 つの歪みが消えた** — **(a)** **「宙に浮いた `client_id`」**（既定値が毎回 `Guid.NewGuid()` で、**登録の無い利用者にも値が入っていた**。`Register` が掃除していた）、**(b)** **「`DELETE` で空にできない」**（NOT NULL ＋ 一意索引 ＋ 外部キーに当たり、**`sql` で `DELETE` が `500`** になった。**`mem` では出なかった**。段階 2 で踏んだ）。**所有者は `Users.Id` で持つ**（**名前ではない** — 利用者名を変えても切れない）。**`ClientName` はラベルとして残す**（`Helper.GetClientName` が「登録が在るか」の判定と `client_credentials` の `sub` に使う）。**`OwnerUserId` は空のことがある**（**E2E の種データ**は所有者を持たない — **以前は外部キーを満たすためだけに、クライアント 1 件につき利用者 1 人を作っていた**）。`RT-307.3` を書き換えた。**管理画面の一覧（段階 5-a-2）** : **`/Manage/Saml2OAuth2DataList` を新設**し、**自分の登録を `client_id` の昇順で並べる**（`ConsentGrants` と同じ流儀）。**`/Manage/Index` は件数と導線 1 本**になり、**削除は一覧の行から**行う。**編集は `?clientId=…` で指す**（**所有者はサーバ側で照合する** — **他人の・所有者の無い・在りもしない `client_id` は、どれも `Error` 画面**で、**撃ち分けない**）。**保存は「自分の持ち物なら更新、無ければ作成」**（**段階 5-a-1 までは、`client_id` が違えば古い 1 件を消していた**）。**編集では `client_id` を作り直せない** — **作り直すと別のクライアントになり、`registration_access_token` を引き継げないため**である。**一覧は `client_secret` と `registration_access_token` を持たない行の VM で出す**（**出し忘れでは防げないので、器ごと分けた**）。**並びを `client_id` の昇順に決めた**（`Saml2OAuth2DataProvider.GetByOwner` の `ORDER BY`。**`mem` も方言 3 つも同じ**）。`RT-277.9` 〜 `.11`。**`client_credentials` 経路（段階 5-b）** : **利用者のパスワードを使わずに登録できる。** **トークンに利用者が居ないので、作る登録の所有者は「認証したクライアントの所有者」から引く** — **構成ファイル発なら `owner` 属性（利用者名）、登録の表なら `OwnerUserId`（`Users.Id`）**。**どちらも決まらなければ `403` ＋ `access_denied`**（**トークンは正しいので `401` にしない** — 「取り直せ」と読めて誤誘導になる）。**見分けは `sub`** でする（**`client_credentials` のトークンは `sub` にクライアント名が入る**）ので、**「利用者が消えたトークン」をクライアントの所有者に付け替えない。** **`EnableDynamicClientRegistration` が true なら、`EnableClientCredentialsGrantType` が false でも、この scope のときだけ通す**（**「CI から登録を作る」ためにグラント全体を開けさせない**。**専用 scope が出ない要求は `unsupported_grant_type`**）。**scope も期限も ROPC と同じ規則で絞る。** **ROPC も残す**（既存の配備を壊さない）。**構成ファイルが名前で持つのは、人が書く物だから**で、**利用者名を変えたら設定も直す**必要がある（**表の側は id なので切れない**）。`RT-307.22` 〜 `.24`（**`.23` / `.24` は net48 では Skip** — **net48 の設定は 1 本の JSON 文字列**で、クライアントを 1 件足せない）。**発行者ごとの上限と、鍵の入れ替え（段階 6）** : **発行者ごとに `allowed_scope` / `allowed_grant_types` を書ける**（**空なら絞らない**）。**範囲外を主張されたら `unapproved_software_statement` で断る**（§3.2.2。**黙って狭めない**）。**本文（plain JSON）由来の値も上限に収める** — **statement に書かれていなければ本文の値が登録の値になる**ためで、**上限は「その発行者の保証で作られる登録」全体に効く**（**`POST` も `PUT` も `Validate` の 1 か所**）。**絞るのは受け入れる側の決め**で、**ベンダが自分で絞る分は statement の中身に書けば済む**（段階 4）ので、**実際に登録に入るのは 2 つの積**である。**`cer_file_path` は空白かカンマ区切りで n 本**書ける（**発行者の鍵の入れ替え**。**書いた順に試し、最初に検証できた鍵で通す**。**1 本目以外で通ったらログに残す** ＝ **古い鍵をいつ消せるかの判断材料**。**読めない行が在っても他を試し、1 本も読めなければ `unapproved_software_statement`**。**`alg` は行で 1 つ**）。**動的登録で作られた行を管理画面から書き替えたときは、監査ログに残す** — **権限の昇格ではない**（**その利用者は好きな `scope` の登録を画面から新規にも作れる**）が、**`software_statement` の保証から外れた点が後から分かるようにする**ためである（**画面に上限は効かせない** — **画面の登録は statement を持たず、どの発行者の上限を当てるかが決まらない**）。`RT-307.25` / `.26`。**発行者の台帳を DB ＋ 画面で持つ（#308）** : **設定ファイルだけだった**ものを、**`SoftwareStatementIssuers` 表（3 方言 ＋ `mem`）と `/SoftwareStatementAdmin` 画面（`SystemAdmin`）でも持てる**ようにした。**読む順は 設定 → DB で、同じ鍵なら設定が勝つ**（`IdFederationUpstreams` と同じ流儀。**画面が編むのは DB の行だけ**で、**設定に在る鍵は追加の時点で断る**）。**DB が読めなくても設定の分は効く**（理由はログに残す）。**`.cer` はパスでも本文でも持てる** — **`CerBody` に PEM を貼れば、ファイルを配備側に置かずに済む**（**公開鍵なので平文**。#297 の対象外）。**本文を先に、次にパスを試す**ので、**入れ替えの途中で片方だけ本文に移せる。** **アップロードの口は作っていない**（**サーバにファイルを書く口を増やさない**）。**`SigningKeys` は証明書を読まない** — **`CreateJwkSetJson`（net48 の exe）からソース参照されており、`X509CertificateLoader` が net48 に無く、`new X509Certificate2(byte[])` は net10.0 で旧形式**（SYSLIB0057）であるため、**読むのは `SoftwareStatementProvider`**（CommonLibrary 側）にし、**`SigningKeys` は「パラメタ → JWS」の対応だけ**を持つ。**表を新設したので、既存の配備は `CREATE TABLE` を流す必要がある。** `RT-308.1` 〜 `.3`。**クライアントの鍵を `jwks_uri` から引く（#309 の段階 1）** : **`jwks`（鍵そのもの）だけを受けていた**ものを、**`jwks_uri` でも受けるようにした**（**RP は鍵を入れ替えても登録を直さなくてよい**）。**列は #307 の段階 1 から在る**ので **DDL は変わらない。** **塞いでいたのは構造である** — **クライアント認証は `static bool` の鎖で、`/token` / `/par` / `/ciba_authz` / `/revoke` / `/introspect` の全部から同期で呼ばれ、そこで取得を待つと net48 で止まる**（**継続が `AspNetSynchronizationContext` へ Post され、その順番を握っているのは待っている自分**）。**そこで「要求の経路では待たない」形にした** — **要求はキャッシュを読むだけ**（`DiscoveryJwks.PickJwksFromCache`）で、**引けなければ `invalid_client` で断り、背景で取り直す**（`RefillInBackground`。**取り直しの下限 1 分 ＋ 取得中は 1 本** — **`kid` を偽った要求で叩かせない**）。**取りに行って待つのは登録の口だけ**（**`POST` / `PUT` は `async`**。`WarmUpJwksUriAsync` → `WarmUpAsync`）で、**読めない URL はその場で `400` ＋ `invalid_client_metadata`**（**後から黙って `private_key_jwt` が通らなくなるより良い**）。**登録の口は下限を見ない**（**毎回取りに行く** — **認可とレート制限が掛かっており、鍵を入れ替えた相手が `PUT` でその場で反映できる**）。**`https` を要求し、ループバックだけ `http` を許す**（RFC 8252 §7.3 と同じ扱い。**鍵を差し替えられればクライアント認証が破れる**）。**`jwks` とは排他**（§2 の MUST NOT。**併記は `400`**。**`PUT` で片方を送ればもう片方は消える**）。**`kid` が無い JWS は、在る鍵を順に 4 本まで試す。** **`private_key_jwt` の「材料」にも数える**（**`jwks` が無くても登録できる**）。**画面の `JwksUri` 欄は前から在ったが、誰も読んでいなかった** — **塞ぐ側に倒れていた**（鍵が無いので認証は失敗する）**ので穴ではない**が、**入れた人には何も起きなかった。** **Device AuthZ の「コンフィデンシャルかどうか」にも数えた**（#307 の段階 3 で閉じた穴と同じ形）。`RT-309.1` 〜 `.3`。**段階 2** : **起動のときに、登録済みの `jwks_uri` を温める**（**設定ファイルの分 ＋ user store の `JwksUri` が空でない行**。**重複を除き、直列に読み、100 本で打ち切る**。**読めなくても起動を止めず、ログに残す**。**起動のたびに `The jwks_uri warm-up read n of m JWK Sets.` が 1 行出る** — **0 件でも出すので、仕掛けが動いていることが分かる**）。**窓は消えない** — **net10.0 版は要求を受ける前に走る**が、**net48 版の `Application_Start` は最初の要求が来てから走り、その要求自身は温めを待たない**ので、**段階 1 の「1 回断って背景で取り直す」はそのまま残してある**（**これは速くする仕掛けで、必ず通す仕掛けではない**）。**`software_statement` が主張した `jwks_uri` も受けるようにした** — **段階 1 は「署名を検証する前に本文の外の URL へ出て行かない」として断っていたが、過剰だった**（**同じ呼び出し元は本文の `jwks_uri` に任意の URL を書けるので、行き先の範囲は変わらない**。**キャッシュは URL → 鍵の対応でしかなく、statement の検証が落ちれば登録は作られないので、温めた分は誰にも使われない**）。**鍵の出どころとして使える URL かの判定は `DiscoveryJwks.IsUsableKeySource` の 1 か所に寄せた**（**登録の検査と起動の温めが同じ規則で絞る**）。`RT-309.4`。**起動のときの温めは E2E では測れない**（**サイトの起動は `test.ps1` が握っており、テストから再起動できない**）ので、**ログで確かめる手順を `TESTING.md` に置いた**（**実測で net48 / net10.0 の両方の呼び出しと、`sql` の列挙までは確かめた**。**`ora` / `npg` の列挙は未測定**）。**あわせて穴が 3 つ閉じた** — **(1)** **`Helper.GetClientScopes` が構成ファイルだけを見ていたため、DB に登録したクライアントには #198 の「クライアントごとの `scope` の絞り」が効いていなかった**（段階 1）。**(2)** **アクセス トークンの検証にある「クライアントがまだ在るか」の確認が効いていなかった**（`GetClientSecret` は**未登録でも空文字を返す**ので、`!= null` が常に真だった）。**`Helper.HasClient` で「行が在るか」を見るようにしたので、登録を消すと既存のアクセス トークンもその場で通らなくなる**（RFC 7592 §2.3。段階 2）。**(3)** **Device AuthZ の「コンフィデンシャルかどうか」の判定に、鍵の登録が入っていなかった**（`DeviceAuthZClientAuthentication` は `client_secret` / `tls_client_auth_subject_dn` / 提示された証明書だけを見ていた）。**秘密も DN も持たず鍵だけを登録したクライアントは、パブリック クライアントとみなされ、`client_id` の確認だけで通っていた**（**#307 とは無関係に、構成ファイルや管理画面からも作れる形**）。**鍵の登録も数えるようにした**ので、**断る側に転ぶ**（この口は `client_assertion` を読まないため。段階 3） |
| D-5 | **`iss` 認可応答パラメタ（RFC 9207）** | **✅ 実装済み**（#231）／**✅ 修正済み（#252）**。成功・失敗の両方に付け、Discovery でも広告する。JARM は JWT 内の `iss`（`RT-231`）。**`form_post` だけ抜けていた**（`iss` は `BuildRedirectUrl` が付けており、**URL を組まない `form_post` はそこを通らない**）。**View で出すようにした**（`RT-231.5` / `RT-231.6`） | Mix-Up 攻撃への対策 |
| D-6 | **同意（consent）の永続化** | **✅ 実装済み（#272 の段階 2）**。`ConsentGrant` 表（DDL 3 方言）。**粒度は（利用者, クライアント）で 1 行、scope は集合として足し込む**。管理画面から取り消せる | C-3 の根本原因だった。これで `prompt=none` を仕様どおり扱える |
| D-7 | `profile` / `address` スコープのクレーム | **✅ 実装済み**（#230）。**設定で対応付ける**（`UserClaimsMapping`）。この実装は氏名・住所の項目を持たず、入れ物（`UnstructuredData`）の中身は導入する側が決めるため、**「どのキーをどのクレームとして返すか」だけを設定に置く**。`claims_supported` も対応付けから作る（`RT-230`） | `scopes_supported` に載っているのに何も返らなかった。**標準クレームのサンプルを持たせた**（#261）。`IsDebug` のとき **2 人目のテスト利用者に OIDC Core 5.1 の形で仕込み**、雛形には対応付けのサンプルを コメントで置いた（`RT-261.1`）。**画面は変えていない**（入れ物の中身は導入する側が決める方針を保つ）。あわせて**クレームの型を JSON のまま返すよう直した**（`updated_at` は数値。以前は文字列。#184 と同種） |
| D-8 | クライアントあたり複数 `redirect_uri` | **✅ 解けた（#306）。** **`redirect_uri_code` / `redirect_uri_token` に空白区切りで n 件登録できる**（設定ファイルでも DB の列でも同じ形）。**照合は全件に対して完全一致**（`Ordinal`。**前方一致にしない**）。**要求で省略できるのは登録が 1 件のときだけ** — **2 件以上なら `invalid_request`**（RFC 6749 §3.1.2.3。`RT-306.1` 〜 `.3`）。**`post_logout_redirect_uri` と `redirect_uri_saml`（ACS）は 1 本のまま** | **既存の配備はそのまま動く**（1 本の登録は 1 件の列挙として読める）。**DB は列幅の変更が要る**（512 → 2000。`CONFIGURATION.md` に `ALTER` を載せた）。**n 件にした RP は、要求に `redirect_uri` を含める必要がある** |
| D-9 | 署名鍵のローテーション運用 | **✅ 解けた（#129 の段階 3）。** **alg → 鍵の対応を `SigningKeys` の表 1 か所に寄せ**、**`CreateJwkSetJson` がその表を回して `jwkcerts` を作る**ようにした（ソース参照）。**JWK Set は追記式**なので、**新しい鍵を先に載せ、RP のキャッシュが切れてから署名に切り替えられる**（手順は `CONFIGURATION.md`）。**広告と鍵が揃っていることは `RT-129.6` で測る** | **無停止で替えられるようになった**（残り : 旧い `kid` を外すのは手作業） |
| D-15 | **ID フェデレーションの上流が 1 つだけ**（✅ 解けた。#292 の段階 1・2） | **設定 `IdFederationUpstreams` で n 件登録でき、導線も n 個出る**（`CN-5.4` 〜 `CN-5.6` で実測）。**同じものを user store（`IdFederationUpstreams` 表。DDL は 3 方言）にも置け、管理画面（`/IdFederationAdmin`）から足せる**（#292 の段階 2。`RT-292.*`）。**読む順は 設定 → DB で、同じ鍵なら設定が勝つ。****相手ごとの値（`issuer` / `client_id` / 口 / 鍵 / メタデータ）は、その行が持つ。****折り返し口は共通設定のまま**（自分の URL なので相手ごとに変わらない） | **(2) の署名鍵は上流ごとに替えられる**（#292 の段階 4-a・4-b。Open棟梁 #606 の追随。`signing_pfx_file_path`。**設定でも DB でもよく、管理画面から入れられる**。`RT-292.4`）。**`client_secret` の暗号化は解けた**（#297。`UserStoreSecretPassword`）。**鍵の入れ替え（ロールオーバー）は、段階 3 で解けた**（出す側は 2 本広告し、受け取る側は 2 本試す。`SA-2.2` / `SA-6.6`）。**連携キーの幅も広げた**（`UserLogins.LoginProvider` 512 / `ProviderKey` 256。**上流が n 件になると長い値を踏む確率が上がる**ため。**SQL Server 2016 以降が前提**になった） |
| D-9-2 | **PPID の秘密（`SaltParameter`）のローテーション** | **✅ 解けた（#151 の段階 2）。** **発行した `sub` を対応表（`SubjectIdentifier`）に記録する**ようにしたので、**秘密を替えても発行済みの値は動かない**（表から引くため）。以前は導出していたので替えられなかった（A-14） | **漏洩時に替えられるようになった** |
| D-10 | **`typ: at+jwt`（RFC 9068）** | **✅ 解けた（#302）。** **access_token は `typ: at+jwt`**（段階 2。Open棟梁 #611 の追随）、**`jku` は出さない**（段階 1）。**受ける側も期待値を明示する** — `VerifyAccessToken` は `at+jwt`、`id_token_hint` の `VerifySignature` は `JWT`。**`RT-302.1`** で access_token / id_token / JARM の 3 つを測る | **トークン取り違え（token confusion）を型で見分けられるようになった。** **`jku` の SSRF も解けた** |
| D-11 | 応答の `scope` | **✅ 返している**（`CmnEndpoints.CreateAccessTokenResponse`。**#198 でスコープを絞るようにしたときに、同時に入った**）。**発行したスコープを空白区切りで返す** — **要求と違うことがあるので必須**（RFC 6749 §5.1）。**測定は `RT-198.*`**（「トークン応答の `scope` が、発行したスコープと一致する」） | **解けた。** 要求と付与が違っても RP が判別できる |
| D-12 | **OAuth 2.1 への整合** | **✅ 既定を変えた（#220）**。雛形の Implicit / ROPC は `false`。PKCE は `client_secret` と併用可、`plain` は `RequirePkceS256`、`code_challenge` の必須化は `RequirePkce` で選べる（どちらも既定は従来どおり）。`permittedLevel` と `clientMode` も分離した（C-7 の 3）。**クライアント単位の `require_pkce` も追加**（#221）。**トークンはヘッダでのみ受け付けることを実測**（`21-2.1`。`?access_token=` は 401。#222） | 残り : 無し（`OAuth21Mode` の 1 キー化は見送り） |
| D-13 | **レート制限 / ブルートフォース対策**（#305） | **✅ 解けた（#305）。** **段階 1** : ポーリングが `interval` より速ければ **`slow_down`**（`LastPolledAt`。`RT-305.1` / `.2`）。**段階 2** : **クライアント認証と `user_code` の投入の失敗を数え、一定回数で一定時間断る**（`AuthFailure` 表。`RT-305.3` / `.4`）。**段階 3** : **口ごとのレート制限** — **`client_id` ごと・送信元ごとに窓の中の要求を数え、超えた分に `429`**（`RateLimitProvider`。`RT-305.5` / `.6`）。**段階 4** : **失敗の数えを「クライアント ＋ 送信元」ごとにし**（`client_id` だけで数えると、**ロックアウトがそのまま妨害の手段になる**。`RT-305.7`）、**`/token` の `grant_type=password` を画面と同じ利用者ロックアウトに合流させた**（`RT-305.8`）。**行には寿命を入れた**（期限の切れた行を掃除する）。**判定は両アプリで 1 か所**（net48 に組み込みが無いため） | **既定は「制限しない」**（`RateLimitPerClientPermits` / `RateLimitPerIpPermits` が 0。**雛形は 120 回 / 600 回 / 60 秒**）。**失敗の数えは雛形で有効**（5 回 / 300 秒）。**プロセスの中に覚えるので、インスタンスを増やすとその数だけ緩くなる**（レート制限の方。失敗の数えは表に持つ）。**鍵の粒度は利用者の数に追随しない** — **同じ `client_id` に利用者が多数いる配備では、閾値をその全員分に合わせることになる**（`CONFIGURATION.md`） |
| D-14 | **適合性テスト** | 仕組みが無い | OpenID Foundation Conformance Suite を回せば A・B の大半は自動で検出できる |

---

## 6. E. 実装・運用の品質

| # | 内容 |
|---|---|
| E-1 | `Startup.cs` 方式のまま。.NET 6 以降の Minimal Hosting（`WebApplication.CreateBuilder`）へ寄せると、`Program.cs` の `IWebHost` / `IHost` のコメント アウト群も整理できる |
| E-2 | **✅ 修正済み（#256）**。`AddDistributedMemoryCache()` 固定をやめ、**`SessionStoreType`（`mem` / `sql` / `redis`）で選べるようにした**（`UserStoreType` と同じ流儀）。**既定は `mem`**（キーを書かなければも `mem`。既存の配備は従来どおり）。**単一インスタンスならそれが正しい**ので、**雛形を `redis` にはしない**（[`TESTING.md`](../TESTING.md) 1 節の「既定は `mem`」と同じ理由）。**セッションには途中の状態が載っている** — ID 連携の `state` / `nonce` / `code_verifier`、管理画面の `access_token`、FIDO2 の challenge、自己テスト画面の値（**実測 14 キー・46 か所。net10.0 版**）。`mem` のまま増やすと、要求が別のインスタンスへ回った時にそれらが読めず、**途中で失敗する**。**Cookie へ寄せる案（案 B）は採らなかった**（量と、`access_token` を Cookie に置きたくないため）。**`sql` は `Create_SessionCache.sql`**（`dotnet sql-cache create` と同じスキーマ。スキーマ名・表名は `Const` に置き、設定キーにしない）。**Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い**ので、**3 方言が揃わない唯一の設定**であり、それらのストアでは `redis` を使う。**`mem` 以外で接続文字列が空なら、`ConfigureServices` で落とす**（`IDistributedCache` は遅延で落ちるため、放っておくと「画面が 500 を返すだけ」になる）。**DataProtection の方は C-13 / #251 で済んでいる**（`DataProtectionKeyPath`）。**検証は通し × 3 通り ＋ ストア側の件数**（[`TESTING.md`](../TESTING.md) 1 節） |
| E-3 | ✅ **CORS の 3 重定義を片付けた**（C-9 / #265）。既定のポリシーを置かず、口ごとに属性で選ぶ。`AllowAllOrigins` は自己テスト用の口だけが使う |
| E-4 | **✅ 直した（#304）。** **`Views/_ViewImports.cshtml` / `Views/Manage/ManageTwoFactorAuthenticator.cshtml` / `CommonLibrary/ViewModels/ErrorViewModel.cs` を UTF-8 ＋ BOM にした**（中身は 1 文字も変えていない）。**`root/programs/z_Common2.bat` は cp932 のまま** — **bat は cmd がバイト単位で読む**ので、**筋は ASCII 化**である（[`CODING.md`](../CODING.md) 4 節で追っている） |
| E-5 | **✅ 解消済み**。`log4net` を **3.2.0 → 3.3.0** に上げた（[`MultiPurposeAuthSiteCore/ANALYSIS.md`](MultiPurposeAuthSiteCore/ANALYSIS.md) 9.1 節。**`NU1902` は解消**し、**版の割れ（実行時の `FileNotFoundException`）も直った**）。**net48 側は `OpenTouryoAssemblies` の 3.3.0 を使う**ので、元から対象外 |
| E-6 | **✅ Deny ボタンは入れた（#272 の段階 2）**。認可画面で拒否でき、**`access_denied` を `redirect_uri` へ返す**（RFC 6749 §4.1.2.1。`RT-272.6`）。**拒否は記録しない**。残るのは **scope が生の識別子のまま**であること |
| E-7 | **✅ 解けた（#303）。** **ファイルの更新だけを見て覚える**（`Extensions/Sts/JwkSetDocument`）。**`ETag` を常に付け、`If-None-Match` に `304`**。**`Cache-Control` は `JwkSetCacheMaxAgeSeconds`**（0 なら `no-store` ＝ 従来どおり）。**鍵の入れ替えに追随する**（`RT-303.2`） |
| E-8 | `AccountController.cs` 4402 行 / `ManageController.cs` 3262 行。STS 部分（`#region STS` 以下 約 1800 行）を別 Controller へ切り出すと、以降の改修が安全になる。**#294 で両方を責務ごとの partial に分けた**（`AccountController.*.cs` / `ManageController.*.cs`。**別 Controller への切り出しはしていない**） |
| E-9 | **✅ 修正済み（#140 の段階 3）**。ID フェデレーションの `/token` 呼び出しが **`Sts.Helper` を通っており、宛先のホストがコンテナの認可サーバへ書き換えられていた**（`GetContainerizatedAuthZServerUri`）。**相手は他の IdP なので壊れる。** `/userinfo` は #246 で外していたが、こちらが残っていた |
| E-10 | **✅ 修正済み（#140 の段階 3）**。同じ呼び出しが **`code_verifier` に `""` を渡しており、PKCE を使っていないのに PKCE のオーバーロード（`client_secret_post`）を選んでいた。** いまは実際の `code_verifier` を渡す |
| E-11 | **✅ 修正済み（#140 の段階 3）**。ID フェデレーションが **認可応答の `iss`（RFC 9207）を見ていなかった。** `id_token` の `iss` は照合していたが、**OAuth 2.1 が Mix-Up 対策として挙げているのは応答パラメタの方。** いまは `SpRp_Isser` と照合する（**来なければ通す** — 実装していない OP があるため） |
| E-12 | **✅ 修正済み（#140 の段階 3）**。ID フェデレーションの要求スコープに**独自の `userid` / `roles`** が入っていた。**厳格な OP では `invalid_scope` になりうる**（この IdP 自身も #198 でスコープを絞る）。**標準だけにした。** `userid` は連携キーでなくなったので不要（`(iss, sub)` へ移行済み）。`state` も 10 → 32 文字にした |
| E-13 | **refresh_token を失効させても、そこから出た access_token は期限まで使える**（RFC 7009 §2.1 は SHOULD で、同じ認可グラントのトークンも無効にすることを求める）。**refresh_token の一族は失効させている**（#188 の段階 3）が、**access_token の `jti` と一族を結び付ける列が無い。** **列（または表）と DDL（3 方言 ＋ `mem`）が要る**ので、#294 では見送った |
| E-14 | **ROPC のパスワードの失敗の数えが、読み・足し・書きの 3 手で、原子的でない**（`RecordUserAccessFailed`）。**同時に送られた試行は、少なく数えられることがある**（レート制限（#305 の段階 3）が頭を打つ）。**DB の更新 1 文で数える**には、user store の口を足す必要があるので、#294 では見送った。**画面のサインインの失敗の数えも同じ**（`CmnUserStore.Update` が行全体を上書きするので、並行した要求の書き込みが消し合う）。**楽観排他の列を足す方向で、#316 で検討する**（**回復コードを同時に使うと 2 回使える件も、同じ根なので含める**） |
| E-15 | **1 つの要求で、複数のクライアント認証の方法を送っても断らない**（RFC 6749 §2.3 : 1 要求に 1 つ。MUST NOT）。**Basic とフォームの `client_secret`、Basic と `client_assertion` などが同時に来ると、優先順位で 1 つを使い、残りは黙って無視する**（`/token`・`/revoke`・`/introspect`・`/par`・`/device_authz`・`/ciba_authz`）。**認証を素通りできる穴ではない**（使う 1 つは必ず検証する）。**断ると、混ぜて送ってくる既存のクライアントが通らなくなる**ので、#294（`OAuth2EndpointController.*.cs` の最後のレビュー）では記録に留めた |
| E-16 | **CIBA でプッシュを送れなかったとき、保存した要求が期限まで残る**（`OAuth2EndpointController.CibaAuthorizeAsync`）。**クライアントには `server_error` を返し、`auth_req_id` を渡さない**ので、**誰も使えない要求が残るだけで実害は無い。****消すには `CibaProvider` に削除の口（mem と DB の 3 方言）が要る**ので、#294 では記録に留めた |
| E-17 | **デバイス認可の `user_code` を、mem・Oracle・PostgreSQL では大文字小文字を区別して照合する**（SQL Server は照合順序で区別しない）。**`user_code` は英数字 8 文字（大文字と小文字が混ざる）**で、RFC 8628 §6.1 は**区別しない入力を推奨（SHOULD）**している。**場所は `DeviceAuthZProvider` と検証画面**（`OAuth2EndpointController` の範囲外）なので、#294 では記録に留めた |

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
| 8 | ✅ **A-3 の残り : JARM の `exp` を数値に** #201 | 24 行 | Lib |

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
| ✅ **A-11 `/revoke` `/introspect` を RFC 7009 / 7662 に合わせる（本体を `CmnEndpoints` に集約）** #200 |
| ✅ **A-7 エラーの HTTP ステータス（400 / 401）** #196 |
| ✅ **A-10 discovery の誤りと未広告の整備**（#189 の 2〜8。`RT-189`）。残り（仕様方針の判断を伴う 9〜14）は #228 |
| ✅ **A-12 `max_age` を超えたときの応答**（再認証、`prompt=none` なら `login_required`、数値以外は `invalid_request`）**#247**／**未サインイン ＋ `prompt=none` も `login_required`（#254）**。`prompt` の残り（`login` / `consent` / `select_account`）は C-3 |

### フェーズ 2 — セキュリティの底上げ

| 項目 |
|---|
| ✅ **C-1 `/device_authz` のクライアント認証** #193 |
| ✅ **C-2 `/revoke` `/introspect` の所有者確認、mTLS の有効化（net10.0 版）** #194 |
| ✅ **C-4 / C-5 / C-11 有効期限の実装**（code / refresh_token / request object）**＋ ワンタイム化 ＋ 再利用検知** #188 / #229 |
| ✅ **C-8 検証アルゴリズムの固定** #129 の段階 1 |
| ✅ **C-9 CORS をエンドポイント単位に** #265 |
| ✅ **C-10 `redirect_uri` の厳密比較** #263 ／ **テスト用抜け道の削除**（`test_self_code_manage`） |
| ✅ **C-12 Cookie 有効期限の設定反映** #223 ／ ✅ **C-13 DataProtection の永続化** #251 ／ ✅ **E-2 セッションの置き場を選べるように** #256（`SessionStoreType`） |
| ✅ **C-17 宣言外のスコープと、クライアントに許されていないスコープを発行しない** #198 |
| ✅ **C-22 `code_challenge` を送ったコードは `code_verifier` を必須にする** #245 |
| ✅ **C-25 mTLS で、登録が空のときに空の Subject DN が一致していた** #305 の段階 4 |
| ✅ **C-26 独自 scope の `userid` が、`pairwise` のクライアントにも共通の利用者 Id を渡していた** #294 |
| ✅ **C-27 独自 scope の `auth` で、どのクライアントも同意画面を飛ばせた** #294 |
| ✅ **C-28〜C-31 サインアップ・パスワードの失念**（確認待ちの利用者の差し替え／存在の露見／リセット画面のメアド／メールの送り過ぎ） #294 |
| ✅ **C-32 / C-33 サインイン**（WebAuthn のロックアウト判定／確認待ちの利用者へのメールと文言） #294 |
| ✅ **C-34 TOTP・回復コードでサインインしたとき、セッションを初期化していなかった** #294 |
| ✅ **C-35 2FA のプッシュ承認を待つスクリプトが、`ReturnUrl` を符号化せずに埋め込んでいた** #294 |
| ✅ **C-36 メールの送信に失敗すると、プロセスが落ちえた（`async void`）** #294 |
| ✅ **C-37 `/device_verify` の承認が、AntiForgery トークンを検証していなかった** #294 |
| ✅ **C-38 Implicit と Hybrid は、同意を確かめずにトークンを発行していた** #294 |
| ✅ **C-39 `auth_time` と再認証の印を、署名の無い Cookie で持っていた** #294 |

### フェーズ 3 — OAuth 2.1 / FAPI 2.0 への整合

| 項目 |
|---|
| ✅ **C-7 PKCE**（#220 / #221。同時送信・`plain`・`code_challenge` の必須化・クレームと権限判定の分離・クライアント単位の必須化）。**判定側（`CheckClientMode`）は表に置き換え**（#224 の段階 1）、**振る舞いを見直した**（段階 2 : 使えない `refresh_token` を出さない・早い拒否・`unauthorized_client`・不正な登録値の拒否）。**mTLS の経路の E2E も張った**（#226。`FA-6`） |
| ✅ **C-3 / D-6 同意の永続化と `prompt` の正しい処理** #272（段階 1 : `prompt` を集合として扱う / 段階 2 : `ConsentGrant` 表。**あわせて E-6 の Deny ボタンも**） |
| ✅ **D-2 `/ros` を PAR（RFC 9126）へ寄せる** #229（`/par` を新設。`/ros` は RFC 9101 §5.2.1 の任意機能として残す） |
| ✅ **D-5 `iss` 認可応答パラメタ（RFC 9207）** #231 ／ **✅ 修正済み（#252）**（成功・失敗の両方に付け、Discovery でも広告する） |
| ✅ **D-10 `typ: at+jwt`、`jku` の除去** **#302**（段階 1 : `jku` の除去／段階 2 : `at+jwt` ＋ 受ける側の期待値。Open棟梁 #611 の追随） |
| ✅ **D-12 Implicit / ROPC を既定 無効に**（#220。コードは残し、設定で戻せる） |

### フェーズ 4 — 機能の追加

| 項目 |
|---|
| ✅ **D-1-2 Front / Back-Channel Logout**（**#310**。`sid` ＋ 台帳（段階 1）＋ Back-Channel（段階 2）＋ Front-Channel（段階 3）。**Session Management だけ見送り**） |
| ✅ **D-3 DPoP**（**#311。段階 1〜4**。発行 ＋ 照合 ＋ 使い回しの拒否 ＋ **`dpop_jkt` / `refresh_token` の縛り ＋ `DPoP` チャレンジ ＋ `nonce`**） |
| ✅ **D-4 Dynamic Client Registration**（**#307 の段階 1〜6 ＋ #308 ＋ #309**。`POST /register` ＋ 専用 scope ＋ RFC 7591 §2 の列 ＋ **RFC 7592 の `GET` / `PUT` / `DELETE`** ＋ **`token_endpoint_auth_method` / `jwks` / DN** ＋ **`software_statement`** ＋ **1 利用者 n クライアント** ＋ **管理画面の一覧** ＋ **`client_credentials` 経路** ＋ **発行者ごとの上限と鍵の入れ替え**。**#308** : **`software_statement` の発行者を DB ＋ 管理画面で持つ**。**#309** : **クライアントの鍵を `jwks_uri` から引く**（**要求の経路では待たない**）） |
| ✅ **D-7 `profile` / `address` クレーム**（**#230**。**設定で対応付ける**（`UserClaimsMapping`）。`claims_supported` も対応） |
| ✅ **D-8 複数 `redirect_uri`**（**#306**。空白区切りで n 件。照合は全件と完全一致。省略できるのは 1 件のときだけ） |
| ✅ **D-9 鍵ローテーション**（alg → 鍵の表に寄せ、`jwkcerts` をその表から作る）**#129 の段階 3** |
| ✅ **D-13 レート制限**（**#305**。**段階 1** `slow_down` ／ **段階 2** 失敗の回数 ／ **段階 3** 口ごとのレート制限 ／ **段階 4** 送信元ごとの数えと `grant_type=password`） |

### フェーズ 5 — 土台

| 項目 |
|---|
| D-14 適合性テスト（OpenID Foundation Conformance Suite）を回す手順の整備 |
| E-1 Minimal Hosting への移行 |
| E-8 `AccountController` からの STS 部分の切り出し |

---

## 8. 作業時の注意（このリポジトリ固有）

- **指摘の多くは `CommonLibrary` に在るため、直すと net48 版にも効く。**
  逆に言えば、**net48 版の回帰確認をせずにマージできない。**
  `MultiPurposeAuthSite/ANALYSIS.md` 9 節のとおり、net48 は **Debug 構成でのみ**ビルドできる。
- **`Config` にプロパティを足したら `_appsettings.json` と `_app.config` の両方**に既定値を足す。
  実ファイル（`appsettings.json` / `app.config`）は `.gitignore` 対象で秘密情報を含むため、
  **中身を報告・Issue・コミット メッセージに転記しない。**
- **エンドポイントを足したら、net48 側の `App_Start/WebApiConfig.cs` / `RouteConfig.cs` にも登録が要る。**
  **API は Web API（`WebApiConfig` のルート、または `[Route]`）として登録すること。**
  net48 版では OWIN の Cookie 認証が、401 の応答をログイン画面への 302 に書き換える。
  `StartupAuth.IsWebApiRequest` が Web API のルートから判定して書き換えの対象から外すので、
  別の一覧を直す必要は無い。MVC の Controller に置いた API は対象にならない（A-7）。
- ヘッダ コメントの更新履歴に 1 行追記する（Contributing.ja.md）。
- **1 つの "プルリクエスト" に複数のタスクを混ぜない。** 本書のロードマップは
  そのまま Issue の単位になるよう項目を切ってある。
