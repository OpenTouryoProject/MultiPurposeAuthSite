# テストケース一覧（原本）

`root/programs/Tests/E2ETests/Tests/` のテストが、
**何を・何を根拠に確かめるのか**を並べたもの。
実行結果は含まない（そちらは `Result/E2ETests.report.md`）。

> **この文書は生成物である。** テストを変えたら作り直すこと。
>
> ```powershell
> cd root
> .\2_RunAllTests.ps1 -Launch -UpdateTestCases
> ```
>
> 元になるのは、各テストが `TestReport` に書かせた内容である。
> **テスト コードが一次情報**であり、この文書はその写しにすぎない。

## 読み方

- **観点** … 何が満たされていれば良いのか
- **根拠** … その期待値がどの仕様に基づくのか（RFC / OIDC の該当箇所）
- **手順** … 何を送るか
- **検証** … **合否を判定する項目。** 1 つでも外れればテストは失敗する
- **観測** … **判定しない項目。** 仕様が幅を持つもの、現状を記録するもの

**「検証」と「観測」は別物である。**
観測に「望ましくない」と書かれていても、テストは成功する。
仕様が幅を持つ項目を合否に混ぜると、「通った」の意味が薄まるため。

テストはアプリを **HTTP で外から叩く**（ブラックボックス）。
JWT のデコードと署名検証は、実装側のコードを使わず独立に行っている。
同じテストを net10.0 版と net48 版の両方に流す。

---

# SM. 疎通（テスト基盤そのものの確認）

## SM-1 Discovery 文書が取得でき、必須のメタデータが揃っている

| | |
|---|---|
| 観点 | RP は、この 1 つの URL から各エンドポイントの位置を知る。ここが欠けると、RP は認可サーバに繋げない。 |
| 根拠 | OIDC Discovery 1.0 §3（issuer / authorization_endpoint / token_endpoint / jwks_uri は REQUIRED） |
| テスト | `SM01_Discovery文書が取得できる` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- HTTP 200 が返る
- JSON として解釈できる
- 必須メタデータ issuer が文字列で存在する
- 必須メタデータ authorization_endpoint が文字列で存在する
- 必須メタデータ token_endpoint が文字列で存在する
- 必須メタデータ jwks_uri が文字列で存在する

**観測（判定しない）**

- issuer
  - id_token の iss は、この値と完全一致しなければならない（SM-5 / TC-6.2）。

## SM-2 Discovery 文書のキー名に前後の空白が無い

| | |
|---|---|
| 観点 | キー名に空白が混じると、RP はそのメタデータを**見つけられない。**JSON のキーは完全一致で引かれるため、目視では気付きにくい。 |
| 根拠 | OIDC Discovery 1.0 §3（メタデータ名は仕様で定義された文字列） / #189 の一部として修正済み |
| テスト | `SM02_Discovery文書のキー名に空白が混じっていない` |

**手順**

1. GET /.well-known/openid-configuration し、全キー名を調べる

**検証（合否を判定する）**

- すべてのキー名に前後の空白が無い

## SM-3 Discovery の jwks_uri から JWK Set が取得できる

| | |
|---|---|
| 観点 | RP は、ここで公開される鍵だけで id_token の署名を検証する。取得できなければ、署名検証そのものが成立しない。 |
| 根拠 | OIDC Core §10.1 / OIDC Discovery 1.0 §3（jwks_uri は REQUIRED） |
| テスト | `SM03_JWKSetが取得できる` |

**手順**

1. Discovery 文書から jwks_uri を取り出す
1. その URL を GET する

**検証（合否を判定する）**

- HTTP 200 が返る
- keys が配列で存在する

**補足**

- jwks_uri = https://localhost:44300/jwkcerts

## SM-4 テスト ユーザでサインインできる

| | |
|---|---|
| 観点 | **他のテストの前提。** 認可エンドポイントを叩く前に、利用者が認証済みである必要がある。ここが落ちると、以降の失敗は認可の問題ではなく資格情報の問題。 |
| 根拠 | このリポジトリの前提（UserStoreType=mem。テスト ユーザは初回アクセスで作られる） |
| テスト | `SM04_サインインできる` |

**手順**

1. GET /Account/Login して __RequestVerificationToken を取る
1. POST /Account/Login に資格情報を送る

**検証（合否を判定する）**

- サインインできた

## SM-5 認可コード フローが端から端まで通る

| | |
|---|---|
| 観点 | **テスト基盤が正しく組めているかの確認。**ここが通らなければ、以降のテストの失敗は仕様への不適合ではなく基盤の問題である可能性が高い。 |
| 根拠 | RFC 6749 §4.1 / OIDC Core §3.1 |
| テスト | `SM05_認可コードフローでトークンが取得できる` |

**手順**

1. 認可 → トークン交換までを通し、応答の形を見る

**検証（合否を判定する）**

- HTTP 200 が返る
- エラーにならない
- access_token が返る
- id_token が返る

# TC. 基本テストケース

## TC-1.1 state が認可応答でそのまま返る（CSRF 対策）

| | |
|---|---|
| 観点 | 認可リクエストで送った state と、認可応答の state が完全一致すること。一致しなければ、RP はレスポンスを自分のリクエストと結び付けられない。 |
| 根拠 | RFC 6749 §4.1.1（state は RECOMMENDED）/ §10.12（CSRF） |
| テスト | `TC0101_stateが往復する` |

**手順**

1. GET /authorize に state="a&b=c d" を付けて送る（区切り文字を含む値）

**検証（合否を判定する）**

- 認可コードが発行される
- 応答の state が送信値と完全一致する

## TC-1.2 state 無しの認可リクエストの扱い

| | |
|---|---|
| 観点 | state は RFC 6749 では RECOMMENDED であって REQUIRED ではない。拒否するのも受理するのも仕様の範囲内なので、**実装の挙動を記録する**。受理する場合、応答に state を付けてはならない（送っていないものを返さない）。 |
| 根拠 | RFC 6749 §4.1.1 / OAuth 2.0 Security BCP §2.1 |
| テスト | `TC0102_stateを送らないとき` |

**手順**

1. GET /authorize を state 無しで送る

**検証（合否を判定する）**

- 送っていない state を応答に含めない

**観測（判定しない）**

- state 無しのリクエストを受理するか
  - RFC 6749 は state を必須にしていない。OAuth 2.0 Security BCP は state か PKCE のいずれかで CSRF に対処することを求めており、この実装は PKCE を別途持つ。受理は違反ではない。

## TC-1.3 事前登録と一致しない redirect_uri が拒否される

| | |
|---|---|
| 観点 | 事前登録された値と完全一致しない redirect_uri では、**認可コードを発行してはならず、その URI へリダイレクトしてもならない。**リダイレクトすると、認可サーバがオープン リダイレクタになる。 |
| 根拠 | RFC 6749 §3.1.2.3 / §4.1.2.1 / OIDC Core §3.1.2.1 |
| テスト | `TC0103_未登録のredirect_uriが拒否される` |

**手順**

1. GET /authorize に redirect_uri=https://attacker.example.com/callback を指定する

**検証（合否を判定する）**

- 認可コードを発行しない
- 指定された不正な URI へリダイレクトしない

**観測（判定しない）**

- エラーの返し方
  - redirect_uri を信頼できない以上、そこへエラーを返さないのが正しい（RFC 6749 §4.1.2.1）。画面で知らせる形は妥当。

## TC-1.4 未定義のスコープを要求したときの扱い

| | |
|---|---|
| 観点 | 認可サーバは、未定義のスコープを **invalid_scope で拒否するか、無視して認めた分だけを返すか**のいずれかを選べる（RFC 6749 §3.3）。どちらを選ぶにせよ、**発行するスコープは、認可サーバ自身がDiscovery で宣言した scopes_supported の範囲に収まるべきである。**宣言外の文字列をそのまま載せると、スコープ文字列で認可するリソース サーバを、クライアントが任意の値で騙せる余地が生まれる。 |
| 根拠 | RFC 6749 §3.3（発行スコープは要求と異なってよい）/ §4.1.2.1（invalid_scope） / RFC 8414 §2（scopes_supported） |
| テスト | `TC0104_未定義のスコープの扱い` |

**手順**

1. GET /authorize に scope="openid email bogus_scope_not_defined" を指定する（3 つ目は scopes_supported に無い）

**検証（合否を判定する）**

- トークンが発行される
- 発行されたスコープが scopes_supported の範囲に収まる

**観測（判定しない）**

- 認可の段階で拒否したか
  - 受理したので、発行されたトークンのスコープを見る。

**補足**

- Discovery の scopes_supported = [profile, email, phone, address, auth, userid, roles, openid]

## TC-1.5 アクセス トークンの exp と expires_in が整合する

| | |
|---|---|
| 観点 | exp が現在時刻より未来にあり、expires_in（秒）と辻褄が合うこと。**期限切れ後に使えなくなるかは、ここでは確かめない**（待つ必要があるため。#188 を参照）。 |
| 根拠 | RFC 6749 §5.1（expires_in）/ RFC 7519 §4.1.4（exp は NumericDate） |
| テスト | `TC0105_トークンの有効期限が妥当` |

**手順**

1. 認可コード フローでアクセス トークンを取得し、exp と expires_in を見る

**検証（合否を判定する）**

- トークンが発行される
- expires_in が正の整数である
- exp が数値である（NumericDate）
- exp が現在時刻より未来である
- exp と expires_in が整合する（差が 60 秒以内）

## TC-2.1 認可コードを取得し、トークンに交換できる

| | |
|---|---|
| 観点 | 認可エンドポイントで code を得て、トークン エンドポイントで access_token（と refresh_token）に交換できること。フローの骨格。 |
| 根拠 | RFC 6749 §4.1（Authorization Code Grant） |
| テスト | `TC0201_認可コードからトークンを取得できる` |

**手順**

1. GET /authorize?response_type=code&scope=openid email …（サインイン済み）
1. POST /token に grant_type=authorization_code と code を送る

**検証（合否を判定する）**

- 認可コードが発行される
- 認可コードはクエリ文字列で返る
- エラーにならない
- access_token が返る
- refresh_token が返る
- token_type が Bearer である

## TC-2.2 使用済みの認可コードが再利用できない

| | |
|---|---|
| 観点 | 同じ code での 2 回目のトークン要求が拒否されること。**1 回目で発行済みのトークンを失効させるかは SHOULD** なので、そちらは観測にとどめる。 |
| 根拠 | RFC 6749 §4.1.2（code は 1 回限り）/ §10.5（再利用時は発行済みトークンを取り消す SHOULD） |
| テスト | `TC0202_認可コードは1回しか使えない` |

**手順**

1. code を 1 つ取得し、トークンに交換する
1. 同じ code で、もう一度トークン要求を送る
1. 1 回目に発行されたトークンがまだ使えるかを見る

**検証（合否を判定する）**

- 1 回目は成功する
- 2 回目は拒否される
- 2 回目でトークンを発行しない

**観測（判定しない）**

- エラー コード
  - RFC 6749 §5.2 は invalid_grant を求める。
- 再利用検知後、1 回目のトークンが失効しているか
  - RFC 6749 §10.5 は SHOULD であって MUST ではない。使えるままでも仕様違反ではないが、推奨からは外れる。

## TC-2.3 不正な client_id / client_secret のトークン要求が拒否される

| | |
|---|---|
| 観点 | コンフィデンシャル クライアントは、トークン エンドポイントで認証されなければならない。誤った資格情報でトークンが出てはならない。 |
| 根拠 | RFC 6749 §4.1.3 / §5.2（invalid_client） |
| テスト | `TC0203_不正なクライアント資格情報が拒否される` |

**手順**

1. 正しい code に、誤った client_secret を添えて送る
1. 存在しない client_id で送る

**検証（合否を判定する）**

- 誤った client_secret ではトークンを発行しない
- 存在しない client_id ではトークンを発行しない

**観測（判定しない）**

- エラー コード
  - RFC 6749 §5.2 はクライアント認証の失敗に invalid_client を求める。

## TC-2.4 PKCE の code_verifier が一致しないとトークンを発行しない

| | |
|---|---|
| 観点 | code_challenge を伴って得た code は、**対応する code_verifier を示せた要求にだけ**交換されること。一致しない要求でトークンが出ると、PKCE が意味を成さない。 |
| 根拠 | RFC 7636 §4.6（検証失敗は invalid_grant） |
| テスト | `TC0204_PKCEのcode_verifier不一致が拒否される` |

**手順**

1. code_challenge_method=S256, code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM で認可
1. 誤った code_verifier でトークン要求を送る
1. 正しい code_verifier で、別の code を交換する（対照）

**検証（合否を判定する）**

- 認可コードが発行される
- 誤った code_verifier ではトークンを発行しない

**観測（判定しない）**

- 正しい code_verifier のときの結果
  - **ここが拒否されると、PKCE を使うパブリック クライアントが動かない。**この実装は PKCE の扱いが OAuth 2.1 と噛み合っていない（ANALYSIS-IdP.md の C-7）。安全側の失敗ではあるが、機能はしない。

## TC-3.2 トークン応答に Cache-Control: no-store が付く

| | |
|---|---|
| 観点 | トークンを含む応答は、中間キャッシュやブラウザ履歴に残してはならない。RFC 6749 は **Cache-Control: no-store と Pragma: no-cache** を MUST としている。 |
| 根拠 | RFC 6749 §5.1（successful response）/ §5.2（error response） |
| テスト | `TC0302_トークン応答のキャッシュ制御` |

**手順**

1. POST /token で正常にトークンを取得し、応答ヘッダを見る

**検証（合否を判定する）**

- Cache-Control に no-store が付く
- Pragma に no-cache が付く
- この応答にトークンが含まれている（前提の確認）

**補足**

- どちらも #218 で付けた。それ以前は、両系統ともヘッダが無かった。エラー応答（RFC 6749 §5.2）でも返るよう、アクションの入口で付けている。

## TC-5.1 client_id / client_secret だけでトークンを取得できる

| | |
|---|---|
| 観点 | ユーザの文脈を持たない、アプリケーション自身のためのトークンが得られること。 |
| 根拠 | RFC 6749 §4.4（Client Credentials Grant） |
| テスト | `TC0501_クライアント資格情報でトークンを取得できる` |

**手順**

1. POST /token に grant_type=client_credentials を送る

**検証（合否を判定する）**

- エラーにならない
- access_token が返る

**観測（判定しない）**

- refresh_token の有無
  - RFC 6749 §4.4.3 は「refresh_token を含めるべきではない」としている（クライアントは同じ資格情報でいつでも再取得できるため）。
- sub（このトークンの主体）
  - ユーザの文脈を持たないので、クライアント自身を指すのが自然。

## TC-5.2 クライアント クレデンシャルのトークンで /userinfo を取得できない

| | |
|---|---|
| 観点 | このトークンには**エンドユーザの文脈が無い**。/userinfo はエンドユーザの Claim を返す口なので、**email や phone_number といったユーザの属性が返ってはならない。**sub をどう扱うかは実装差があるため、そちらは観測にとどめる。 |
| 根拠 | RFC 6749 §4.4 / OIDC Core §5.3（UserInfo はエンドユーザの Claim を返す） |
| テスト | `TC0502_クライアント資格情報のトークンでUserInfoを取得できない` |

**手順**

1. grant_type=client_credentials でトークンを取得する
1. そのトークンで GET /userinfo を叩く

**検証（合否を判定する）**

- エンドユーザの属性が返らない

**観測（判定しない）**

- /userinfo の応答
  - エンドユーザの Claim が返るなら、そのトークンの権限範囲が広すぎる。
- sub に何が入るか
  - エンドユーザが居ないので、クライアントの識別子が入るのが自然。ただし OIDC Core §5.3 の UserInfo は**エンドユーザの sub を返す口**であり、RP がこれをユーザ識別子と取り違える余地がある。openid スコープを伴わない要求は拒否する（403 insufficient_scope）方が安全。

## TC-6.1 scope に openid を含めたときだけ id_token が返る

| | |
|---|---|
| 観点 | openid が無ければ、それは OAuth 2.0 の認可であって OIDC の認証ではない。id_token を返してはならない。 |
| 根拠 | OIDC Core §3.1.2.1（openid は REQUIRED）/ §2 |
| テスト | `TC0601_openidスコープがあるときだけid_tokenが返る` |

**手順**

1. scope="openid email" で認可コード フローを通す
1. scope="email"（openid 無し）で通す

**検証（合否を判定する）**

- openid あり → id_token が返る
- openid なし → id_token が返らない
- openid なしでも access_token は返る

## TC-6.2 id_token の iss / sub / aud / exp / iat / nonce が妥当

| | |
|---|---|
| 観点 | RP は id_token のこれらを検証して初めて、「誰が」「誰のために」「いつまで」認証したのかを信頼できる。 |
| 根拠 | OIDC Core §2（ID Token）/ §3.1.3.7（ID Token の検証） |
| テスト | `TC0602_id_tokenの必須クレームが妥当` |

**手順**

1. 認可コード フローで id_token を取得する（nonce=nonce-tc0602）

**検証（合否を判定する）**

- iss が Discovery の issuer と完全一致する
- sub が認証したユーザである
- aud が自クライアントの client_id と一致する
- exp が数値である（NumericDate）
- iat が数値である（NumericDate）
- exp が現在時刻より未来である
- iat が未来ではない（時計のずれを 60 秒まで許容）
- 認可リクエストの nonce がそのまま入る

**補足**

- iss の期待値は、Discovery 文書の issuer から取る（決め打ちにしない）。

## TC-6.3 id_token の署名が JWK Set の公開鍵で検証できる

| | |
|---|---|
| 観点 | RP は、**認可サーバの公開鍵だけで** id_token の真正性を確かめられなければならない。検証できなければ、id_token は誰でも作れる文字列と変わらない。改竄したトークンが検証を通らないことも併せて見る。 |
| 根拠 | OIDC Core §3.1.3.7 (6)（JWS で検証）/ §10.1（署名鍵は jwks_uri で公開） |
| テスト | `TC0603_id_tokenの署名をJWKSで検証できる` |

**手順**

1. 認可コード フローで id_token を取得する
1. Discovery の jwks_uri から JWK Set を取得する
1. 公開鍵だけで署名を検証する（実装側の JWS クラスは使わない）
1. ペイロードを書き換えた id_token を検証する（通ってはならない）

**検証（合否を判定する）**

- JWK Set が取得できる
- 正規の id_token の署名が検証できる
- 改竄した id_token は検証できない

**補足**

- id_token のヘッダ : alg=RS256 / kid=W8YPrSZDTP6XB0VTKqFG3OAduynh5itxMmfrjmlXWLg

## TC-6.4 alg=none に書き換えたトークンを認可サーバが受け付けない

| | |
|---|---|
| 観点 | 署名を外した JWT を受理する実装は、**誰でも任意のトークンを作れる。**ここでは RP 側ではなく、**認可サーバの保護資源（/userinfo）が拒否するか**を見る。 |
| 根拠 | JWT BCP（RFC 8725）§3.1（alg=none を拒否する）/ OIDC Core §3.1.3.7 |
| テスト | `TC0604_alg_noneのトークンが受け付けられない` |

**手順**

1. 正規の access_token を取得する
1. 対照として、正規のトークンで /userinfo を叩く
1. 同じトークンを alg=none（署名なし）に書き換えて叩く
1. ペイロードだけ書き換え、署名はそのままのトークンで叩く

**検証（合否を判定する）**

- 正規のトークンでは /userinfo が応答する
- alg=none のトークンでユーザ情報を返さない
- 改竄したトークンでユーザ情報を返さない

**観測（判定しない）**

- 拒否のしかた
  - OIDC Core §5.3.3 / RFC 6750 §3.1 は 401 と WWW-Authenticate を求める（#196 で対応。RT-196.6 で検証）。

## TC-6.5 UserInfo が、要求したスコープに応じた属性を返す

| | |
|---|---|
| 観点 | Bearer トークンで /userinfo を叩くと、sub と、email / phone などスコープに対応した Claim が返ること。**要求していないスコープの属性が返ってはならない。** |
| 根拠 | OIDC Core §5.3（UserInfo Endpoint）/ §5.4（スコープと Claim の対応） |
| テスト | `TC0605_UserInfoがスコープに応じた属性を返す` |

**手順**

1. scope="openid email" で取得したトークンで /userinfo を叩く
1. scope="openid email phone" で取得したトークンで叩く
1. トークン無しで叩く

**検証（合否を判定する）**

- JSON が返る
- sub がテスト ユーザである
- email スコープの属性が返る
- 要求していない phone_number は返らない
- phone を要求すれば phone_number が返る
- email_verified が真偽値である
- Bearer トークン無しではユーザ情報を返さない

# EX. 拡張仕様

## EX-1.1 refresh_token で、新しい access_token を得られる

| | |
|---|---|
| 観点 | access_token の期限が切れても、**ユーザに再び認可を求めずに**取り直せること。refresh_token の存在理由そのもの。取り直したトークンは、**同じユーザの、同じ範囲の**ものでなければならない。 |
| 根拠 | RFC 6749 §6（scope を省略したら、元と同じ範囲とみなす）/ §1.5 |
| テスト | `EX0101_refresh_tokenで新しいaccess_tokenを得られる` |

**手順**

1. 認可コード フローで access_token と refresh_token を得る
1. POST /token に grant_type=refresh_token を送る（scope は省略）

**検証（合否を判定する）**

- エラーにならない
- access_token が返る
- 元とは別の access_token である
- 同じユーザのトークンである（sub）
- 元と同じ範囲である（scopes）

**観測（判定しない）**

- 新しい refresh_token
  - 発行し直すかどうかは任意（RFC 6749 §6）。発行し直すなら、古い方は使えなくするのが望ましい（EX-1.2）。

## EX-1.2 一度使った refresh_token は、もう使えない（ローテーション）

| | |
|---|---|
| 観点 | この実装は、更新のたびに新しい refresh_token を発行する（ローテーション）。**ならば古い方は使えなくなっていなければならない。**使えるなら、漏れた refresh_token を、正規のクライアントと並行して使い続けられる。 |
| 根拠 | RFC 9700（OAuth 2.0 Security BCP）§4.14.2 / RFC 6749 §10.4 |
| テスト | `EX0102_使用済みのrefresh_tokenは再利用できない` |

**手順**

1. 認可コード フローで refresh_token（旧）を得る
1. 旧で更新し、新しい refresh_token（新）を得る
1. 旧を、もう一度使う
1. 新で更新する

**検証（合否を判定する）**

- invalid_grant で拒否される
- トークンを発行しない
- 旧が再び提示された後は、新も使えない（一族ごと失効）

**補足**

- **使用済みが再び提示されたら、その一族（同じ認可から派生した refresh_token）をすべて失効させる**（#188 の段階 3）。漏れたトークンと正規のトークンを、サーバは見分けられないため（BCP §4.14.2）。正規の利用者は、認可からやり直すことになる。

## EX-1.3 別のクライアントに発行された refresh_token は使えない

| | |
|---|---|
| 観点 | refresh_token は、発行先のクライアントに結び付いている。他のクライアントが（自分の正しい資格情報で認証したうえで）提示しても、トークンを出してはならない。 |
| 根拠 | RFC 6749 §6（提示したクライアントが発行先であることを確かめる）/ §10.4 |
| テスト | `EX0103_他のクライアントのrefresh_tokenは使えない` |

**手順**

1. MVC_Sample で refresh_token を得る
1. TestClient の資格情報で、その refresh_token を提示する
1. 発行先の MVC_Sample が、その refresh_token を使う

**検証（合否を判定する）**

- invalid_grant で拒否される
- トークンを発行しない

**観測（判定しない）**

- 他者に提示された後も、正規のクライアントが使えるか
  - 拒否する前に refresh_token を消費していると、正規の利用者が巻き添えで失う。他者はトークンを奪えないが、正規の利用を妨害できることになる。

## EX-1.4 refresh_token を失効させると、そこから派生した新しい refresh_token も使えない

| | |
|---|---|
| 観点 | **漏れたトークンを失効させたのに、そこから派生した新しいトークンが生き残っては意味がない。**RFC 7009 §2.1 は、refresh_token を失効させるとき、**同じ認可グラントに基づくトークンも無効にすべき**としている。この実装は、同じ認可から派生した refresh_token を**一族**として扱い、まとめて失効させる（#188）。 |
| 根拠 | RFC 7009 §2.1 / #188 |
| テスト | `EX0104_失効させると派生した新しいrefresh_tokenも使えない` |

**手順**

1. 認可コード フローで refresh_token（旧）を得る
1. 旧で更新し、新しい refresh_token（新）を得る
1. 新を失効させる（POST /revoke）
1. 失効させた新で、更新を試みる

**検証（合否を判定する）**

- 失効の要求は HTTP 200
- 使えない

**補足**

- **旧（使用済み）も、同じ一族なので残っていない。**失効の対象を 1 本だけにすると、漏れた側が生き残る余地ができる。

## EX-2.1 access_token を失効させると、以後そのトークンは使えない

| | |
|---|---|
| 観点 | ログアウトや漏えいのときに、**期限を待たずに**トークンを無効にできること。失効の応答が成功しても、実際に使えてしまっては意味がないので、**使えなくなったことまで確かめる。** |
| 根拠 | RFC 7009 §2.1 / §2.2 |
| テスト | `EX0201_access_tokenを失効させると使えなくなる` |

**手順**

1. 認可コード フローで access_token を得て、/userinfo が応答することを確かめる
1. POST /revoke に token と token_type_hint=access_token を送る
1. 同じ access_token で、もう一度 /userinfo を叩く

**検証（合否を判定する）**

- 失効要求がエラーにならない
- 失効要求の HTTP ステータスが 200（RFC 7009 §2.2）
- 失効後は /userinfo がユーザ情報を返さない

## EX-2.2 refresh_token を失効させると、以後それで更新できない

| | |
|---|---|
| 観点 | refresh_token は長く生きるので、**失効できることの重みは access_token より大きい。**失効させた refresh_token で、新しいトークンが出てはならない。 |
| 根拠 | RFC 7009 §2.1 / §2.2 |
| テスト | `EX0202_refresh_tokenを失効させると更新できなくなる` |

**手順**

1. 認可コード フローで access_token と refresh_token を得る
1. POST /revoke に token と token_type_hint=refresh_token を送る
1. 失効させた refresh_token で更新を試みる
1. 一緒に発行されていた access_token で /userinfo を叩く

**検証（合否を判定する）**

- 失効要求がエラーにならない
- トークンを発行しない

**観測（判定しない）**

- 同じ認可から出た access_token は、まだ使えるか
  - RFC 7009 §2.1 は、refresh_token を失効させたら、同じ認可に基づく access_token も無効にすべき（SHOULD）としている。

## EX-2.3 他のクライアントに発行されたトークンは、失効させられない

| | |
|---|---|
| 観点 | 失効は、そのトークンの発行先だけが行える。誰でも失効させられるなら、**他人のトークンを無効にして利用を妨害できる。** |
| 根拠 | RFC 7009 §2.1（発行先のクライアントかを確かめ、違えば要求を拒否する）/ #194 |
| テスト | `EX0203_他のクライアントのトークンは失効させられない` |

**手順**

1. MVC_Sample で access_token を得る
1. TestClient の資格情報で、その access_token の失効を要求する
1. 元の access_token で /userinfo を叩く

**検証（合否を判定する）**

- 要求を拒否する（error を返す）
- トークンは失効していない（/userinfo が応答する）

## EX-2.4 token_type_hint を省略しても、失効できる

| | |
|---|---|
| 観点 | token_type_hint は**任意のヒント**にすぎない。省略されたら、サーバがトークンの種類を調べて失効させる。ヒントが無いことを理由に断ると、トークンを無効にできないまま残る。 |
| 根拠 | RFC 7009 §2.1（token_type_hint は OPTIONAL。ヒントで見つからなければ、対応する全種類から探す） |
| テスト | `EX0204_token_type_hintを省略しても失効できる` |

**手順**

1. 認可コード フローで access_token を得る
1. POST /revoke に token だけを送る（token_type_hint なし）
1. 同じ access_token で /userinfo を叩く

**検証（合否を判定する）**

- 失効要求がエラーにならない
- 失効後は /userinfo がユーザ情報を返さない

## EX-2.5 無効なトークンの失効要求を、エラーにしない

| | |
|---|---|
| 観点 | **失効させたいトークンが既に無効なら、目的は達している。**クライアントはこのエラーに対してできることが無いので、エラーを返さない。 |
| 根拠 | RFC 7009 §2.2（無効なトークンでも 200。invalid token はエラー応答の理由にならない） |
| テスト | `EX0205_無効なトークンの失効要求はエラーにしない` |

**手順**

1. POST /revoke に、存在しないトークン（token_type_hint=access_token）を送る

**検証（合否を判定する）**

- エラーを返さない
- HTTP ステータスが 200（RFC 7009 §2.2）

## EX-2.6 token_type_hint が実際の種類と違っていても、失効できる

| | |
|---|---|
| 観点 | ヒントは手掛かりにすぎず、**外れていてもトークンを探し当てる**のがサーバの責務。クライアントがヒントを取り違えただけで失効が効かないと、トークンが生き残る。 |
| 根拠 | RFC 7009 §2.1（ヒントで見つからなければ、対応する全種類から探す。MUST）/ #200 |
| テスト | `EX0206_token_type_hintが違っていても失効できる` |

**手順**

1. 認可コード フローで access_token を得る
1. access_token を、token_type_hint=refresh_token（取り違え）で失効させる
1. 同じ access_token で /userinfo を叩く

**検証（合否を判定する）**

- 失効要求がエラーにならない
- 失効後は /userinfo がユーザ情報を返さない

## EX-3.1 有効な access_token について、active=true と答える

| | |
|---|---|
| 観点 | リソース サーバが「このトークンは今使えるか」を認可サーバに問い合わせる口。**active は必ず返す真偽値。**それ以外の項目（scope / sub / exp など）は任意。 |
| 根拠 | RFC 7662 §2.1 / §2.2（active は REQUIRED の boolean） |
| テスト | `EX0301_有効なaccess_tokenはactiveがtrue` |

**手順**

1. 認可コード フローで access_token を得る
1. POST /introspect に token と token_type_hint=access_token を送る（発行先の資格情報で）

**検証（合否を判定する）**

- active が true（JSON の真偽値）

**観測（判定しない）**

- 返った項目
  - active 以外は任意（§2.2）。
- scope

## EX-3.2 有効な refresh_token についても、active=true と答える

| | |
|---|---|
| 観点 | 問い合わせの対象は access_token に限らない。この実装は token_type_hint=refresh_token を受け付けている。 |
| 根拠 | RFC 7662 §2.1（token は access_token または refresh_token の値） |
| テスト | `EX0302_有効なrefresh_tokenもactiveがtrue` |

**手順**

1. 認可コード フローで refresh_token を得る
1. POST /introspect に token と token_type_hint=refresh_token を送る

**検証（合否を判定する）**

- active が true（JSON の真偽値）

**観測（判定しない）**

- token_type
  - **リフレッシュ トークンには RFC 6749 §5.1 の型が無いので、付けない**（#218）。RFC 7662 §2.2 の token_type は OPTIONAL。
- 返った項目

## EX-3.3 他のクライアントに発行されたトークンには、active=false とだけ答える

| | |
|---|---|
| 観点 | 問い合わせ元に知る権限の無いトークンについて、**中身（ユーザや範囲）を漏らさない。**active=false だけを返すのが仕様の答え方。 |
| 根拠 | RFC 7662 §2.2（知る権限が無ければ active=false）/ §4 / #194 |
| テスト | `EX0303_他のクライアントのトークンはactiveがfalseだけ` |

**手順**

1. MVC_Sample で access_token を得る
1. TestClient の資格情報で、その access_token を問い合わせる

**検証（合否を判定する）**

- active が false
- active 以外を返さない

## EX-3.4 無効なトークンには、エラーではなく active=false で答える

| | |
|---|---|
| 観点 | 存在しない・失効したトークンについての「使えない」は、**問い合わせの正常な答え**である。エラーにすると、リソース サーバは「問い合わせに失敗した」のか「トークンが使えない」のかを区別できない。 |
| 根拠 | RFC 7662 §2.2（無効なトークンには active=false を返す。MUST） |
| テスト | `EX0304_無効なトークンにはactiveがfalseで答える` |

**手順**

1. 存在しないトークンを問い合わせる
1. access_token を得て失効させ、それを問い合わせる

**検証（合否を判定する）**

- 存在しないトークン : active=false と答える
- 失効させたトークン : active=false と答える

## EX-3.5 token_type_hint を省略しても、答えられる

| | |
|---|---|
| 観点 | token_type_hint は**任意のヒント**。省略されたら、サーバが種類を調べて答える。ヒントが無いことを理由に答えないと、リソース サーバはトークンを確かめられない。 |
| 根拠 | RFC 7662 §2.1（token_type_hint は OPTIONAL） |
| テスト | `EX0305_token_type_hintを省略しても答えられる` |

**手順**

1. 認可コード フローで access_token を得る
1. POST /introspect に token だけを送る（token_type_hint なし）

**検証（合否を判定する）**

- active が true（JSON の真偽値）

## EX-3.6 クライアント認証の無い問い合わせには、トークンの情報を返さない

| | |
|---|---|
| 観点 | イントロスペクションは、トークンの中身（ユーザ・範囲）を明かす口。**誰でも問い合わせられると、拾ったトークンの持ち主や権限を調べられる。** |
| 根拠 | RFC 7662 §2.1（問い合わせ元の認可を要求する。MUST）/ §4 |
| テスト | `EX0306_クライアント認証が無ければトークンの情報を返さない` |

**手順**

1. 認可コード フローで access_token を得る
1. client_id / client_secret を付けずに POST /introspect を送る

**検証（合否を判定する）**

- active=true を返さない
- sub や scope を返さない

**観測（判定しない）**

- 拒否のしかた
  - RFC 7662 §2.3 は、認証に失敗したら 401 を返すとしている（#196 で対応。RT-196.11 で検証）。

## EX-3.7 token_type_hint が実際の種類と違っていても、答えられる

| | |
|---|---|
| 観点 | ヒントは手掛かりにすぎない。**外れていても探し当てて答える。**取り違えただけで active=false になると、リソース サーバは使えるトークンを拒んでしまう。 |
| 根拠 | RFC 7662 §2.1（ヒントで見つからなければ、対応する全種類から探す。MUST）/ #200 |
| テスト | `EX0307_token_type_hintが違っていても答えられる` |

**手順**

1. 認可コード フローで access_token を得る
1. access_token を、token_type_hint=refresh_token（取り違え）で問い合わせる

**検証（合否を判定する）**

- active が true（JSON の真偽値）
- token_type が bearer である

## EX-4.1 デバイス認可の応答に、必須の項目が揃っている

| | |
|---|---|
| 観点 | 入力手段の乏しい機器（TV など）が、**別の端末でユーザに承認してもらう**ための起点。機器はこの応答だけを頼りに、ユーザへの案内とポーリングを行う。 |
| 根拠 | RFC 8628 §3.1 / §3.2（device_code / user_code / verification_uri / expires_in は REQUIRED） |
| テスト | `EX0401_デバイス認可の応答に必須の項目が揃っている` |

**手順**

1. POST /device_authz に client_id と scope を送る
1. （参考）Discovery に、このエンドポイントが載っているかを見る

**検証（合否を判定する）**

- device_code がある
- user_code がある
- verification_uri がある
- expires_in がある

**観測（判定しない）**

- verification_uri
  - ユーザが別の端末で開く URL。
- 任意の項目
- expires_in / interval の JSON 型
  - 秒数なので数値（Number）が自然（§3.2 の例も数値）。文字列だと、型に厳しいクライアントは読めない。
- Discovery での広告
  - RFC 8628 §4 の認可サーバ メタデータ。Discovery の不備は #189 で扱っている。

## EX-4.2 ユーザが承認する前のポーリングには、authorization_pending を返す

| | |
|---|---|
| 観点 | 機器は、ユーザの操作を待ちながらトークン エンドポイントを繰り返し叩く。**まだ承認されていないこと**を、失敗とは区別できる形で伝える必要がある。 |
| 根拠 | RFC 8628 §3.4 / §3.5（authorization_pending） |
| テスト | `EX0402_承認前のポーリングはauthorization_pending` |

**手順**

1. 機器 : POST /device_authz で device_code を得る
1. 機器 : ユーザが何もしないうちに、grant_type=device_code でトークンを要求する

**検証（合否を判定する）**

- authorization_pending を返す
- トークンを発行しない

## EX-4.3 ユーザが承認すると、機器はトークンを取得できる

| | |
|---|---|
| 観点 | **フローの骨格。** トークンを受け取る機器（device_code を持つ）と、承認するユーザ（user_code を入力する）は、別の端末である。承認したユーザの権限で、機器にトークンが出ること。 |
| 根拠 | RFC 8628 §3.3（ユーザの操作）/ §3.4 / §3.5 |
| テスト | `EX0403_ユーザが承認すると機器はトークンを取得できる` |

**手順**

1. 機器 : POST /device_authz で device_code と user_code を得る
1. ユーザ : サインインした端末で /device_verify を開き、user_code を入力して許可する
1. 機器 : grant_type=device_code でトークンを要求する

**検証（合否を判定する）**

- 検証画面が承認を受け付ける
- エラーにならない
- access_token が返る
- 承認したユーザのトークンである（sub）

**観測（判定しない）**

- refresh_token / id_token
  - この実装は refresh_token を生成・保存するが、応答には含めていない（CmnEndpoints.GrantDeviceAuthZ）。渡さないなら、生成しない方がよい。

**補足**

- このテストでは 1 つの HTTP クライアントが両方の役を務める。機器側の要求（/device_authz と /token）は Cookie に依存しないので、役の区別には影響しない。

## EX-4.4 ユーザが拒否すると、機器には access_denied を返す

| | |
|---|---|
| 観点 | 拒否されたら、機器はポーリングをやめる必要がある。**pending のままだと、期限が切れるまで叩き続ける。** |
| 根拠 | RFC 8628 §3.5（access_denied） |
| テスト | `EX0404_ユーザが拒否すると機器にはaccess_deniedを返す` |

**手順**

1. 機器 : device_code と user_code を得る
1. ユーザ : /device_verify で user_code を入力して拒否する
1. 機器 : トークンを要求する

**検証（合否を判定する）**

- access_denied を返す
- トークンを発行しない

## EX-4.5 トークンを受け取った後の device_code は、もう使えない

| | |
|---|---|
| 観点 | device_code は、承認 1 回につきトークン 1 回。**再び使えるなら、device_code を盗み見た者もトークンを得られる。** |
| 根拠 | RFC 8628 §3.5 / RFC 6749 §4.1.2（認可コードは 1 回限り。device_code も同じ役割を担う） |
| テスト | `EX0405_トークンを受け取った後のdevice_codeは使えない` |

**手順**

1. 承認まで済ませ、トークンを 1 回受け取る
1. 同じ device_code で、もう一度トークンを要求する

**検証（合否を判定する）**

- 2 回目はトークンを発行しない
- 2 回目は JSON のエラー応答を返す
- 2 回目の error が RFC の値である

## EX-4.6 登録されていない client_id では、デバイス認可を始められない

| | |
|---|---|
| 観点 | 未登録のクライアントの名義で user_code を発行すると、ユーザは**誰に権限を渡すのか分からないまま**承認させられる。 |
| 根拠 | RFC 8628 §3.1 / RFC 6749 §5.2（invalid_client）/ #193 |
| テスト | `EX0406_登録されていないclient_idでは始められない` |

**手順**

1. POST /device_authz に、登録されていない client_id を送る

**検証（合否を判定する）**

- invalid_client で拒否される
- device_code を発行しない

## EX-4.7 発行していない・送らない device_code は、HTTP 500 にせずエラーとして返す

| | |
|---|---|
| 観点 | 機器が送ってくる device_code は、信用できない入力である。**どんな値でも、サーバが落ちずに、機器が解釈できるエラーを返す**こと。（EX-4.5 は使用済みの値。こちらは最初から存在しない値と、値が無い場合） |
| 根拠 | RFC 8628 §3.4（device_code は REQUIRED）/ RFC 6749 §5.2（invalid_grant / invalid_request）/ #199 |
| テスト | `EX0407_不正なdevice_codeは500にならずエラーで返る` |

**手順**

1. 発行していない device_code でトークンを要求する
1. device_code を付けずにトークンを要求する

**検証（合否を判定する）**

- 発行していない値 : JSON のエラー応答を返す（HTTP 500 にならない）
- 発行していない値 : invalid_grant で拒否される
- 値が無い : JSON のエラー応答を返す（HTTP 500 にならない）
- 値が無い : invalid_request で拒否される

## EX-5.1 response_type=code id_token : フラグメントで返り、id_token の c_hash が code と一致する

| | |
|---|---|
| 観点 | id_token を認可エンドポイントで先に受け取り、code は後でトークンに交換する形。**c_hash は「この id_token とこの code は同じ応答のものだ」という結び付け。**合わなければ、code だけを差し替えられても RP は気付けない。 |
| 根拠 | OIDC Core §3.3.2.5（フラグメントで返す）/ §3.3.2.10（c_hash による code の検証） / §3.3.2.11（この形では c_hash は REQUIRED） |
| テスト | `EX0501_code_id_tokenでc_hashがcodeと一致する` |

**手順**

1. GET /authorize に response_type=code id_token と nonce を付けて送る

**検証（合否を判定する）**

- フラグメント（#）で返る
- code が返る
- id_token が返る
- access_token は返さない（response_type に token が無い）
- id_token の署名を JWKS で検証できる
- nonce が送った値と一致する
- c_hash が、code から計算した値と一致する

**観測（判定しない）**

- s_hash と、state から計算した値（計算方法の対照）
  - s_hash は FAPI の拡張で、OIDC Core では任意。
- at_hash
  - この形では access_token を返さないので、at_hash は任意（§3.3.2.11）。

## EX-5.2 response_type=code token : code と access_token がフラグメントで返る

| | |
|---|---|
| 観点 | access_token を返すなら、**token_type も添える**（Implicit と同じ規則）。id_token は要求していないので返さない。 |
| 根拠 | OIDC Core §3.3.2.5 / RFC 6749 §4.2.2（token_type は REQUIRED、大小文字を区別しない。expires_in は RECOMMENDED） |
| テスト | `EX0502_code_tokenでcodeとaccess_tokenが返る` |

**手順**

1. GET /authorize に response_type=code token を付けて送る

**検証（合否を判定する）**

- フラグメント（#）で返る
- code が返る
- access_token が返る
- token_type が Bearer
- id_token は返さない（response_type に id_token が無い）

**観測（判定しない）**

- expires_in
  - RECOMMENDED。

## EX-5.3 response_type=code id_token token : at_hash と c_hash の両方が一致する

| | |
|---|---|
| 観点 | 3 つを同時に返す形。**id_token が code と access_token の両方に結び付いている**ことを確かめる。片方でも合わなければ、その値だけを差し替えられる。 |
| 根拠 | OIDC Core §3.3.2.11（この形では at_hash も c_hash も REQUIRED）/ §3.3.2.9 / §3.3.2.10 |
| テスト | `EX0503_code_id_token_tokenでat_hashとc_hashが一致する` |

**手順**

1. GET /authorize に response_type=code id_token token と nonce を付けて送る

**検証（合否を判定する）**

- フラグメント（#）で返る
- code / id_token / access_token がすべて返る
- id_token の署名を JWKS で検証できる
- nonce が送った値と一致する
- at_hash が、access_token から計算した値と一致する
- c_hash が、code から計算した値と一致する

**観測（判定しない）**

- s_hash と、state から計算した値（計算方法の対照）
  - s_hash は FAPI の拡張で、OIDC Core では任意。

## EX-5.4 Hybrid で受け取った code をトークンに交換でき、両方の id_token が同じユーザを指す

| | |
|---|---|
| 観点 | code の交換で得る id_token は、認可エンドポイントで受け取ったものと**同じ発行者・同じユーザ**でなければならない。違えば、RP はどちらを信じればよいか分からない。 |
| 根拠 | OIDC Core §3.3.3.6（iss と sub は、認可エンドポイントの id_token と同一。MUST） |
| テスト | `EX0504_Hybridのcodeを交換でき両方のid_tokenが同じユーザを指す` |

**手順**

1. response_type=code id_token で code と id_token を受け取る
1. その code を、同じ redirect_uri でトークンに交換する

**検証（合否を判定する）**

- エラーにならない
- access_token が返る
- id_token が返る
- iss が同じ
- sub が同じ

## EX-6.1 response_mode=fragment : 認可コードがフラグメントで返る

| | |
|---|---|
| 観点 | response_mode は、応答パラメタの**置き場所**をクライアントが選ぶ仕組み。code は既定ではクエリで返るが、fragment を指定すればフラグメントで返る（フラグメントはサーバへ送られないので、リダイレクト先のアクセス ログに残らない）。 |
| 根拠 | OAuth 2.0 Multiple Response Type Encoding Practices §2.1（response_mode） |
| テスト | `EX0601_response_modeがfragmentならcodeがフラグメントで返る` |

**手順**

1. GET /authorize に response_mode=fragment を付けて送る

**検証（合否を判定する）**

- フラグメント（#）で返る
- code が返る
- state がそのまま返る
- クエリには code を載せない

## EX-6.2 response_mode=form_post : redirect_uri へ自動送信する HTML フォームで返る

| | |
|---|---|
| 観点 | パラメタを URL に載せずに返す方法。**ブラウザの履歴・Referer・アクセス ログに code が残らない。**応答はリダイレクトではなく、redirect_uri へ POST される HTML フォームになる。 |
| 根拠 | OAuth 2.0 Form Post Response Mode §2（HTML フォームを自動送信し、パラメタは hidden で送る） |
| テスト | `EX0602_response_modeがform_postなら自動送信フォームで返る` |

**手順**

1. GET /authorize に response_mode=form_post を付けて送る
1. フォームで受け取った code を、トークンに交換する

**検証（合否を判定する）**

- リダイレクトしない（HTML を返す）
- フォームの送信先が redirect_uri
- フォームは POST で送る
- 読み込んだら自動で送信する
- code を hidden で送る
- state がそのまま返る
- トークンに交換できる

## EX-6.3 response_mode=query.jwt（JARM）: 応答が署名付き JWT 1 つにまとまり、検証できる

| | |
|---|---|
| 観点 | 応答パラメタ（code / state）を**認可サーバの署名付き JWT に包んで**返す。RP は署名・iss・aud・exp を確かめることで、応答の差し替えや、別の RP 向けの応答の流用を検知できる。 |
| 根拠 | JARM（JWT Secured Authorization Response Mode for OAuth 2.0）§2.1（iss / aud / exp は REQUIRED）/ §2.3.1（query.jwt）/ §4（検証） |
| テスト | `EX0603_JARMの応答は署名付きJWTで検証できる` |

**手順**

1. GET /authorize に response_mode=query.jwt を付けて送る
1. JWT の署名を JWKS で確かめ、中身を読む
1. JWT から取り出した code を、トークンに交換する

**検証（合否を判定する）**

- クエリで返る
- response パラメタ（JWT）が返る
- code を URL に直接載せない
- 署名を JWKS で検証できる
- iss が Discovery の issuer と一致する
- aud が client_id と一致する
- exp がある
- state が送った値と一致する
- code が JWT の中にある
- トークンに交換できる

## EX-6.4 JARM の exp は NumericDate（JSON の数値）である

| | |
|---|---|
| 観点 | exp は RFC 7519 の NumericDate であり、**数値**でなければならない。文字列だと、JWT ライブラリの多くは有効期限の検証に失敗するか、検証を素通りさせる。（id_token / access_token では #184 で直した問題） |
| 根拠 | JARM §2.1（exp は RFC 7519 の定義による）/ RFC 7519 §2（NumericDate）/ §4.1.4 |
| テスト | `EX0604_JARMのexpはNumericDateである` |

**手順**

1. GET /authorize に response_mode=query.jwt を付けて送り、JWT の exp の型を見る

**検証（合否を判定する）**

- exp が JSON の数値である

## EX-7.1 クライアントが署名した JWT（assertion）で、トークンを取得できる

| | |
|---|---|
| 観点 | パスワードやシークレットを送らずに、**秘密鍵による署名**で自分を証明してトークンを得る。サーバは、登録済みの公開鍵で署名を確かめる。 |
| 根拠 | RFC 7523 §2.1（grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer）/ §3（JWT の要件） |
| テスト | `EX0701_署名したassertionでトークンを取得できる` |

**手順**

1. iss=sub=client_id、aud=トークン エンドポイント、exp=5 分後 の JWT を RS256 で署名する
1. POST /token に grant_type と assertion を送る
1. 同じ assertion を、もう一度送る

**検証（合否を判定する）**

- エラーにならない
- access_token が返る

**観測（判定しない）**

- access_token の sub
  - ユーザの文脈を持たないので、クライアント自身を指すのが自然。
- 同じ assertion の再利用
  - jti による再利用の防止は任意（RFC 7523 §3 (7) : MAY）。

**補足**

- **トークン要求に scope を付けなければ、assertion の中の scope を使う**（#218）。付けた場合は、そちらが優先される（RFC 7521 §4.1 / RFC 7523 §2.1）。EX-7.5 で測る。

## EX-7.2 aud が認可サーバを指していない assertion は拒否される

| | |
|---|---|
| 観点 | **他のサーバ向けに作られた assertion の流用**を防ぐ。aud が自分（トークン エンドポイント）でなければ、受け付けてはならない。 |
| 根拠 | RFC 7523 §3 (3)（aud に自分が含まれなければ拒否。MUST） |
| テスト | `EX0702_audが違うassertionは拒否される` |

**手順**

1. aud=https://attacker.example.com/token の assertion を送る（署名は正しい）

**検証（合否を判定する）**

- トークンを発行しない

**観測（判定しない）**

- error
  - RFC 7523 §3.1 は invalid_grant としている。

## EX-7.3 署名が正しくない assertion（改ざん / alg=none）は拒否される

| | |
|---|---|
| 観点 | 署名が合わない JWT を受け付けるなら、**誰でも任意のクライアントを名乗れる。** |
| 根拠 | RFC 7523 §3（署名または MAC が必須。検証できなければ拒否）/ RFC 8725 §3.1（alg=none） |
| テスト | `EX0703_署名が正しくないassertionは拒否される` |

**手順**

1. ペイロードだけを書き換え、署名はそのままの assertion を送る
1. alg=none に書き換え、署名を落とした assertion を送る

**検証（合否を判定する）**

- 改ざんした assertion : トークンを発行しない
- alg=none の assertion : トークンを発行しない

## EX-7.4 期限切れの assertion は拒否される

| | |
|---|---|
| 観点 | assertion は短命であることが前提。**古い assertion が使えると、漏れたものを後から使われる。** |
| 根拠 | RFC 7523 §3 (4)（exp を過ぎていれば拒否。MUST） |
| テスト | `EX0704_期限切れのassertionは拒否される` |

**手順**

1. exp=10 分前 の assertion を送る（署名は正しい）

**検証（合否を判定する）**

- トークンを発行しない

## EX-7.5 トークン要求の scope が、assertion の中の scope より優先される

| | |
|---|---|
| 観点 | **scope は、assertion の中身ではなくトークン要求のパラメタである。**仕様どおり scope を送るクライアントの指定が黙って無視されると、要らない権限の付いたトークンを受け取ることになる。 |
| 根拠 | RFC 7521 §4.1 / RFC 7523 §2.1（scope はトークン要求のパラメタ）/ #218 |
| テスト | `EX0705_トークン要求のscopeが使われる` |

**手順**

1. scope を送らずに要求し、発行されたスコープを見る（基準）
1. 同じ assertion に、トークン要求の scope=email を付けて要求する

**検証（合否を判定する）**

- 要求した email が発行される
- assertion にしか無い profile は発行されない

**観測（判定しない）**

- 送らないとき発行されたスコープ
  - assertion の中の scope（profile email）から、発行できるものだけが返る。

## EX-8.1 認証デバイスで許可すると、クライアントはトークンを取得できる

| | |
|---|---|
| 観点 | CIBA の本筋。ユーザは、クライアントの画面ではなく**手元の認証デバイス**で承認する。承認までは authorization_pending を返し、**承認した後にだけトークンを出す**こと。プッシュ通知は、登録した端末に、要求の binding_message を載せて届くこと。 |
| 根拠 | CIBA Core §7（認証リクエスト）/ §10（ポーリング）/ §11（authorization_pending）/ #196 |
| テスト | `EX0801_認証デバイスで許可するとクライアントはトークンを取得できる` |

**手順**

1. ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）
1. クライアント : CIBA の認証リクエストを送る（/ros に登録 → POST /ciba_authz）
1. サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）
1. クライアント : 承認の前にポーリングする
1. ユーザ : 認証デバイスで「許可」を押す（POST /ciba_result、result=true）
1. クライアント : もう一度ポーリングする

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- 認証リクエスト : HTTP 200
- auth_req_id が返る
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- binding_message が載る
- authorization_pending が返る
- トークンを出さない
- 返答 : HTTP 200
- 返答 : 本文は OK
- access_token が返る

**観測（判定しない）**

- id_token
  - CIBA Core は、成功のトークン応答に id_token を含めるとしている。

## EX-8.2 認証デバイスで拒否すると、クライアントには access_denied を返す

| | |
|---|---|
| 観点 | ユーザが身に覚えのない要求を**手元で断れる**ことが、CIBA の安全性の要。拒否した要求で、トークンが出てはならない。 |
| 根拠 | CIBA Core §11（access_denied）/ #196 |
| テスト | `EX0802_認証デバイスで拒否するとaccess_denied` |

**手順**

1. ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）
1. クライアント : CIBA の認証リクエストを送る
1. サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）
1. ユーザ : 認証デバイスで「拒否」を押す（POST /ciba_result、result=false）
1. クライアント : ポーリングする

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- 返答 : HTTP 200
- 返答 : 本文は OK
- access_denied が返る
- トークンを出さない

## EX-8.3 返答は、その auth_req_id の要求だけに効く（他の保留中の要求に波及しない）

| | |
|---|---|
| 観点 | **返答は 1 つの要求に閉じなければならない。** 以前はメモリのストアで auth_req_id を見ておらず、1 つの「許可」が保留中の全ての要求に書き込まれた。この状態では、承認していない要求にもトークンが出てしまう。 |
| 根拠 | CIBA Core §10（ポーリング）/ §11（authorization_pending） |
| テスト | `EX0803_返答はそのauth_req_idだけに効く` |

**手順**

1. ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）
1. クライアント : CIBA の認証リクエストを 2 件送る（A と B）
1. サーバ → 認証デバイス : 2 件のプッシュ通知を受け取る（送信箱）
1. ユーザ : A だけに「許可」を返す（POST /ciba_result）
1. クライアント : B をポーリングする（まだ誰も返答していない）
1. クライアント : A をポーリングする（許可済み）

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- 2 件の auth_req_id は別のもの
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- 返答 : HTTP 200
- 返答 : 本文は OK
- B は authorization_pending のまま
- B にトークンを出さない
- A にはトークンを出す

## EX-8.4 別の利用者のトークンでは、他人の CIBA 要求を承認できない

| | |
|---|---|
| 観点 | **承認は、要求が宛てられた利用者だけができなければならない。**他人が承認できると、本人の知らないうちにクライアントへトークンが出る。要求が無い場合と自分宛てでない場合は、**同じ応答**で返すこと（区別すると auth_req_id の存在を推測できる）。 |
| 根拠 | CIBA Core §7（認証リクエストは特定の利用者に宛てられる） |
| テスト | `EX0804_別の利用者は承認できない` |

**手順**

1. 宛先の利用者 : 認証デバイスを登録し、CIBA の要求を 1 件保留にする
1. **別の利用者**のトークンを得る
1. 別の利用者のトークンで、その auth_req_id に「許可」を送る
1. クライアント : ポーリングしても、まだ承認されていない
1. 対照 : 宛先の利用者が「許可」を送るとトークンが出る

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- 別の利用者のトークンである
- 返答 : HTTP 400
- 返答 : 本文は NG
- authorization_pending のまま
- トークンを出さない
- 宛先の利用者の返答 : HTTP 200
- access_token が返る

# RT. 個別 Issue の回帰

## RT-182.1 expires_in が 0 にならない

| | |
|---|---|
| 観点 | expires_in は「トークンの有効期間の秒数」。0 だと RP は「即座に期限切れ」と解釈し、受け取った直後に再取得へ回るか、トークンを捨てる。 |
| 根拠 | RFC 6749 §5.1（expires_in は有効期間の秒数） / 修正前は TimeSpan.Seconds（分内の秒）を返しており常に 0 だった（#182） |
| テスト | `RT182_01_expires_inが0でない` |

**手順**

1. 認可コード フローでトークンを取得し、expires_in を見る

**検証（合否を判定する）**

- expires_in が存在する
- expires_in が正の整数である

## RT-183.1 nonce を送らない Authorization Code フローでも id_token が返る

| | |
|---|---|
| 観点 | **Authorization Code フローでは nonce は任意。**送らなかったことを理由に id_token を出さないのは、OIDC の認証そのものが成立しなくなる。 |
| 根拠 | OIDC Core §3.1.2.1（Authorization Code フローの nonce は OPTIONAL） / #183 |
| テスト | `RT183_01_nonceなしでもid_tokenが返る` |

**手順**

1. nonce を送らずに認可コード フローを通す

**検証（合否を判定する）**

- エラーにならない
- id_token が返る

**補足**

- **当初 #183 は「nonce 無しだと id_token が返らない」と報告したが、これは誤検出だった**（呼び出し元まで追わずに判断した）。実際の欠陥は RT-191.1 の方である。

## RT-184.1 JWT の exp / nbf / iat が JSON の数値である

| | |
|---|---|
| 観点 | NumericDate は **JSON の数値**と定められている。文字列で入れると、仕様どおりに実装された RP のライブラリが型エラーで検証に失敗する。 |
| 根拠 | RFC 7519 §2（NumericDate は JSON number）/ §4.1.4・4.1.5・4.1.6 / 修正前は文字列だった（#184） |
| テスト | `RT184_01_時刻クレームが数値である` |

**手順**

1. 認可コード フローで access_token と id_token を取得し、型を見る

**検証（合否を判定する）**

- access_token の exp が数値である
- id_token の exp が数値である
- access_token の nbf が数値である
- access_token の iat が数値である
- id_token の iat が数値である

## RT-184.2 access_token の email_verified / phone_number_verified が真偽値である

| | |
|---|---|
| 観点 | OIDC はこれらを boolean と定めている。文字列の "true" は、**JavaScript では "false" も真**になるため、RP 側で検証の意味が反転しうる。 |
| 根拠 | OIDC Core §5.1（email_verified / phone_number_verified は boolean） / 修正前は文字列だった（#184） |
| テスト | `RT184_02_真偽値クレームが真偽値である` |

**手順**

1. scope に email と phone を含めてトークンを取得し、型を見る

**観測（判定しない）**

- 対象のクレーム
  - スコープの絞り込み次第で載らないことがある。その場合は型を確かめようがない。

## RT-184.3 UserInfo の email_verified / phone_number_verified が真偽値である

| | |
|---|---|
| 観点 | **JWT と UserInfo は別の経路**で組み立てられる。片方だけ直っている状態があり得るので、両方を見る。 |
| 根拠 | OIDC Core §5.1 / §5.3.2（UserInfo の応答は JSON） / 修正前は文字列だった（#184） |
| テスト | `RT184_03_UserInfoの真偽値クレームが真偽値である` |

**手順**

1. scope に email と phone を含めてトークンを取得する
1. そのトークンで GET /userinfo を叩き、型を見る

**検証（合否を判定する）**

- UserInfo が JSON を返す
- email_verified が真偽値である
- phone_number_verified が真偽値である

## RT-185.1 トークン エンドポイントに不正な入力を送っても、JSON のエラー応答になる

| | |
|---|---|
| 観点 | **未処理の例外（HTTP 500 や HTML のエラー画面）にしない。**RP はエラーを JSON として解釈する。HTML が返ると解析に失敗し、何が悪かったのかを利用者に伝えられない。加えて、例外のスタック トレースが外に出る恐れがある。 |
| 根拠 | RFC 6749 §5.2（エラー応答は error を含む JSON）/ #185 |
| テスト | `RT185_01_不正な入力でもJSONのエラーを返す` |

**手順**

1. POST /token に、次の 5 通りの不正な入力を順に送る：grant_type が空 / grant_type が未知 / code が存在しない（PKCE 経路） / code が存在しない（client_secret 経路） / refresh_token が存在しない

**検証（合否を判定する）**

- grant_type が空 で HTTP 500 にならない
- grant_type が空 の応答が JSON である
- grant_type が空 に error が含まれる
- grant_type が未知 で HTTP 500 にならない
- grant_type が未知 の応答が JSON である
- grant_type が未知 に error が含まれる
- code が存在しない（PKCE 経路） で HTTP 500 にならない
- code が存在しない（PKCE 経路） の応答が JSON である
- code が存在しない（PKCE 経路） に error が含まれる
- code が存在しない（client_secret 経路） で HTTP 500 にならない
- code が存在しない（client_secret 経路） の応答が JSON である
- code が存在しない（client_secret 経路） に error が含まれる
- refresh_token が存在しない で HTTP 500 にならない
- refresh_token が存在しない の応答が JSON である
- refresh_token が存在しない に error が含まれる

**補足**

- HTTP ステータスは、#196 で 400 / 401 に直した（RT-196.1 〜 196.4 で検証）。

## RT-186.1 認可時と同じ redirect_uri なら成功する（ケース A）

| | |
|---|---|
| 観点 | **照合を足したことで、正当な交換まで弾いていないこと。**拒否のテスト（RT-186.2 / 186.3）だけでは、常に拒否する実装でも通ってしまう。 |
| 根拠 | RFC 6749 §4.1.3（認可リクエストに含めたなら、トークン リクエストにも含め、一致しなければならない）/ OIDC Core §3.1.3.1 / #186 |
| テスト | `RT186_01_同じredirect_uriなら成功する` |

**手順**

1. redirect_uri を指定して認可し、code を得る
1. 同じ redirect_uri でトークンに交換する

**検証（合否を判定する）**

- 認可コードが発行される
- エラーにならない
- access_token が返る

## RT-186.2 認可時と違う redirect_uri は拒否される（ケース B）

| | |
|---|---|
| 観点 | **これが本題。** code と redirect_uri が結び付いていないと、攻撃者が奪った code を自分の登録済み URI で交換できる余地が残る。多重防御の 1 枚。 |
| 根拠 | RFC 6749 §4.1.3（認可リクエストに含めたなら、トークン リクエストにも含め、一致しなければならない）/ OIDC Core §3.1.3.1 / #186 |
| テスト | `RT186_02_違うredirect_uriは拒否される` |

**手順**

1. 正しい redirect_uri で認可し、code を得る
1. https://attacker.example.com/callback を指定して交換する

**検証（合否を判定する）**

- invalid_grant で拒否される
- トークンを発行しない

## RT-186.3 認可時に送った redirect_uri を、トークン時に省略すると拒否される（ケース C）

| | |
|---|---|
| 観点 | **省略を「一致」とみなしてはならない。**そう扱うと、RT-186.2 の照合を省略するだけで迂回できる。 |
| 根拠 | RFC 6749 §4.1.3（認可リクエストに含めたなら、トークン リクエストにも含め、一致しなければならない）/ OIDC Core §3.1.3.1 / #186 |
| テスト | `RT186_03_redirect_uriの省略は拒否される` |

**手順**

1. 正しい redirect_uri で認可し、code を得る
1. redirect_uri を付けずに交換する

**検証（合否を判定する）**

- invalid_grant で拒否される
- トークンを発行しない

**補足**

- **この経路には穴が残っている。** `request_uri`（JAR）で認可した code は照合が効かない（#197 / RT-197.1）。

## RT-186.4 認可コードは 1 回しか使えない

| | |
|---|---|
| 観点 | code は使い捨て。2 回目が通ると、盗まれた code が繰り返し使える。（TC-2.2 と同じ観点。こちらは #186 の修正で壊れていないことの確認） |
| 根拠 | RFC 6749 §4.1.2（code は 1 回限り）/ §10.5 |
| テスト | `RT186_04_認可コードは再利用できない` |

**手順**

1. code を 1 つ取得し、トークンに交換する
1. 同じ code で、もう一度交換する

**検証（合否を判定する）**

- 1 回目は成功する
- 2 回目は拒否される
- 2 回目でトークンを発行しない

## RT-187.1 state に & や = や空白が含まれていても、そのまま往復する

| | |
|---|---|
| 観点 | **修正前は文字列連結でリダイレクト URL を組み立てていた。**state に区切り文字が入るとパラメタの境界が壊れ、後続のパラメタ（code など）まで読み違える。RP が state に構造化した値（JSON や URL）を入れると踏む。 |
| 根拠 | RFC 3986 §2.2（予約文字はパーセント符号化する） / RFC 6749 §4.1.2（state はそのまま返す）/ #187 |
| テスト | `RT187_01_stateに区切り文字があっても壊れない` |

**手順**

1. GET /authorize に state="a&b=c d" を付けて送る

**検証（合否を判定する）**

- 認可コードが発行される
- state が送信値と完全一致する

## RT-187.2 state を送らなければ、応答にも state を含めない

| | |
|---|---|
| 観点 | **送っていないものを返してはならない。**空の state を返すと、RP 側の照合処理が「空文字どうしで一致した」と誤判定しうる。 |
| 根拠 | RFC 6749 §4.1.2（state は、あったときに返す）/ #187 |
| テスト | `RT187_02_stateを送らなければ返さない` |

**手順**

1. GET /authorize を state 無しで送る

**検証（合否を判定する）**

- 認可コードが発行される
- 応答に state が含まれない

## RT-187.3 未知の response_type では認可コードを発行しない

| | |
|---|---|
| 観点 | **どのフローを要求されたのか決まらない以上、何も発行してはならない。**エラーの返し方（リダイレクトか画面か）は RT-187.4 で別に見る。 |
| 根拠 | RFC 6749 §3.1.1 / §4.1.2.1（unsupported_response_type）/ #187 |
| テスト | `RT187_03_未知のresponse_typeでは認可コードを発行しない` |

**手順**

1. GET /authorize に response_type=bogus を指定する

**検証（合否を判定する）**

- 認可コードを発行しない

**観測（判定しない）**

- エラーの返し方
  - RFC 6749 §4.1.2.1 は、redirect_uri が妥当ならリダイレクトしてerror を返すことを求める。RT-187.4 を参照。

## RT-187.4 未知の response_type を unsupported_response_type でリダイレクトする

| | |
|---|---|
| 観点 | client_id と redirect_uri が妥当なら、エラーは**リダイレクトで RP へ返す。**画面で止めると、RP は何が起きたのか分からない。ただし認可コードは発行されない（RT-187.3）ので、**安全側には倒れている。**以前はエラー画面（HTTP 200）になっていた（2026/09/09 実測）。 |
| 根拠 | RFC 6749 §4.1.2.1（redirect_uri が妥当ならリダイレクトして error を返す） |
| テスト | `RT187_04_未知のresponse_typeはunsupported_response_typeでリダイレクトする` |

**手順**

1. GET /authorize に response_type=bogus を指定する（妥当な redirect_uri 付き）

**検証（合否を判定する）**

- unsupported_response_type が返る

## RT-187.5 client_id が不正なときは、指定された redirect_uri へリダイレクトしない

| | |
|---|---|
| 観点 | **client_id が分からなければ、redirect_uri を検証できない。**検証できない URI へエラーを返すと、認可サーバがオープン リダイレクタになる。この場合は画面で知らせるのが正しい。 |
| 根拠 | RFC 6749 §4.1.2.1（redirect_uri が不正・未検証ならリダイレクトせず、利用者に知らせる）/ #187 |
| テスト | `RT187_05_不正なclient_idではリダイレクトしない` |

**手順**

1. GET /authorize に client_id=deadbeef…（未登録）を指定する

**検証（合否を判定する）**

- 認可コードを発行しない
- 指定された redirect_uri へリダイレクトしない

## RT-188.4 一度 認可に使った request_uri は、2 回目の認可要求には使えない

| | |
|---|---|
| 観点 | **預けた認可要求を、何度でも使い回せてはいけない。**以前は `Delete` が呼ばれず、期限内なら**同じ request_uri で何度でも認可できた**。1 回の認可の中では複数回読む（同意画面・コードの生成）ので、**認可応答を作り終えた時点**で消している（#188 の段階 2）。 |
| 根拠 | RFC 9126 §2.2（PAR は一回限りを求める）/ RFC 9101 / #188 |
| テスト | `RT188_04_request_uriは使い切り` |

**手順**

1. Request Object を預け、その request_uri で認可する
1. まったく同じ URL（同じ request_uri）で、もう一度 認可する

**検証（合否を判定する）**

- 1 回目は認可コードが返る
- 2 回目は認可コードを返さない

**観測（判定しない）**

- 2 回目の返り方
  - 消した後は「存在しない request_uri」と同じ扱いになる。返し方は記録するだけで、判定しない。

## RT-189.1 Discovery が device_authorization_endpoint と device_code のグラントを広告する

| | |
|---|---|
| 観点 | **実装しているのに広告していなかった。**`/device_authz` を公開し、`device_code` のグラントも実装しているのに、Discovery は `Config.EnableDeviceAuthZGrantType` を一度も見ていなかった。RP は Discovery だけを見て設定するので、**使えるのに使えないと判断される。** |
| 根拠 | RFC 8628 §4 / #189 の 6・7 |
| テスト | `RT189_01_DeviceAuthorizationGrantを広告する` |

**手順**

1. GET /.well-known/openid-configuration
1. 広告された口が、実際に応答することを確かめる

**検証（合否を判定する）**

- device_authorization_endpoint がある
- grant_types_supported に device_code が入る
- その URL は存在する（404 ではない）

## RT-189.2 Discovery の値が、仕様どおりの型（boolean / 配列）で返る

| | |
|---|---|
| 観点 | **素直に読む RP は、型が違うと落ちる。**boolean を文字列の "false" で返すと、多くの実装では**真**として読まれる。配列であるべき項目を文字列で返すと、解析でそのまま失敗する。 |
| 根拠 | CIBA Core §4 / OIDC Discovery 1.0 §3 / #189 の 3・4 |
| テスト | `RT189_02_値の型が仕様どおり` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- backchannel_user_code_parameter_supported は boolean
- backchannel_authentication_request_signing_alg_values_supported は配列

## RT-189.3 mTLS の紐づけは tls_client_certificate_bound_access_tokens（boolean）で広告する

| | |
|---|---|
| 観点 | **以前は草案の名前（mutual_tls_sender_constrained_access_tokens）に、文字列の "true" を入れていた。**RFC 8705 §3.3 の名前で出さなければ、RP は**この IdP が紐づけに対応していない**と読む。紐づけそのものは `FA-6.4` で測っている。 |
| 根拠 | RFC 8705 §3.3 / #189 の 2 |
| テスト | `RT189_03_mTLSの紐づけをRFCの名前で広告する` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- tls_client_certificate_bound_access_tokens が boolean の true
- 草案の名前は載せない

## RT-189.4 id_token の暗号化は alg と enc の対で、JARM は応答の署名アルゴリズムまで広告する

| | |
|---|---|
| 観点 | **片方だけでは使えない。** 暗号化は alg（鍵）と enc（本文）の両方が要り、`*.jwt` の response_mode を出すなら、RP は**何で検証するか**を知る必要がある。実装は JWE が RSA-OAEP ＋ A256GCM、JARM の署名が RS256。 |
| 根拠 | OIDC Discovery 1.0 §3 / JARM §7 / #189 の 5・8 |
| テスト | `RT189_04_暗号化とJARMは対の項目まで広告する` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- id_token_encryption_enc_values_supported がある（A256GCM）
- response_modes_supported に *.jwt がある（JARM）
- authorization_signing_alg_values_supported がある（RS256）

## RT-189.5 code_challenge_methods_supported は設定どおりで、service_documentation にプレースホルダを出さない

| | |
|---|---|
| 観点 | **広告は、実装に合わせる。**`plain` を受けるかどうかは `RequirePkceS256`（サーバ全体の設定）だけで決まるので、締めた配置では `plain` を広告しない。`service_documentation` は任意の項目なので、**値が無ければ出さない**（以前は "・・・" というプレースホルダを配っていた）。 |
| 根拠 | OAuth 2.1 / FAPI（S256 のみ）/ OIDC Discovery 1.0 §3 / #228 の 9・12 |
| テスト | `RT189_05_広告が実装と食い違わない` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- code_challenge_methods_supported に S256 がある
- 既定では plain も広告する（実装が受け付けるため）
- service_documentation にプレースホルダが出ない

**観測（判定しない）**

- RequirePkceS256 = true のとき
  - その場合、plain は広告されない（Discovery は要求のたびに設定を読む）。

## RT-190.1 Implicit / Hybrid フローで nonce が無ければ拒否される

| | |
|---|---|
| 観点 | **このフローでは nonce は必須。**id_token がリダイレクトで直接返るため、nonce が無いと RP は**トークンの再送（リプレイ）を検知できない。**Authorization Code フロー（RT-183.1）とは要否が逆になる。 |
| 根拠 | OIDC Core §3.2.2.1（Implicit の nonce は REQUIRED） / §3.3.2.1（Hybrid も REQUIRED）/ #190 |
| テスト | `RT190_01_Implicitでnonce無しは拒否される` |

**手順**

1. GET /authorize を nonce 無しで送る

**検証（合否を判定する）**

- invalid_request で拒否される
- トークンを発行しない

## RT-190.2 Implicit フローで nonce があれば通る

| | |
|---|---|
| 観点 | **RT-190.1 の対照。** 必須チェックを足したことで、正当なリクエストまで弾いていないことを確かめる。「拒否する」だけのテストは、常に拒否する実装でも通ってしまう。 |
| 根拠 | OIDC Core §3.2.2.1 / §3.2.2.5（Implicit はフラグメントで返す）/ #190 |
| テスト | `RT190_02_Implicitでnonce有りは通る` |

**手順**

1. GET /authorize に nonce=nonce1 を付けて送る

**検証（合否を判定する）**

- エラーにならない
- フラグメント（#）で返る
- id_token が返る

## RT-191.1 nonce を送らなかったとき、id_token に nonce クレームを作らない

| | |
|---|---|
| 観点 | **修正前は state の値を nonce として詰めていた。**クライアントは nonce を送っていないので、その値を検証しようがなく、リプレイ検知の役に立たない。さらに state は CSRF 対策の値であり、役割が違う。 |
| 根拠 | OIDC Core §3.1.3.6（nonce は認可リクエストで送られた値をそのまま入れる） / #191 |
| テスト | `RT191_01_nonceを送らなければnonceクレームは付かない` |

**手順**

1. nonce を送らず、state だけを送って認可コード フローを通す

**検証（合否を判定する）**

- id_token に nonce クレームが無い

## RT-191.2 認可リクエストで送った nonce が、そのまま id_token に載る

| | |
|---|---|
| 観点 | RP は、自分が送った値と一致することを確かめてリプレイを検知する。**値が変換されていては照合できない。**（RT-191.1 の対照） |
| 根拠 | OIDC Core §3.1.3.6 / §15.5.2（nonce の実装に関する注意）/ #191 |
| テスト | `RT191_02_送ったnonceがそのままid_tokenに載る` |

**手順**

1. nonce="nonce-abc-123" を送って認可コード フローを通す

**検証（合否を判定する）**

- id_token に nonce クレームがある
- 送った値と完全一致する

## RT-196.1 /token : クライアント認証の失敗（client_secret_post）は HTTP 401

| | |
|---|---|
| 観点 | invalid_client は、要求の中身ではなく**誰が要求したか**の失敗。400 と区別されていれば、クライアントは「資格情報を見直す」と判断できる。 |
| 根拠 | RFC 6749 §5.2（invalid_client は 401 を返してよい）/ #196 |
| テスト | `RT196_01_tokenでクライアント認証の失敗は401` |

**手順**

1. POST /token に grant_type=client_credentials と誤った client_secret をフォームで送る

**検証（合否を判定する）**

- 誤った client_secret : HTTP 401 で返る
- 誤った client_secret : 本文は error を含む JSON のまま
- 誤った client_secret : error

**観測（判定しない）**

- WWW-Authenticate
  - フォームで認証を試みた場合は任意。付けると、受け付ける認証方式をクライアントに示せる。

## RT-196.2 /token : Authorization ヘッダでの認証の失敗は、HTTP 401 と WWW-Authenticate

| | |
|---|---|
| 観点 | Authorization ヘッダ（client_secret_basic）で認証を試みたクライアントには、**401 と、同じ方式の WWW-Authenticate を必ず返す**。HTTP 認証の約束事であり、ここを外すと汎用の HTTP クライアントが認証の失敗と認識できない。 |
| 根拠 | RFC 6749 §5.2（Authorization ヘッダで認証した場合は 401 と WWW-Authenticate が MUST） / §2.3.1 / #196 |
| テスト | `RT196_02_tokenでBasic認証の失敗は401とWWW_Authenticate` |

**手順**

1. POST /token に grant_type=client_credentials を送り、client_id と誤った client_secret を Authorization: Basic で渡す

**検証（合否を判定する）**

- 誤った client_secret（Basic） : HTTP 401 で返る
- 誤った client_secret（Basic） : 本文は error を含む JSON のまま
- 誤った client_secret（Basic） : error
- WWW-Authenticate が Basic 方式を示す

## RT-196.3 /token : クライアント認証以外のエラーは HTTP 400

| | |
|---|---|
| 観点 | 要求の中身の誤り（無効な refresh_token、grant_type の欠落・未知の値）は 400。**正しく認証したクライアントの要求は、401 にしない**（資格情報の問題と取り違えさせない）。 |
| 根拠 | RFC 6749 §5.2（エラーは 400）/ #196 |
| テスト | `RT196_03_tokenでそれ以外のエラーは400` |

**手順**

1. 存在しない refresh_token で更新する
1. grant_type を付けずに送る
1. 未知の grant_type を送る

**検証（合否を判定する）**

- 存在しない refresh_token : HTTP 400 で返る
- 存在しない refresh_token : 本文は error を含む JSON のまま
- 存在しない refresh_token : error
- grant_type なし : HTTP 400 で返る
- grant_type なし : 本文は error を含む JSON のまま
- 未知の grant_type : HTTP 400 で返る
- 未知の grant_type : 本文は error を含む JSON のまま

**観測（判定しない）**

- error の値（grant_type なし / 未知）
  - RFC 6749 §5.2 では、欠落は invalid_request、未知の値は unsupported_grant_type が相当する。本 Issue（HTTP ステータス）の範囲外なので、値は判定しない。

## RT-196.4 /token : 成功は HTTP 200 のまま（対照）

| | |
|---|---|
| 観点 | **RT-196.1 〜 196.3 の対照。** エラーの返し方を変えたことで、成功の応答まで変わっていないことを確かめる（Basic 認証の成功も含む）。 |
| 根拠 | RFC 6749 §5.1（成功は 200）/ #196 |
| テスト | `RT196_04_tokenの成功は200のまま` |

**手順**

1. client_secret_post（フォーム）で client_credentials を送る
1. client_secret_basic（Authorization ヘッダ）で同じ要求を送る

**検証（合否を判定する）**

- フォーム : HTTP 200
- フォーム : access_token が返る
- Basic : HTTP 200
- Basic : access_token が返る

## RT-196.5 /userinfo : Bearer トークンの無い要求は、HTTP 401 と WWW-Authenticate: Bearer（エラー コードなし）

| | |
|---|---|
| 観点 | トークンを付け忘れた（または別の方式で認証しようとした）クライアントに、**Bearer トークンが要ることを、HTTP の約束事で伝える。**認証情報が無いだけなので、エラー コードは付けない。 |
| 根拠 | RFC 6750 §3 / §3.1（認証情報の無い要求にはエラー情報を含めない）/ OIDC Core §5.3.3 / #196 |
| テスト | `RT196_05_userinfoでトークン無しは401とBearerの要求` |

**手順**

1. Authorization ヘッダを付けずに GET /userinfo を送る
1. Bearer ではなく Basic 方式の Authorization ヘッダで GET /userinfo を送る
1. 観測 : 方式だけで値の無い Authorization ヘッダ（Bearer のみ）で GET /userinfo を送る

**検証（合否を判定する）**

- ヘッダ無し : HTTP 401 で返る
- ヘッダ無し : WWW-Authenticate が Bearer 方式を示す
- ヘッダ無し : WWW-Authenticate にエラー コードを付けない
- ヘッダ無し : 本文に、エラー情報もユーザ情報も含めない
- Basic 方式 : HTTP 401 で返る
- Basic 方式 : WWW-Authenticate が Bearer 方式を示す

**観測（判定しない）**

- 値の無い Bearer
  - Open棟梁 の AuthenticationHeader.GetCredentials は、方式の後ろの値を確かめずに読む。値が無いと例外になり、HTTP 500 になり得る（#196 の範囲外）。

## RT-196.6 /userinfo : 無効なトークンは、HTTP 401 と error="invalid_token"

| | |
|---|---|
| 観点 | 壊れた・改竄された・失効したトークンは、**クライアントが取り直すべき**トークン。401 と invalid_token で伝えれば、クライアントは refresh_token での更新や再認可に進める。以前は invalid_request（400 に当たるコード）を HTTP 200 で返していた。 |
| 根拠 | RFC 6750 §3.1（invalid_token は 401）/ OIDC Core §5.3.3 / #196 |
| テスト | `RT196_06_userinfoで無効なトークンは401とinvalid_token` |

**手順**

1. 認可コード フローで access_token を得る
1. JWT でない文字列を Bearer トークンとして送る
1. ペイロードを書き換えた（署名はそのままの）トークンを送る
1. トークンを失効させてから送る

**検証（合否を判定する）**

- JWT でない文字列 : HTTP 401 で返る
- JWT でない文字列 : 本文は error を含む JSON のまま
- JWT でない文字列 : error
- JWT でない文字列 : WWW-Authenticate が Bearer 方式を示す
- JWT でない文字列 : WWW-Authenticate に error="invalid_token" が付く
- 改竄したトークン : HTTP 401 で返る
- 改竄したトークン : 本文は error を含む JSON のまま
- 改竄したトークン : error
- 改竄したトークン : WWW-Authenticate が Bearer 方式を示す
- 改竄したトークン : WWW-Authenticate に error="invalid_token" が付く
- 失効させたトークン : HTTP 401 で返る
- 失効させたトークン : 本文は error を含む JSON のまま
- 失効させたトークン : error
- 失効させたトークン : WWW-Authenticate が Bearer 方式を示す
- 失効させたトークン : WWW-Authenticate に error="invalid_token" が付く

## RT-196.7 /userinfo : 有効なトークンでの成功は HTTP 200 のまま（対照）

| | |
|---|---|
| 観点 | **RT-196.5 / 196.6 の対照。** エラーの返し方を変えたことで、成功の応答（ユーザ情報の JSON）まで変わっていないことを確かめる。 |
| 根拠 | OIDC Core §5.3.2（成功は 200 と JSON）/ #196 |
| テスト | `RT196_07_userinfoの成功は200のまま` |

**手順**

1. 認可コード フローで access_token を得て、GET /userinfo を送る

**検証（合否を判定する）**

- HTTP 200
- sub がテスト ユーザである
- WWW-Authenticate を付けない

## RT-196.8 /revoke : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）

| | |
|---|---|
| 観点 | 失効も、トークン エンドポイントと同じくクライアントを認証してから行う。**認証の失敗は、要求の中身の誤り（400）と区別して 401 で返す。** |
| 根拠 | RFC 7009 §2.2.1（エラーは RFC 6749 §5.2 のとおり）/ RFC 6749 §5.2 / #196 |
| テスト | `RT196_08_revokeでクライアント認証の失敗は401` |

**手順**

1. POST /revoke に token と、誤った client_secret をフォームで送る
1. 同じ要求を、client_id と誤った client_secret を Authorization: Basic で渡して送る

**検証（合否を判定する）**

- 誤った client_secret（フォーム） : HTTP 401 で返る
- 誤った client_secret（フォーム） : 本文は error を含む JSON のまま
- 誤った client_secret（フォーム） : error
- 誤った client_secret（Basic） : HTTP 401 で返る
- 誤った client_secret（Basic） : 本文は error を含む JSON のまま
- 誤った client_secret（Basic） : error
- Basic : WWW-Authenticate が Basic 方式を示す

## RT-196.9 /revoke : クライアント認証以外のエラーは HTTP 400

| | |
|---|---|
| 観点 | token の欠落（invalid_request）や、他のクライアントのトークンの失効要求（invalid_grant）は、**正しく認証したクライアントの要求の誤り**なので 400。401 にしない。 |
| 根拠 | RFC 7009 §2.1 / §2.2.1 / RFC 6749 §5.2 / #196 |
| テスト | `RT196_09_revokeでそれ以外のエラーは400` |

**手順**

1. token を付けずに POST /revoke を送る（資格情報は正しい）
1. MVC_Sample の access_token の失効を、TestClient の資格情報で要求する

**検証（合否を判定する）**

- token なし : HTTP 400 で返る
- token なし : 本文は error を含む JSON のまま
- token なし : error
- 他のクライアントのトークン : HTTP 400 で返る
- 他のクライアントのトークン : 本文は error を含む JSON のまま
- 他のクライアントのトークン : error

## RT-196.10 /revoke : 成功は HTTP 200 のまま（Authorization ヘッダでの認証を含む）

| | |
|---|---|
| 観点 | **RT-196.8 / 196.9 の対照。** エラーの返し方を変えたことで、成功の応答まで変わっていないことを確かめる。フォームでの失効と、無効なトークンの失効が 200 であることは EX-2.1 / EX-2.5 が見ているので、ここでは Authorization ヘッダ（client_secret_basic）での失効を見る。 |
| 根拠 | RFC 7009 §2.2（成功は 200）/ #196 |
| テスト | `RT196_10_revokeの成功は200のまま` |

**手順**

1. 認可コード フローで access_token を得る
1. POST /revoke に token を送り、client_id と client_secret は Authorization: Basic で渡す
1. 同じ access_token で /userinfo を叩く

**検証（合否を判定する）**

- HTTP 200
- error を返さない
- 失効している（/userinfo が 401 を返す）

## RT-196.11 /introspect : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）

| | |
|---|---|
| 観点 | イントロスペクションは、トークンの中身（ユーザ・範囲）を明かす口。**認証できない問い合わせ元には、401 で断る。**資格情報を付けない問い合わせも、認証の失敗として扱う。 |
| 根拠 | RFC 7662 §2.3（認証に失敗したら RFC 6749 §5.2 のとおり 401）/ §2.1 / #196 |
| テスト | `RT196_11_introspectでクライアント認証の失敗は401` |

**手順**

1. POST /introspect に token と、誤った client_secret をフォームで送る
1. 同じ要求を、client_id と誤った client_secret を Authorization: Basic で渡して送る
1. 資格情報を何も付けずに送る

**検証（合否を判定する）**

- 誤った client_secret（フォーム） : HTTP 401 で返る
- 誤った client_secret（フォーム） : 本文は error を含む JSON のまま
- 誤った client_secret（フォーム） : error
- 誤った client_secret（Basic） : HTTP 401 で返る
- 誤った client_secret（Basic） : 本文は error を含む JSON のまま
- 誤った client_secret（Basic） : error
- Basic : WWW-Authenticate が Basic 方式を示す
- 資格情報なし : HTTP 401 で返る
- 資格情報なし : 本文は error を含む JSON のまま
- 資格情報なし : error

## RT-196.12 /introspect : token の無い問い合わせは HTTP 400

| | |
|---|---|
| 観点 | token は必須のパラメタ。欠けているのは要求の誤りなので 400（invalid_request）。**正しく認証したクライアントの要求は、401 にしない。** |
| 根拠 | RFC 7662 §2.1（token は REQUIRED）/ RFC 6749 §5.2 / #196 |
| テスト | `RT196_12_introspectでtokenが無ければ400` |

**手順**

1. token を付けずに POST /introspect を送る

**検証（合否を判定する）**

- token なし : HTTP 400 で返る
- token なし : 本文は error を含む JSON のまま
- token なし : error

## RT-196.13 /introspect : 問い合わせへの答えは、active=true でも active=false でも HTTP 200（対照）

| | |
|---|---|
| 観点 | **RT-196.11 / 196.12 の対照。** 使えないトークンについての「使えない」（active=false）は、エラーではなく正常な答え。**4xx にしてはならない。**あわせて、Authorization ヘッダ（client_secret_basic）での問い合わせを見る。 |
| 根拠 | RFC 7662 §2.2（active=false も正常な応答）/ §2.3 / #196 |
| テスト | `RT196_13_introspectの答えはactiveによらず200` |

**手順**

1. 認可コード フローで access_token を得る
1. その access_token を、Authorization: Basic で認証して問い合わせる
1. 存在しないトークンを、同じく問い合わせる

**検証（合否を判定する）**

- 有効なトークン : HTTP 200
- 有効なトークン : active が true
- 無効なトークン : HTTP 200（エラーにしない）
- 無効なトークン : active が false

## RT-196.14 /device_authz : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）

| | |
|---|---|
| 観点 | デバイス認可エンドポイントのクライアント認証は、トークン エンドポイントと同じ。**登録されていない client_id や、誤った資格情報は 401 で断る。**パブリック クライアントは client_id だけで識別する（#193）。 |
| 根拠 | RFC 8628 §3.1（クライアント認証は RFC 6749 §3.2.1 のとおり）/ RFC 6749 §5.2 / #196 |
| テスト | `RT196_14_device_authzでクライアント認証の失敗は401` |

**手順**

1. POST /device_authz に、登録されていない client_id をフォームで送る
1. コンフィデンシャル クライアントの client_id と誤った client_secret を、Authorization: Basic で渡して送る

**検証（合否を判定する）**

- 登録されていない client_id : HTTP 401 で返る
- 登録されていない client_id : 本文は error を含む JSON のまま
- 登録されていない client_id : error
- 誤った client_secret（Basic） : HTTP 401 で返る
- 誤った client_secret（Basic） : 本文は error を含む JSON のまま
- 誤った client_secret（Basic） : error
- Basic : WWW-Authenticate が Basic 方式を示す
- device_code を発行しない

## RT-196.15 /device_authz : 成功は HTTP 200 のまま（対照）

| | |
|---|---|
| 観点 | **RT-196.14 の対照。** エラーの返し方を変えたことで、成功の応答（device_code / user_code の JSON）まで変わっていないことを確かめる。 |
| 根拠 | RFC 8628 §3.2（成功は 200 と JSON）/ #196 |
| テスト | `RT196_15_device_authzの成功は200のまま` |

**手順**

1. POST /device_authz に client_id と scope を送る

**検証（合否を判定する）**

- HTTP 200
- device_code が返る
- error を返さない

## RT-196.16 /ciba_authz : request_uri が無い・存在しない要求は、HTTP 400 と invalid_request

| | |
|---|---|
| 観点 | CIBA の認証リクエストは、事前に /ros へ登録した Request Object を request_uri で指す。**指していない・指す先が無い要求は、要求の誤りとして 400 で返す。** |
| 根拠 | CIBA Core §13（invalid_request は 400）/ #196 |
| テスト | `RT196_16_ciba_authzでrequest_uriの不備は400` |

**手順**

1. request_uri を付けずに POST /ciba_authz を送る
1. 登録されていない request_uri を送る

**検証（合否を判定する）**

- request_uri なし : HTTP 400 で返る
- request_uri なし : 本文は error を含む JSON のまま
- request_uri なし : error
- 存在しない request_uri : HTTP 400 で返る
- 存在しない request_uri : 本文は error を含む JSON のまま
- 存在しない request_uri : error

## RT-196.17 /ciba_authz : 認証リクエストの中身の誤りは、HTTP 400 と CIBA Core §13 のエラー コード

| | |
|---|---|
| 観点 | 以前は、これらの誤りで error が**空文字列**のまま返っていた（コードが無いと、クライアントは原因を判断できない）。CIBA Core §13 のコードを返し、HTTP ステータスはコードから決める（invalid_client 以外は 400）。 |
| 根拠 | CIBA Core §7.1 / §13 / #196 |
| テスト | `RT196_17_ciba_authzで要求の中身の誤りは400とCIBAのコード` |

**手順**

1. scope に openid が無い要求
1. nbf が未来の要求（まだ有効になっていない）
1. exp が過去の要求（期限切れ）

**検証（合否を判定する）**

- openid なし : HTTP 400 で返る
- openid なし : 本文は error を含む JSON のまま
- openid なし : error
- nbf が未来 : HTTP 400 で返る
- nbf が未来 : 本文は error を含む JSON のまま
- nbf が未来 : error
- exp が過去 : HTTP 400 で返る
- exp が過去 : 本文は error を含む JSON のまま
- exp が過去 : error

## RT-196.18 /ciba_authz : login_hint のユーザが見つからない要求は、HTTP 400 と unknown_user_id

| | |
|---|---|
| 観点 | CIBA では、認証を求める相手（ユーザ）を login_hint などで指す。**見つからないなら、それを unknown_user_id で伝える。**以前は error が空のまま返っていた。 |
| 根拠 | CIBA Core §13（unknown_user_id は 400）/ #196 |
| テスト | `RT196_18_ciba_authzでユーザが見つからなければ400とunknown_user_id` |

**手順**

1. login_hint に存在しないユーザを入れた要求を /ros に登録し、その request_uri を送る

**検証（合否を判定する）**

- ユーザ不明 : HTTP 400 で返る
- ユーザ不明 : 本文は error を含む JSON のまま
- ユーザ不明 : error

**補足**

- 成功経路（見つかったユーザへのプッシュ通知）は FCM に送るので、E2E では測らない。

## RT-196.19 /SetDeviceToken : 失敗は本文 NG のまま、パラメタの不備は HTTP 400、トークンの不備は 401

| | |
|---|---|
| 観点 | 認証デバイスを登録する口。以前は失敗でも HTTP 200 と NG だった。**本文（OK / NG）は認証デバイス（authentication_device）が見ているので変えず、ステータスだけを直す。**トークンの不備には、Bearer トークンが要ることを WWW-Authenticate で示す。 |
| 根拠 | RFC 6750 §3 / #196 |
| テスト | `RT196_19_SetDeviceTokenの失敗は400と401` |

**手順**

1. device_token を付けずに送る
1. Authorization ヘッダを付けずに送る
1. 無効なトークンで送る

**検証（合否を判定する）**

- device_token なし : HTTP 400 で返る
- device_token なし : 本文は NG のまま
- トークンなし : HTTP 401 で返る
- トークンなし : 本文は NG のまま
- トークンなし : WWW-Authenticate が Bearer 方式を示す
- トークンなし : WWW-Authenticate にエラー コードを付けない
- 無効なトークン : HTTP 401 で返る
- 無効なトークン : 本文は NG のまま
- 無効なトークン : WWW-Authenticate が Bearer 方式を示す
- 無効なトークン : WWW-Authenticate に error="invalid_token" が付く

**補足**

- 成功（200 と OK）は EX-8 で見る。ここで登録すると、並行して動く CIBA のテストの宛先を書き換えてしまう。

## RT-196.20 /ciba_result : 失敗は本文 NG のまま、トークンの不備は HTTP 401、パラメタの不備は 400

| | |
|---|---|
| 観点 | 認証デバイスが、CIBA の要求に「許可 / 拒否」を返す口。以前は失敗でも HTTP 200 と NG だった。本文（OK / NG）は変えず、ステータスだけを直す。 |
| 根拠 | RFC 6750 §3 / #196 |
| テスト | `RT196_20_ciba_resultの失敗は400と401` |

**手順**

1. Authorization ヘッダを付けずに送る
1. 無効なトークンで送る
1. ユーザの有効なトークンで、auth_req_id を付けずに送る
1. result が真偽値でない値で送る

**検証（合否を判定する）**

- トークンなし : HTTP 401 で返る
- トークンなし : 本文は NG のまま
- トークンなし : WWW-Authenticate が Bearer 方式を示す
- トークンなし : WWW-Authenticate にエラー コードを付けない
- 無効なトークン : HTTP 401 で返る
- 無効なトークン : 本文は NG のまま
- 無効なトークン : WWW-Authenticate が Bearer 方式を示す
- 無効なトークン : WWW-Authenticate に error="invalid_token" が付く
- auth_req_id なし : HTTP 400 で返る
- auth_req_id なし : 本文は NG のまま
- result が不正 : HTTP 400 で返る
- result が不正 : 本文は NG のまま

**補足**

- 成功（200 と OK）は EX-8 で見る。なお auth_req_id が自分宛ての要求でない場合も、ここと同じ 400 ＋ NG で返る（EX-8.4）。

## RT-197.1 FAPI2 の自己テストが、PAR 登録から request_uri の認可リクエストまで到達する

| | |
|---|---|
| 観点 | **以降のテストの前提。** アプリ同梱の自己テストが、Request Object を作って PAR（`/ros`）へ登録し、`request_uri` 付きの認可リクエストを組み立てられること。ここで止まる場合、原因は経路の不備ではなく**起動 URL の食い違い**であることが多い。 |
| 根拠 | RFC 9101（JAR）/ RFC 9126（PAR。ただしこの実装の `/ros` は独自仕様） |
| テスト | `RT197_01_FAPI2の自己テストがrequest_uriを組み立てる` |

**手順**

1. POST /Home/Saml2OAuth2Starters に submit.AuthorizationCodeFAPI2 を送る

**検証（合否を判定する）**

- リダイレクトする
- リダイレクト先に request_uri が付く

## RT-197.2 FAPI2 クライアントは、client_secret だけのトークン要求を受け付けない

| | |
|---|---|
| 観点 | `oauth2_oidc_mode=fapi2` のクライアントは、より強いクライアント認証（mTLS / private_key_jwt）を要求する。**この性質のため、FAPI2 の経路では redirect_uri の照合まで到達しない。**照合そのものは RT-197.4 で、normal モードのクライアントを使って測る。 |
| 根拠 | FAPI 2.0 Security Profile（クライアント認証は mTLS または private_key_jwt）/ RFC 6749 §5.2 |
| テスト | `RT197_02_FAPI2クライアントはclient_secretのトークン要求を拒否する` |

**手順**

1. FAPI2 の自己テストで request_uri 経路の code を得る
1. client_secret を添えてトークンに交換する

**検証（合否を判定する）**

- request_uri 経路で認可コードが発行される
- トークンを発行しない
- unauthorized_client で拒否される

## RT-197.3 自前で署名した Request Object でも、認可コードが発行される

| | |
|---|---|
| 観点 | **RT-197.4 / 197.5 の前提。** 実装側の JWS クラスを使わず、テスト側で RS256 の署名を作って PAR に登録し、認可まで通せること。normal モードのクライアントを使うのは、FAPI2 だとクライアント認証で先に弾かれる（RT-197.2）ため。 |
| 根拠 | RFC 9101 §4（Request Object の署名）/ OIDC Core §6.2（request_uri） |
| テスト | `RT197_03_request_uriの認可リクエストで認可コードが発行される` |

**手順**

1. SpRp_RsaPfxFilePath の秘密鍵で Request Object に署名する
1. POST /ros に登録して request_uri を得る
1. GET /authorize?request_uri=… で認可する

**検証（合否を判定する）**

- 認可コードが発行される

## RT-197.4 request_uri 経路でも、同じ redirect_uri ならトークンが取得できる

| | |
|---|---|
| 観点 | **RT-197.5 の対照。** この経路が機能していること自体を先に示す。これが通らなければ、RT-197.5 の結果は「照合が効いていない」ではなく「経路が壊れている」になる。 |
| 根拠 | RFC 6749 §4.1.3 / OIDC Core §3.1.3.1 |
| テスト | `RT197_04_request_uri経路で同じredirect_uriなら成功する` |

**手順**

1. Request Object に redirect_uri を入れて認可する
1. 同じ redirect_uri でトークンに交換する

**検証（合否を判定する）**

- エラーにならない
- access_token が返る

## RT-197.5 request_uri 経路でも、redirect_uri が認可コードに紐付いている

| | |
|---|---|
| 観点 | Request Object には redirect_uri が入っている。**クエリ文字列で渡したときと扱いが変わってはならない。**以前は `AuthorizationCodeProvider.Create` がクエリ文字列だけを読んだため、この経路では null が保存され、照合が素通りになっていた（#186 の対応が及んでいなかった。#197 で修正）。 |
| 根拠 | RFC 6749 §4.1.3 / OIDC Core §3.1.3.1 / #197 |
| テスト | `RT197_05_request_uri経路でもredirect_uriが照合される` |

**手順**

1. Request Object に正しい redirect_uri を入れて認可する
1. https://attacker.example.com/callback を指定して交換する

**検証（合否を判定する）**

- トークンを発行しない
- invalid_grant で拒否される

## RT-197.6 request_uri 経路でも PKCE が働く（正しい検証子で通り、誤った検証子で拒否される）

| | |
|---|---|
| 観点 | `code_challenge` は redirect_uri と同じく Request Object の中にある。以前は記録されず、正しい `code_verifier` を示しても `invalid_client` になっていた（安全側だが、`request_uri` ＋ PKCE のパブリック クライアントが機能しない）。**正しい検証子で通り、誤った検証子では通らないこと**の両方を確かめる。片方だけでは、常に拒否する実装も常に通す実装も見逃す。 |
| 根拠 | RFC 7636 §4.5 / §4.6 / RFC 9101 / #197 |
| テスト | `RT197_06_request_uri経路でもPKCEが働く` |

**手順**

1. Request Object に code_challenge（S256）を入れて認可する
1. 正しい code_verifier で交換する（client_secret は送らない）
1. 誤った code_verifier で交換する（別の code を取り直す）

**検証（合否を判定する）**

- 認可コードが発行される
- 正しい code_verifier でトークンが発行される
- 誤った code_verifier ではトークンを発行しない

## RT-198.1 client_credentials : scopes_supported に無いスコープを発行しない

| | |
|---|---|
| 観点 | 起票時の再現手順そのもの。宣言外の `admin` `superuser` `whatever` まで、認可サーバの署名付きで発行されていた。**宣言済みのものは残し、宣言外のものだけを外す**こと、そして**要求と異なる発行をしたことを、トークン応答の scope で伝える**ことを確かめる。 |
| 根拠 | RFC 6749 §3.3（発行スコープは要求と異なってよい）/ §5.1（異なる場合は scope が必須） / RFC 8414 §2（scopes_supported）/ #198 |
| テスト | `RT198_01_client_credentialsで宣言外のスコープを発行しない` |

**手順**

1. POST /token に grant_type=client_credentials、scope="roles userid auth admin superuser whatever" を送る

**検証（合否を判定する）**

- 発行されたスコープが scopes_supported の範囲に収まる
- 宣言済みのスコープは落とさない（絞り込みすぎない）
- トークン応答の scope が、発行したスコープと一致する

**補足**

- Discovery の scopes_supported = [profile, email, phone, address, auth, userid, roles, openid]

## RT-198.2 password : scopes_supported に無いスコープを発行しない

| | |
|---|---|
| 観点 | ユーザの文脈を持つトークンでも同じであること。RT-198.1（client_credentials）とはサーバ側の発行経路が別なので、個別に確かめる。 |
| 根拠 | RFC 6749 §3.3 / §5.1 / #198 |
| テスト | `RT198_02_passwordで宣言外のスコープを発行しない` |

**手順**

1. POST /token に grant_type=password、scope="email profile admin" を送る

**検証（合否を判定する）**

- 発行されたスコープが scopes_supported の範囲に収まる
- 宣言済みのスコープは落とさない（絞り込みすぎない）
- トークン応答の scope が、発行したスコープと一致する

**補足**

- Discovery の scopes_supported = [profile, email, phone, address, auth, userid, roles, openid]

## RT-198.3 クライアントの登録（scope）の範囲に収める : client_credentials

| | |
|---|---|
| 観点 | scopes_supported に載っていても、**そのクライアントに許していないスコープは発行しない。**登録の scope は、RFC 7591 §2 の client metadata と同じく、要求してよいスコープの一覧。許した範囲は残し、許していないもの（phone / roles）と宣言外のもの（admin）だけを外すことを確かめる。 |
| 根拠 | RFC 6749 §3.3 / §5.1 / RFC 7591 §2（scope）/ #198 |
| テスト | `RT198_03_登録したscopeの範囲に収める_client_credentials` |

**手順**

1. POST /token に grant_type=client_credentials、scope="profile email phone roles admin" を送る

**検証（合否を判定する）**

- 登録の scope に無いスコープを発行しない
- 発行されたスコープが scopes_supported の範囲に収まる
- 宣言済みのスコープは落とさない（絞り込みすぎない）
- トークン応答の scope が、発行したスコープと一致する

**補足**

- Discovery の scopes_supported = [profile, email, phone, address, auth, userid, roles, openid]

## RT-198.4 クライアントの登録（scope）の範囲に収める : 認可コード フロー

| | |
|---|---|
| 観点 | 認可エンドポイントを通る経路（CreateCodeInAuthZNRes）でも同じであること。この経路は device / CIBA も通る。openid は許しているので、id_token も発行されることを確かめる（絞り込みすぎていない）。 |
| 根拠 | RFC 6749 §3.3 / OIDC Core §3.1.2.1 / RFC 7591 §2（scope）/ #198 |
| テスト | `RT198_04_登録したscopeの範囲に収める_認可コード` |

**手順**

1. GET /authorize に scope="openid profile email phone roles" を付けて code を得る
1. code をトークンに交換する

**検証（合否を判定する）**

- 登録の scope に無いスコープを発行しない
- 発行されたスコープが scopes_supported の範囲に収まる
- 宣言済みのスコープは落とさない（絞り込みすぎない）
- トークン応答の scope が、発行したスコープと一致する
- id_token が返る（openid は許している）

## RT-210.1 /ciba_authz : 端末が登録されていないユーザ宛ての要求は、HTTP 400 と access_denied

| | |
|---|---|
| 観点 | CIBA は、ユーザの**別の端末**に承認を求める。その端末が登録されていなければ、要求は成立しない。**以前は空の宛先のままプッシュ通知を送ろうとして例外になり、HTTP 500 と JSON でない本文を返していた**（#210）。ユーザ自体は見つかっているので、unknown_user_id（RT-196.18）ではなく access_denied で返す。 |
| 根拠 | CIBA Core §13（access_denied は 400）/ #210 |
| テスト | `RT210_01_ciba_authzで端末が未登録なら400とaccess_denied` |

**手順**

1. 端末を登録していない利用者を login_hint に入れた要求を /ros に登録し、その request_uri を送る

**検証（合否を判定する）**

- 端末未登録 : HTTP 400 で返る
- 端末未登録 : 本文は error を含む JSON のまま
- 端末未登録 : error

**補足**

- 送信そのものの失敗（server_error）は、E2E では測れない。test.ps1 -Launch は送信箱を使い、FcmService は宛先を検証せずファイルに書くため。

## RT-213.1 /2fa_result : 失敗は本文 NG のまま、トークンの不備は HTTP 401、コードの不備は 400

| | |
|---|---|
| 観点 | 認証デバイスが、プッシュ通知で受け取った 2FA のコードを送り返す口（#213）。**合わないコードを記録させない**のが要点で、コードは保存する前に検証する。存在を推測させないよう、合わないコードは「コードが無い」と同じ 400 ＋ NG で返す。 |
| 根拠 | RFC 6750 §3 / #213 |
| テスト | `RT213_01_2fa_resultの失敗は400と401` |

**手順**

1. Authorization ヘッダを付けずに送る
1. 無効なトークンで送る
1. ユーザの有効なトークンで、code を付けずに送る
1. ユーザの有効なトークンで、合わない code を送る

**検証（合否を判定する）**

- トークンなし : HTTP 401 で返る
- トークンなし : 本文は NG のまま
- トークンなし : WWW-Authenticate が Bearer 方式を示す
- トークンなし : WWW-Authenticate にエラー コードを付けない
- 無効なトークン : HTTP 401 で返る
- 無効なトークン : 本文は NG のまま
- 無効なトークン : WWW-Authenticate が Bearer 方式を示す
- 無効なトークン : WWW-Authenticate に error="invalid_token" が付く
- code なし : HTTP 400 で返る
- code なし : 本文は NG のまま
- 合わない code : HTTP 400 で返る
- 合わない code : 本文は NG のまま

**補足**

- 成功（200 と OK）は E2E では測れない。2FA を有効にした利用者のコードが要るが、共用のテスト ユーザで 2FA を有効にすると他の全テストのサインインが変わるため。成功経路は手で確かめる（CHEATSHEET.md）。

## RT-218.1 /introspect・/userinfo・/device_authz・/ciba_authz にもキャッシュ制御が付く

| | |
|---|---|
| 観点 | **RFC が MUST としているのは /token だけ**（RFC 6749 §5.1 / §5.2）。しかしこの 4 つも、資格情報（device_code / auth_req_id）や利用者の属性を返すので、**中間キャッシュやブラウザ履歴に残ると困る点は同じ**。 |
| 根拠 | RFC 6749 §5.1 / §5.2（/token の MUST）/ #218 |
| テスト | `RT218_01_資格情報や属性を返す口にもキャッシュ制御が付く` |

**手順**

1. 認可コード フローでトークンを得る
1. /introspect の応答ヘッダを見る
1. /userinfo の応答ヘッダを見る
1. /device_authz の応答ヘッダを見る
1. /ciba_authz の応答ヘッダを見る（要求の中身は問わない）

**検証（合否を判定する）**

- /introspect : Cache-Control に no-store が付く
- /introspect : Pragma に no-cache が付く
- /userinfo : Cache-Control に no-store が付く
- /userinfo : Pragma に no-cache が付く
- /device_authz : Cache-Control に no-store が付く
- /device_authz : Pragma に no-cache が付く
- /ciba_authz : Cache-Control に no-store が付く
- /ciba_authz : Pragma に no-cache が付く

**補足**

- (5) は要求が不正でもよい。**エラー応答にも付くこと**を確かめる（RFC 6749 §5.2 と同じ考え方）。

## RT-220.1 コンフィデンシャル クライアントでも、client_secret と PKCE を併用できる

| | |
|---|---|
| 観点 | PKCE は当初「client_secret を持てないクライアントの代わり」だったが、**いまは種別によらない標準的な防壁**で、client_secret と併用される（OAuth 2.1 / 最近の RP ライブラリ）。**以前は、両方を送るとどの分岐にも入らず invalid_client になっていた**（#220）。 |
| 根拠 | RFC 7636 / OAuth 2.1 §4.1.1（PKCE は全クライアント種別で必須）/ #220 |
| テスト | `RT220_01_client_secretとPKCEを併用できる` |

**手順**

1. code_challenge_method=S256 で認可コードを得る
1. client_secret と code_verifier の**両方**を送って交換する
1. 対照 : client_secret は正しく、code_verifier だけ誤った要求を送る

**検証（合否を判定する）**

- トークンが返る
- 誤った code_verifier ではトークンを発行しない

**補足**

- **PKCE を素通りさせていないこと**を確かめる。client_secret で認証が通っても、PKCE の検証に失敗すれば発行してはならない。

## RT-220.2 plain の PKCE は、既定では受理される（設定で拒否できる）

| | |
|---|---|
| 観点 | **plain は保護にならない**（横取りした者が challenge をそのまま送れる）。OAuth 2.1 / FAPI は S256 のみを許すが、**下位互換のため既定では受理する**。設定 RequirePkceS256 を true にすると拒否する（#220）。 |
| 根拠 | RFC 7636 §4.2（plain は非推奨）/ OAuth 2.1 / #220 |
| テスト | `RT220_02_plainのPKCEは既定では受理される` |

**手順**

1. code_challenge_method=plain で認可コードを得る
1. 同じ値を code_verifier として交換する

**検証（合否を判定する）**

- 既定（RequirePkceS256=false）では受理される

**補足**

- **RequirePkceS256=true のときに拒否すること**は、E2E では測っていない（設定ファイルを変えて起動し直す必要があるため）。設定は CONFIGURATION.md を参照。

## RT-220.3 code_challenge を送らない認可リクエストは、既定では通る（設定で必須にできる）

| | |
|---|---|
| 観点 | **OAuth 2.1 は、クライアントの種別によらず PKCE を必須とする。**ただし必須にすると PKCE 無しの既存クライアントが通らなくなるため、**既定は従来どおり任意**。設定 RequirePkce を true にすると、認可エンドポイントで invalid_request になる（#220）。 |
| 根拠 | OAuth 2.1 draft §4.1.1 / RFC 7636 / #220 |
| テスト | `RT220_03_PKCE無しの認可は既定では通る` |

**手順**

1. code_challenge 無しで認可リクエストを出す

**検証（合否を判定する）**

- 既定（RequirePkce=false）では認可コードが返る

**補足**

- **RequirePkce=true のときに invalid_request で拒否すること**は、E2E では測っていない（設定ファイルを変えて起動し直す必要があるため）。設定は CONFIGURATION.md を参照。
- **Device AuthZ / CIBA は、この判定の対象外**（認可エンドポイントを通らないため）。EX-7 / EX-8 は影響を受けない。

## RT-220.4 normal 登録のクライアントが S256 の PKCE を使っても、トークンは fapi を名乗らない

| | |
|---|---|
| 観点 | **PKCE のメソッドは「クライアント認証の強度」ではない。**S256 を使うと、その経路で通す登録種別（ClientModePolicy の表。#224）に fapi1 が加わるが、**それはクライアントが何として登録されているか（clientMode）とは別**。アクセス トークンの fapi クレームは clientMode で書く（#220）。 |
| 根拠 | FAPI 1.0 Advanced / RFC 7636 / #220 |
| テスト | `RT220_04_S256で取ったトークンがfapiを名乗らない` |

**手順**

1. code_challenge_method=S256 で認可コードを得る
1. client_secret を送らず、code_verifier だけで交換する
1. アクセス トークンのクレームを見る

**検証（合否を判定する）**

- fapi クレームが載っていない

**補足**

- **このクライアントは normal 登録。** fapi1 で登録されたクライアントがPKCE で通ること自体は、これまでどおり（表の「PKCE の S256」の行が fapi1 を通す）。

## RT-221.1 登録で require_pkce を true にしたクライアントは、PKCE 無しの認可を拒否する

| | |
|---|---|
| 観点 | **サーバ全体の RequirePkce（#220）は、全クライアントが揃わないと有効にできない。**移行の途中でも、**締められるクライアントから順に締められる**必要がある。oauth2_oidc_mode=fapi1 でも PKCE は必須になるが、**そちらは ROPC / client_credentials / refresh_token も巻き添えで塞ぐ**（#222）。 |
| 根拠 | OAuth 2.1 draft §4.1.1 / #221 |
| テスト | `RT221_01_クライアント単位でPKCEを必須にできる` |

**手順**

1. code_challenge を送らずに認可リクエストを出す
1. 同じクライアントに、PKCE（S256）を付けて出す

**検証（合否を判定する）**

- 認可コードを発行しない
- エラーは invalid_request
- PKCE を付ければ認可コードが返る

**補足**

- **認可エンドポイントで弾いている。** oauth2_oidc_mode=fapi1 の経路は認可コードを発行してから /token で拒否するので、**利用者が同意まで進んだ後に失敗する**（#222）。

## RT-221.2 require_pkce は、そのクライアントにだけ効く

| | |
|---|---|
| 観点 | **クライアント単位の設定が、他のクライアントに漏れないこと。**サーバ全体の RequirePkce が false なら、登録で締めていないクライアントは従来どおり PKCE 無しで通る（#221）。 |
| 根拠 | #221 |
| テスト | `RT221_02_他のクライアントには波及しない` |

**手順**

1. code_challenge を送らずに認可リクエストを出す

**検証（合否を判定する）**

- 認可コードが返る（従来どおり）

**補足**

- **サーバ全体の RequirePkce を true にすれば、こちらも通らなくなる。**クライアント側の設定は「個別の引き上げ」であって、**床を下げることはできない**。

## RT-229.1 /par に認可要求を預けると request_uri と expires_in が返り、その request_uri で認可できる

| | |
|---|---|
| 観点 | **PAR は、認可要求をブラウザ経由ではなく、先にサーバ同士で預ける仕組み。**URL に載らないので改ざんされず、長い要求も送れる。FAPI 2.0 は PAR を必須としている。独自の `/ros` と違い、**クライアント認証**を行い、応答は **`expires_in`**（秒）を返す。 |
| 根拠 | RFC 9126 §2 / §2.2 / #229 |
| テスト | `RT229_01_parに預けた要求で認可できる` |

**手順**

1. Discovery から pushed_authorization_request_endpoint を引く
1. client_secret_basic で認証し、認可要求を預ける
1. その request_uri で認可する

**検証（合否を判定する）**

- PAR の口が広告されている
- HTTP 201
- request_uri が返る
- expires_in（秒）が返る
- 認可コードが返る
- state がそのまま返る

## RT-229.2 /par は、クライアント認証がなければ受け付けない

| | |
|---|---|
| 観点 | **これが独自の `/ros` との一番の違い。**`/ros` は Request Object の署名だけで受け付けるので、**登録済みの鍵を持たないクライアントでも、誰の要求かを主張できてしまう。**PAR は、トークン エンドポイントと同じクライアント認証を求めている（RFC 9126 §2）。 |
| 根拠 | RFC 9126 §2 / §2.3 / #229 |
| テスト | `RT229_02_クライアント認証が要る` |

**手順**

1. 資格情報を付けずに預ける
1. 誤った client_secret で預ける

**検証（合否を判定する）**

- HTTP 401
- エラーは invalid_client
- request_uri を返さない
- HTTP 401
- エラーは invalid_client

## RT-229.3 /par は、フォームの request に署名付き Request Object（JAR）を入れる形でも受け付ける

| | |
|---|---|
| 観点 | **FAPI 2.0 の実運用では、PAR に JAR を入れて送る形が多い。**この実装は、`request` があればその中身を、無ければフォームの個別パラメタを預かる。**署名の検証に加えて、クライアント認証も行う**ので、`/ros`（署名だけ）より厳しい。 |
| 根拠 | RFC 9126 §3 / RFC 9101 / #229 |
| テスト | `RT229_03_requestのJARでも預けられる` |

**手順**

1. Request Object を作り、request に入れて預ける
1. その request_uri で認可する

**検証（合否を判定する）**

- HTTP 201
- request_uri が返る
- 認可コードが返る

## RT-229.4 /par に request_uri を渡すと invalid_request になる

| | |
|---|---|
| 観点 | **預ける口に、預けた結果を渡させない。**RFC 9126 §2.1 は、PAR の要求に `request_uri` を含めてはならないとしている（入れ子にすると、検証の前提が崩れる）。 |
| 根拠 | RFC 9126 §2.1 / #229 |
| テスト | `RT229_04_parにrequest_uriは渡せない` |

**手順**

1. request_uri を付けて預ける

**検証（合否を判定する）**

- HTTP 400
- エラーは invalid_request

## RT-230.1 UserClaimsMapping で対応付けたクレームが、profile / address スコープで /userinfo に出る

| | |
|---|---|
| 観点 | **`scopes_supported` に profile / address が載っているのに、空実装で何も返らなかった**（ANALYSIS-IdP.md の D-7）。RP から見ると「要求できるのに返ってこない」状態だった。**この実装は氏名・住所の項目を持たない**ので、入れ物（UnstructuredData）の**どのキーをどのクレームとして返すかを設定で対応付ける**。 |
| 根拠 | OIDC Core §5.1 / §5.1.1 / §5.4 / #230 |
| テスト | `RT23001_対応付けたクレームがuserinfoに出る` |

**手順**

1. 利用者 : 画面から非構造化データを入れる（POST /Manage/AddUnstructuredData）
1. クライアント : profile と address を要求してトークンを取る
1. /userinfo を呼ぶ
1. address が、副フィールドを持つオブジェクトで返る

**検証（合否を判定する）**

- 非構造化データを保存できる
- HTTP 200
- name が、usd1 に入れた値で返る
- preferred_username が、UserName で返る
- address.locality が、usd2 に入れた値で返る

**補足**

- **address は JSON オブジェクト**（OIDC Core §5.1.1）。設定に `address.locality` と書くと、副フィールドとして組み立てる。

## RT-230.2 profile / address を要求しなければ、対応付けたクレームは返らない

| | |
|---|---|
| 観点 | **どのクレームがどのスコープに属するかは、仕様が決めている**（OIDC Core §5.4）。設定にはスコープを書かせず、**クレーム名から仕様の表で引く。**対応付けただけで無条件に返すと、**利用者が許可していない情報を渡す**ことになる。 |
| 根拠 | OIDC Core §5.4 / #230 |
| テスト | `RT23002_スコープを要求しなければ返らない` |

**手順**

1. 利用者 : 画面から非構造化データを入れる
1. openid email だけを要求してトークンを取り、/userinfo を呼ぶ

**検証（合否を判定する）**

- HTTP 200
- name は返らない
- address も返らない
- email は返る（要求したので）

## RT-230.3 対応付けた先が空なら、そのクレームは返さない

| | |
|---|---|
| 観点 | **空の項目を並べても RP の役に立たない**（`"name": ""` を返すより、返さない方が正しい）。入れ物の中身は導入する側が決めるので、**一部だけ埋まっている状態が普通にある。** |
| 根拠 | OIDC Core §5.3.2 / #230 |
| テスト | `RT23003_値が空ならクレームを返さない` |

**手順**

1. 利用者 : usd1 を空、usd2 だけ入れる
1. profile と address を要求して /userinfo を呼ぶ

**検証（合否を判定する）**

- 空の name は返らない（キーごと出さない）
- 入っている address.locality は返る

## RT-230.4 Discovery の claims_supported に、対応付けたクレームが載る

| | |
|---|---|
| 観点 | **固定の一覧にすると、設定と食い違う**（#228 の 13 : profile / address のクレームが`claims_supported` に無かった）。**対応付けから作れば、設定を変えても追随する。**`address.<副フィールド>` は、クレームとしては `address` ひとつにまとめる。 |
| 根拠 | OIDC Discovery / #228 / #230 |
| テスト | `RT23004_claims_supportedが対応付けから作られる` |

**手順**

1. Discovery を読む

**検証（合否を判定する）**

- name が載る（対応付けたので）
- preferred_username が載る
- address が載る（副フィールドではなく address）
- address.locality は載らない（クレーム名ではない）
- 元からの項目（sub / email）も残る

**観測（判定しない）**

- claims_supported
  - 対応付けと固定の項目の合成。

## RT-231.1 認可コードを返す応答に、iss（発行者）が付く

| | |
|---|---|
| 観点 | **RP が複数の IdP を使うとき、応答の取り違えを誘う攻撃（Mix-Up）がある。**RP は `iss` を見て、**自分が要求した IdP からの応答か**を確かめられる。以前は付けていなかったので、対策が RP 側任せだった。 |
| 根拠 | RFC 9207 §2 / #231 |
| テスト | `RT231_01_成功の認可応答にissが付く` |

**手順**

1. Discovery の issuer を読む
1. 認可コードを要求する

**検証（合否を判定する）**

- 認可コードが返る
- 応答の iss が Discovery の issuer と一致する

**補足**

- issuer = https://ssoauth.opentouryo.com

## RT-231.2 エラーを返す応答にも、iss が付く

| | |
|---|---|
| 観点 | **エラーも取り違えの対象になる。** RFC 9207 §2 は、**成功・失敗のどちらの認可応答にも** `iss` を含めることを求めている。エラーだけ付けないと、RP は「どの IdP が断ったのか」を確かめられない。 |
| 根拠 | RFC 9207 §2 / RFC 6749 §4.1.2.1 / #231 |
| テスト | `RT231_02_失敗の認可応答にもissが付く` |

**手順**

1. Discovery の issuer を読む
1. 未知の response_type で認可を要求する（RP へエラーが返る）

**検証（合否を判定する）**

- RP へリダイレクトで返る
- エラーは unsupported_response_type
- エラー応答の iss が Discovery の issuer と一致する

## RT-231.3 JARM（response_mode=query.jwt）では、平文の iss を付けない（JWT の中に入っている）

| | |
|---|---|
| 観点 | **JARM は応答を認可サーバの署名付き JWT に包む。**その JWT に `iss` が入っており、**署名で守られている分だけ強い。**平文の `iss` を重ねて付ける必要はない。 |
| 根拠 | JARM / RFC 9207 §2 / #231 |
| テスト | `RT231_03_JARMでは平文のissを付けない` |

**手順**

1. Discovery の issuer を読む
1. response_mode=query.jwt で認可を要求する

**検証（合否を判定する）**

- response（JWT）が返る
- 平文の iss は付かない
- JWT の中の iss が Discovery の issuer と一致する

## RT-231.4 Discovery が authorization_response_iss_parameter_supported: true を広告する

| | |
|---|---|
| 観点 | **RP は Discovery を見て、`iss` を確かめる処理を有効にする。**広告していなければ、対応していても使われない。 |
| 根拠 | RFC 9207 §3 / #231 |
| テスト | `RT231_04_Discoveryがissの対応を広告する` |

**手順**

1. GET /.well-known/openid-configuration

**検証（合否を判定する）**

- authorization_response_iss_parameter_supported が boolean の true

## RT-233.1 /ciba_authz に request（署名付き JWT）を直接送ると、CIBA が成立する

| | |
|---|---|
| 観点 | **CIBA Core が定めている送り方**（§7.1.1 : 署名した認証要求を request パラメタで POST）。以前は /ros に預けた request_uri しか受け付けておらず、これは CIBA Core に無い独自拡張だった。**標準の CIBA クライアントが繋がるかどうか**を、ここで見る。 |
| 根拠 | CIBA Core §7.1.1 / #233 |
| テスト | `RT23301_requestを直接送ってCIBAが成立する` |

**手順**

1. 利用者 : 認証デバイスを登録する（POST /SetDeviceToken）
1. クライアント : request に署名付き JWT を入れて POST /ciba_authz
1. サーバ → 認証デバイス : プッシュ通知を受け取る（送信箱）
1. 利用者 : 認証デバイスで「許可」を押す（POST /ciba_result、result=true）
1. クライアント : ポーリングしてトークンを取る

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- 認証リクエスト : HTTP 200
- auth_req_id が返る
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- request に入れた binding_message が載る
- 返答 : HTTP 200
- access_token が返る

**補足**

- **/ros を一度も呼んでいない。** 認証要求は request で直接渡している。

## RT-233.2 request と request_uri の両方を送ると、request が使われる

| | |
|---|---|
| 観点 | **後方互換のため request_uri の受け口を残す**ので、両方が届き得る。そのとき**どちらが効くかを決めておく**（仕様にある request を優先）。決めていないと、実装によって結果が変わる。 |
| 根拠 | CIBA Core §7.1.1 / #233 |
| テスト | `RT23302_両方あればrequestを優先する` |

**手順**

1. 利用者 : 認証デバイスを登録する
1. /ros に別の binding_message の要求を預けて、request_uri を得る
1. クライアント : request と request_uri の両方を入れて POST /ciba_authz
1. プッシュ通知の binding_message を見る

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- 認証リクエスト : HTTP 200
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- request 側の binding_message が届く（request_uri 側ではない）

## RT-233.3 署名が壊れている request は、認証要求として受け付けない

| | |
|---|---|
| 観点 | **request は署名だけがクライアントの証明**である（/ciba_authz は HTTP のクライアント認証を行わない）。署名を確かめずに中身を信じると、誰でも他人のクライアントを名乗れる。**利用者に通知を送る前に断る**こと。 |
| 根拠 | CIBA Core §7.1.1 / §13 / #233 |
| テスト | `RT23303_署名が壊れたrequestを断る` |

**手順**

1. 正しい request を作り、署名の部分だけを書き換える
1. POST /ciba_authz

**検証（合否を判定する）**

- auth_req_id を返さない（利用者へ通知しない）
- HTTP 400
- エラーは invalid_request

## RT-233.4 request も request_uri も無い認証要求は、invalid_request で断る

| | |
|---|---|
| 観点 | **受け口を 2 つにしたので、「どちらも無い」が新しい入口になる。**エラーの形（400 と invalid_request）が変わっていないことを見る。 |
| 根拠 | CIBA Core §13 / #233 |
| テスト | `RT23304_requestもrequest_uriも無ければ断る` |

**手順**

1. POST /ciba_authz（scope だけを入れ、request も request_uri も入れない）

**検証（合否を判定する）**

- HTTP 400
- エラーは invalid_request

## RT-234.1 aud が OP の Issuer Identifier でない認証要求は、invalid_request で断る

| | |
|---|---|
| 観点 | **CIBA Core §7.1.1 は、aud に OP の Issuer Identifier を入れることを MUST としている。**見ないと、**別の認可サーバ宛てに作られた要求**を、同じクライアントの鍵が登録されているこの IdP でも受け付けてしまう。以前は exp / nbf だけを見ており、aud は取り出してもいなかった。 |
| 根拠 | CIBA Core §7.1.1 / §13 / #234 の段階 1 |
| テスト | `RT23401_audがissuerでなければ断る` |

**手順**

1. Discovery から issuer を読む（テストに値を書かない）
1. aud に別の認可サーバの識別子を入れた request を送る

**検証（合否を判定する）**

- issuer が広告されている
- auth_req_id を返さない（利用者へ通知しない）
- HTTP 400
- エラーは invalid_request

**観測（判定しない）**

- issuer
  - **待ち受けている URL とは別の値**（設定キー IssuerId）。aud はこちらでなければならない。

**補足**

- **署名は正しい。** 正しい鍵で署名されていても、宛先が違えば受け付けない。

## RT-234.2 aud が入っていない認証要求は、invalid_request で断る

| | |
|---|---|
| 観点 | **CIBA Core §7.1.1 の必須クレーム**（aud / iss / exp / iat / nbf / jti）の 1 つ。欠落は、Open棟梁 が返す server_error ではなく invalid_request に読み替える（#196 と同じ扱い）。 |
| 根拠 | CIBA Core §7.1.1 / §13 / #234 の段階 1 |
| テスト | `RT23402_audが無ければ断る` |

**手順**

1. aud を入れずに request を作って送る

**検証（合否を判定する）**

- HTTP 400
- エラーは invalid_request

## RT-234.3 同じ認証要求（同じ jti）を送り直すと、invalid_request で断る

| | |
|---|---|
| 観点 | **CIBA Core §7.1.1 は jti を「署名した認証要求の一意な識別子」としている。**見ないと、**同じ要求 JWT を exp まで何度でも送り直せる**。`/ciba_authz` はクライアント認証をしないので（段階 3 で入れる）、要求を手に入れた者が、利用者に通知を繰り返し送れてしまう。`request_uri` の経路も同じで、`/ros` に預け直せば新しい参照を取れた。 |
| 根拠 | CIBA Core §7.1.1 / §13 / #234 の段階 2 |
| テスト | `RT23403_同じjtiの要求を二度は受け付けない` |

**手順**

1. 認証要求を 1 回送る
1. まったく同じ要求を、もう一度送る

**検証（合否を判定する）**

- 1 回目 : エラーは unknown_user_id（検証は通っている）
- 2 回目 : HTTP 400
- 2 回目 : エラーは invalid_request（jti は使用済み）
- 2 回目 : エラーが変わる（1 回目と同じ応答ではない）

**補足**

- **記録は Request Object のストアを使い回している**（接頭辞付きのキー）。#188 で入れた有効期限と掃除がそのまま効くので、新しい表を作っていない。

## RT-234.4 クライアント認証の無い認証要求は、invalid_client（401）で断る

| | |
|---|---|
| 観点 | **CIBA Core §7.1 は、この口でのクライアント認証を MUST としている**（FAPI-CIBA は private_key_jwt を求める）。以前は署名だけで識別しており、`/token` や `/device_authz` と違って`ClientAuthentication` を呼んでいなかった。**署名が正しくても、資格情報が無ければ受け付けない。** |
| 根拠 | CIBA Core §7.1 / §13 / #234 の段階 3 |
| テスト | `RT23404_クライアント認証が無ければ断る` |

**手順**

1. 資格情報を付けずに POST /ciba_authz
1. 誤った client_secret で POST /ciba_authz

**検証（合否を判定する）**

- auth_req_id を返さない（利用者へ通知しない）
- HTTP 401
- エラーは invalid_client
- WWW-Authenticate が付く（RFC 6749 §5.2）
- HTTP 401
- エラーは invalid_client

## RT-234.5 自分の資格情報で認証し、他人の client_id を iss にした要求は断る

| | |
|---|---|
| 観点 | **認証を入れただけでは足りない。**CIBA Core §7.1.1 は `iss` を「クライアントの client_id」と定めている。**これを確かめないと、自分の資格情報で認証して、他人の要求を代わりに送れる**（要求の署名は、その他人の鍵で正しく検証できてしまう）。 |
| 根拠 | CIBA Core §7.1 / §7.1.1 / #234 の段階 3 |
| テスト | `RT23405_認証したクライアントとissが違えば断る` |

**手順**

1. CIBA クライアントの鍵で、正しく署名した要求を作る
1. 別のクライアントの資格情報で認証して送る

**検証（合否を判定する）**

- auth_req_id を返さない（利用者へ通知しない）
- HTTP 400
- エラーは invalid_request

**補足**

- **認証そのものは通っている**（資格情報は正しい）。断っているのは、認証したクライアントと要求の iss が違うため。

# FA

## FA-1.1 oauth2_oidc_mode=fapi1 のクライアントは、PKCE(S256) の認可コードだけが通る

| | |
|---|---|
| 観点 | **登録が上位のクライアントほど、通る経路が狭い。**CheckClientMode は ClientModePolicy の表（経路 × 何を証明したか）で判定する。認可コードを client_secret で取る行は normal だけを通すので、fapi1 の登録は通らない。**PKCE の S256 で取る行は fapi1 も通すので、そこだけが通る。** |
| 根拠 | FAPI 1.0 Advanced / #222 |
| テスト | `FA0101_fapi1はPKCEの経路だけを通す` |

**手順**

1. 対照 : normal 登録のクライアントは、client_secret で通る
1. fapi1 ＋ client_secret（PKCE 無し）
1. fapi1 ＋ PKCE(S256)（client_secret 無し）
1. fapi1 ＋ ROPC / client_credentials

**検証（合否を判定する）**

- 対照（normal）は通る
- client_secret だけでは通らない
- エラーは unauthorized_client
- PKCE(S256) なら通る
- ROPC は通らない
- client_credentials は通らない

**補足**

- **ROPC / client_credentials は、サーバ全体では有効**（-Launch は Implicit / ROPC を有効にして起動する。#220）。**塞いでいるのは、このクライアントの登録**であることが、(1) の対照で分かる。

## FA-1.2 fapi1 のクライアントには、refresh_token を発行しない

| | |
|---|---|
| 観点 | **使えない資格情報は渡さない。**表の refresh_token の行は、証明によらず normal だけを通すため、fapi1 の登録は使えない。以前は発行していて、使うと必ず拒否された（#222 で記録）。#224 の段階 2 で、**登録種別で使えない経路の refresh_token は発行しない**ようにした。 |
| 根拠 | RFC 6749 §5.1（refresh_token は任意）/ #224 |
| テスト | `FA0102_fapi1にはrefresh_tokenを発行しない` |

**手順**

1. 対照 : normal 登録では、refresh_token で更新できる
1. fapi1 で PKCE(S256) のトークンを取る

**検証（合否を判定する）**

- 対照（normal）は更新できる
- refresh_token は発行されない

**補足**

- **(1) の対照で、サーバ全体では refresh_token が有効**であることが分かる。発行しないのは、このクライアントの登録種別による。

## FA-1.3 fapi1 のクライアントが client_secret と PKCE(S256) を両方送ると、拒否される

| | |
|---|---|
| 観点 | **表の「認可コード × client_secret と PKCE の併用」の行は、normal だけを通す。**fapi1 を通すのは、client_secret を送らない「PKCE の S256」の行だけ（併用の経路では PKCE は検証だけ行い、判定には使わない。#220）。FAPI 1.0 Advanced は client_secret を認めていないので、拒否は設計どおり（#224）。 |
| 根拠 | FAPI 1.0 Advanced §5.2.2 / RFC 7636 / #224 |
| テスト | `FA0103_fapi1はclient_secretとPKCEの併用を通さない` |

**手順**

1. PKCE(S256) で認可コードを取り、client_secret と code_verifier の両方を送って交換する

**検証（合否を判定する）**

- トークンを返さない
- エラーは unauthorized_client

**補足**

- **設計どおり**（#224 の段階 2 で、拒否のままとすることにした）。FAPI 1.0 Advanced は client_secret によるクライアント認証を認めていない（private_key_jwt か mTLS）。同じクライアントが client_secret を送らなければ通る（FA-1.1）のは、PKCE の S256 の行による。

## FA-1.4 fapi1 のクライアントは、Hybrid フロー（code id_token）で code も id_token も受け取らず、unauthorized_client が RP へ返る

| | |
|---|---|
| 観点 | **表の Hybrid の行は normal だけを通す。**以前はトークンを作る時点で拒否し、error=access_denied を返していた（#224 の段階 0 で記録）。段階 2 で、**要求を検証する時点**（redirect_uri を確かめた直後）で判定し、unauthorized_client を RP へリダイレクトで返すようにした。 |
| 根拠 | RFC 6749 §4.2.2.1 / OIDC Core §3.3 / FAPI 1.0 Advanced / #224 |
| テスト | `FA0104_fapi1はHybridフローを通さない` |

**手順**

1. 対照 : normal 登録のクライアントは、Hybrid で code と id_token を受け取る
1. fapi1 登録のクライアントで、同じ要求を送る

**検証（合否を判定する）**

- 対照（normal）は code を受け取る
- code を受け取らない
- id_token を受け取らない
- RP へリダイレクトで返す
- エラーは unauthorized_client

## FA-2.1 oauth2_oidc_mode=fapi2 のクライアントは、client_secret でも PKCE でも通らない

| | |
|---|---|
| 観点 | **fapi2 に達するのは x509（mTLS）だけ。**PKCE の S256 で上がるのは fapi1 までなので、**平文の経路は全滅する**。FAPI2 のクライアントは、Request Object（JAR）＋ 証明書で使う想定（`RT-197` が request_uri 経路を測っている）。 |
| 根拠 | FAPI 2.0 / #222 |
| テスト | `FA0201_fapi2はclient_secretもPKCEも通さない` |

**手順**

1. client_secret（PKCE 無し）
1. PKCE(S256)（client_secret 無し）

**検証（合否を判定する）**

- client_secret では通らない
- PKCE(S256) でも通らない
- エラーは unauthorized_client

**補足**

- **これは設計どおり。** fapi2 の登録は、証明書（x509）を伴う経路でだけ通る。**通る側は FA-6.1 で測る**（net10.0 版のみ。net48 版は手動。#226）。

## FA-3.1 oauth2_oidc_mode=device のクライアントは、PKCE(S256) の認可コードが通る

| | |
|---|---|
| 観点 | **表の「認可コード × PKCE の S256」の行は、device も通す**（LIR 用）。以前の大小比較では device は fapi2 より大きい値で、この経路は例外措置としてハードコードされていた（#224 の段階 1 で表に置き換えた）。**その行が効いていることを測る。** |
| 根拠 | RFC 8628（Device Authorization Grant）/ #222 |
| テスト | `FA0301_deviceはPKCEの経路を通る` |

**手順**

1. PKCE(S256) で認可コードを取り、交換する

**検証（合否を判定する）**

- トークンが返る
- refresh_token は発行されない

**補足**

- **表のこの行から device を外すと、ここは通らない。**表を書き換えるときは、この経路を壊さないこと（#224）。
- **refresh_token の経路は normal の登録だけ**なので、device の登録には発行しない（#224 の段階 2。以前は発行していたが、使えなかった）。

## FA-4.1 Device AuthZ グラントは、登録種別が normal と device のクライアントにだけ許す

| | |
|---|---|
| 観点 | **このグラントは client_secret（またはパブリック）で通る。**fapi1 / fapi2 / fapi_ciba の登録は、より強いクライアント認証（PKCE / private_key_jwt / mTLS）を求めているので、この経路を使わせてはならない。**以前は登録種別を判定しておらず、client_secret だけでトークンが出ていた**（#224）。 |
| 根拠 | RFC 8628 / RFC 6749 §5.2（unauthorized_client）/ #224 |
| テスト | `FA0401_DeviceAuthZはnormalとdeviceの登録にだけ許す` |

**手順**

1. 対照 : device / normal の登録は、開始できる
1. fapi1 / fapi2 / fapi_ciba の登録は、開始の時点で拒否される

**検証（合否を判定する）**

- TestClient3 は device_code を得る
- MVC_Sample は device_code を得る
- TestClient1 は unauthorized_client（400）
- TestClient2 は unauthorized_client（400）
- TestClient4 は unauthorized_client（400）

**補足**

- **client_secret は正しいものを送っている。** 拒否の理由は認証の失敗ではなく、**登録種別がこのグラントを許さないこと**（だから invalid_client ではなく unauthorized_client）。
- **トークン発行（/token）側でも同じ判定をしている**が、開始で弾かれるため到達できず、この E2E では単独で測っていない。

## FA-5.1 CIBA を normal 登録のクライアントで使うと、開始（/ciba_authz）で unauthorized_client になる

| | |
|---|---|
| 観点 | **利用者にプッシュ通知を送る前に断る。**以前は開始で登録種別を見ておらず、利用者に通知が届き、承認させた後でトークンの段階（unsupported_grant_type）で拒否していた（#224 の段階 0 で記録）。段階 2 で、開始の時点で判定するようにした（Device AuthZ の C-18 と同じ考え方）。 |
| 根拠 | OpenID Connect CIBA Core §13 / #224 |
| テスト | `FA0501_CIBAはfapi_ciba以外の登録を開始で断る` |

**手順**

1. 利用者 : 認証デバイスを登録する（通知を受けられる状態にしておく）
1. normal 登録のクライアントで、CIBA の認証リクエストを送る

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- auth_req_id を返さない（利用者へ通知しない）
- HTTP 400
- エラーは unauthorized_client

**補足**

- **(1) で端末を登録してあるので、以前の実装なら通知が送られていた。**開始で断ったので、auth_req_id は発行されず、利用者は何も操作しない。

## FA-5.2 oauth2_oidc_mode が既知でない値（fapi_1）のクライアントは、開始（/ciba_authz）で unauthorized_client になる

| | |
|---|---|
| 観点 | **既知でない登録値は、不正な登録として拒否する**（#224 の段階 2）。以前は fapi2 とみなしていた。「一番厳しい種別」に倒す作りは、種別が増えると意味が変わるため、やめた。なお oauth2_oidc_mode を書いていない登録は normal で、これには当たらない。 |
| 根拠 | #224 |
| テスト | `FA0502_登録種別が既知でない値ならCIBAを断る` |

**手順**

1. 利用者 : 認証デバイスを登録する
1. 登録値が不正なクライアントで、CIBA の認証リクエストを送る

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- auth_req_id を返さない（利用者へ通知しない）
- HTTP 400
- エラーは unauthorized_client

## FA-6.1 oauth2_oidc_mode=fapi2 のクライアントは、mTLS（Subject が一致する証明書）の認可コードで通る

| | |
|---|---|
| 観点 | **fapi2 を通すのは、ClientModePolicy の表の「認可コード × mTLS」の行だけ。**FA-2.1 は client_secret / PKCE では通らないことを測っており、本テストは**その対照（通る側）**。net48 版は -NetFxMtls のときだけ（TESTING.md）。 |
| 根拠 | RFC 8705 §2.1（tls_client_auth）/ FAPI 2.0 / #226 |
| テスト | `FA0601_fapi2はmTLSの認可コードで通る` |

**手順**

1. 認可コードを取り、Subject が一致する自己署名の証明書を添えて交換する（client_secret は送らない）

**検証（合否を判定する）**

- トークンが返る
- fapi クレームは登録どおり fapi2
- アクセス トークンに cnf が載る（証明書に紐づく）
- refresh_token は発行されない

**補足**

- **refresh_token の経路は normal の登録だけ**なので、fapi2 には発行しない（#224 の段階 2）。

## FA-6.2 mTLS のクライアントは、証明書が無い・Subject が一致しないと invalid_client（401）になる

| | |
|---|---|
| 観点 | **クライアント認証は、証明書の Subject と登録の tls_client_auth_subject_dn の一致で行う。**client_secret を送らず、証明書も一致しなければ、認証に失敗する（RFC 6749 §5.2 : invalid_client）。 |
| 根拠 | RFC 8705 §2.1 / RFC 6749 §5.2 / #226 |
| テスト | `FA0602_証明書が無いかSubjectが違うならinvalid_client` |

**手順**

1. 証明書を添えずに交換する
1. Subject が違う証明書を添えて交換する

**検証（合否を判定する）**

- トークンを返さない
- HTTP 401
- エラーは invalid_client
- トークンを返さない
- HTTP 401
- エラーは invalid_client

## FA-6.3 oauth2_oidc_mode が既知でない値（fapi_1）のクライアントは、Subject が一致する証明書でも通らない

| | |
|---|---|
| 観点 | **既知でない登録値は、不正な登録として拒否する**（#224 の段階 2 の E）。以前は fapi2 とみなしていたので、**この経路（認可コード × mTLS）では通っていた**。FA-5.2（CIBA）は以前の扱いでも拒否されるため区別できず、違いが出るのはここだけ。 |
| 根拠 | #224 / #226 |
| テスト | `FA0603_登録種別が既知でない値なら証明書が一致しても通さない` |

**手順**

1. 認可リクエストを送る
1. 証明書で認証できることを、トークン エンドポイント（client_credentials）で確かめる

**検証（合否を判定する）**

- 認可コードを発行しない
- エラーは unauthorized_client
- トークンを返さない
- エラーは unauthorized_client（認証は通っている）
- 説明は「登録値が不正」

## FA-6.4 mTLS で得たアクセス トークンは cnf を持ち、その証明書を提示した要求でしか使えない

| | |
|---|---|
| 観点 | **cnf は、トークンを証明書に紐づける**（sender-constrained。RFC 8705 3）。値は**証明書（DER）の SHA-256 を BASE64URL したもの**（同 3.1）。保護されたリソース（ここでは /userinfo）は、**提示された証明書と照合して**、合わなければ受け付けない。紐づいていないトークン（cnf 無し）は、これまでどおり bearer として扱う。 |
| 根拠 | RFC 8705 §3 / §3.1 / RFC 6750 §3.1 |
| テスト | `FA0604_証明書に紐づくトークンはその証明書の要求でしか使えない` |

**手順**

1. mTLS でトークンを取り、cnf の値を確かめる
1. 同じ証明書を提示して /userinfo を呼ぶ
1. 証明書を提示せずに /userinfo を呼ぶ
1. 別の証明書を提示して /userinfo を呼ぶ

**検証（合否を判定する）**

- cnf の x5t#S256 は、証明書の SHA-256（BASE64URL）
- HTTP 200
- sub が返る
- HTTP 401
- エラーは invalid_token
- 利用者の属性を返さない
- HTTP 401
- エラーは invalid_token

# 21

## 21-1.1 OAuth 2.1 が許さない経路（Implicit / ROPC / PKCE 無し）が、締めた登録では塞がる

| | |
|---|---|
| 観点 | **サーバ全体は開いたままで測る。** -Launch は Implicit / ROPC を有効にし、RequirePkce も false のまま。**塞いでいるのはクライアントの登録**であることを、対照（normal 登録は通る）と並べて確かめる（#222）。 |
| 根拠 | OAuth 2.1 draft §2.1.2 / §4.1.1 / #222 |
| テスト | `OA2101_締めたクライアントでは許されない経路が塞がる` |

**手順**

1. 対照 : normal 登録は、PKCE 無しでも ROPC でも通る
1. PKCE 無しの認可 : require_pkce のクライアントでは塞がる
1. ROPC : fapi1 のクライアントでは塞がる
1. Implicit : fapi1 のクライアントでは塞がる

**検証（合否を判定する）**

- 対照は PKCE 無しで認可コードが返る
- 対照は ROPC が通る（＝サーバ全体では有効）
- 認可コードを発行しない
- エラーは invalid_request
- ROPC は拒否される
- access_token を返さない

**補足**

- **(1) との対比が要点。** 同じサーバ・同じ設定で、**登録の違いだけで経路が塞がっている**。移行では、締められるクライアントから順に登録を変えていける（#221）。

## 21-2.1 アクセス トークンは Authorization ヘッダでのみ受け付ける（クエリ文字列では受けない）

| | |
|---|---|
| 観点 | **OAuth 2.1 は、URI クエリ文字列でのトークン送信を禁止している**（RFC 6750 §2.3 の form-encoded / URI query は廃止）。**URL はログ・Referer・履歴に残る**ため。`ANALYSIS-IdP.md` の D-12 で「ヘッダのみ（要再確認）」としていた項目を、実際に測る。 |
| 根拠 | OAuth 2.1 draft §4.3 / RFC 6750 §2.3 / #222 |
| テスト | `OA2102_アクセストークンはヘッダでのみ受け付ける` |

**手順**

1. トークンを取得する
1. 対照 : Authorization ヘッダで /userinfo を呼ぶ
1. クエリ文字列（?access_token=...）で /userinfo を呼ぶ

**検証（合否を判定する）**

- ヘッダなら答える
- クエリ文字列では答えない
- 401 を返す

**補足**

- **要求 URL はここに出さない**（トークンを含むため）。

# TC. 基本テストケース

## TC-3.1 インプリシットのトークンがフラグメントで返り、クエリに漏れない

| | |
|---|---|
| 観点 | アクセス トークンは **URL フラグメント（#）**で返さなければならない。クエリ（?）に入れると、Referer ヘッダやサーバのアクセス ログを通じて第三者に渡る。 |
| 根拠 | RFC 6749 §4.2.2（フラグメントで返す）/ §10.3 / OIDC Core §3.2.2.5 |
| テスト | `TC0301_トークンがフラグメントで返りクエリに漏れない` |

**手順**

1. GET /authorize?response_type=id_token token&scope=openid&nonce=… を送る

**検証（合否を判定する）**

- エラーにならない
- フラグメント（#）で返る
- access_token が返る
- クエリ（? より前）にトークンが含まれない
- state がそのまま返る

## TC-4.1 正しい username / password でトークンを取得できる

| | |
|---|---|
| 観点 | トークン エンドポイントへ資格情報を直接送り、access_token を得られること。 |
| 根拠 | RFC 6749 §4.3（Resource Owner Password Credentials Grant） |
| テスト | `TC0401_正しい資格情報でトークンを取得できる` |

**手順**

1. POST /token に grant_type=password と username / password を送る

**検証（合否を判定する）**

- エラーにならない
- access_token が返る
- sub がテスト ユーザである

## TC-4.2 誤ったパスワード / 存在しないユーザが拒否される

| | |
|---|---|
| 観点 | 誤った資格情報でトークンが出てはならない。また、**「ユーザが居ない」と「パスワードが違う」を応答で区別できると、ユーザ名の存在を調べられる。**両者の応答が同じであることも見る。 |
| 根拠 | RFC 6749 §4.3.2 / §5.2（invalid_grant） |
| テスト | `TC0402_誤った資格情報が拒否される` |

**手順**

1. 実在するユーザ ＋ 誤ったパスワード
1. 存在しないユーザ

**検証（合否を判定する）**

- 誤ったパスワードでトークンを発行しない
- 存在しないユーザでトークンを発行しない

**観測（判定しない）**

- 2 つの応答を区別できるか
  - 同じ応答であることが望ましい（ユーザ名の存在が漏れないため）。

**補足**

- ブルート フォース対策（連続失敗でのロックアウト）と、HTTPS 非適用時の拒否は、このテストでは扱わない。前者は試行を繰り返す必要があり、後者は待ち受け構成の話であるため。

