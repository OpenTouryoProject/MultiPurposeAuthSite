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

## SM-4.2 テスト ユーザのメアドでもサインインできる

| | |
|---|---|
| 観点 | **利用者名とメアドの両方を受ける**（#151 の段階 3）。入力が `@` を含めばメアドとして引く。**どちらか一方しか通らないなら、片方の経路が壊れている。** |
| 根拠 | #151 の段階 3（利用者名とメアドの両方でサインイン） |
| テスト | `SM0402_メアドでもサインインできる` |

**手順**

1. GET /Account/Login して __RequestVerificationToken を取る
1. POST /Account/Login に、利用者名ではなくメアドを送る

**検証（合否を判定する）**

- メアドでサインインできた

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

- Discovery の scopes_supported = [profile, email, phone, address, auth, roles, openid, client_registration]

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
- sub が返る
- sub が /userinfo の sub と一致する（＝ 利用者を指している）
- aud が自クライアントの client_id と一致する
- exp が数値である（NumericDate）
- iat が数値である（NumericDate）
- exp が現在時刻より未来である
- iat が未来ではない（時計のずれを 60 秒まで許容）
- 認可リクエストの nonce がそのまま入る

**補足**

- iss の期待値は、Discovery 文書の issuer から取る（決め打ちにしない）。
- **sub の値では、誰かを判定しない**（#151 の段階 4）。**既定が public になり、sub は利用者 ID になった。**ただし**発行済みの組み合わせでは、以前の値（利用者名）が返る**ので（対応表。段階 2）、**値の形は配備によって違う。****sub は「同じ利用者・同じ RP なら同じ値」であることに意味がある。**

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
- sub が id_token の sub と一致する
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
- verification_uri は絶対 URI である

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
- 承認したユーザのトークンである（/userinfo の email）
- /userinfo の sub が、トークンの sub と一致する

**観測（判定しない）**

- refresh_token / id_token
  - **device の登録には refresh_token を発行しない**（ClientModePolicy の表。#224）。**normal の登録には返す**（以前は生成・保存するだけで返していなかった。RT-294.41）。

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

## RT-C10.1 登録された折り返し先は、登録したクライアントでだけ使える

| | |
|---|---|
| 観点 | **`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**管理画面の「トークンを取る」の折り返し先と完全一致する `redirect_uri` は、**その client_id にその URI が登録されているかを見ずに通っていた。****`IsLockedDownTestEndpoints` の対象外**なので、**本番でも閉じられなかった。****分岐を消し、登録どおりの照合だけになった。例外は無い。****その画面は、その後に廃止された**（記号も落とした）が、**この性質は測り続ける。** |
| 根拠 | RFC 6749 §3.1.2.3 / ANALYSIS-IdP.md の C-10 |
| テスト | `RTC1001_他のクライアントに登録された折り返し先は使えない` |

**手順**

1. 登録していないクライアントが、この折り返し先を指定する
1. 登録しているクライアントが、同じ折り返し先を指定する

**検証（合否を判定する）**

- 片方にだけ登録された URI である
- 認可コードを発行しない
- その URI へリダイレクトしない
- 認可コードを発行する

**観測（判定しない）**

- 応答
  - **redirect_uri が照合できないときは、その URI へエラーも返さない**（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。
- 応答
  - **登録どおりなので、通常の照合で通る**（分岐は要らない）。

**補足**

- **(1) が、消した分岐そのものである。**分岐が在った間は、**登録済みのどのクライアントでもこの URI を宛先にできた。**
- **(2) は、消したことで普通の経路が壊れていないことを見ている。****登録どおりの `redirect_uri` は、これまでどおり通る。**

## RT-129.1 ES256 で署名した client_assertion でも、クライアント認証が通る

| | |
|---|---|
| 観点 | **以前は RS256 しか通らなかった。**`CmnEndpoints.ClientAuthentication` が **`jwk_rsa_publickey` しか渡していなかった**ため（框の `JwtAssertion.Verify` は **JWK の `kty` を見て RSA / EC を選ぶ**ので、**ECDSA の公開鍵を渡せば ES256 が通る**）。**登録された RSA / ECDSA の鍵を順に試す**ようにした（#129 の段階 2）。**アサーションの `alg` ヘッダでは選ばない**（C-8 と同じ轍を踏まないため）。 |
| 根拠 | RFC 7523 §2.2 / OIDC Core §9（private_key_jwt）/ #129 の段階 2 |
| テスト | `RT12901_ES256のclient_assertionでも認証できる` |

**手順**

1. ES256 の client_assertion で client_credentials を要求する
1. （対照）RS256 でも従来どおり通る
1. Discovery が ES256 を広告している

**検証（合否を判定する）**

- トークンが返る
- トークンが返る
- token_endpoint_auth_signing_alg_values_supported

**補足**

- **広告と実装を揃えた**（#129 の段階 0 で作った対照表の 1 行目）。**`PS256` は通らない**（Open棟梁 に `JWS_PS*` が無い）。

## RT-129.2 ヘッダの alg を書き換えたトークンを、認可サーバが受け付けない

| | |
|---|---|
| 観点 | **この認可サーバが発行する alg は `JwsFactory.SupportedAlgs`** で、`jwkcerts` と Discovery も、その一覧から作っている。**以前は、知らない alg を RS256 として扱っていた**（C-8）。**関門は 3 つ**で、**発行しない alg は即、拒否**し、**発行する alg でも、鍵（kty / crv）が合わなければ拒否**し（#129 の段階 3）、**鍵まで合っても、署名が合わなければ拒否**する（#129 の段階 4）。 |
| 根拠 | JWT BCP（RFC 8725）§3.1 / OIDC Core §3.1.3.7 / C-8 |
| テスト | `RT12902_受けるalgは自分が発行するものだけ` |

**手順**

1. 正規の access_token を取得する（対照）
1. **発行しない alg** に書き換えて叩く（署名と kid は、そのまま）
1. **発行するが、鍵の種類が合わない alg** に書き換えて叩く（#129 の段階 3）
1. **鍵までは合うが、パディングが違う alg** に書き換えて叩く（#129 の段階 4）

**検証（合否を判定する）**

- 正規のトークンでは /userinfo が応答する
- alg=HS256 のトークンでユーザ情報を返さない
- alg=HS384 のトークンでユーザ情報を返さない
- alg=none のトークンでユーザ情報を返さない
- alg=ES256（RSA の kid なのに EC の alg）でユーザ情報を返さない
- alg=ES384（RSA の kid なのに EC の alg）でユーザ情報を返さない
- alg=ES512（RSA の kid なのに EC の alg）でユーザ情報を返さない
- alg=PS256（RSA の鍵は合うが PKCS #1 v1.5 の署名）でユーザ情報を返さない
- alg=PS384（RSA の鍵は合うが PKCS #1 v1.5 の署名）でユーザ情報を返さない
- alg=PS512（RSA の鍵は合うが PKCS #1 v1.5 の署名）でユーザ情報を返さない

**補足**

- **`HS256` / `HS384` は、公開鍵を共通鍵として使わせる古典的な混同**である。**`RS384` / `RS512` は段階 2、`ES384` / `ES512` は段階 3、`PS*` は段階 4 で発行するようになった**ので、**(2) の一覧からは外した**（**増やしたら、このテストの一覧も直すこと**）。
- **(2) 〜 (4) は、別々の関門である。** トークンは `RS256` で署名してあり、`kid` は RSA の鍵を指す。**(2)** は `SupportedAlgs` に無いので**即、拒否**。**(3)** は `ES*` なので**鍵の種類（`kty`）が食い違って拒否**。**(4)** は `PS*` で**鍵は同じ RSA の 1 本**だから `kty` では弾けず、**パディング（RSASSA-PSS）が違うので署名の検証で落ちる。****`ES*` 同士の食い違い（曲線）は `RT-129.5`**、**`PS*` が正しく通ること自体は `RT-129.7`** で見る。
- **`alg=none` は `TC-6.4` でも見ている。**あちらは**ヘッダを丸ごと作り替えて署名を落とす**（`kid` も消える）。**こちらは `kid` を残す**ので、**鍵が引けたうえで alg だけが違う**形になり、**alg の判定そのもの**を測れる。

## RT-129.3 登録した alg（RS512）で署名され、jwkcerts の同じ鍵で検証できる

| | |
|---|---|
| 観点 | **#129 の段階 2 で RS384 / RS512 を足した。****鍵は RS256 と同じ**で、**ダイジェストだけが違う。****`kid` は鍵から作る**（RFC 7638）ので**同じ値**になり、**RP は `jwkcerts` の同じ鍵で検証できる**（どのダイジェストかは `alg` が伝える）。**自分の検証経路（C-8 で固定した受ける集合）も、これを受けること**まで見る。 |
| 根拠 | OIDC Dynamic Registration §2（id_token_signed_response_alg）/ RFC 7638 / #129 の段階 2 |
| テスト | `RT12903_登録したalgで署名され同じ鍵で検証できる` |

**手順**

1. 認可コード フローでトークンを取る
1. ヘッダの alg を見る
1. jwkcerts の公開鍵で、RP の立場で検証する
1. kid は RS256 のクライアントと同じ（鍵が 1 つだから）
1. 自分の検証経路も、RS512 の access_token を受ける

**検証（合否を判定する）**

- access_token の alg が RS512
- id_token の alg も RS512（access_token に揃う）
- JWK Set の公開鍵で検証できる
- RS256 のクライアントの alg は RS256（対照）
- **kid は 2 つのクライアントで同じ**
- /userinfo が応答する（受ける集合に RS512 が入っている）

**補足**

- **C-8 で「受ける alg」を固定した**（#129 の段階 1）。**段階 2 で RS384 / RS512 を足した**ので、**ここが通ることが、その証拠**になる。**受ける集合は `JwsFactory.SupportedAlgs` の 1 か所**で、**Discovery の `id_token_signing_alg_values_supported` も、そこから作っている。**

## RT-129.4 Discovery の id_token_signing_alg_values_supported が、実際に発行する alg と一致する

| | |
|---|---|
| 観点 | **広告と実装が食い違うと、RP は使えない alg を選ぶ。****#129 の段階 0 で作った対照表の続き**で、**段階 2 で増やした RS384 / RS512 が広告に出ている**ことを見る。 |
| 根拠 | OIDC Discovery 1.0 §3 / #129 の段階 0・2 |
| テスト | `RT12904_Discoveryが広告する` |

**手順**

1. Discovery 文書を読む

**検証（合否を判定する）**

- id_token_signing_alg_values_supported が 9 つ（RSA の 6 つ → EC の 3 つ の順）

**補足**

- **順序まで固定している。** 一覧は `SigningKeys` の表 1 か所から作っており、**順序が変わるときは、そこを触ったとき**である（気付けた方がよい）。**並びは鍵ごと**で、**RSA の 1 本を使う 6 つ**（`RS*` ＋ `PS*`）のあと、**曲線ごとに鍵が分かれる 3 つ**（`ES*`）が来る。**順序そのものに仕様上の意味は無い**（RFC 8414 / OIDC Discovery）。

## RT-129.5 ES384 / ES512 で署名され、jwkcerts の曲線の合う鍵で検証できる

| | |
|---|---|
| 観点 | **EC は曲線が alg に紐づく**（JWA : `ES256`→P-256、`ES384`→P-384、`ES512`→P-521）。**RSA と違って鍵が分かれる**ので、**`kid` も曲線ごとに違う。****`jwkcerts` に 3 本とも載っていること**と、**曲線が食い違うトークンを受けないこと**（`kty` だけでは足りない）まで見る。 |
| 根拠 | JWA（RFC 7518）§3.4 / RFC 7638 / #129 の段階 3 |
| テスト | `RT12905_ECは曲線の合う鍵で検証できる` |

**手順**

1. (ES384) 認可コード フローでトークンを取り、ヘッダと署名を見る
1. (ES384) 自分の検証経路も、この access_token を受ける
1. (ES512) 認可コード フローでトークンを取り、ヘッダと署名を見る
1. (ES512) 自分の検証経路も、この access_token を受ける
1. (kid) 曲線ごとに kid が違う（鍵が別だから）
1. (crv) ES384 のトークンの alg を ES512 に書き換えると受けない（#129 の段階 3）

**検証（合否を判定する）**

- access_token の alg が ES384
- id_token の alg も ES384（access_token に揃う）
- JWK Set の P-384 の公開鍵で検証できる
- /userinfo が応答する（受ける集合に ES384 が入っている）
- access_token の alg が ES512
- id_token の alg も ES512（access_token に揃う）
- JWK Set の P-521 の公開鍵で検証できる
- /userinfo が応答する（受ける集合に ES512 が入っている）
- ES384 と ES512 で kid が違う
- 曲線が食い違うトークンを受けない

**補足**

- **`RS256` / `RS384` / `RS512` は kid が同じ**（1 本の鍵で、ダイジェストだけが違う。`RT-129.3` で見ている）。**EC は曲線ごとに鍵が違う**ので、**kid も違う。**＝ **`jwkcerts` に載る鍵は 4 本**（RSA 1 本 ＋ EC 3 本。`RT-129.6`）。
- **`kty` だけで判定していると、ここが通ってしまう**（どちらも `kty=EC`）。**`crv` まで突き合わせる**ようにした（`JwsFactory.IsSameKeyType`）。**実害が出る前に入れた**（ES384 / ES512 を発行し始めるのと同じ段階）。

## RT-129.6 Discovery が広告する alg すべてについて、jwkcerts に検証できる鍵が在る

| | |
|---|---|
| 観点 | **広告・発行・公開鍵の 3 つが揃っていること**を見る（D-9）。**鍵と alg の対応は `SigningKeys` の表 1 か所**にあり、**`jwkcerts`（`JwkSet.json`）は `CreateJwkSetJson` がその表を回して作る。****表に足したのに JWK Set を作り直していない**という食い違いは、ここで落ちる。 |
| 根拠 | OIDC Discovery 1.0 §3 / RFC 7517 / D-9 |
| テスト | `RT12906_広告するalgすべてに鍵が在る` |

**手順**

1. Discovery と jwkcerts を読み、突き合わせる

**検証（合否を判定する）**

- alg=RS256 を検証できる公開鍵が jwkcerts に在る
- alg=RS384 を検証できる公開鍵が jwkcerts に在る
- alg=RS512 を検証できる公開鍵が jwkcerts に在る
- alg=PS256 を検証できる公開鍵が jwkcerts に在る
- alg=PS384 を検証できる公開鍵が jwkcerts に在る
- alg=PS512 を検証できる公開鍵が jwkcerts に在る
- alg=ES256 を検証できる公開鍵が jwkcerts に在る
- alg=ES384 を検証できる公開鍵が jwkcerts に在る
- alg=ES512 を検証できる公開鍵が jwkcerts に在る

**補足**

- **鍵の本数は alg の数と一致しない。****`RS256` / `RS384` / `RS512` は 1 本の鍵を共有する**ので、**6 つの alg に対して鍵は 4 本**（RSA 1 本 ＋ EC 3 本）である。
- **鍵を入れ替えるとき（D-9）も、この関係は変わらない。****新しい鍵を `jwkcerts` に先に載せ、RP のキャッシュが切れてから署名に使う**（手順は `CONFIGURATION.md`）。**`JwkSet.json` は追記式**なので、**退役した鍵も、消すまで載り続ける。**

## RT-129.7 PS256 / PS384 / PS512 で署名され、jwkcerts の同じ RSA 鍵で検証できる

| | |
|---|---|
| 観点 | **FAPI 1.0 Advanced / FAPI-CIBA は `PS256` または `ES256` を求める。****`PS*` は RSASSA-PSS** で、**鍵は `RS*` と同じ 1 本**（違いはパディング）。**`kid` も `RS256` と同じ**（RFC 7638 は kty / n / e から作る）ので、**`jwkcerts` に鍵を足す必要が無い。****自分の検証経路（C-8 で固定した受ける集合）も、これを受けること**まで見る。 |
| 根拠 | FAPI 1.0 Advanced §8.6 / JWA（RFC 7518）§3.5 / RFC 7638 / #129 の段階 4 |
| テスト | `RT12907_PSSで署名され同じ鍵で検証できる` |

**手順**

1. (PS256) 認可コード フローでトークンを取り、ヘッダと署名を見る
1. (PS384) 認可コード フローでトークンを取り、ヘッダと署名を見る
1. (PS512) 認可コード フローでトークンを取り、ヘッダと署名を見る

**検証（合否を判定する）**

- access_token の alg が PS256
- id_token の alg も PS256（access_token に揃う）
- **kid は RS256 と同じ**（鍵が 1 本だから）
- JWK Set の RSA 公開鍵で検証できる（RSASSA-PSS として）
- /userinfo が応答する（受ける集合に PS256 が入っている）
- access_token の alg が PS384
- id_token の alg も PS384（access_token に揃う）
- **kid は RS256 と同じ**（鍵が 1 本だから）
- JWK Set の RSA 公開鍵で検証できる（RSASSA-PSS として）
- /userinfo が応答する（受ける集合に PS384 が入っている）
- access_token の alg が PS512
- id_token の alg も PS512（access_token に揃う）
- **kid は RS256 と同じ**（鍵が 1 本だから）
- JWK Set の RSA 公開鍵で検証できる（RSASSA-PSS として）
- /userinfo が応答する（受ける集合に PS512 が入っている）

**補足**

- **`jwkcerts` の鍵は 4 本のまま**である（RSA 1 本 ＋ EC 3 本）。**`PS*` は `RS*` と同じ鍵を使う**ので、**9 つの alg に対して鍵は 4 本**になる。**JWK の `alg` は `RS256` のまま**だが、**それでよい**（RFC 7517 の `alg` は「用途」で任意。照合は `kty` で行う）。
- **パディングが違えば、鍵が合っていても通らない。**`RS256` で署名したトークンの alg を `PS256` に書き換えても受けないことは、**`RT-129.2` の (4)** で見ている。

## RT-137.1 WebAuthn の登録画面が、CredentialCreateOptions を組み立てて返す

| | |
|---|---|
| 観点 | **`RequestNewCredential` は 4.x で引数オブジェクトになった**（`RequestNewCredentialParams`）。**戻り値の直列化も Newtonsoft から System.Text.Json に変わっている。****組み立てた JSON が、W3C の `PublicKeyCredentialCreationOptions` の形で出ているか**を見る。**net48 版はこの口を持たない**（現行版のライブラリが netstandard2.0 を支えていない）。 |
| 根拠 | W3C WebAuthn Level 2 §5.4 / fido2-net-lib 4.2.0 / #137 |
| テスト | `RT13701_登録の要求が組み立てられる` |

**手順**

1. 登録画面を開いて、options を受け取る
1. options の中身が、W3C の形になっている

**検証（合否を判定する）**

- 登録画面が開く
- options が隠しフィールドに入る
- status が ok
- challenge がある
- rp.id がある（RPID）
- user.id がある
- pubKeyCredParams に鍵アルゴリズムが並ぶ
- 認証器の指定が渡る（cross-platform）

**補足**

- **`status` / `errorMessage` は、こちらで付けている封筒である**（#137）。**4.x の options は `Status` も `ErrorMessage` も持たない**（成功は「例外が出ないこと」で表す形になった）。**画面は form post で値を往復させる**ので、**HTTP のステータス コードでエラーを伝える余地が無い。**

## RT-137.2 サインイン画面が、AssertionOptions を組み立てて返す

| | |
|---|---|
| 観点 | **`GetAssertionOptions` も 4.x で引数オブジェクトになった**（`GetAssertionOptionsParams`）。**1.x では `UserVerificationRequirement.Discouraged` 固定で、画面の指定を捨てていた**ので、**渡るようにした。****net48 版は、サインイン画面に WebAuthn のボタンを出さない。** |
| 根拠 | W3C WebAuthn Level 2 §5.5 / fido2-net-lib 4.2.0 / #137 |
| テスト | `RT13702_認証の要求が組み立てられる` |

**手順**

1. サインイン画面に WebAuthn のボタンが在るかを見る
1. 利用者名を送って、options を受け取る

**検証（合否を判定する）**

- net10.0 版にはボタンが在る
- 応答が返る
- 段階が 1 へ進む
- options が隠しフィールドに入る
- status が ok
- challenge がある
- rpId がある
- userVerification に画面の指定が渡る

**補足**

- **`allowCredentials` は空である**（この利用者は認証器を登録していない）。**登録には実際の認証器が要る**ので、**この基盤では踏めない。**

## RT-137.3 壊れた attestation を送っても、例外が画面に漏れない

| | |
|---|---|
| 観点 | **4.x は失敗を `Fido2VerificationException` で返す**（`Status` を持たない形になった）。**封筒の `status` が `error` になり、HTTP 500 にならないこと**を見る。**JSON の直列化が System.Text.Json に変わった**ので、**形の違う JSON は `JsonException` で落ちる。** それも封筒に入る必要がある。 |
| 根拠 | fido2-net-lib 4.2.0 / #137 |
| テスト | `RT13703_壊れた入力はエラーとして返る` |

**手順**

1. 段階 0 を通して、段階 1 のトークンを得る
1. 段階 1 に、attestation ではない JSON を送る

**検証（合否を判定する）**

- 段階 0 が通る
- 画面が返る（500 ではない）
- 結果が隠しフィールドに入る
- status が error
- 理由が入る

**補足**

- **画面を白くしない**のが要点である。**net48 版は `customErrors` が例外を 302 に変える**ため、**「未認証のリダイレクト」と見分けがつかなくなる**（#272 で踏んだ）。**net10.0 版は 500 になる**ので、**封筒に入れて 200 で返す。**

## RT-137.4 challenge は要求ごとに作り直される（使い回さない）

| | |
|---|---|
| 観点 | **challenge は再生攻撃を防ぐためのもの**なので、**要求ごとに新しい値でなければならない**（W3C WebAuthn §13.4.3）。**`Fido2Configuration.ChallengeSize` の既定は 16 バイト**で、**`RequestNewCredential` が毎回作る。****セッションに置いた値を使い回していないこと**を、2 回取って確かめる。 |
| 根拠 | W3C WebAuthn Level 2 §13.4.3 / #137 |
| テスト | `RT13704_challengeは要求ごとに変わる` |

**手順**

1. options を 2 回取る
1. challenge が違うことを確かめる

**検証（合否を判定する）**

- 2 回とも返る
- challenge が違う
- 16 バイト分の長さがある（base64url で 22 文字）

**補足**

- **値そのものは出さない。** 長さだけを記録する。

## RT-140.2 subject_types=pairwise のクライアントでも、/userinfo が sub 以外のクレームを返す

| | |
|---|---|
| 観点 | **PPID は「OP 以外が戻せない」ことが要件**で、**一方向であることは求められていない。**以前は salted hash だったため **OP 自身も戻せず**、`GetUserFromSub` が null を返していた。**その結果 `/userinfo` は `sub` しか返さず、pairwise は機能していなかった**（#140 の段階 2）。 |
| 根拠 | OIDC Core §8（Subject Identifier Types）/ §5.3（UserInfo Endpoint）/ #140 の段階 2 |
| テスト | `RT14002_pairwiseでもuserinfoがクレームを返す` |

**手順**

1. 認可コードを取ってトークンに交換する
1. sub が PPID になっている（利用者名でも UserId でもない）
1. /userinfo を叩く

**検証（合否を判定する）**

- access_token が返る
- sub が返る
- sub が利用者名そのものではない
- HTTP 200
- sub は access_token と同じ
- **sub 以外のクレームが返る**（email）

**補足**

- **ここが段階 2 の要**。**以前はこの検証が通らなかった**（`GetUserFromSub` が null を返し、`user != null` の中だけでクレームを詰めているため、`sub` だけが返っていた）。

## RT-140.3 pairwise の sub は、同じ利用者でもクライアントごとに違い、毎回同じ値になる

| | |
|---|---|
| 観点 | **pairwise の目的は、RP 同士が sub を突き合わせても同じ人だと分からないこと。**同時に、**RP は sub を利用者の主キーとして保存する**ので、**同じ利用者・同じクライアントなら毎回同じ値**でなければならない（毎回変わると、RP から見て別人になる）。**暗号化に変えたので、この 2 つが両立しているかを測る**（#140 の段階 2）。 |
| 根拠 | OIDC Core §8.1（Pairwise Identifier Algorithm）/ #140 の段階 2 |
| テスト | `RT14003_PPIDはクライアントごとに違う` |

**手順**

1. pairwise のクライアントで 2 回、トークンを取る
1. 別のクライアントで取る

**検証（合否を判定する）**

- 2 回とも同じ sub（毎回変わらない）
- 別のクライアントでは違う sub

**補足**

- **(2) の相手は subject_types の既定（public）**なので、**利用者 ID がそのまま sub になる。****ここで見たいのは「突き合わせられないこと」**で、pairwise 同士の比較は、クライアントをもう 1 つ差し込まないと測れない。**既定が public であること自体は RT-151.2 が測る。**

## RT-140.4 上流の IdP へ委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **下流は自分で認証せず、上流の認証結果を受け取る。**認可コード ＋ PKCE(S256) で `code` を受け、`/token`・`/userinfo` で利用者を特定し、**下流のアカウントに結び付けてサインインさせる。****この経路は #140 の段階 3 で直したが、長く E2E で駆動できていなかった**（#250）。 |
| 根拠 | OIDC Core §3.1 / #140 / #250 の段階 5 |
| テスト | `RT14004_ID連携でサインインできる` |

**手順**

1. 上流でサインインしておく（この経路の確認を 1 本に絞るため）
1. 下流で「ID連携でサインイン」を押す
1. 上流が認可応答（form_post）を返す
1. 下流の Redirect エンドポイントへ渡す

**検証（合否を判定する）**

- 上流にサインインできる
- 上流の認可エンドポイントへ送られる
- PKCE(S256) を付けて要求する
- prompt は付けない（上流が画面を出してよい）
- code が返る
- 下流にサインインできている

## RT-140.5 二度目の ID 連携でも、同じ下流アカウントになる

| | |
|---|---|
| 観点 | **連携キーは `(iss, sub)` である**（#140 の段階 3。以前は独自の `userid`）。**同じ上流の同じ利用者なら、何度連携しても同じアカウント**に結び付く。毎回新しいアカウントが作られるなら、連携キーが効いていない。 |
| 根拠 | OIDC Core §2（sub は Issuer 内で一意）/ #140 の段階 3 |
| テスト | `RT14005_二度目の連携でも同じ利用者になる` |

**手順**

1. ID 連携を 2 回行い、下流の /userinfo が返す sub を比べる

**検証（合否を判定する）**

- 1 回目の sub が取れる
- 2 回目の sub が、1 回目と一致する

## RT-140.6 上流にセッションが無ければ、ID 連携は成立しない

| | |
|---|---|
| 観点 | **下流は、上流の認証結果を受け取るだけ**である。**上流が認証していないのにサインインさせてしまっては、委譲の意味が無い。****`prompt=none` を外したので、上流はサインイン画面を出す**（#287）。**そこで認証されるまで `code` は返らない**ので、**下流はサインインしない。****外す前は `login_required` で終わっていた**（#254）が、**どちらでも下流はサインインしない**という点は変わらない。 |
| 根拠 | OIDC Core §3.1.2.1 / §3.1.2.6 / #140 / #254 / #287 |
| テスト | `RT14006_上流が未サインインなら連携は成立しない` |

**手順**

1. 上流にサインインせずに、下流で「ID連携でサインイン」を押す

**検証（合否を判定する）**

- 上流の認可エンドポイントへは送られる
- 認可コードは返らない
- 下流はサインインしない

## RT-140.7 ID 連携の認可応答（form_post）にも、iss が付く

| | |
|---|---|
| 観点 | **下流は認可応答の `iss` を照合する**（#140 の段階 3。Mix-Up 対策）。**上流が返さなければ、その照合は一度も働かない。****form_post だけ `iss` が抜けていた**（#252）ので、実経路で確かめる。 |
| 根拠 | RFC 9207 §2 / #252 / #140 の段階 3 |
| テスト | `RT14007_連携の認可応答にもissが付く` |

**手順**

1. 上流の Discovery から issuer を読む
1. ID 連携を行い、認可応答の hidden を見る

**検証（合否を判定する）**

- iss が上流の issuer と一致する

**補足**

- 上流の issuer = https://ssoauth.opentouryo.com

## RT-151.1 subject_types を書かないクライアントの sub は、利用者名ではなく利用者 ID

| | |
|---|---|
| 観点 | **既定は public で、`sub` は利用者 ID である**（#151 の段階 4）。**以前は `sub` に利用者名がそのまま入っていた**（当時は利用者名＝メアド）ので、**メアドが全ての RP に渡っていた。****`sub` は RP の中で利用者を指す識別子**であって、表示用の属性ではない。 |
| 根拠 | OIDC Core §8（Subject Identifier Types）/ §5.1（preferred_username）/ #151 の段階 4 |
| テスト | `RT15101_既定のsubは利用者名ではなく利用者ID` |

**手順**

1. 認可コードを取ってトークンに交換する
1. sub を見る
1. /userinfo が、その sub から利用者を引けている
1. もう一度取っても、同じ sub になる

**検証（合否を判定する）**

- sub が返る
- sub が利用者名ではない
- sub がメアドでもない
- sub が利用者 ID の形（GUID）である（＝ public）
- HTTP 200
- sub は access_token と同じ
- **sub 以外のクレームが返る**（email）
- 2 回とも同じ sub

**補足**

- **RP は `sub` を利用者の主キーとして保存する**ので、**同じ利用者・同じクライアントなら毎回同じ値**でなければならない。**発行した値は対応表に記録される**ので（#151 の段階 2）、**この後で既定を変えても、この値は動かない。**

## RT-151.2 public の sub は、同じ利用者なら RP が違っても同じ（pairwise との対照）

| | |
|---|---|
| 観点 | **public と pairwise の違いは、ここに出る。**public は **RP をまたいで同じ値**なので、**RP 同士が突き合わせられる。**突き合わせを嫌うなら pairwise を選ぶ（#140 の段階 2）。**既定を public にしたので、何も書かなければ「同じ値」になる**（#151 の段階 4）。 |
| 根拠 | OIDC Core §8（public / pairwise）/ #151 の段階 4 |
| テスト | `RT15102_publicのsubはクライアントが違っても同じ` |

**手順**

1. 既定のクライアント 2 つで、それぞれ sub を取る
1. pairwise のクライアントで取る（対照）

**検証（合否を判定する）**

- クライアントが違っても同じ sub
- pairwise だけは違う sub

**補足**

- **public は「隠さない」選択である。**`sub` は利用者 ID なので、**RP 同士が突き合わせれば同じ人だと分かる。****それが困る RP には pairwise を登録する。**

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
- sub が id_token の sub と一致する
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
| 観点 | `client_mode=fapi2` のクライアントは、より強いクライアント認証（mTLS / private_key_jwt）を要求する。**この性質のため、FAPI2 の経路では redirect_uri の照合まで到達しない。**照合そのものは RT-197.4 で、normal モードのクライアントを使って測る。 |
| 根拠 | FAPI 2.0 Security Profile（クライアント認証は mTLS または private_key_jwt）/ RFC 6749 §5.2 |
| テスト | `RT197_02_FAPI2クライアントはclient_secretのトークン要求を拒否する` |

**手順**

1. FAPI2 の自己テストで request_uri 経路の code を得る
1. client_secret を添えてトークンに交換する

**検証（合否を判定する）**

- request_uri 経路で認可コードが発行される
- トークンを発行しない
- invalid_client で拒否される

**補足**

- **#307 の段階 3 より前は `unauthorized_client` だった** — **`client_secret` で認証が通った後、登録種別の判定で断っていた。****いま断るのはクライアント認証**（**登録された方法が `private_key_jwt`**）なので、**`RT-197.2` の観点（FAPI2 では秘密だけでトークンが出ない）は、より早い段で守られている。**

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
- auth は発行されない（登録に明記していない）

**補足**

- Discovery の scopes_supported = [profile, email, phone, address, auth, roles, openid, client_registration]

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

- Discovery の scopes_supported = [profile, email, phone, address, auth, roles, openid, client_registration]

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

- Discovery の scopes_supported = [profile, email, phone, address, auth, roles, openid, client_registration]

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
| 観点 | **サーバ全体の RequirePkce（#220）は、全クライアントが揃わないと有効にできない。**移行の途中でも、**締められるクライアントから順に締められる**必要がある。client_mode=fapi1 でも PKCE は必須になるが、**そちらは ROPC / client_credentials / refresh_token も巻き添えで塞ぐ**（#222）。 |
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

- **認可エンドポイントで弾いている。** client_mode=fapi1 の経路は認可コードを発行してから /token で拒否するので、**利用者が同意まで進んだ後に失敗する**（#222）。

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

## RT-231.5 response_mode=form_post の応答にも、iss が hidden で付く

| | |
|---|---|
| 観点 | **返し方を変えても、Mix-Up への守りは同じだけ要る。**`iss` を付けているのは URL を組む経路だけで、**自動送信フォームで返すときは抜けていた**（Discovery は対応を広告しているのに）。 |
| 根拠 | RFC 9207 §2 / OAuth 2.0 Form Post Response Mode §2 / #252 |
| テスト | `RT231_05_form_postの認可応答にもissが付く` |

**手順**

1. Discovery の issuer を読む
1. response_mode=form_post で認可を要求する

**検証（合否を判定する）**

- リダイレクトしない（自動送信フォームを返す）
- code を hidden で送る
- iss を hidden で送る（Discovery の issuer と一致）

**補足**

- issuer = https://ssoauth.opentouryo.com

## RT-231.6 JARM（response_mode=form_post.jwt）では、平文の iss を付けない

| | |
|---|---|
| 観点 | **JARM は応答を署名付き JWT に包む。** その JWT に `iss` が入っており、**署名で守られている分だけ強い。** 平文の `iss` を重ねて付ける必要はない。**query.jwt（RT-231.3）と同じ規則が、form_post.jwt にも掛かること**を確かめる。 |
| 根拠 | JARM / RFC 9207 §2 / #252 |
| テスト | `RT231_06_form_post_jwtでは平文のissを付けない` |

**手順**

1. Discovery の issuer を読む
1. response_mode=form_post.jwt で認可を要求する

**検証（合否を判定する）**

- response（JWT）を hidden で送る
- 平文の iss は付かない
- JWT の中の iss が Discovery の issuer と一致する

## RT-232.1 Discovery が end_session_endpoint を広告する

| | |
|---|---|
| 観点 | **RP は Discovery だけを見てログアウトの口を知る。**実装していても広告しなければ、RP からは使えない（実装も広告も無い状態だった。D-1）。 |
| 根拠 | OpenID Connect RP-Initiated Logout 1.0 §2.1（REQUIRED） |
| テスト | `RT23201_end_session_endpointをDiscoveryが広告する` |

**手順**

1. end_session_endpoint を読む

**検証（合否を判定する）**

- end_session_endpoint が有る
- https である
- Front-Channel Logout も広告されている（#310 の段階 3）

**観測（判定しない）**

- 広告された URL
  - 設定キー OAuth2EndSessionEndpoint（既定 /end_session）で決まる。
- Session Management
  - **見送っている**（third-party cookie を読む仕組み。#310）。

## RT-232.2 id_token_hint 付きの GET で、サインアウトして post_logout_redirect_uri へ戻る

| | |
|---|---|
| 観点 | **RP 主導のログアウトの本筋。**id_token_hint で要求元が確かめられるので、**確認画面を挟まずに**ログアウトし、登録された戻り先へ state を添えて返す。 |
| 根拠 | RP-Initiated Logout 1.0 §2 / §3 |
| テスト | `RT23202_id_token_hintつきのGETでログアウトしRPへ戻る` |

**手順**

1. ログアウト要求を送る
1. サインアウトされたことを確かめる

**検証（合否を判定する）**

- 前提: サインインしている
- HTTP 302
- 登録された戻り先へ返す
- state をそのまま返す
- iss は付けない（認可応答ではない）
- セッションが消えている

**補足**

- **id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。

## RT-232.3 POST でもログアウト要求を受ける

| | |
|---|---|
| 観点 | **GET と POST の両方を受けることが MUST。**GET しか受けないと、id_token_hint が長い（URL 長の上限に当たる）ときにRP はログアウトできない。 |
| 根拠 | RP-Initiated Logout 1.0 §2（MUST） |
| テスト | `RT23203_POSTでもログアウトを受ける` |

**手順**

1. ログアウト要求を送る

**検証（合否を判定する）**

- HTTP 302
- 登録された戻り先へ返す
- state をそのまま返す
- セッションが消えている

**補足**

- **id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。

## RT-232.4 登録と完全一致しない post_logout_redirect_uri へは戻さない

| | |
|---|---|
| 観点 | **戻り先は、オープン リダイレクタになりうる。**登録値と完全一致しなければ戻してはならない（§3）。**仕様が exactly match と書いているので、正規化せずそのまま比較している。****`redirect_uri` の照合も、いまは同じ単純文字列比較である**（#263 で揃えた。それまではあちらだけ大文字小文字を無視していた。C-10）。 |
| 根拠 | RP-Initiated Logout 1.0 §3（MUST）／§4 |
| テスト | `RT23204_登録と一致しないpost_logout_redirect_uriへは戻さない` |

**手順**

1. 登録されていない URL を指定する
1. 大文字小文字だけが違う URL を指定する

**検証（合否を判定する）**

- HTTP 200（確認画面。リダイレクトしない）
- その URL へは飛ばさない
- セッションは残っている（勝手にログアウトしない）
- HTTP 200（完全一致でないので戻さない）

**補足**

- **id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。
- **完全一致にしている。** 大文字小文字を無視すると、登録と違う URL へ戻すことになる（§3 は exactly match）。

## RT-232.5 id_token_hint が無ければ、利用者に確認してからログアウトする

| | |
|---|---|
| 観点 | **確認なしに応じると、誰でも他人をログアウトさせられる**（§6 : DoS の手段）。id_token_hint が無い要求は、要求元が確かめられないので**確認しなければならない**（§2 の MUST）。 |
| 根拠 | RP-Initiated Logout 1.0 §2（MUST）／§6 |
| テスト | `RT23205_id_token_hintが無ければ確認してからログアウトする` |

**手順**

1. id_token_hint を付けずに要求する
1. 確認画面で「はい」を押す

**検証（合否を判定する）**

- HTTP 200（確認画面）
- まだサインアウトしていない
- HTTP 302（自サイトへ戻る）
- サインアウトされた

## RT-232.6 client_id が id_token_hint の aud と一致しなければ、要求として扱わない

| | |
|---|---|
| 観点 | **両方来ているなら、一致を確かめることが MUST**（§2）。一致を見ないと、**他のクライアントに発行された id_token で**自分の戻り先へ戻させることができてしまう。 |
| 根拠 | RP-Initiated Logout 1.0 §2（MUST） |
| テスト | `RT23206_client_idがid_tokenのaudと違えば断る` |

**手順**

1. 食い違う client_id を添えて要求する
1. 壊れた id_token_hint も同じ扱いになることを確かめる

**検証（合否を判定する）**

- HTTP 200（確認画面。リダイレクトしない）
- セッションは残っている
- HTTP 200（500 にしない）

**補足**

- **id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。
- **JWT でない値でも 500 にしない**（#241 と同じ扱い）。id_token_hint は署名検証の前に payload を読む必要がある。

## RT-232.7 サインインしていなくても、ログアウト要求はエラーにしない

| | |
|---|---|
| 観点 | **ログアウト要求は冪等である**（§4）。「その RP でログインしていない」ことは**エラーではない**と明記されている。RP は、OP 側の状態を知らずにログアウトを要求できる。 |
| 根拠 | RP-Initiated Logout 1.0 §4 |
| テスト | `RT23207_サインインしていなくてもエラーにしない` |

**手順**

1. 先に自サイトからサインアウトする
1. その状態でログアウト要求を送る

**検証（合否を判定する）**

- サインアウトできた
- HTTP 302（エラーにしない）
- 登録された戻り先へ返す
- state をそのまま返す

**補足**

- **id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。
- **確認画面は出さない。** 消すセッションが無いので、確認を求める意味が無い（§4 : エラーでもない）。

## RT-232.8 アプリ同梱の自己テスト（Starters）のボタンから、ログアウトを試せる

| | |
|---|---|
| 観点 | **手で試せる口を、他のフローと同じ場所に置く。**この画面は id_token を持たないので、**確認画面の経路**（§2 の MUST）を通る。`id_token_hint` 付きの経路は `RT-232.9` で見る。 |
| 根拠 | RP-Initiated Logout 1.0 §2 ／ #232 |
| テスト | `RT23208_自己テストのボタンから確認画面まで進める` |

**手順**

1. ボタンを押す
1. 飛び先（/end_session）を開く
1. 確認画面で「はい」を押す

**検証（合否を判定する）**

- HTTP 302
- Discovery が広告する end_session_endpoint へ飛ばす
- HTTP 200（確認画面）
- まだサインアウトしていない
- HTTP 302
- サインアウトされた

## RT-232.9 認可コード フローの結果画面から、id_token_hint 付きでログアウトできる

| | |
|---|---|
| 観点 | **取得した id_token をそのまま `id_token_hint` に使える**ことを、画面の側から確かめる。`RT-232.2` は要求の組み立てをテストが行うが、ここは**画面が出しているフォーム**をそのまま送る（自己テストの口が壊れていないこと）。 |
| 根拠 | RP-Initiated Logout 1.0 §2 / §3 ／ #232 |
| テスト | `RT23209_認可コードの結果画面からid_token_hintつきでログアウトできる` |

**手順**

1. 自己テストで認可コード フローを通し、結果画面まで進む
1. 画面が出しているログアウトのフォームを確かめる
1. そのフォームを送る

**検証（合否を判定する）**

- 結果画面が開く（HTTP 200）
- フォームの宛先が end_session_endpoint である
- id_token_hint に id_token が入っている
- 戻り先が test_self_logout の解決先と一致する
- state を返す
- サインアウトされた

**観測（判定しない）**

- 戻り先
  - **登録（post_logout_redirect_uri）が有る**ので、確認なしで RP へ戻った。

## RT-232.10 openid が無いフローの結果画面は、戻り先を送らず、理由を表示する

| | |
|---|---|
| 観点 | **`scope` に `openid` が無ければ `id_token` は発行されない**（自己テストの `Test Authorization Code Flow` は `openid` を付けない）。`id_token_hint` を送れないので、**戻り先を送っても仕様上戻せない**（§3）。画面が戻り先を送ってしまうと、押すたびに`post_logout_redirect_uri requires id_token_hint.` になる。**送らずに、理由を画面に出す。** |
| 根拠 | RP-Initiated Logout 1.0 §2 / §3 ／ #232 |
| テスト | `RT23210_openidが無いフローでは戻り先を送らず理由を出す` |

**手順**

1. 自己テストを通し、結果画面まで進む
1. 画面が出しているものを確かめる
1. それでもログアウトはできる（確認画面の経路）

**検証（合否を判定する）**

- 結果画面が開く（HTTP 200）
- id_token_hint に id_token が載らない
- 戻り先（post_logout_redirect_uri）を送らない
- 理由を画面に出す
- HTTP 200（確認画面）
- 確認すればログアウトする（HTTP 302）
- サインアウトされた

**補足**

- **Razor の分岐は実行時にコンパイルされる**ので、この経路（id_token が無い側）も叩いておく。ビルドでは確かめられない。

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

## RT-237.1 form-urlencode した Basic で、記号を含む client_secret のクライアントが認証できる

| | |
|---|---|
| 観点 | **RFC 6749 §2.3.1 に従うクライアントが認証できない**という不整合だった。秘密が base64（`+` `/` `=` を含む）で生成されることは普通にあるため、**仕様どおりに送る相手ほど繋がらない**という状態になっていた（#237）。 |
| 根拠 | RFC 6749 §2.3.1 / Appendix B |
| テスト | `RT23701_符号化したBasicで記号を含む秘密のクライアントが認証できる` |

**手順**

1. POST /token に、符号化した Basic（Authorization ヘッダ）で client_credentials を送る

**検証（合否を判定する）**

- HTTP 200
- エラーにならない
- access_token が返る

**補足**

- 秘密は `+` `/` `=` を含む。符号化すると `%2B` `%2F` `%3D` になるので、**復号しないと一致しない**。

## RT-237.2 符号化しない Basic でも、記号を含む client_secret のクライアントが認証できる

| | |
|---|---|
| 観点 | **符号化しないクライアントは配備済みである**（Open棟梁 の従来のクライアントを含む）。復号だけを入れると、そちらが繋がらなくなる。**復号後で認証できなければ復号前の値でも照合する**ことで、どちらも受ける（#237）。 |
| 根拠 | RFC 6749 §2.3.1 |
| テスト | `RT23702_符号化しないBasicでも認証できる` |

**手順**

1. POST /token に、符号化しない Basic で client_credentials を送る

**検証（合否を判定する）**

- HTTP 200
- エラーにならない
- access_token が返る

**補足**

- この秘密は `+` を含むので、**復号すると空白に変わる**（`WebUtility.UrlDecode`）。つまり復号後の値では一致せず、**復号前で照合して初めて通る**。ここが通ることが、互換が保たれている証拠になる。

## RT-237.3 client_secret に `:` を含む場合、符号化したときだけ認証できる

| | |
|---|---|
| 観点 | **`:` は Basic の区切り文字そのもの**なので、符号化しないと `id:secret` の分割位置が決まらない。**符号化が仕様で要求されている理由**がここに出る。復号を入れたことで、こういう秘密も扱えるようになった（#237）。 |
| 根拠 | RFC 6749 §2.3.1 / RFC 7617 §2 |
| テスト | `RT23703_コロンを含む秘密は符号化したときだけ通る` |

**手順**

1. 符号化した Basic（`:` は `%3A` になる）
1. 符号化しない Basic（`:` がそのまま載る）

**検証（合否を判定する）**

- HTTP 200
- access_token が返る
- トークンは返らない

**観測（判定しない）**

- 符号化しない場合の応答
  - ヘッダが 3 つに割れ、資格情報として読めない。**500 ではなく、認証の失敗として返る**ことを見ている。

**補足**

- **これは仕様上やむを得ない**（符号化しないクライアントは、`:` を含む秘密を送る手段を持たない）。秘密を発行する側が `:` を含めない、という運用もありうる。

## RT-238.1 RFC 7523 §2.2 の client_assertion で、private_key_jwt のクライアント認証が通る

| | |
|---|---|
| 観点 | **仕様の名前は `client_assertion`**（＋ `client_assertion_type`）。この実装は `assertion` だけを読んでいたため、**仕様に従うクライアントは private_key_jwt で認証できなかった**（#238）。Open棟梁 の PAR / CIBA のクライアント（OpenTouryo#592）は `client_assertion` を送る。 |
| 根拠 | RFC 7523 §2.2 / RFC 9126 §2 / #238 |
| テスト | `RT23801_client_assertionでparに預けられる` |

**手順**

1. client_assertion（RS256）を作り、client_assertion_type を添えて POST /par

**検証（合否を判定する）**

- HTTP 201（RFC 9126 §2.2）
- request_uri が返る

**補足**

- **client_secret は送っていない。** 署名したアサーションだけで認証している。

## RT-238.2 従来の名前（assertion）でも、private_key_jwt のクライアント認証が通る

| | |
|---|---|
| 観点 | **Open棟梁 の既存のクライアントは `assertion` を送る**（`GetAccessTokenByCodeAsync` の private_key_jwt）。名前を仕様に合わせるだけだと、**既存のクライアントが繋がらなくなる。**`client_assertion` を優先し、**無ければ `assertion` も読む。** |
| 根拠 | RFC 7523 §2.2 / #238 |
| テスト | `RT23802_従来のassertionでも通る` |

**手順**

1. assertion（従来の名前）で POST /par

**検証（合否を判定する）**

- HTTP 201
- request_uri が返る

## RT-238.3 client_assertion_type が仕様の値でなければ、クライアント認証を通さない

| | |
|---|---|
| 観点 | **RFC 7523 §2.2 は型を URN で定めている**（`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`）。型が違うものを受け付けると、**別の種類のアサーションを取り違える**。**省略されていれば受ける**（この実装は従来、型を見ていなかったため）。 |
| 根拠 | RFC 7523 §2.2 / #238 |
| テスト | `RT23803_client_assertion_typeが違えば断る` |

**手順**

1. client_assertion_type に別の URN を入れて POST /par

**検証（合否を判定する）**

- HTTP 401
- エラーは invalid_client
- request_uri は返らない

**補足**

- **型が違うときは「アサーション無し」として扱う**ので、クライアント認証の失敗（invalid_client）になる。

## RT-238.4 トークン エンドポイントでも、client_assertion で認証してトークンを得られる

| | |
|---|---|
| 観点 | **FAPI 2.0 は、クライアント認証を private_key_jwt か mTLS に限っている。**fapi2 の登録は client_secret を通さない（`FA-2.1`）ので、**この経路が通らないと、fapi2 のクライアントはトークンを得られない。** |
| 根拠 | RFC 7523 §2.2 / FAPI 2.0 / #238 |
| テスト | `RT23804_tokenでもclient_assertionが通る` |

**手順**

1. FAPI2 の自己テストで、request_uri 経路の code を得る
1. client_assertion を添えて、code をトークンに交換する

**検証（合否を判定する）**

- HTTP 200
- access_token が返る

**観測（判定しない）**

- 応答
  - 切り分け用（値は伏せられる）。

**補足**

- **client_secret は送っていない**（fapi2 の登録は受け付けない）。`client_id` も送っていない（アサーションの `iss` から引く）。

## RT-239.1 refresh_token の更新を、private_key_jwt のクライアント認証で行える

| | |
|---|---|
| 観点 | **RFC 6749 §6 は、コンフィデンシャル クライアントの認証を求めている**が、方式は限定していない。**FAPI 2.0 は MTLS と private_key_jwt に限る**ので、ここが通らないと、**アクセス トークンが切れるたびに認可からやり直す**ことになる。`GrantRefreshTokenCredentials` は**引数にアサーションを持っていなかった**（#239）。 |
| 根拠 | RFC 6749 §6 / RFC 7523 §2.2 / FAPI 2.0 / #239 |
| テスト | `RT23901_refresh_tokenをprivate_key_jwtで更新できる` |

**手順**

1. 認可コード フローで refresh_token を得る（交換も client_assertion）
1. client_secret を送らず、client_assertion で更新する

**検証（合否を判定する）**

- HTTP 200
- access_token が返る

**補足**

- **client_id も送っていない。** アサーションの `iss` から引く（RFC 7523 §3）。refresh_token と発行先の結び付け（#188）も、その client_id で確かめられる。

## RT-239.2 トークンの失効（/revoke）を、private_key_jwt のクライアント認証で行える

| | |
|---|---|
| 観点 | **RFC 7009 §2.1 は「RFC 6749 §2.3 の資格情報を含める」としている**（＝トークン エンドポイントと同じ方式）。以前は `client_assertion` を読んでおらず、**秘密を持たないクライアントは失効できなかった。**失効できないと、**漏れたトークンを止める手段が無い。** |
| 根拠 | RFC 7009 §2.1 / RFC 7523 §2.2 / #239 |
| テスト | `RT23902_revokeをprivate_key_jwtで呼べる` |

**手順**

1. トークンを得る（交換も client_assertion）
1. client_assertion で POST /revoke
1. 失効したことを確かめる（/userinfo が 401）

**検証（合否を判定する）**

- HTTP 200（RFC 7009 §2.2）
- 失効後は 401

## RT-239.3 トークンの問い合わせ（/introspect）を、private_key_jwt のクライアント認証で行える

| | |
|---|---|
| 観点 | **RFC 7662 §2.1 は、この口に認証を求めている**（トークン エンドポイントと同じ方式）。以前は `client_assertion` を読んでおらず、**秘密を持たないクライアントは問い合わせできなかった。** |
| 根拠 | RFC 7662 §2.1 / RFC 7523 §2.2 / #239 |
| テスト | `RT23903_introspectをprivate_key_jwtで呼べる` |

**手順**

1. トークンを得る（交換も client_assertion）
1. client_assertion で POST /introspect

**検証（合否を判定する）**

- HTTP 200
- active が true

## RT-239.4 署名が壊れた client_assertion では、/revoke も /introspect も通らない

| | |
|---|---|
| 観点 | **受け口を増やしたら、そこが緩んでいないことも確かめる。**アサーションは署名だけがクライアントの証明なので、**検証せずに通すと、誰でも他人のトークンを失効できる。** |
| 根拠 | RFC 7009 §2.1 / RFC 7662 §2.1 / #239 |
| テスト | `RT23904_誤ったアサーションは断る` |

**手順**

1. 署名を壊した client_assertion を作る
1. POST /revoke
1. POST /introspect

**検証（合否を判定する）**

- /revoke : HTTP 401
- /revoke : エラーは invalid_client
- /introspect : HTTP 401
- /introspect : エラーは invalid_client

## RT-239.5 fapi2 の登録でも、非対称の証明なら refresh_token を使える

| | |
|---|---|
| 観点 | **FAPI 1.0 Advanced も FAPI 2.0 も refresh token を禁じていない。**以前は ClientModePolicy が認可コード以外を normal に限っていたため、**fapi1 / fapi2 は refresh_token を受け取れなかった**（MayUse が false なので発行もされない）。**client_secret では開かない**（FAPI は秘密ベースの認証を認めない）。 |
| 根拠 | FAPI 2.0 / RFC 6749 §6 / #239 の段階 3 |
| テスト | `RT23905_fapi2もrefresh_tokenを使える` |

**手順**

1. FAPI2 の自己テストで code を得て、client_assertion で交換する
1. client_assertion で refresh_token を更新する

**検証（合否を判定する）**

- fapi2 にも refresh_token が発行される
- HTTP 200
- access_token が返る
- 更新後も fapi クレームは登録どおり fapi2

**補足**

- **client_secret では通らない**（fapi2 は秘密を持たず、表も開いていない）。mTLS でも通る（同じ行に Mtls を置いた）。

## RT-241.1 /ros に JWT でない本文を渡しても、HTTP 400 で返す（500 にしない）

| | |
|---|---|
| 観点 | **処理されない例外は、JSON でない本文（開発モードでは例外の平文）を返す**ので、RP は何が起きたか読めない（#196 / #210 と同じ理由）。公開鍵を引くために**署名検証の前に payload を読む**必要があり、そこが外から来た文字列で壊れていた（#241）。 |
| 根拠 | RFC 6749 §5.2 / #196 / #210 / #241 |
| テスト | `RT24101_rosにJWTでない本文を渡しても500にしない` |

**手順**

1. `.` が無い文字列
1. `.` はあるが Base64URL でない文字列
1. JSON がオブジェクトでない JWT

**検証（合否を判定する）**

- HTTP 400
- HTTP 400
- HTTP 400

## RT-241.2 client_assertion が JWT でなければ、クライアント認証の失敗（401）で返す

| | |
|---|---|
| 観点 | **`client_assertion` は #238 / #239 で受け口が増えた**（`/token` の各グラント・`/par`・`/ciba_authz`・`/revoke`・`/introspect`）。**どの口からでも 500 に落とせる**状態だったので、**アサーション無しとして扱い**、認証失敗にする（`client_assertion_type` が誤りのときと同じ扱い。#238）。 |
| 根拠 | RFC 7523 §2.2 / RFC 6749 §5.2 / #241 |
| テスト | `RT24102_client_assertionにJWTでない値を渡しても500にしない` |

**手順**

1. `.` が無い文字列を client_assertion に入れる
1. トークン エンドポイント（refresh_token グラント）でも同じ

**検証（合否を判定する）**

- /revoke : HTTP 401
- /revoke : エラーは invalid_client
- /introspect : HTTP 401
- /introspect : エラーは invalid_client
- /token : HTTP 401
- /token : エラーは invalid_client

## RT-241.3 iss が無い・未登録のクライアントを指す client_assertion も、401 で返す

| | |
|---|---|
| 観点 | **公開鍵は `iss` で引く**ので、`iss` が無ければ引けない（以前は辞書の参照で例外）。**未登録のクライアントでは登録値が空**で、それを Base64URL として復号しようとして例外になっていた（**空かどうかを確かめる前に復号していた**）。 |
| 根拠 | RFC 7523 §3 / #241 |
| テスト | `RT24103_issが無いか未登録でも500にしない` |

**手順**

1. iss の無い JWT
1. 未登録の client_id を iss にした JWT

**検証（合否を判定する）**

- HTTP 401
- エラーは invalid_client
- HTTP 401
- エラーは invalid_client

**補足**

- **登録の値が壊れている場合も同じ扱い**（運用の誤りだが、要求の側から区別できないので認証失敗にする）。

## RT-243.1 jti が長くても、使い切りの記録ができる（HTTP 500 にならない）

| | |
|---|---|
| 観点 | **`jti` はクライアントが決める値で、長さの上限が無い。**記録先（`RequestObject.Urn`）は **38 文字**なので、`jti` をそのままキーに繋いでいると **DB ストアで書き込みが失敗し、HTTP 500** になっていた（#243。`mem` は辞書なので桁の制限が無く、`RT-234.3` では現れなかった）。**キーを固定長の要約にして**、長さに依らず記録できるようにした。 |
| 根拠 | CIBA Core §7.1.1 / #234 の段階 2 / #243 |
| テスト | `RT24301_長いjtiでも使い切りが効く` |

**手順**

1. 長い jti の認証要求を 1 回送る
1. まったく同じ要求を、もう一度送る

**検証（合否を判定する）**

- 1 回目 : HTTP 400（500 にしない）
- 1 回目 : エラーは unknown_user_id（検証は通っている）
- 2 回目 : HTTP 400
- 2 回目 : エラーは invalid_request（jti は使用済み）

**補足**

- **このテストは `mem` でも通るが、意味があるのは DB ストア**（`-UserStoreType sql` など）。`mem` は桁の制限が無いため、直す前でも通ってしまう。#243 の再発は、ストアを変えた通しで捕まる。

## RT-245.1 `/par` に預けた request_uri は `/ciba_authz` では使えず、CIBA の request は `/par` に預けられない

| | |
|---|---|
| 観点 | **`/ros` と `/par` は、保存先（`RequestObjectProvider`）と `urn:` の名前空間を共有している**（どちらも GUID キーで `urn:…` を返す）。**口をまたいで参照を持ち込めないことを、テストで固定する**（#245 の段階 2）。いまは `/par` が**認可リクエストとして検証する**ので CIBA の要求は預けられないが、**それは検証の副作用で、設計上の分離ではない。** |
| 根拠 | RFC 9126 / CIBA Core §7.1.1 / #245 の段階 2 |
| テスト | `RT24501_request_uriは預けた口でしか使えない` |

**手順**

1. /par に認可要求を預けて request_uri を得る
1. その request_uri を /ciba_authz に渡す
1. 逆向き : CIBA の request（ES256）を /par に預ける

**検証（合否を判定する）**

- request_uri が返る
- auth_req_id を返さない（利用者へ通知しない）
- request_uri を返さない

**観測（判定しない）**

- /ciba_authz の応答
  - **認可リクエストの参照は、CIBA の認証要求として成立しない。**エラー コードは実装の都合で決まるため、観察として残す。
- /par の応答
  - **CIBA の認証要求は、認可リクエストの検証を通らない**（`response_type` などが無い）。

**補足**

- **保存先が同じでも、口をまたいだ参照は成立しない**ことを、この 2 方向で押さえた（#245 の段階 2）。

## RT-245.2 改竄した認可コードと、他クライアントに発行された認可コードは、トークンに交換できない

| | |
|---|---|
| 観点 | **使用済み（`TC-2.2` / `RT-186.4`）と期限切れ（`RT-188.1`）は測っていたが、改竄と「他人のコード」は測っていなかった**（#245 の段階 2）。コードは**発行先のクライアントに紐づく**（RFC 6749 §4.1.3 : 認証したクライアントに発行されたものであることを確かめる）。 |
| 根拠 | RFC 6749 §4.1.3 / §5.2（invalid_grant）/ #245 の段階 2 |
| テスト | `RT24502_改竄した認可コードと他クライアントの認可コードは使えない` |

**手順**

1. 1 文字だけ書き換えたコードは交換できない
1. 別のクライアントの資格情報では交換できない
1. その試行で、コードは失効している
1. （対照）本来のクライアントが、自分のコードを 1 度出せば交換できる

**検証（合否を判定する）**

- トークンを発行しない
- エラーは invalid_grant
- トークンを発行しない
- エラーは invalid_grant
- トークンが返る

**観測（判定しない）**

- 本来のクライアントが同じコードを出したときの応答
  - **他のクライアントが提示した時点で、コードは消えている。**`Receive` が照合の**前に**削除するため。**これは安全側の振る舞いで、RFC 6819 §5.2.1.1 / OAuth 2.1 §4.1.3 が求める「誤用されたコードの失効」に当たる**（コードを提示できるのは、既にコードを握っている者だけなので、これで正当な利用者が害を受ける経路は無い）。利用者は認可をやり直せばよい。

**補足**

- **「壊したら通らない」だけでは足りない。**(4) の対照が無いと、**壊し方に関係なく全部落ちている**状態と区別できない。

## RT-245.3 code_challenge を送った認可の code は、code_verifier が無ければトークンに交換できない

| | |
|---|---|
| 観点 | **不一致（`TC-2.4`）は測っていたが、欠落は測っていなかった**（#245 の段階 2）。**欠落を通してしまうと、PKCE を付けた意味が無くなる**（横取りしたコードは、検証子を知らなくても使えてしまう）。 |
| 根拠 | RFC 7636 §4.6 / RFC 6749 §5.2（invalid_grant）/ #245 の段階 2 |
| テスト | `RT24503_code_verifierの欠落は拒否される` |

**手順**

1. code_challenge（S256）を付けて認可コードを取る
1. code_verifier を送らずに交換する
1. （対照）正しい code_verifier なら交換できる
1. パブリック クライアント（client_secret 無し）では、そもそも認証が通らない

**検証（合否を判定する）**

- トークンを発行しない
- エラーは invalid_grant
- トークンが返る
- トークンを発行しない

**観測（判定しない）**

- パブリック クライアントの応答
  - **`client_secret` も証明書も無いので、クライアント認証そのものが通らない**（`invalid_client`）。つまり**パブリック クライアントは、PKCE 以外に交換の手段が無い。****この項の影響は、秘密や鍵・証明書を持つクライアントに限られる**（C-22 の「影響」の根拠。実測で押さえておく）。

## RT-245.4 登録値とパスの大文字小文字が違う redirect_uri は、認可応答を返さない

| | |
|---|---|
| 観点 | **未登録（`TC-1.3`）は測っていたが、「似ているが違う」は測っていなかった**（#245 の段階 2）。RFC 6749 §3.1.2 は**単純な文字列比較**を求めている（スキームとホストは大文字小文字を区別しないが、**パスは区別する**）。**緩い比較は、別のパスへコードを送る余地になる。****#263 で単純文字列比較に直した**（`StringComparison.Ordinal`）。それまでは `ToLower()` 同士で比べており、**認可コードが発行されていた**（C-10）。 |
| 根拠 | RFC 6749 §3.1.2 / RFC 3986 §6.2.2.1 / #245 の段階 2 |
| テスト | `RT24504_redirect_uriは大文字小文字まで一致しなければ通らない` |

**手順**

1. パスの大文字小文字を変えた redirect_uri で認可を要求する

**検証（合否を判定する）**

- 登録値とは違う値になっている（パスだけを変えた）
- 認可コードを発行しない
- その URI へリダイレクトしない

**観測（判定しない）**

- 応答
  - **redirect_uri が照合できないときは、その URI へエラーも返さない**（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。

## RT-245.5 client_assertion の aud が違う・exp が切れていれば、クライアント認証を通さない

| | |
|---|---|
| 観点 | **署名の壊れ（`RT-239.4`）と JWT でない値（`RT-241.2`）、`iss` の不備（`RT-241.3`）は測っていたが、`aud` と `exp` は測っていなかった**（#245 の段階 2）。**`aud` を見ないと、他のサーバへ送ったアサーションを転用できる**（RFC 7523 §3 は `aud` の検証を求めている）。 |
| 根拠 | RFC 7523 §3 / RFC 6749 §5.2（invalid_client）/ #245 の段階 2 |
| テスト | `RT24505_client_assertionのaud違いとexp切れは通らない` |

**手順**

1. aud が別のサーバを指すアサーションで client_credentials を要求する
1. exp が切れたアサーションで要求する
1. （対照）aud と exp が正しいアサーションなら通る

**検証（合否を判定する）**

- トークンを発行しない
- エラーは invalid_client
- HTTP 401
- トークンを発行しない
- エラーは invalid_client
- トークンが返る

## RT-245.6 自己テストの「FAPI1 PC, PKCE」は、S256 で計算した値を S256 と宣言する

| | |
|---|---|
| 観点 | **壊れたパラメタを数えていて、自己テスト側の取り違えが 1 件出た**（#245 の段階 2）。**S256 で計算した `code_challenge` を `code_challenge_method=plain` と宣言していた**ため、トークン要求では `challenge == verifier` の比較になり、**このボタンは必ず失敗していた。****FAPI 1.0 Advanced は S256 を求める**ので、plain は宣言としても誤りである。**E2E が押していなかったボタン**なので、ここで固定する。 |
| 根拠 | RFC 7636 §4.2 / FAPI 1.0 Advanced §5.2.2 / #245 の段階 2 |
| テスト | `RT24506_FAPI1のPKCEボタンはS256を宣言する` |

**手順**

1. ボタンを押して、認可エンドポイントへのリダイレクト先を見る

**検証（合否を判定する）**

- 認可エンドポイントへ送る
- code_challenge_method は S256
- code_challenge は S256 の長さ（43 文字の BASE64URL）

**観測（判定しない）**

- リダイレクト先

**補足**

- **値そのものは照合できない**（`code_verifier` はサイトのセッションにある）。**宣言と長さが噛み合っていることまでを見る。**実際に交換できるかは、同意まで通す目視の経路で確かめる。

## RT-246.1 自己テストの PAR ボタンが、Open棟梁 のクライアントで /par に預け、その request_uri で認可できる

| | |
|---|---|
| 観点 | **#229 で実装した PAR を、この実装自身のクライアントが呼んでいなかった**（自己テストの FAPI2 は `/ros` を使っていた）。**自己テストは Open棟梁 のクライアント ライブラリを使う唯一の場**なので、ここを通すことが、クライアントとサーバの相互接続性の確認になる（#246）。**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。 |
| 根拠 | RFC 9126 / FAPI 2.0 / #229 / #246 |
| テスト | `RT24601_自己テストのPARボタンで預けて認可できる` |

**手順**

1. ボタンを押す（Open棟梁 のクライアントが /par に預ける）
1. 画面に、預けた結果が出ていることを確かめる
1. リンクを辿って、認可できることを確かめる
1. 結果画面が、トークンを取れていることを確かめる

**検証（合否を判定する）**

- HTTP 200（預けた結果の画面）
- request_uri が画面に出る
- クライアント認証が private_key_jwt である
- その request_uri で認可へ進むリンクが出る
- 認可コードが返る
- 結果画面が開く（HTTP 200）
- エラー画面ではない
- access_token が画面に出る

**補足**

- **トークン交換は private_key_jwt で行う**（#246）。FAPI 2.0 は MTLS と private_key_jwt の 2 つを認めており、**証明書の配置を前提にしない方**に寄せた。mTLS の経路は `FA-6` が測る。

## RT-246.2 自己テストの CIBA ボタンが、判定とその理由を画面に出す

| | |
|---|---|
| 観点 | **以前は `?ret=OK_ABNORMAL_END` という URL に移るだけだった。**`OK_` が接頭辞で、その後ろが判定という形なので、**可否が読めず、失敗した理由も出ていなかった**（#246 の 3-a）。**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。ここでは login_hint が **端末（device_token）を登録していない 2 人目の利用者**（tanaka_core）なので、**認証要求が受け付けられず ABNORMAL_END で終わるのが正しい。** |
| 根拠 | #246 の 3-a / 3-b |
| テスト | `RT24602_自己テストのCIBAボタンが判定と理由を画面に出す` |

**手順**

1. ボタンを押す（CIBA を通す）
1. 判定が画面に出ていることを確かめる
1. 失敗した理由が画面に出ていることを確かめる

**検証（合否を判定する）**

- HTTP 200（結果の画面）
- エラー画面ではない
- 判定が出る（端末が無いので ABNORMAL_END）
- `OK_` の接頭辞は付かない
- 理由（/ciba_authz が受け付けなかった）が出る
- 認証デバイスの登録と承認が要ることが書かれている

**補足**

- **net10.0 版の Razor は非 ASCII を数値文字参照で出す**ので、この確認は HTML の実体参照を戻してから行っている（net48 版はそのまま出す）。
- **承認まで通す経路（NORMAL_END）は、実機の認証デバイスが要るので目視で確かめる**（authentication_device/CHEATSHEET.md）。ここで測るのは、**判定と理由が画面に出ること**と、**端末が無い場合に待ち続けずに終わること**（#246 の 3-b）。

## RT-246.3 自己テストの Device AuthZ ボタンが、ポーリングの判定を画面に出す

| | |
|---|---|
| 観点 | **以前は `?ret=OK_NORMAL_END` という URL に移るだけだった**（CIBA と同じ形。#246 の 3-a）。`OK_` が接頭辞なので可否が読めず、ポーリングの実値も出ていなかった。**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。**承認まで通す経路を測れるのは、この流れだけである**（CIBA は実機の認証デバイスが要るため、`RT-246.2` は異常系しか測れない）。 |
| 根拠 | RFC 8628 §3.4 / §3.5 / #246 の 3-a / 3-b |
| テスト | `RT24603_自己テストのDeviceAuthZボタンが判定を画面に出す` |

**手順**

1. 機器 : ボタンを押して device_code と user_code を得る
1. 利用者 : 別の端末で user_code を入力して許可する
1. 機器 : [Start polling.] を押して、結果の画面を確かめる

**検証（合否を判定する）**

- HTTP 200（DeviceAuthZResponse 画面）
- user_code が画面に出る
- interval を hidden で持ち回す（RFC 8628 §3.5）
- 承認の画面へのリンクがある
- そのリンクが開く（HTTP 200）
- 検証画面が承認を受け付ける
- HTTP 200（結果の画面）
- エラー画面ではない
- 判定は NORMAL_END（承認済みなので通る）
- `OK_` の接頭辞は付かない
- トークンの応答が画面に出る
- ポーリングの回数が画面に出る

**補足**

- **承認済みなので 1 回で終わる。** 承認しなければ interval（既定 5 秒）ごとに問い合わせ、上限（60 秒）で打ち切って ABNORMAL_END になる（#246 の 3-b）。以前は `ExponentialBackoff(10, 5)` で、**間隔がサーバの interval と無関係**だった。

## RT-246.4 自己テストが、Redirect Binding（GET）で受け取ったアサーションを画面に出す

| | |
|---|---|
| 観点 | **#246 の項目 3 で「最も手薄」とした箇所。**検証はしていたが、**結果を `?ret=認証完了（nameId=…）` という URL に載せるだけ**で、**署名の検証で落ちたのか Issuer の不一致で落ちたのかが分からず、読み取った属性も、アサーションの XML も捨てていた。****画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。 |
| 根拠 | SAML 2.0 Core / Bindings（HTTP-Redirect）/ #246 の項目 3 |
| テスト | `RT24604_SAMLのアサーションを画面に出す_Redirect` |

**手順**

1. 自己テストの SAML ボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の結果画面を確かめる

**検証（合否を判定する）**

- IdP のエンドポイントへ送られる
- SP（AssertionConsumerService）へリダイレクトで返る
- HTTP 200（結果の画面）
- エラー画面ではない
- 判定は NORMAL_END
- 署名を検証できたことが出る
- Issuer の一致が出る
- バインディングが出る（Redirect（GET…）
- アサーションの XML が画面に出る
- SigAlg が画面に出る（署名はクエリ文字列に付く）
- 属性（NameID / NameIDFormat など）が表になって出る
- RelayState が送った state と一致する

**観測（判定しない）**

- XML の中の署名
  - **Redirect Binding では、署名は XML ではなくクエリ文字列に付く**（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。

**補足**

- **Redirect Binding は、クエリ文字列そのものが署名の対象**である。**`SigAlg` は実際のアルゴリズム**（既定は `rsa-sha256`）であり、**受け手はそれでハッシュを選ぶ**（Open棟梁 #604）。**以前は `rsa-sha1` 固定で、受け手も `rsa-sha1` だけを受けていた。**

## RT-246.5 自己テストが、POST Binding で受け取ったアサーションを画面に出す

| | |
|---|---|
| 観点 | **署名の対象が Redirect Binding と違う**（クエリ文字列ではなく XML の中）。**自動送信フォームで戻る経路**も、同じ画面で見えるようにする（#246 の項目 3）。 |
| 根拠 | SAML 2.0 Bindings（HTTP-POST）/ #246 の項目 3 |
| テスト | `RT24605_SAMLのアサーションを画面に出す_Post` |

**手順**

1. 自己テストの SAML ボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の結果画面を確かめる

**検証（合否を判定する）**

- IdP のエンドポイントへ送られる
- 自動送信フォームで返る（action は SP）
- フォームに SAMLResponse がある
- HTTP 200（結果の画面）
- エラー画面ではない
- 判定は NORMAL_END
- 署名を検証できたことが出る
- Issuer の一致が出る
- バインディングが出る（POST（署名は XML の中）…）
- アサーションの XML が画面に出る
- 署名の要素も XML に出る
- 属性（NameID / NameIDFormat など）が表になって出る
- RelayState が送った state と一致する

**補足**

- **IdP は自動送信フォーム（`PostBinding` 画面）で返す。**テストは、そのフォームの hidden をそのまま POST している。

## RT-246.6 認可画面（同意）が「何を確かめる画面か」を出し、結果画面がクライアント認証の方式を出す

| | |
|---|---|
| 観点 | **#246 の項目 3 の残り 2 つ。**認可画面は押せても**何を確かめるのかが書かれておらず**、**どのクライアント認証でトークンを交換したのかも画面から分からなかった。**`prompt` / `max_age` は固定だったので、**効き方を試せなかった。****画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。 |
| 根拠 | OIDC Core §3.1.2.1（prompt / max_age）/ #246 の項目 3 |
| テスト | `RT24606_認可画面に確かめる内容とpromptとmax_ageが出る` |

**手順**

1. prompt と max_age を選んで、認可コード フロー（OIDC）を始める
1. 認可画面（同意）に、確かめる内容が出ていることを確かめる
1. 同意して、結果画面にクライアント認証の方式が出ることを確かめる

**検証（合否を判定する）**

- 認可エンドポイントへ送られる
- 要求に prompt が乗る
- 要求に max_age が乗る（選んだ値）
- max_age が二重にならない
- HTTP 200（認可画面）
- 「この画面で確かめること」が出る
- なぜこの画面が出たかが書かれている
- prompt の値が出る
- max_age の値が出る
- 同意を記録することが書かれている
- 取り消しの場所が書かれている
- 認可コードが返る
- 結果画面が開く（HTTP 200）
- エラー画面ではない
- クライアント認証の方式が出る
- この経路は client_secret_basic である

**補足**

- **以前は「prompt=consent は無視される」と書いていた**（同意を記録しなかったため、毎回この画面になっていた。C-3）。**#272 の段階 2 で記録するようになった**ので、**画面の文面も直した。解説を測るテストは、文面を変えると落ちる。**
- **PKCE の経路は `client_secret_post`**（Open棟梁 のクライアントの既定が違う）、**FAPI1 / FAPI2 は `private_key_jwt`** と出る。**どれを送ったのかが画面から分かるようになった**（#246 の項目 3）。

## RT-246.7 自己テストが、要求を POST・応答を Redirect で受ける組み合わせも試せる

| | |
|---|---|
| 観点 | **バインディングの組み合わせは 4 通りあるが、ボタンは 3 つだけだった**（Redirect-Redirect / Redirect-Post / Post-Post）。**要求を POST で送り、応答を Redirect で受ける**組み合わせが抜けていた（#246 の項目 2）。`ProtocolBinding` が応答の受け取り方を決めるので、指定を変えるだけで足りる。 |
| 根拠 | SAML 2.0 Bindings（HTTP-POST / HTTP-Redirect）/ #246 の項目 2 |
| テスト | `RT24607_SAMLの4つ目の組み合わせが通る` |

**手順**

1. 自己テストの SAML ボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の結果画面を確かめる

**検証（合否を判定する）**

- 要求の自動送信フォームが返る（HTTP 200）
- フォームの action が IdP のエンドポイントである
- フォームに SAMLRequest がある
- SP（AssertionConsumerService）へリダイレクトで返る
- HTTP 200（結果の画面）
- エラー画面ではない
- 判定は NORMAL_END
- 署名を検証できたことが出る
- Issuer の一致が出る
- バインディングが出る（Redirect（GET…）
- アサーションの XML が画面に出る
- SigAlg が画面に出る（署名はクエリ文字列に付く）
- 属性（NameID / NameIDFormat など）が表になって出る
- RelayState が送った state と一致する

**観測（判定しない）**

- XML の中の署名
  - **Redirect Binding では、署名は XML ではなくクエリ文字列に付く**（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。

**補足**

- **要求は POST、応答は Redirect。** 応答の署名はクエリ文字列に付くので、XML には署名の要素が無い（`RT-246.4` と同じ）。

## RT-247.1 max_age を超えていれば、エラー画面ではなく再認証へ送る

| | |
|---|---|
| 観点 | **以前は、文面の無いエラー画面だった**（`ANALYSIS-IdP.md` の A-12）。OIDC Core §3.1.2.1 は「経過が `max_age` を超えていれば、**利用者を再認証しなければならない**」としている。**サインイン画面へ送る**（サインアウトして同じ URL に戻すので、認証が要る）。 |
| 根拠 | OIDC Core §3.1.2.1 / #247 |
| テスト | `RT24701_max_ageを超えていれば再認証へ送る` |

**手順**

1. max_age=0（毎回、再認証）で認可リクエストを送る
1. その先が、サインイン画面（再認証）であることを確かめる
1. 再認証すると先へ進む（繰り返しにならない）
1. OIDC のボタンは prompt を固定しない（#272 の段階 2）
1. 自己テストのボタン（max_age=0）でも、再認証へ送られることを確かめる

**検証（合否を判定する）**

- エラー画面ではなく、リダイレクトで返る
- 認可コードは発行されない
- サインイン画面へ送られる
- 先へ進む（再びサインインへ送られない）
- prompt は付かない（画面で選んでいないので）
- 自己テストが max_age=0 を乗せる
- prompt は付かない（このボタンは付けない）
- 自己テスト経由でも、リダイレクトで返る（同じ URL へ）

**補足**

- **`prompt=none` を試したいときは、画面の選択で指定する**（#246 の項目 3）。**手順 1〜3 が、`prompt=none` を送ったときの `login_required` を測っている。**
- **固定で `prompt=none` を付けていたのをやめた**（#272 の段階 2）。**同意を記録するようになったので、付けたままだと記録が無い配備で初回に必ず `consent_required` になる。**
- **画面で prompt を選べば、このボタンの prompt=none を上書きできる**（#247 で直した）。**選択と実際が食い違っていた**（`max_age` を選んでも prompt=none のままだった）。
- **再認証を求めた時刻を Cookie（`re_auth_at`）に残している**（#247）。`max_age=0` は再認証の直後でも経過が 0 を超えるため、印が無いと「送る → 認証する → また超過」で戻り続ける。**この手順 (3) が、その繰り返しが起きないことを押さえている。**

## RT-247.2 max_age を超えていて prompt=none なら、redirect_uri へ login_required を返す

| | |
|---|---|
| 観点 | **UI を出せない指定**（`prompt=none`）で再認証が必要になったときは、**エラーを `redirect_uri` へ返す**のが仕様（OIDC Core §3.1.2.6）。**以前はエラー画面**で、RP はエラーの理由を受け取れなかった。 |
| 根拠 | OIDC Core §3.1.2.6（login_required）/ #247 |
| テスト | `RT24702_promptがnoneならlogin_requiredを返す` |

**手順**

1. max_age=0 と prompt=none を付けて認可リクエストを送る

**検証（合否を判定する）**

- エラー画面ではなく、リダイレクトで返る
- redirect_uri へ返る
- エラーは login_required
- state が返る
- 認可コードは発行されない

## RT-247.3 max_age が数値でなければ、redirect_uri へ invalid_request を返す

| | |
|---|---|
| 観点 | `max_age` は**0 以上の整数**（OIDC Core §3.1.2.1）。**以前は、数値でない値でもエラー画面**になっていた（`CheckAuthTime` が false を返し、そのまま落ちていた）。**不正なパラメタは `invalid_request` として `redirect_uri` へ返す**（RFC 6749 §4.1.2.1）。 |
| 根拠 | RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.1 / #247 |
| テスト | `RT24703_max_ageが数値でなければinvalid_request` |

**手順**

1. max_age=abc（数値でない）で認可リクエストを送る
1. （対照）負の値でも同じであることを確かめる

**検証（合否を判定する）**

- エラー画面ではなく、redirect_uri へ返る
- エラーは invalid_request
- 認可コードは発行されない
- max_age=-1 も invalid_request

## RT-247.4 サインインしていない状態で prompt=none なら、redirect_uri へ login_required を返す

| | |
|---|---|
| 観点 | **`prompt=none` は「画面を出すな」という指定**である（OIDC Core §3.1.2.1）。**認証できないなら、エラーを `redirect_uri` へ返す**（同 §3.1.2.6）。**以前はサインイン画面が出ていた。** RP は「セッションが無い」ことを**黙って確かめられなかった**（サイレント認証・セッション監視ができない）。 |
| 根拠 | OIDC Core §3.1.2.1 / §3.1.2.6 / #254 |
| テスト | `RT24704_未サインインでpromptがnoneならlogin_requiredを返す` |

**手順**

1. サインインせずに、prompt=none で認可リクエストを送る

**検証（合否を判定する）**

- サインイン画面を出さない（リダイレクトで返る）
- redirect_uri へ返る（ログイン画面ではない）
- エラーは login_required
- state がそのまま返る

## RT-257.1 利用者名とメアドを入れると、サインアップできる

| | |
|---|---|
| 観点 | **利用者を作る唯一の口**（種データ以外）。**#151 の段階 3 で、利用者名とメアドを別々に受け取る形に変えた**ので、**両方を入れて通ることを押さえる。**成功すると**メアド検証の画面**へ進む（リダイレクトではない）。 |
| 根拠 | #151 の段階 3 / #257 |
| テスト | `RT25701_利用者名とメアドでサインアップできる` |

**手順**

1. サインアップ画面を開く
1. 利用者名・メアド・パスワードを送る
1. 後片付け : 管理画面から削除する

**検証（合否を判定する）**

- HTTP 200
- **サインアップ画面が再表示されない**（＝ 検証エラーが無い）
- メアド検証の画面へ進む（入力欄が無く、エラーも無い）
- 作った利用者を削除できた（DB ストアに残さない）

**観測（判定しない）**

- 作った利用者の状態
  - **この利用者ではサインインできない**（サインインは EmailConfirmed を見る）。**メールは送られる**が、`IsDebug` のときは送信せずデバッグ出力に書くだけである。

**補足**

- **後片付けを、同じテストの中で行う。** `mem` では再起動で消えるが、**DB ストアでは残る**ので、**次の回の一覧に積み上がる。**削除には**管理者のサインイン**が要る（`SystemAdmin` ロール）。

## RT-257.2 利用者名に「@」を入れると弾かれる（モデル全体のエラーになる）

| | |
|---|---|
| 観点 | **サインインは 1 つの欄で受け、`@` を含むならメアドとして引く**（#151 の段階 3）。**利用者名に `@` を許すと、入力がどちらなのか決まらなくなる。****欄のエラーではなくモデル全体のエラー**になることまで見るのは、**空欄のときと入れ替わらない**ことを押さえるためである。 |
| 根拠 | #151 の段階 3 / #257 |
| テスト | `RT25702_利用者名にアットマークは使えない` |

**手順**

1. 利用者名に「@」を入れて送る

**検証（合否を判定する）**

- HTTP 200（再表示。500 にならない）
- サインアップ画面が再表示される（入力欄が在る）
- エラーが出ている
- **モデル全体のエラーである**（利用者名の欄のエラーではない）

**補足**

- **入力した値は出力しない方針だが、ここは例外にしている。**`bad@name` は**テストが作った値**で、秘密ではない。

## RT-257.3 利用者名が空／メアドが空のとき、それぞれの欄のエラーになる

| | |
|---|---|
| 観点 | **ここが「あべこべ」だった。****空欄なのに「利用者名に `@` は使えません」と出ていた**（#151 の段階 3 で、空と `@` 入りを区別していなかった）。**両方を `[Required]` にして、属性に言わせる形に直した。****欄のエラーとして出ること**が、その直し方が効いている証拠になる。 |
| 根拠 | #151 の段階 3（目視で見つかった不具合）/ #257 |
| テスト | `RT25703_空欄はそれぞれの欄のエラーになる` |

**手順**

1. 利用者名だけ空で送る
1. メアドだけ空で送る

**検証（合否を判定する）**

- HTTP 200（再表示）
- **利用者名の欄のエラーになる**
- メアドの欄のエラーにはならない
- HTTP 200（再表示）
- **メアドの欄のエラーになる**
- 利用者名の欄のエラーにはならない

**補足**

- **文言は見ない。** 画面の言語は配備で変わる。**「どの欄が間違っていると言われたか」**で判定している（`input-validation-error`）。

## RT-257.4 メアドの形式が不正なら弾かれる（メアドの欄のエラー）

| | |
|---|---|
| 観点 | **メアドは、サインインの識別子であり、ID 連携の鍵でもある**（#151 の段階 3）。**形になっていない値を入れさせない。** |
| 根拠 | #151 の段階 3 / #257 |
| テスト | `RT25704_メアドの形式が不正なら弾かれる` |

**手順**

1. メアドの形になっていない値を送る

**検証（合否を判定する）**

- HTTP 200（再表示）
- **メアドの欄のエラーになる**
- 利用者は作られない（入力欄が残る）

## RT-257.5 一覧が開き、利用者名とメアドが別の列で出る

| | |
|---|---|
| 観点 | **#151 の段階 3 で、利用者名とメアドは別の項目になった。**一覧は**利用者名しか出していなかった**ので、メアドの列を足した。**両方が、それぞれの列に出ている**ことを押さえる。 |
| 根拠 | #151 の段階 3 / #257 |
| テスト | `RT25705_一覧に利用者名とメアドが別の列で出る` |

**手順**

1. 管理者で一覧を開く
1. テスト利用者の行を読む

**検証（合否を判定する）**

- 一覧の画面が開く（検索の欄が在る）
- テスト利用者の行が在る
- **メアドの列に、その利用者のメアドが出る**

**補足**

- **利用者名の列とメアドの列を、別に読んでいる。****同じ値が両方に出ていた**のが、段階 3 より前の姿である（当時は「利用者名＝メアド」だった）。

## RT-257.6 作成の検証エラーで 500 にならず、ロールの選択肢が出たまま再表示される

| | |
|---|---|
| 観点 | **ここが HTTP 500 になっていた**（#151 の段階 3）。**検証エラーの再表示で `ViewBag.RoleId` を詰めていなかった**ため、**ビューがロールの一覧を描こうとして落ちていた。****選択肢が出たまま再表示される**ことが、直っている証拠になる。 |
| 根拠 | #151 の段階 3（目視で見つかった不具合）/ #257 |
| テスト | `RT25706_作成の検証エラーで500にならない` |

**手順**

1. 利用者名に「@」を入れて作成する

**検証（合否を判定する）**

- **HTTP 200（500 にならない）**
- 作成の画面が再表示される（入力欄が在る）
- **ロールの選択肢が出ている**（ViewBag.RoleId を詰めている）
- エラーが出ている

## RT-257.7 作成でき、編集画面に利用者名とメアドが別々に保存されている

| | |
|---|---|
| 観点 | **#151 の段階 3 で、作成・編集を 2 欄にした。****入れた 2 つが、それぞれの項目として保存される**ことを押さえる（以前は「利用者名＝メアド」で、片方しか残らなかった）。 |
| 根拠 | #151 の段階 3 / #257 |
| テスト | `RT25707_作成できて編集画面に別々に出る` |

**手順**

1. 利用者名とメアドを入れて作成する（ロールも付ける）
1. 一覧で、利用者名とメアドを読む
1. 編集画面で、2 つの欄の値を読む
1. 後片付け : 作った利用者を削除する

**検証（合否を判定する）**

- 一覧へリダイレクトする（作成の成功）
- 一覧に出る
- メアドの列が、入れたメアドである
- HTTP 200
- 利用者名の欄に、入れた利用者名が入っている
- メアドの欄に、入れたメアドが入っている
- ロールのチェックボックスが出ている
- 削除できた（DB ストアに残さない）

**補足**

- **削除まで 1 つのテストで行う。** `mem` では再起動で消えるが、**DB ストアでは残る**ので、**次の回の一覧に積み上がる。****削除そのものの確認**にもなっている。
- **ロールを 1 つ付けて作っている。** **net48 版は、ロールを選ばないと一覧へ戻らない**（`params string[]` に何も来ないと null になり、**利用者は作られるのに作成画面が再表示される**）。**net10.0 版は空の配列が来る**ので一覧へ戻る。**この非対称は #257 で作ったものではなく、元から在る。**

## RT-257.8 編集の検証エラーで 500 にならず、ロールのチェックボックスが出たまま再表示される

| | |
|---|---|
| 観点 | **作成と同じ不具合が、編集にも在った**（#151 の段階 3）。**再表示で `RolesList` を詰めていなかった**ため、ビューが落ちていた。**チェックボックスが出たまま再表示される**ことが、直っている証拠になる。 |
| 根拠 | #151 の段階 3（目視で見つかった不具合）/ #257 |
| テスト | `RT25708_編集の検証エラーで500にならない` |

**手順**

1. 測る対象の利用者を作る
1. 利用者名に「@」を入れて更新する
1. 利用者名が変わっていない
1. 後片付け : 作った利用者を削除する

**検証（合否を判定する）**

- **HTTP 200（500 にならない）**
- **ロールのチェックボックスが出ている**（RolesList を詰めている）
- エラーが出ている
- 利用者名は元のまま
- 削除できた（DB ストアに残さない）

## RT-257.9 管理画面は SystemAdmin のときだけ開く（付与すると開き、無ければ開かない）

| | |
|---|---|
| 観点 | **これは認可の確認である。****門番（`Authorize`）とメニューの出し分けは、どちらも `SystemAdmin` を見る**（`Admin` では開かない。雛形のテスト利用者は `User` / `Admin` しか持たない）。**付与の前後を 1 つのテストで通す**ので、**「誰でも開ける」退行と「誰も開けない」退行の両方**を捕まえられる。 |
| 根拠 | #257 / #258（導線は EnableAdministrationOfUsersAndRoles でも出し分ける） |
| テスト | `RT25709_管理画面はSystemAdminでだけ開く` |

**手順**

1. 管理者が、使い捨ての利用者を作る（ロールは User）
1. その利用者でサインインする（SystemAdmin は持っていない）
1. 管理者が、その利用者に SystemAdmin を付ける
1. 入り直して、開けるようになる
1. 後片付け : 使い捨ての利用者を削除する

**検証（合否を判定する）**

- **一覧が開かない**
- メニューに導線が出ない
- 付与できた（一覧へリダイレクトする）
- **一覧が開く**
- メニューに導線が出る（UsersAdmin / RolesAdmin）
- 削除できた（SystemAdmin を持つ利用者を残さない）

**観測（判定しない）**

- 断り方
  - **門番は例外を投げる**ので、エラー画面になる（401 / 403 ではない。そこは直していない）。

**補足**

- **入り直さないと効かない。** ロールは**サインインのときに Cookie のクレームへ入る**ので、**付与しただけでは、その人の今のセッションは変わらない。**テストが `force: true` で入り直しているのは、そのためである。
- **種データの利用者には付与しない。** 戻し忘れると、**DB ストアで権限が残り続け、他のテストの前提が変わる。****使い捨ての利用者なら、消せば終わる。**

## RT-257.10 ロールの一覧が開き、種データの 3 つのロールが出る

| | |
|---|---|
| 観点 | **この画面も、一度も叩いていなかった。****ビューの文字列は実行時に反射で探される**ので、**足し忘れはビルドでも E2E でも分からなかった**（`CODING.md`）。**#258 で net10.0 版へ移植したばかり**でもあり、**退行に気付く手段が無い**状態だった。 |
| 根拠 | #257 / #258 |
| テスト | `RT25710_一覧に種データのロールが出る` |

**手順**

1. 管理者でロールの一覧を開く

**検証（合否を判定する）**

- SystemAdmin が出る
- Admin が出る
- User が出る

**補足**

- **行を読んで判定している**（ロール名の列と、編集のリンクの id）。**本文に文字列が在るかどうかでは見ていない**（メニューや他の語に含まれてしまう）。

## RT-257.11 ロールを作ると一覧に出て、削除すると消える

| | |
|---|---|
| 観点 | **ロールは、管理画面からしか作れない**（種データ以外）。**作成と削除は、利用者へのロール割り当ての前提**でもある。 |
| 根拠 | #257 |
| テスト | `RT25711_ロールを作って消せる` |

**手順**

1. ロールを作る
1. 一覧に出る
1. 削除する（後片付けでもある）
1. 一覧から消えている

**検証（合否を判定する）**

- 一覧へリダイレクトする（作成の成功）
- 作ったロールが一覧に在る
- 削除できた
- 一覧から消えている

**補足**

- **削除まで 1 つのテストで行う。** `mem` では再起動で消えるが、**DB ストアでは残る。** 名前に `Guid` を混ぜて、回をまたいだ衝突も避けている。

## RT-257.12 ロールの詳細に、そのロールに属する利用者が出る（属さなければ出ない）

| | |
|---|---|
| 観点 | **詳細は、全利用者を 1 人ずつ `IsInRole` で確かめて一覧する。****0 人のときと 1 人以上のときで、画面の分岐が違う**（`ViewBag.UserCount`）。**両方を通す。** |
| 根拠 | #257 |
| テスト | `RT25712_詳細に属する利用者が出る` |

**手順**

1. 種データのロール（User）の詳細を開く
1. 誰も属していないロールを作って、詳細を開く
1. 後片付け : 作ったロールを削除する

**検証（合否を判定する）**

- HTTP 200
- **属している利用者が出る**（テスト利用者）
- HTTP 200（0 人でも落ちない）
- 属していない利用者は出ない
- 削除できた

## RT-257.13 ロール名が空のとき、500 にならず、その欄のエラーとして再表示される

| | |
|---|---|
| 観点 | **利用者管理の作成・編集は、ここで 500 になっていた**（#151 の段階 3）。**同じ形の画面なので、こちらも押さえる。**ロール名は `[Required]` なので、**欄のエラーになる**のが正しい姿である。 |
| 根拠 | #151 の段階 3（同じ性質の不具合）/ #257 |
| テスト | `RT25713_作成の検証エラーで500にならない` |

**手順**

1. ロール名を空で送る

**検証（合否を判定する）**

- **HTTP 200（500 にならない）**
- 作成の画面が再表示される（入力欄が在る）
- **ロール名の欄のエラーになる**

## RT-261.1 仕込んだ標準クレームが、profile / address スコープで /userinfo に出る

| | |
|---|---|
| 観点 | **IdP として何を返せるのかが、触っても分からなかった**（#261）。入力画面は `usd1` / `usd2` の 2 欄で、`UserClaimsMapping` の既定は空だった。**入れ物（`UnstructuredData`）は JSON のまま**にしつつ、**`IsDebug` のときに標準クレームのサンプルを仕込む**ようにした。**雛形の対応付けも、設定ファイルにコメントで示してある。** |
| 根拠 | OIDC Core §5.1 / §5.1.1 / §5.4 / #261 |
| テスト | `RT26101_標準クレームのサンプルがuserinfoに出る` |

**手順**

1. profile と address を要求してトークンを取り、/userinfo を呼ぶ
1. profile のクレームが、仕込んだ値で返る
1. updated_at は数値で返る（NumericDate。OIDC Core §5.1）
1. address は、副フィールドを持つオブジェクトで返る（OIDC Core §5.1.1）
1. 入れていないキーは返らない

**検証（合否を判定する）**

- HTTP 200
- given_name
- family_name
- nickname
- profile
- picture
- website
- gender
- birthdate
- zoneinfo
- locale
- updated_at の型が数値
- updated_at の値
- address が JSON オブジェクト
- address.formatted
- address.street_address
- address.region
- address.postal_code
- address.country
- middle_name は返らない（サンプルに入れていない）

**補足**

- **`name` と `address.locality` は、ここでは見ない。**雛形の対応付けは、その 2 つを **`usd1` / `usd2`（管理画面で入れられる 2 欄）**へ向けてある。**画面から入れた値が返ることは `RT-230.*` で測る**ので、**サンプルと二重に持たせていない**（#261 の判断）。
- **`preferred_username` / `email` / `phone_number` もサンプルに入れていない。****`user:` で `ApplicationUser` から直に取れる**ため（#151 の段階 1）。
- **管理画面で入れられるのは `usd1` / `usd2` の 2 欄だけ**である。**このサンプルは、管理画面で保存すると消える**（画面が持たないキーは、読み込みで捨てられ、保存で JSON ごと置き換わる）。**1 人目ではなく 2 人目に仕込んでいるのは、そのため**である。

## RT-262.1 token_endpoint_auth_signing_alg を登録すると、その alg 以外の client_assertion は通らない

| | |
|---|---|
| 観点 | **いまは「サーバが受ける集合」だけがあり、「このクライアントはこの alg で来る」という宣言が無かった**（#262）。**鍵を両方登録したクライアントは、RS256 でも ES256 でも認証が通る。****登録で片方に絞れる**ようにした（OIDC Registration 1.0 §2）。**書かなければ、従来どおり両方が通る**（`RT-129.1`）。 |
| 根拠 | OIDC Registration 1.0 §2 / FAPI 1.0 Advanced §8.6 / #262 |
| テスト | `RT26201_登録で絞ったalg以外のアサーションは通らない` |

**手順**

1. 登録した alg（RS256）の client_assertion は通る
1. 絞った alg と違う ES256 の client_assertion は通らない
1. （対照）alg を絞っていないクライアントは、ES256 でも通る

**検証（合否を判定する）**

- トークンが返る
- トークンが返らない
- トークンが返る（登録を書かなければ従来どおり）

**補足**

- **絞るのは「受ける側」だけ**である。**発行する側（`id_token_signed_response_alg`）は #129 の段階 2 で入っており、別の項目。**
- **`token_endpoint_auth_signing_alg` と `token_endpoint_auth_method` は別物。****方法（#307 の段階 3）は「何で認証するか」**、**alg（#262）は「`private_key_jwt` のとき、どの署名を受けるか」**である。**どちらの対照も `private_key_jwt` のクライアントで測る。**
- **`request_object_signing_alg` も同じ形で足した**（#262）。**ただし、受ける集合が `RS256` だけ**なので（上流の `RequestObject.Verify` が RS256 固定）、**いまは書ける値が 1 つしか無く、絞っても結果が変わらない。****受ける alg を増やすのは「広げる側」の話**で、#262 では扱っていない。

## RT-265.1 公開情報は全開、ブラウザから叩く口は登録から導いたオリジンだけ、/revoke と /introspect には CORS を付けない

| | |
|---|---|
| 観点 | **以前は全エンドポイントで `AllowAnyOrigin` だった**（#265）。`Startup.cs` の `UseCors` にインラインの全開ポリシーが在り、**`/token` `/revoke` `/introspect` まで任意オリジンから叩けた。****開ける必要があるのは `/userinfo` と公開情報、それに SPA が叩く `/token` 程度**で、**`/revoke` `/introspect` はブラウザから叩く口ではない。****許すオリジンは、登録した `redirect_uri` から導く**（Keycloak の Web origins の既定値 `+` と同じ考え方）。 |
| 根拠 | Fetch Standard（CORS）/ OAuth 2.0 for Browser-Based Apps / #265 |
| テスト | `RT26501_CORSが口の性質ごとに分かれている` |

**手順**

1. 公開情報は、許していないオリジンにも開く
1. ブラウザから叩く口は、導出したオリジンだけ通る
1. /revoke と /introspect には CORS を付けない
1. 資格情報は許さない

**検証（合否を判定する）**

- 導出したオリジンが、サイト自身のオリジンとは違う（測る前提）
- /.well-known/openid-configuration の Access-Control-Allow-Origin
- /jwkcerts の Access-Control-Allow-Origin
- /token は、導出したオリジンを許す
- /token は、それ以外を許さない
- /SetDeviceToken は、導出したオリジンを許す
- /SetDeviceToken は、それ以外を許さない
- /ciba_result は、導出したオリジンを許す
- /ciba_result は、それ以外を許さない
- /2fa_result は、導出したオリジンを許す
- /2fa_result は、それ以外を許さない
- /userinfo は、導出したオリジンを許す
- /userinfo は、それ以外を許さない
- /revoke は、許したオリジンにも CORS を付けない
- /introspect は、許したオリジンにも CORS を付けない
- /token に Access-Control-Allow-Credentials を付けない

**補足**

- **`Access-Control-Allow-Credentials` は、どちらのポリシーにも付けていない。****Cookie で通る口をこの範囲に入れない**ため（入れると、他オリジンの JS から利用者の資格情報で呼べる）。
- **プリフライトは、実際に叩くメソッドで測ること。**ASP.NET Core は `Access-Control-Request-Method` で経路を選ぶので、**GET だけの口に `POST` を書くと、経路が当たらず 404 になる**（実測で踏んだ）。

## RT-266.1 クライアント登録の web_origins が、CORS の許可オリジンになる

| | |
|---|---|
| 観点 | **#265 では、許可オリジンを「構成ファイルの public クライアントの `redirect_uri_*`」から導いていた。****画面から登録した SPA は導出に含まれず**、配備側で `CorsAllowedOrigins` に 書く必要があった。**クライアント単位の登録項目 `web_origins` を足した**（#266）。**空なら従来どおり `redirect_uri_*` から導く**（Keycloak の Web origins の既定値 `+` と同じ考え方）。 |
| 根拠 | Fetch Standard（CORS）/ OIDC Dynamic Client Registration（web_origins 相当）/ #266 |
| テスト | `RT26601_web_originsを登録するとそのオリジンだけが許される` |

**手順**

1. 登録した web_origins は許される（画面登録＝user store の経路）
1. web_origins を書いたら、redirect_uri_code からは導出しない
1. CORS を付けない口は、web_origins を登録しても開かない

**検証（合否を判定する）**

- /token が web_origins を許す
- /token は redirect_uri_code のオリジンを許さない
- /revoke は CORS を付けない

**補足**

- **(1) が #266 の本題である。****画面から登録したクライアントのオリジンが、設定を書かずに効く。**種データは user store（`saml2OAuth2Data`）に入るので、**画面登録と同じ経路**である。
- **(2) は、`web_origins` が `redirect_uri_*` に勝つことを見ている。****書いたときは導出しない**（登録どおりに絞る）。**空なら従来どおり導出する**（`RT-265.1` が、その経路を測っている）。
- **許可オリジンはキャッシュしている**（60 秒＋登録の保存で破棄）。**複数インスタンスでは、他のインスタンスのキャッシュは捨てられない。****期限が、その取りこぼしを拾う**（共有キャッシュには E-2 が要る）。

## RT-267.1 response_type の並びを変えても、同じ応答になる

| | |
|---|---|
| 観点 | **`response_type` は順不同の空白区切り集合**である（OAuth 2.0 Multiple Response Type Encoding Practices §3。**並びは意味を持たない**）。**以前は文字列の完全一致で照合していた**ため、`OAuth2AndOIDCConst` の定数の並び（`code id_token token` など）でなければ**`unsupported_response_type` で弾いていた**（#267）。**`id_token code` と書く RP が通らない**という相互運用性の問題である。 |
| 根拠 | OAuth 2.0 Multiple Response Type Encoding Practices §3 / OIDC Core §3.3 / #267 |
| テスト | `RT26701_response_typeの並びを変えても同じ応答になる` |

**手順**

1. (code id_token) と、並べ替えた (id_token code) を比べる
1. (id_token token) と、並べ替えた (token id_token) を比べる
1. (code token) と、並べ替えた (token code) を比べる
1. (code id_token token) と、並べ替えた (token id_token code) を比べる

**検証（合否を判定する）**

- `code id_token` は通る（前提）
- `id_token code` のエラー（`code id_token` と同じ）
- `id_token code` が返す項目（`code id_token` と同じ）
- `id_token token` は通る（前提）
- `token id_token` のエラー（`id_token token` と同じ）
- `token id_token` が返す項目（`id_token token` と同じ）
- `code token` は通る（前提）
- `token code` のエラー（`code token` と同じ）
- `token code` が返す項目（`code token` と同じ）
- `code id_token token` は通る（前提）
- `token id_token code` のエラー（`code id_token token` と同じ）
- `token id_token code` が返す項目（`code id_token token` と同じ）

**補足**

- **値そのものは比べていない。** code / id_token / access_token は毎回変わるため、**返る項目の有無**で比べている。**どの項目が返るかは `response_type` の集合で決まる**ので、これで十分である。
- **大文字小文字の扱いは変えていない。****仕様では値は case-sensitive** だが、**以前から `ToLower()` していて `CODE` も通っていた。** **弾く範囲が変わるだけ**なので、寛容さを残した。

## RT-269.1 2000 文字を超えるクライアント登録も、保存でき、読み出せる

| | |
|---|---|
| 観点 | **`UnstructuredData` の幅が 3 方言で揃っていなかった**（#269）。**SQL Server は `nvarchar(max)`、Oracle と PostgreSQL は 2000 文字**で、**SQL Server で保存できる登録が Oracle / PostgreSQL では保存できなかった**（`22001: value too long`）。**クライアント登録は全項目が 1 つの JSON に入る**ので（`Saml2OAuth2Data.UnstructuredData`）、**画面から入れられる範囲でも 2000 文字を超える**（`Const.MaxLengthOfUri` = 512 の項目が 5 つ ＋ JWK 2 本）。**Oracle は `NCLOB`、PostgreSQL は `text`** にした。 |
| 根拠 | #269 / #266 で踏んだ |
| テスト | `RT26901_2000文字を超える登録も保存でき読み出せる` |

**手順**

1. 保存できていれば、登録した web_origins で CORS が通る
1. 24 件の末尾まで読めている（途中で切れていない）

**検証（合否を判定する）**

- /token が、長い登録の web_origins を許す
- /token が、web_origins の末尾のオリジンも許す

**補足**

- **`mem` では、このテストは幅の問題を測れない**（辞書なので上限が無い）。**効くのは `sql` / `ora` / `npg`** で、**直す前は Oracle / PostgreSQL で種データの作成そのものが失敗していた**（`GET /Account/Login` が HTTP 500 になり、その対象のテストが大量に落ちる）。**4 ストアの実測は `TESTING.md` 1 節。**
- **切れていないことを、先頭と末尾の両方で見ている。****幅が足りないと、黙って切り捨てる方言もある**ため（今回の Oracle / PostgreSQL は例外にしたが、設定で変わりうる）。

## RT-270.1 画面登録（user store）に書いた require_pkce も、構成ファイルと同じように効く

| | |
|---|---|
| 観点 | **`RT-221.1` の TestClient6 は構成ファイル側のクライアントである。**そのため、**画面登録側の `require_pkce` は測られていなかった**。**#270 で登録を JSON 1 列から専用列に切り出した**とき、**`require_pkce` だけが bool** で、**方言ごとに形が違う**（SQL Server : `bit` / PostgreSQL : `boolean` / Oracle : `NUMBER(3)` の -1）。**この往復が落ちると、登録で締めたつもりのクライアントが、黙って PKCE 無しを受け入れる。** |
| 根拠 | OAuth 2.1 draft §4.1.1 / #221 / #270 |
| テスト | `RT27001_登録経由のrequire_pkceも効く` |

**手順**

1. code_challenge を送らずに認可リクエストを出す
1. 同じクライアントに、PKCE（S256）を付けて出す

**検証（合否を判定する）**

- 認可コードを発行しない
- エラーは invalid_request
- PKCE を付ければ認可コードが返る

**補足**

- **4 つのストアで回すと、方言ごとの往復をまとめて測れる**（`mem` は変換無し、`sql` は `bit`、`npg` は `boolean`、`ora` は `NUMBER(3)`）。

## RT-272.1 prompt に none と他の値を併記したら、redirect_uri へ invalid_request を返す

| | |
|---|---|
| 観点 | **`prompt` は空白区切りの集合**（OIDC Core §3.1.2.1）。**`none` は他の値と併記できない**（仕様が「エラーを返す」としている）。**以前は照合が完全一致だった**ため、`prompt=none login` は **`none` と見なされないまま通っていた**（同意画面が出ていた）。**集合の判定に揃えるなら、ここをエラーにしないと「同意を飛ばして code を発行する」ことになる。** |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 1 |
| テスト | `RT27201_promptのnoneは他の値と併記できない` |

**手順**

1. prompt に「none login」を指定して認可リクエストを送る

**検証（合否を判定する）**

- エラー画面ではなく、リダイレクトで返る
- redirect_uri へ返る
- エラーは invalid_request
- state が返る
- 認可コードは発行されない

**補足**

- **判定は `redirect_uri` を確かめた後**に置いてある（`ValidateAuthZReqParamCore`）。**でないとエラーを RP へ返せない**（#187）。

## RT-272.2 prompt=none だけなら、同意画面を出さずに認可コードを返す（従来どおり）

| | |
|---|---|
| 観点 | **集合の判定に替えても、単体の `none` の扱いは変えない。****`prompt=none` で同意画面を飛ばすこと自体は、まだ直していない**（同意を記録していないので「以前に同意済みか」を判定できない。`ANALYSIS-IdP.md` の C-3 / D-6。**この Issue の段階 2**）。 |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 1 |
| テスト | `RT27202_promptのnone単体は従来どおり通る` |

**手順**

1. prompt=none を指定して認可リクエストを送る

**検証（合否を判定する）**

- 認可コードが返る
- state が返る

**補足**

- **`prompt=none` が同意画面を無条件に飛ばすのは、仕様どおりではない。**本来は「同意が必要なら `consent_required` を返す」。**段階 2 で同意を記録してから直す。**

## RT-272.3 prompt=nonexistent は none として扱わない（部分文字列で照合しない）

| | |
|---|---|
| 観点 | **以前は `Contains("none")` で見ていた**ので、**`nonexistent` でも `none` と見なしていた**。**集合の要素として照合する**ようにしたので、一致しない。**既知でない値は、それ自身ではエラーにしない**（§3.1.2.1 は未知の値を `invalid_request` とはしていない）。 |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 1 |
| テスト | `RT27203_noneを含む別の語はnoneとして扱わない` |

**手順**

1. prompt=nonexistent を指定して認可リクエストを送る

**検証（合否を判定する）**

- invalid_request にはならない
- 同意画面で止まる（＝ none 扱いになっていない）
- 認可コードは発行されない

**補足**

- **`none` を含む語でも併記のエラーにならないこと**を見ている（`nonexistent` は `none` ではないので、単独の未知の値として扱う）。**`prompt=nonexistent none` なら併記のエラーになる。**

## RT-272.4 同意の記録が無いまま prompt=none で来たら、redirect_uri へ consent_required を返す

| | |
|---|---|
| 観点 | **これが C-3 そのものである。** 以前は**同意の記録を持っていなかった**ため、`prompt=none` は**同意画面を出さずに code を発行**していた。**セッションさえ生きていれば、どのクライアントも無音で認可を取得できた。**いまは**記録が無ければ UI が必要**と判断し、**UI を出せない指定なのでエラーを返す**（OIDC Core §3.1.2.6）。 |
| 根拠 | OIDC Core §3.1.2.1 / §3.1.2.6（consent_required）/ #272 の段階 2 / C-3 / D-6 |
| テスト | `RT27204_同意の記録が無ければpromptのnoneはconsent_required` |

**手順**

1. prompt=none を指定して認可リクエストを送る

**検証（合否を判定する）**

- エラー画面ではなく、リダイレクトで返る
- redirect_uri へ返る
- エラーは consent_required
- state が返る
- 認可コードは発行されない

**補足**

- **このテストは「許可」を押さない。** 押すと記録が残り、**DB ストアでは 2 回目の実行から測れなくなる**（`TestClients` の表に注記してある）。

## RT-272.5 prompt=consent は、同意済みでも同意画面を出す

| | |
|---|---|
| 観点 | **同意を記録すると「2 回目からは出ない」**ことになるが、**利用者が確かめ直したいときの口が要る。**§3.1.2.1 は `prompt=consent` を「同意を取り直せ」と定めている。 |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 2 |
| テスト | `RT27205_promptのconsentは記録が在っても同意画面を出す` |

**手順**

1. まず同意を記録する（記録が在る状態を作る）
1. prompt を付けずに送ると、同意画面は出ない（記録が効いている）
1. prompt=consent を付けると、同意画面が出る

**検証（合否を判定する）**

- 同意画面は出ない
- 同意画面が出る

**補足**

- **`prompt=none consent` は段階 1 で `invalid_request`** になる（`none` の併記）。**矛盾する指定は、そこで弾いている。**

## RT-272.6 同意画面で「拒否」を押すと、redirect_uri へ access_denied を返す

| | |
|---|---|
| 観点 | **以前は認可画面に Deny ボタンが無く、利用者は拒否できなかった**（`ANALYSIS-IdP.md` の E-6）。**`access_denied` を返す経路も無かった。****同意を記録するなら、拒否もできなければ筋が通らない。** |
| 根拠 | RFC 6749 §4.1.2.1（access_denied）/ E-6 / #272 の段階 2 |
| テスト | `RT27206_同意画面で拒否するとaccess_denied` |

**手順**

1. prompt=consent で同意画面を出す
1. 「拒否」を押す

**検証（合否を判定する）**

- 同意画面が出る
- リダイレクトで返る
- エラーは access_denied
- 認可コードは発行されない

**補足**

- **拒否は記録しない。** 「拒否した」を覚えて次回以降自動で断ると、**利用者が気を変えられなくなる。**

## RT-272.7 管理画面から同意を取り消すと、次の prompt=none が consent_required になる

| | |
|---|---|
| 観点 | **記録するなら、取り消せなければならない。**取り消さないと**記録が増えるだけ**になり、**利用者が「どのアプリに何を許したか」を解除できない。****取り消しても、発行済みのトークンは失効しない**（そちらは `/revoke`（RFC 7009）の役目）。**効果は「次の認可で同意画面が出る」こと**である。 |
| 根拠 | OIDC Core §3.1.2.6 / #272 の段階 2 / D-6 |
| テスト | `RT27207_管理画面から同意を取り消せる` |

**手順**

1. 同意を記録する
1. 管理画面の一覧に、このクライアントが出る
1. 管理画面から取り消す
1. 取り消した後の prompt=none は consent_required

**検証（合否を判定する）**

- prompt=none で認可コードが返る（記録が効いている）
- 一覧に client_name が出る
- 取り消しが受け付けられる
- エラーは consent_required
- 認可コードは発行されない

**補足**

- **このテストは、終わった時点で記録を残さない。****DB ストアでも 2 回目以降の実行で同じ結果になる。**

## RT-272.8 prompt=login は、サインイン済みでも再認証を求める

| | |
|---|---|
| 観点 | **`prompt=login` は「利用者を認証し直せ」という指定**（OIDC Core §3.1.2.1）。**以前は未処理で、無視していた**（`ANALYSIS-IdP.md` の C-3）。**`max_age` の再認証と同じ経路**を使う — 印を残してサインアウトし、同じ URL に戻す。**印（`re_auth_at`）が無いと、戻ってきた要求にも `prompt=login` が付いているので永久に送り返すことになる。** |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 2 |
| テスト | `RT27208_promptのloginは再認証を求める` |

**手順**

1. prompt=login を付けて認可リクエストを送る
1. 戻された先は、サインイン画面（サインアウトされている）
1. 再認証すると先へ進む（繰り返しにならない）
1. 別の要求の prompt=login は、また再認証を求める（印は要求ごと）

**検証（合否を判定する）**

- 認可コードは発行されない
- 同じ URL へ戻される（再認証の経路）
- サインイン画面へ送られる
- 認可コードが返る（印が効いている）
- **別の要求には、印が効かない**（認可コードは発行されず、同じ URL へ戻される）

**補足**

- **印が無いと、ここで永久に送り返す。** `max_age=0` でも同じことが起きるので、**#247 で入れた印（`re_auth_at`）をそのまま使っている。**
- **印は、再認証を求めた要求に結び付けてある**（#294）。**以前は、どの要求にも効いた**ので、途中でやめた再認証の印が残ると、**別の RP の `prompt=login` が再認証なしで通った。**
- **`prompt=none login` は段階 1 で `invalid_request`** になる（`none` の併記）。**「UI を出せないのに再認証」にはならない。**

## RT-272.9 prompt=select_account は、同意済みでも同意画面を出す（アカウントを選べる画面へ）

| | |
|---|---|
| 観点 | **`prompt=select_account` は「アカウントを選ばせろ」という指定**（OIDC Core §3.1.2.1）。**以前は未処理で、無視していた**。**この実装はアカウントの一覧から選ぶ仕組みを持っていない**ので、**同意画面を出す**ところまでである（その画面に「別のアカウントでログイン」が在り、そこから切り替えられる）。 |
| 根拠 | OIDC Core §3.1.2.1 / #272 の段階 2 |
| テスト | `RT27209_promptのselect_accountは同意画面を出す` |

**手順**

1. prompt を付けなければ、同意画面は出ない（記録が効いている）
1. prompt=select_account を付けると、同意画面が出る
1. その画面から、別のアカウントへ切り替えられる

**検証（合否を判定する）**

- 同意画面は出ない
- 同意画面が出る
- 「別のアカウントでログイン」が在る

**補足**

- **アカウントの一覧から選ぶ仕組みは持っていない。** 仕様（§3.1.2.1）は「選ばせろ」だが、**この実装は 1 利用者ずつのサインインしか持たない**。**`account_selection_required` を返す道もあった**が、**切り替えの口が画面に在るので、画面を出す方を選んだ。**

## RT-277.1 クライアント登録は client_id → client_secret → 登録 の 3 回押しで入る

| | |
|---|---|
| 観点 | **`/Manage/AddSaml2OAuth2Data` は、`client_id` が空のままでは登録できない。****1 回目で「登録」を押しても、黙って何も起きない**（`submit.Add` は `model.ClientID` が空なら素通りする）。**#277 の段階 1・3 で手を入れた画面**なので、**登録の経路そのものを測って残す**（段階 7）。 |
| 根拠 | #277 / ManageController.AddSaml2OAuth2Data |
| テスト | `RT27701_クライアント登録は3回押しで入る` |

**手順**

1. 画面を開く
1. この時点で「登録」を押しても、入らない
1. client_id を発行する
1. client_secret を発行する
1. 登録する

**検証（合否を判定する）**

- client_id は空から始まる
- 登録されない
- client_id が入る
- client_secret が入る
- client_id は変わらない
- 登録される
- 消せる（後片付け）

**補足**

- **エラーも出ない。** 画面が出し直されるだけである。**「押したのに何も起きない」ので、3 回押しだと気付けない。**

## RT-277.2 折り返し先の記号が、画面の候補（datalist）から選べる

| | |
|---|---|
| 観点 | **`redirect_uri_*` には記号（`test_self_code` など）を書ける**が、**画面には何も出ておらず、知っている人しか書けなかった**（#277 の段階 3）。**`<input>` ＋ `<datalist>` にして、候補を画面に出した。****新規登録の `redirect_uri_code` の既定も `test_self_code`** である（**以前は `test_self_code_manage`**。管理画面のトークン取得の廃止で戻した）。 |
| 根拠 | #277 / ManageAddSaml2OAuth2DataViewModel の *Candidates |
| テスト | `RT27702_折り返し先の候補がdatalistに出る` |

**手順**

1. 入力欄に datalist が結び付いている
1. 候補の中身
1. 新規登録の redirect_uri_code の既定

**検証（合否を判定する）**

- RedirectUriSaml に候補が付いている
- RedirectUriCode に候補が付いている
- RedirectUriToken に候補が付いている
- PostLogoutRedirectUri に候補が付いている
- BackChannelLogoutUri に候補が付いている
- FrontChannelLogoutUri に候補が付いている
- RedirectUriSaml の候補に test_self_saml が在る
- RedirectUriCode の候補に test_self_code が在る
- RedirectUriToken の候補に test_self_token が在る
- PostLogoutRedirectUri の候補に test_self_logout が在る
- BackChannelLogoutUri の候補に test_self_bclogout が在る
- FrontChannelLogoutUri の候補に test_self_fclogout が在る
- 既定は test_self_code

**補足**

- **`test_self_code_manage` は削除した。** **管理画面の「トークンを取る」（＝ その記号の行き先）ごと廃止した**ため。

## RT-277.3 WebAuthn の資格情報は、選んだものだけが、選んだ数だけ消える

| | |
|---|---|
| 観点 | **画面は同じ名前のチェックボックスを並べる**ので、**選んだ数だけ同名の値が送られる**（`publicKeys=A&publicKeys=B`）。**`string` で受けると先頭の 1 つしか届かない**（`ValueProviderResult.FirstValue`）ので、**複数選んでも 1 件しか消えなかった**（#277 の段階 6）。**`string[]` で受けるように直した。** |
| 根拠 | #277 / ManageController.RemoveWebAuthnData |
| テスト | `RT27703_選んだ資格情報だけが選んだ数だけ消える` |

**手順**

1. 一覧を開く（種データが 3 件入っている）
1. 2 つ選んで削除する

**検証（合否を判定する）**

- 2 件以上ある（前提）
- 選んだ数だけ減る
- 選んだものが消えている
- 選んでいないものは残っている

**観測（判定しない）**

- 登録されている資格情報
  - **種データが用意したもの**（`FIDO.TestCredentials`）。**認証器が無いと作れない**ので、E2E では作れない。
- 削除した値

**補足**

- **直す前は、ここで 1 件しか減らなかった。** **2 つ送っても、先頭の 1 つしか届いていなかった**ためである。
- **描画は測っていない。** **段階 6 のもう一方の不具合**（`class="form-control"` で**チェックの印が描かれない**）は、**ブラウザでなければ見えない。**

## RT-277.4 利用者名を変えると、新しい名前でサインインでき、古い名前では入れない

| | |
|---|---|
| 観点 | **利用者名の編集は、常に出せる**（#151 の段階 3）。**画面が「変えた」と言うだけでは足りない** — **新しい名前で入れて、古い名前では入れない**ことまで見る。**元に戻せること**も押さえる（#277 の段階 7）。 |
| 根拠 | #151 の段階 3 / #277 / ManageController.ChangeUserName |
| テスト | `RT27704_利用者名を変えると新しい名前でサインインできる` |

**手順**

1. 使い捨ての利用者を作る
1. 利用者名を変える
1. 新しい名前で入れて、古い名前では入れない
1. 元に戻す

**検証（合否を判定する）**

- 作った利用者でサインインできる
- 管理画面へ戻る（変更の成功）
- 画面の値が新しい名前になる
- 新しい名前でサインインできる
- 古い名前ではサインインできない
- 元の名前に戻せる

**補足**

- **メアドは変えていない。** 利用者名とメアドは別の項目である（#151 の段階 3）。

## RT-277.5 パスワードを変えると、新しいパスワードで入れ、古いものでは入れない

| | |
|---|---|
| 観点 | **変更の後は再サインインが要る**（`ReSignInAsync`）。**画面が「変えた」と言うだけでは足りない** — **新しいパスワードで入れて、古いものでは入れない**ことまで見る。**元に戻せること**も押さえる（#277 の段階 7）。 |
| 根拠 | #277 / ManageController.ChangePassword |
| テスト | `RT27705_パスワードを変えると新しいパスワードでサインインできる` |

**手順**

1. 使い捨ての利用者を作る
1. パスワードを変える
1. 新しいパスワードで入れて、古いものでは入れない
1. 元に戻す

**検証（合否を判定する）**

- 管理画面へ戻る（変更の成功）
- 新しいパスワードでサインインできる
- 古いパスワードではサインインできない
- 元のパスワードに戻せる

**補足**

- **値は出していない。** 新しいパスワードは構成ファイルの値から作っている（`TESTING.md` 9 節）。

## RT-277.6 メアドの変更は、確認メールを挟む（押しただけでは変わらない）

| | |
|---|---|
| 観点 | **メアドは、その場では変わらない。****確認用の符号を作ってメールを送り、確認画面を返す**（`CustomizedConfirmationProvider` ＋ `VerifyEmailAddress`）。**他人のメアドを勝手に自分のものにできない**ための作りである。**E2E はメールを読めない**ので、**ここまでを測る**（#277 の段階 7）。 |
| 根拠 | #277 / ManageController.ChangeEmail |
| テスト | `RT27706_メアドの変更は確認を挟む` |

**手順**

1. 使い捨ての利用者を作る
1. 管理画面に、いまのメアドが出ている
1. メアドの変更を送る
1. この時点では、まだ変わっていない
1. 古いメアドのままサインインできる

**検証（合否を判定する）**

- いまのメアドが出る
- HTTP 200（確認の画面）
- 入力の画面ではない（確認の画面に移っている）
- その場で変わってはいない
- メアドは元のまま
- 新しいメアドにはなっていない
- 古いメアドでサインインできる

**補足**

- **確認の後（メールの符号を使った先）は測っていない。****E2E はメールを読めない。** 測っているのは**「押しただけでは変わらない」**ところまで。

## RT-277.7 GDPR の参照は、自分の利用者データを JSON のファイルとして返す

| | |
|---|---|
| 観点 | **自分のデータを持ち出せること**（データ ポータビリティ）を見る。**ファイルとして返す**ので、`Content-Type` と `Content-Disposition` も押さえる。**中身は自分のもの**であること（利用者名とメアドが入っている）。 |
| 根拠 | #277 / ManageController.ReferGdprPersonalData |
| テスト | `RT27707_GDPRの参照は自分のデータをJSONで返す` |

**手順**

1. 使い捨ての利用者を作って、サインインする
1. 参照の口を叩く
1. 中身が自分のものである

**検証（合否を判定する）**

- HTTP 200
- application/json で返る
- ファイル名が user.json である
- JSON として読める
- 利用者名が自分のものである
- メアドが自分のものである
- PasswordHash は入っていない
- SecurityStamp は入っていない
- TotpAuthenticatorKey は入っていない
- TotpTokens は入っていない
- DeviceToken は入っていない

## RT-277.8 GDPR の消去で、利用者の行ごと消え、その利用者ではサインインできなくなる

| | |
|---|---|
| 観点 | **消去は、行ごと消す**（#299 でそう改めた）。**`Users` の行と、外部キー（`ON DELETE CASCADE`）で落ちる子**（ロール・外部ログイン・クレーム・2 要素認証のトークン・WebAuthn の資格情報・同意の記録・`sub` の対応表・**その利用者が登録したクライアント**）**が消える。****以前は属性を潰す実装**だったが、**潰す対象（`Users.UserName` / `ClientID`）が外部キーの参照先**で、**WebAuthn を使う人とクライアントを登録した人は、消去が DB に弾かれていた**（例外は握られるので画面は成功に見えた。#300）。 |
| 根拠 | #277 / #299 / ManageController.DeleteGdprPersonalData |
| テスト | `RT27708_GDPRの消去で個人情報が消える` |

**手順**

1. 使い捨ての利用者を作って、属性データとクライアント登録を入れる
1. 消去の口を叩く
1. サインアウトしている
1. 消した利用者では、もうサインインできない
1. 管理画面の一覧から、その利用者が消えている

**検証（合否を判定する）**

- クライアントを登録できている（前提）
- 属性データが入っている（前提）
- どこかへリダイレクトする（消去の成功）
- 管理画面が開かない
- 利用者名では入れない
- メアドでも入れない
- 元の利用者名が出ない
- 元のメアドが出ない
- 利用者 id も一覧に出ない（行ごと消えている）

**補足**

- **行ごと消える**（#299）。**以前は属性を潰すだけだった**ので、**一覧には利用者 id の名前で残っていた。****`Users` への外部キーは 8 本すべて `ON DELETE CASCADE`** なので、**子の行は DB が落とす**（`mem` では WebAuthn の資格情報だけ、画面の側で消している）。
- **クライアントを登録した利用者で測っている**（#299）。**当時は `Saml2OAuth2Data.ClientID` が `Users.ClientID` を参照していた**ので、**「`ClientID` を利用者 id で潰す」実装では、`UPDATE` が外部キーで弾かれ、消去が丸ごと失敗していた**（例外は握られ、画面は成功に見えた。#300）。**行ごと消す形では、cascade で登録も落ちる。** **#307 の段階 5-a-1 で、外部キーは `OwnerUserId` → `Users.Id` に張り替わった** — **1 人が n 件持てるので、n 件とも落ちる。**
- **この 3 つは、別々のことを見ている。****サインインできないこと**は、**行が無くても、属性が潰れていても成り立つ**（以前の実装では `EmailConfirmed = false` が効いていた。実測）。**行ごと消えたかどうかは、利用者 id が一覧に出ないこと**で分かる。

## RT-277.9 管理画面の一覧に n 件出て、**別々に編集できる**

| | |
|---|---|
| 観点 | **1 利用者 n クライアント**になった（#307 の段階 5-a-1）が、**画面は「所有者の先頭 1 件」しか扱えなかった** — **2 件目は、動的登録で作れても画面に出てこなかった。****段階 5-a-2 で一覧にした**ので、**並ぶこと・どれを編集するか指せること・取り違えないこと**を測る。 |
| 根拠 | #307 の段階 5-a-2 / ManageController.Saml2OAuth2DataList |
| テスト | `RT27709_一覧にn件出て別々に編集できる` |

**手順**

1. 画面から 2 件登録する
1. 一覧に 2 件とも出る
1. 並びは client_id の昇順
1. 2 件目を指して編集の画面を開く
1. 2 件目だけを直しても、1 件目は変わらない
1. 後片付け

**検証（合否を判定する）**

- 1 件目が登録できる
- 2 件目も登録できる
- 別の client_id である
- 一覧は 2 件
- 1 件目が出る
- 2 件目が出る
- 昇順である
- その client_id が出る
- 編集中の印が付く
- client_id を作り直すボタンは出ない
- 2 件目は直った
- 1 件目は変わっていない
- 一覧は 2 件のまま
- 全部消える

**補足**

- **段階 5-a-2 より前は、2 件目の保存で 1 件目が消えていた** — **画面が 1 件だけを扱うために、古い行を消していた**ためである。
- **並びを決めたのは段階 5-a-2**（`Saml2OAuth2DataProvider.GetByOwner` の `ORDER BY`）。**`mem` も方言 3 つも同じ順**にしてある — **決めていないと、一覧の行が毎回入れ替わる。**
- **作り直すと別のクライアントになり、更新ではなく新規の登録になる。****`registration_access_token` も引き継げない**ので、**動的登録で作られた行は、管理 API（RFC 7592）から触れなくなる。**

## RT-277.10 **他人の `client_id` は、画面から編集も削除もできない**

| | |
|---|---|
| 観点 | **一覧から `clientId` を受ける**ようにした（#307 の段階 5-a-2）。**URL もフォームも書き換えられる**ので、**所有者の照合はサーバ側で行う。****動的登録の側は `registration_access_token` で守っている**（RFC 7592 §2）が、**画面の側は「サインインしている利用者が所有者か」だけが頼り**である。 |
| 根拠 | #307 の段階 5-a-2 / Saml2OAuth2DataProvider.GetByOwnerAndClientID |
| テスト | `RT27710_他人のclient_idは画面から触れない` |

**手順**

1. 他人の client_id を指して、編集の画面を開く
1. 自分の一覧にも出ない
1. 在りもしない client_id でも、同じように断る
1. 削除も通らない（他人の登録は残る）

**検証（合否を判定する）**

- 編集の画面にならない
- その client_id が画面に出ない
- 一覧に他人の登録が出ない
- 自分の一覧は 0 件
- 編集の画面にならない
- 他人の登録は残っている

**補足**

- **「在るが自分の物でない」と「無い」を撃ち分けない** — **他人の `client_id` を当てられたかどうかを、外から分からせない**ためである（**動的登録の `404` と同じ倒し方**。RFC 7592 §2.1）。

## RT-277.11 一覧から **1 件だけ**消せる（残りは残る）

| | |
|---|---|
| 観点 | **削除は一覧の行から行う**ようにした（#307 の段階 5-a-2）。**段階 5-a-1 までは「所有者の先頭 1 件」を黙って消していた** — **n 件になると、どれが消えるのか押す側に分からない。****行から `clientId` を渡す**ので、**指した 1 件だけが消える。** |
| 根拠 | #307 の段階 5-a-2 / ManageController.RemoveSaml2OAuth2Data |
| テスト | `RT27711_一覧から1件だけ消せる` |

**手順**

1. 2 件登録する
1. 一覧の 2 行目だけを消す
1. 残った 1 行目は、まだ編集できる
1. 消した行は、もう開けない
1. 後片付け

**検証（合否を判定する）**

- 一覧は 2 件
- 一覧の行から送れた
- 一覧は 1 件になる
- 残っているのは 1 行目
- 編集の画面が開く
- 編集の画面にならない
- 全部消える

## RT-279.1 SameSite=None を宣言した Cookie が、Cookie ポリシーで格上げされない

| | |
|---|---|
| 観点 | **`app.UseCookiePolicy()` の引数を外し、DI 側に一本化した**（#279）。**引数を渡す overload は DI の設定を読まない**ので、**一本化し損なうと `MinimumSameSitePolicy` の明示が失われ、`samesite` 属性ごと出なくなる**（実測）。**属性が無ければブラウザ側の既定（Chrome は `Lax`）が適用される**ので、**ID 連携の外部ログインや `response_mode=form_post` の戻りで、Cookie が送られなくなる。****ブラウザを使わないと気付けない**ので、ここで固定する。 |
| 根拠 | #279（上流 Open棟梁 #541） |
| テスト | `RT27901_SameSiteがNoneのCookieが格上げされない` |

**手順**

1. 自己テストのボタンを押して、Set-Cookie を受け取る
1. test_state の Cookie が SameSite=None のままである
1. HttpOnly も効いている

**検証（合否を判定する）**

- Set-Cookie が返る
- test_state の Set-Cookie がある
- samesite=none である
- httponly が付く

**補足**

- **`CookieSecurePolicy` は既定（空）のままなので、`Secure` 属性は各 Cookie の宣言に従う。**`always` にすると全部に付くが、**平文 HTTP ではサインインできなくなる**ので既定では変えない（#279）。

## RT-292.1 上流 IdP の管理画面で、登録を足して・直して・消せる

| | |
|---|---|
| 観点 | **上流の登録を、運用で足せるようにする**（#292 の段階 2）。**設定ファイルを書き換えずに増やせる**ことが、この段階の値打ちである。**上流の登録は配備全体のもの**なので、**画面は `UsersAdmin` の隣**に置き、**認可も同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`）。 |
| 根拠 | #292 の段階 2 |
| テスト | `RT29201_管理画面で上流を足して直して消せる` |

**手順**

1. 一覧が開く
1. 上流を足す（SAML2 の行）
1. 表示名を直す
1. 消す

**検証（合否を判定する）**

- 一覧に「追加」の導線が在る
- 追加すると一覧へ戻る
- 一覧に出る
- 表示名も出る
- 編集すると一覧へ戻る
- 新しい表示名が出る
- 削除できる
- 一覧から消える

## RT-292.2 user store に足した上流が、サインイン画面の導線に出る

| | |
|---|---|
| 観点 | **設定ファイルを書き換えずに、上流を増やせること**（#292 の段階 2）。**読む順は 設定 → user store** なので、**設定の行と DB の行が、両方とも導線に出る。****出なければ、画面は登録を見ていない** — **管理画面だけ在っても、連携は増えない。** |
| 根拠 | #292 の段階 1・2 |
| テスト | `RT29202_DBに足した上流がサインイン画面に出る` |

**手順**

1. 足す前のサインイン画面を見る
1. user store に 1 件足す
1. サインイン画面に、その導線が出る
1. 後片付け（消して、導線も消える）

**検証（合否を判定する）**

- 足す前は、その導線が無い
- 足した上流の導線が出る
- 設定の行（既定の導線）も残っている
- 消すと導線も消える

## RT-292.3 管理者でなければ、上流 IdP の管理画面は開かない

| | |
|---|---|
| 観点 | **上流の登録は配備全体のもの**なので、**`SystemAdmin` だけが編める**（`UsersAdmin` / `RolesAdmin` と同じ認可）。**雛形のテスト利用者は `User` / `Admin` しか持たない**ので、**その利用者では開かないこと**を見る。 |
| 根拠 | #292 の段階 2 / #258 |
| テスト | `RT29203_管理者でなければ上流の管理画面は開かない` |

**手順**

1. テスト利用者でサインインする（管理者とは別の入れ物）
1. 一覧を開く

**検証（合否を判定する）**

- テスト利用者でサインインできている
- 一覧の画面にならない

**観測（判定しない）**

- 応答
  - **門番が例外を投げる**ので、エラー画面か 500 になる（`UsersAdmin` と同じ振る舞い）。

## RT-292.4 上流ごとの署名鍵（`.pfx`）が、user store でも往復する

| | |
|---|---|
| 観点 | **(2) の署名鍵を、上流ごとに替えられるようにした**（#292 の段階 4-a）。**段階 4-b は、それを DB と画面からも扱えるようにしたもの**である。**`.pfx` のパスワードは暗号化して保管する**（#297）ので、**読み直したときに平文に戻ること**を測る — **戻らなければ `.pfx` を開けず、黙って共通設定に倒れる。** |
| 根拠 | #292 の段階 4-b / #297 |
| テスト | `RT29204_上流ごとの署名鍵がuser_storeでも往復する` |

**手順**

1. 署名鍵付きで足す
1. 編集画面を開くと、同じ値が出る
1. 後片付け

**検証（合否を判定する）**

- 追加できる
- `.pfx` のパスが往復する
- パスワードが平文に戻る
- 暗号文がそのまま出ていない
- 消せる

**補足**

- **このケースが測るのは、入れ物（表・辞書）と画面である。****DB の行の鍵で実際に署名するところまでは測っていない** — **配備の `.pfx` のパスワードをテストに持たせない**ためである（`TESTING.md` 9 節）。**指定した鍵で署名していることは、`CN-5.5`（コンテナ。設定の行）とその歯抜けで測っている。**

## RT-294.1 登録に auth を明記していないクライアントは、scope=auth を付けても同意画面を飛ばせない

| | |
|---|---|
| 観点 | **以前は、要求に `auth` を付けるだけで同意画面を飛ばせた**（`AccountController.OAuth2Authorize` が、要求された scope をそのまま見ていた）。**同意を求めるかを、クライアントが決めていた**ことになる。**いまは、登録に明記したクライアントの要求だけを数える。** |
| 根拠 | OIDC Core §3.1.2.4 / §3.1.2.6（consent_required）/ #294 |
| テスト | `RT29401_登録にauthが無ければ同意画面を飛ばさない` |

**手順**

1. scope=openid auth、prompt=none を指定して認可リクエストを送る

**検証（合否を判定する）**

- エラーは consent_required
- 認可コードは発行されない

**補足**

- **このテストは「許可」を押さない。** 押すと記録が残り、**DB ストアでは 2 回目の実行から測れなくなる**（`TestClients` の表に注記してある）。

## RT-294.2 登録に auth を明記したクライアントは、同意画面を出さずに code を返し、scope を auth と openid に絞る

| | |
|---|---|
| 観点 | **`auth` の働きそのものは残す**（認証だけをしたいクライアント向け）。**登録で絞った結果、明記したクライアントで効かなくなっていない**ことを確かめる。**属性は渡さない**ので、`email` を一緒に要求しても発行されない（`FilterClaimAtAuth`）。 |
| 根拠 | OIDC Core §3.1.2.4 / #294 |
| テスト | `RT29402_登録にauthを明記すれば同意画面を飛ばす` |

**手順**

1. scope=openid auth email、prompt=none を指定して認可リクエストを送る
1. code をトークンに交換し、発行された scope を見る

**検証（合否を判定する）**

- 認可コードが返る（同意画面を飛ばした）
- auth が発行される
- email は発行されない（属性を渡さない）

## RT-294.3 scope=AUTH は auth として扱わない（登録に auth を明記したクライアントでも、同意画面を飛ばさない）

| | |
|---|---|
| 観点 | **以前は小文字にしてから比べていた**ので、`AUTH` でも同意画面を飛ばした。**scope の値は case-sensitive**（RFC 6749 §3.3）。**`AUTH` は、この配備が扱わない別の scope** である。 |
| 根拠 | RFC 6749 §3.3 / #294 |
| テスト | `RT29403_authは大文字小文字を区別する` |

**手順**

1. scope=openid AUTH、prompt=none を指定して認可リクエストを送る

**検証（合否を判定する）**

- エラーは consent_required
- 認可コードは発行されない

## RT-294.4 確認待ちのメアドで登録し直しても、既存の利用者は作り直されない

| | |
|---|---|
| 観点 | **以前は、確認待ちの利用者を消して、送られてきたパスワードで作り直していた。****他人が登録し直すとパスワードを差し替えられ**、**確認のメールは本人に届くので、本人が踏むと差し替えたパスワードのまま確認済みになった。****作り直しをやめ、既存の利用者に確認のメールを送り直すだけにした**（画面は成功のときと同じ）。 |
| 根拠 | #294（AccountController.SignUp.cs のレビュー 1・3・4） |
| テスト | `RT29404_確認待ちのメアドで登録し直しても作り直されない` |

**手順**

1. 1 人目をサインアップする（メアドは確認待ちのまま）
1. 同じメアドで、別の利用者名で登録し直す
1. 管理画面の一覧で、利用者を確かめる
1. 後片付け : 管理画面から削除する

**検証（合否を判定する）**

- HTTP 200
- **成功のときと同じ画面**（メアド検証の画面。入力欄もエラーも無い）
- **1 人目が残っている**（消して作り直していない）
- **2 人目は作られていない**

**補足**

- **パスワードは変わらない。** 忘れていれば、パスワードの失念から戻せる（確認前でもリセットできる）。**確認のメールは 1 人目に送り直される**（中身は測れない）。

## RT-294.5 パスワードの失念は、居ないメアドでも、居るメアドと同じ画面になる

| | |
|---|---|
| 観点 | **コメントには「ユーザーが存在しないことを（UI経由で）公開しない」と書いてあった**が、**居なければ入力画面を出し直し、居れば確認画面を出していた。****画面の違いで、メアドが登録されているかが分かった。****どちらも確認画面を返す**ように直した（メールは居るときだけ送る）。 |
| 根拠 | #294（AccountController.SignUp.cs のレビュー 2） |
| テスト | `RT29405_パスワードの失念は居ないメアドでも同じ画面になる` |

**手順**

1. 居る利用者を作る（サインアップ。確認待ちでもリセットできる）
1. 居るメアドで、パスワードの失念を送る
1. 居ないメアドで、パスワードの失念を送る
1. 後片付け : 管理画面から削除する

**検証（合否を判定する）**

- HTTP 200（居る）
- 確認画面になる（入力欄が無い）
- HTTP 200（居ない）
- **確認画面になる**（入力画面を出し直さない）
- **居るときと同じ画面である**（題名・見出し・欄）

## RT-294.6 利用者が居ないメアド検証・リセットは、500 にならずエラー画面になる

| | |
|---|---|
| 観点 | **メールのリンクは、利用者が消えた後にも踏まれる**（古いメール・書き換えた URL）。**以前は、引けなかった利用者（null）をそのまま Identity に渡し、500 になっていた。****4 か所とも、エラー画面を返す**ように直した。 |
| 根拠 | #294（AccountController.SignUp.cs のレビュー 5） |
| テスト | `RT29406_利用者が居ないときはエラー画面になる` |

**手順**

1. GET /Account/EmailConfirmation
1. POST /Account/EmailConfirmation（約款に同意）
1. GET /Account/ResetPassword
1. POST /Account/ResetPassword

**検証（合否を判定する）**

- GET /Account/EmailConfirmation : HTTP 200（500 にならない）
- GET /Account/EmailConfirmation : エラー画面になる
- POST /Account/EmailConfirmation : HTTP 200（500 にならない）
- POST /Account/EmailConfirmation : エラー画面になる
- GET /Account/ResetPassword : HTTP 200（500 にならない）
- GET /Account/ResetPassword : エラー画面になる
- POST /Account/ResetPassword : HTTP 200（500 にならない）
- POST /Account/ResetPassword : エラー画面になる

**補足**

- **(2) は約款を出す配備（DisplayAgreementScreen）でだけ、利用者を引く枝に入る。****出さない配備では、入口でエラー画面になる**（どちらでもエラー画面であることは同じ）。

## RT-294.7 リセット画面は、code が合わなければメアドを出さない（エラー画面になる）

| | |
|---|---|
| 観点 | **以前は code を確かめずに、userId の利用者のメアドを画面に出していた。****userId が分かれば、code が何でもメアドが読めた。****code を確かめてから画面を出す**ように直した（合わなければエラー画面）。 |
| 根拠 | #294（AccountController.SignUp.cs のレビュー 6） |
| テスト | `RT29407_リセット画面はcodeが合わなければメアドを出さない` |

**手順**

1. 利用者を作り、管理画面の一覧で id を引く
1. でたらめな code で、リセット画面を開く
1. 後片付け : 管理画面から削除する

**検証（合否を判定する）**

- HTTP 200（500 にならない）
- **エラー画面になる**
- **メアドが画面に出ない**

**補足**

- **正しい code での表示は測れない**（code はメールでしか届かない）。

## RT-294.8 TOTP でサインインすると、セッションが初期化され、1 回間違えても戻り先へ戻る

| | |
|---|---|
| 観点 | **パスワード・コードの 2FA・プッシュ承認は、サインインの後にセッションを初期化する**（セッション ID の切り替え、`auth_time` と OP のセッション（#310 の `sid`）の Cookie）。**TOTP の 2 か所だけ、それを呼んでいなかった。****また、1 回間違えると画面を出し直すときに戻り先を渡さず、認可要求の続きに戻れなかった。** |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 1・4） |
| テスト | `RT29408_TOTPでサインインするとセッションが初期化される` |

**手順**

1. 利用者を作り、認証アプリを登録して 2FA を有効にする
1. パスワードでサインインし、手段に認証アプリを選ぶ
1. まず、間違ったコードを送る
1. 正しいコードを送る（再表示されたフォームから）

**検証（合否を判定する）**

- TOTP の入力画面へ送られる
- HTTP 200（再表示）
- エラーが出ている
- **再表示のフォームが、戻り先を持っている**
- **戻り先へリダイレクトする**
- **`auth_time` の Cookie が書かれている**（InitSessionAfterlogin）
- **OP のセッションの Cookie が書かれている**（#310 の `sid` の元）
- 保護された画面が開く

## RT-294.9 回復コードでサインインしても、セッションが初期化され、戻り先へ戻る

| | |
|---|---|
| 観点 | **RT-294.8 と同じ穴が、回復コードの口にもあった。** |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 1） |
| テスト | `RT29409_回復コードでサインインするとセッションが初期化される` |

**手順**

1. 利用者を作り、認証アプリを登録して 2FA を有効にする（回復コードも受け取る）
1. パスワードでサインインし、認証アプリを選んだ後、回復コードの画面へ
1. 回復コードを送る

**検証（合否を判定する）**

- 回復コードの入力画面が開く
- **戻り先へリダイレクトする**
- **`auth_time` の Cookie が書かれている**（InitSessionAfterlogin）
- **OP のセッションの Cookie が書かれている**（#310 の `sid` の元）

## RT-294.10 2FA の途中でなければ、TOTP・回復コードの画面はエラー画面になる

| | |
|---|---|
| 観点 | **コードの 2FA（SendCode / VerifyCode）は、パスワードを通った後でなければエラー画面を返す。****TOTP・回復コードの画面だけ、確かめるコードがコメントアウトされていて、誰でも開けた。** |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 5） |
| テスト | `RT29410_2FAの途中でなければTOTPの画面は開かない` |

**手順**

1. GET /Account/LoginWithTwoFactorAuthenticator?rememberMe=false
1. GET /Account/LoginWithTwoFactorAuthenticatorRecoveryCode

**検証（合否を判定する）**

- /Account/LoginWithTwoFactorAuthenticator?rememberMe=false : HTTP 200
- /Account/LoginWithTwoFactorAuthenticator?rememberMe=false : **エラー画面になる**（入力画面を出さない）
- /Account/LoginWithTwoFactorAuthenticatorRecoveryCode : HTTP 200
- /Account/LoginWithTwoFactorAuthenticatorRecoveryCode : **エラー画面になる**（入力画面を出さない）

## RT-294.11 TOTP を続けて間違えると、ロックアウトの画面になる（404 にならない）

| | |
|---|---|
| 観点 | **`Lockout` はアクションではなく画面である**（`Views/Shared/Lockout.cshtml`）。**TOTP・回復コードの 2 か所だけ `RedirectToAction("Lockout")` で、行き先が 404 だった。** |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 3） |
| テスト | `RT29411_TOTPを続けて間違えるとロックアウトの画面になる` |

**手順**

1. パスワードでサインインし、認証アプリを選ぶ
1. ロックアウトするまで、間違ったコードを送る（上限 20 回）

**検証（合否を判定する）**

- HTTP 200（404 にならない）
- **ロックアウトの画面になる**

## RT-294.12 画面に出していない手段を選ぶと、送らずに選び直しになる

| | |
|---|---|
| 観点 | **選ばれた手段を、画面に出した選択肢と突き合わせていなかった。****知らない値は TOTP として扱い、認証アプリを登録していない利用者も TOTP の画面へ送っていた。** |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 9） |
| テスト | `RT29412_画面に出していない手段は選べない` |

**手順**

1. パスワードでサインインし、存在しない手段を選ぶ

**検証（合否を判定する）**

- HTTP 200（選び直しの画面）
- **手段の選択画面が、エラー付きで出し直される**

## RT-294.13 コードの 2FA（Email）で間違えると文言が出て、ブラウザ記憶は既定で入っていない

| | |
|---|---|
| 観点 | **net10.0 版は、コードの誤り（`Failed`）で文言を出していなかった**（`IsNotAllowed` だけを見ていた）。**両版とも、ブラウザ記憶を常に入れた状態で画面を出していた**（既定のままだと、そのブラウザでは次から 2FA を飛ばした）。 |
| 根拠 | #294（AccountController.TwoFactor.cs のレビュー 2・6） |
| テスト | `RT29413_コードの2FAで間違えると文言が出る` |

**手順**

1. 利用者を作り、2FA を有効にする
1. パスワードでサインインし、手段に Email を選ぶ
1. 間違ったコードを送る

**検証（合否を判定する）**

- **ブラウザ記憶のチェックボックスが、既定で入っていない**
- HTTP 200（再表示）
- **エラーの文言が出る**

## RT-294.14 メールの送信に失敗しても、画面は普段どおりで、サイトは落ちない

| | |
|---|---|
| 観点 | **メールの送信は `async void` で、呼ぶ側は待っていなかった。****SMTP の失敗が処理されない例外になり、net10.0 版ではプロセスが落ちた**（サインアップ・パスワードの失念は、誰でも押せる）。**送信を要求から切り離し、失敗は受け止めて記録する**ように直した。 |
| 根拠 | #294（AccountController.Helper.cs のレビュー 1） |
| テスト | `RT29414_メールの送信に失敗してもサイトは落ちない` |

**手順**

1. サインアップする（確認のメールの送信が失敗する）
1. 同じメアドで、パスワードの失念を送る（リセットのメールの送信も失敗する）
1. 送信の失敗が起きるのを待ってから、サイトがまだ応えるかを見る
1. 後片付け : 管理画面から削除する

**検証（合否を判定する）**

- HTTP 200
- **メアド検証の画面になる**（送信の失敗を画面に出さない）
- HTTP 200
- 確認画面になる（入力欄が無い）
- **サイトが応える**（プロセスが落ちていない）

**補足**

- **送信の失敗は、OPERATION ログに「could not be sent」として残る**（E2E では読まない）。

## RT-294.15 /device_verify は、AntiForgery トークンが無ければ承認しない

| | |
|---|---|
| 観点 | **画面はトークンを埋めていたが、アクションが検証していなかった。****認証の Cookie は `SameSite=None`** なので、**別のサイトからの POST にも Cookie が付く。****利用者が意図しない `user_code` の承認を送らせられた。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー S1）/ RFC 8628 §5.4 |
| テスト | `RT29415_device_verifyはトークンが無ければ承認しない` |

**手順**

1. 機器 : デバイス認可を始める
1. サインイン済みの利用者のブラウザから、トークン無しで承認を送る
1. 機器 : トークンを要求する

**検証（合否を判定する）**

- **承認されない**（"Accepted." を出さない）
- **まだ authorization_pending**（承認は通っていない）
- トークンを発行しない

## RT-294.16 同意の記録が無いクライアントの Hybrid は、同意を求める（prompt=none なら consent_required）

| | |
|---|---|
| 観点 | **同意の判定は、code の分岐の中にしか無かった。****Implicit と Hybrid は、サインインしていれば同意を確かめずにトークンを発行した**（#272 の `consent_required` も効いていなかった）。**3 つのフローで共通にした。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー S2）/ OIDC Core §3.1.2.6 |
| テスト | `RT29416_同意の無いHybridは同意を求める` |

**手順**

1. prompt=none で要求する
1. prompt を付けずに要求する

**検証（合否を判定する）**

- **consent_required が返る**
- code も id_token も返さない
- **フラグメントで返る**（トークンを含む応答の形）
- **同意画面が出る**（トークンを返さない）

**補足**

- **「許可」は押さない**（`TestClient_19` に同意の記録を残さない）。

## RT-294.17 auth_time の Cookie を書き換えても、max_age の再認証は飛ばせない

| | |
|---|---|
| 観点 | **`max_age` の判定と id_token の `auth_time` は、平文の Cookie を読んでいた。****ブラウザ側で書き換えると、再認証を飛ばし、偽の時刻を RP に保証した。****値を改ざんできない形で包む**ようにした（DataProtection / MachineKey）。 |
| 根拠 | #294（AccountController.Authorize.cs のレビュー S3）/ OIDC Core §3.1.2.1 |
| テスト | `RT29417_auth_timeのCookieを書き換えても再認証は飛ばせない` |

**手順**

1. サインインから 2 秒待ち、auth_time の Cookie を「いま」の平文に書き換える
1. max_age=1 で要求する

**検証（合否を判定する）**

- **認可コードは発行されない**（書き換えた時刻を信じない）
- **再認証の経路へ送られる**（同じ URL へ戻される）

## RT-294.18 再認証の印の Cookie を書き換えても、prompt=login の再認証は飛ばせない

| | |
|---|---|
| 観点 | **`prompt=login` の印は、平文の Cookie が有るか無いかしか見ていなかった。****ブラウザ側で置くだけで、再認証を飛ばせた。****印は改ざんできない形で包み、再認証を求めた要求に結び付けた。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー S3）/ OIDC Core §3.1.2.1 |
| テスト | `RT29418_再認証の印を書き換えてもprompt_loginは飛ばせない` |

**手順**

1. 再認証の印の Cookie を、平文で置く
1. prompt=login で要求する

**検証（合否を判定する）**

- **認可コードは発行されない**（置いた印を信じない）
- **再認証の経路へ送られる**（同じ URL へ戻される）

## RT-294.19 Hybrid のエラーを JARM（fragment.jwt）で求めると、iss・aud・exp の入った JWT で返る

| | |
|---|---|
| 観点 | **エラーは、response_mode に関係なく query の平文で返していた。****また、Implicit の JARM は aud / exp / iss を入れていなかった**（JARM §2.1 では必須）。**応答の組み立てを 1 か所にまとめ、エラーも response_mode に従うようにした。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー 4・6）/ JARM §2.1 / §2.3 |
| テスト | `RT29419_HybridのエラーはJARMで返る` |

**検証（合否を判定する）**

- **フラグメントに response（JWT）が返る**
- error は consent_required
- **iss が入る**
- **aud は client_id**
- **exp が数値で入る**

## RT-294.20 Hybrid に response_mode=query は使えない（invalid_request が、フラグメントで返る）

| | |
|---|---|
| 観点 | **トークンを含む応答に query は使わない**（OAuth 2.0 Multiple Response Types §5）。**以前は、発行した後で応答を作れず、`error` が空のまま RP へ返っていた。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー 6） |
| テスト | `RT29420_Hybridにresponse_modeのqueryは使えない` |

**検証（合否を判定する）**

- **invalid_request が返る**（error が空でない）
- **フラグメントで返る**（その response_type の既定の形）
- code も id_token も返さない

## RT-294.21 request_uri（PAR）の Request Object と違う client_id を付けると、断る

| | |
|---|---|
| 観点 | **クエリの client_id を、Request Object の値で確かめずに上書きしていた**（RFC 9126 §4 / RFC 9101 §5 は一致を求める）。 |
| 根拠 | #294（AccountController.Authorize.cs のレビュー 8） |
| テスト | `RT29421_RequestObjectと違うclient_idは断る` |

**手順**

1. TestClient で、認可要求を預ける
1. 別のクライアントの client_id と、その request_uri で認可する

**検証（合否を判定する）**

- **認可コードは発行されない**
- **RP へ送らず、エラー画面になる**（どちらの redirect_uri も信じない）

## RT-294.22 同意画面のボタン（許可・拒否・別のアカウント）を送らない POST は、invalid_request を RP へ返す

| | |
|---|---|
| 観点 | **以前は画面を出し直していたが、画面の値（ViewBag）を組まずに返していた。** |
| 根拠 | #294（AccountController.Authorize.cs のレビュー 7） |
| テスト | `RT29422_同意画面のボタンが無いPOSTはinvalid_request` |

**手順**

1. 同意画面を出す
1. ボタンを付けずに POST する（トークンだけを送る）

**検証（合否を判定する）**

- **invalid_request を RP へ返す**
- state がそのまま返る

## RT-294.23 OIDC の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る

| | |
|---|---|
| 観点 | **以前は、ID 連携の後は常に Home へ戻していた**（`RedirectToLocal(絶対 URL)` はローカルと判定されず Home になる）。**認可要求の途中で ID 連携を使うと、RP への認可が続かなかった。****連携を始めるときに ReturnUrl を控え、戻ってきたら、そこへ返す**ようにした。 |
| 根拠 | #294（AccountController.*.cs のレビュー：ID 連携の戻り先） |
| テスト | `RT29423_OIDCのID連携の後はReturnUrlへ戻る` |

**手順**

1. ReturnUrl を付けて「ID連携でサインイン」を押し、最後まで流す

**検証（合否を判定する）**

- **ReturnUrl へ戻る**（Home ではない）

## RT-294.24 SAML2 の ID 連携でサインインすると、連携を始めた画面の ReturnUrl へ戻る

| | |
|---|---|
| 観点 | **RT-294.23 と同じ穴が、SAML2 の ID 連携にもあった。** |
| 根拠 | #294（AccountController.*.cs のレビュー：ID 連携の戻り先） |
| テスト | `RT29424_SAML2のID連携の後はReturnUrlへ戻る` |

**手順**

1. ReturnUrl を付けて「SAML2 の ID 連携」を押し、最後まで流す

**検証（合否を判定する）**

- **ReturnUrl へ戻る**（Home ではない）

## RT-294.25 登録されていない外部ログインの provider は、500 にならず、サインイン画面へ戻す

| | |
|---|---|
| 観点 | **net10.0 版は、知らない provider で `Challenge` が例外を出し、500 になっていた。****登録されている provider かを確かめてから始める**ようにした（両版）。 |
| 根拠 | #294（AccountController.*.cs のレビュー B4） |
| テスト | `RT29425_知らない外部ログインのproviderはサインイン画面へ戻す` |

**検証（合否を判定する）**

- **500 にならない**
- **サインイン画面へ戻す**

## RT-294.26 サインアップして、メールの確認のリンクを踏むと、サインインできるようになる

| | |
|---|---|
| 観点 | **確認のリンクはメールでしか届かない**ので、**この流れは E2E で 1 度も通していなかった**（カバレッジで `EmailConfirmation` が通っていなかった）。**メールの送信箱（`MailOutbox`）から読む。** |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29426_メアドの確認のリンクを踏むとサインインできる` |

**手順**

1. サインアップする
1. 送信箱から、確認のメールを読む
1. リンクを踏む（約款を出す配備なら、同意して送る）
1. サインインする

**検証（合否を判定する）**

- 確認の前は、サインインできない
- 確認のメールが届く
- HTTP 200
- **エラー画面にならない**（確認が通る）
- **確認の後は、サインインできる**

## RT-294.27 パスワードの失念のメールのリンクから、パスワードをリセットできる

| | |
|---|---|
| 観点 | **リセットのリンクはメールでしか届かない**ので、**この流れは E2E で 1 度も通していなかった。****正しい code のときは、画面に利用者のメアドが出る**（C-30 の裏返し）。 |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29427_パスワードをリセットできる` |

**手順**

1. パスワードの失念を送る
1. 送信箱から、リセットのメールを読む
1. リンクを踏む
1. 新しいパスワードを送る
1. 新しいパスワードでサインインする

**検証（合否を判定する）**

- リセットのメールが届く
- **リセットの画面が開く**（正しい code）
- **画面に利用者のメアドが出る**（正しい code のときだけ。C-30）
- **完了の画面になる**（入力欄もエラーも無い）
- **新しいパスワードで入れる**
- **古いパスワードでは入れない**

## RT-294.28 確認待ちの利用者は、パスワードが合っても違っても、サインインできない（画面にエラーが出る）

| | |
|---|---|
| 観点 | **確認待ちの利用者でサインインするテストが無かった**（C-33 の経路）。**パスワードが合えば確認のメールを送り直し、違えば利用者が居ないときと同じ応答にする。** |
| 根拠 | #294（E2E の拡充 / C-33） |
| テスト | `RT29428_確認待ちの利用者はサインインできない` |

**手順**

1. 正しいパスワードでサインインする
1. 違うパスワードでサインインする

**検証（合否を判定する）**

- 正しいパスワード : **サインインしない**（画面を出し直し、エラーを出す）
- 違うパスワード : **サインインしない**（画面を出し直し、エラーを出す）

## RT-294.29 コードの 2FA（Email）で、メールのコードを入れるとサインインでき、戻り先へ戻る

| | |
|---|---|
| 観点 | **コードはメールでしか届かない**ので、**コードの 2FA が成功する経路は E2E で通していなかった**（RT-294.13 は、間違ったコードの経路だけ）。 |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29429_メールのコードで2FAを通る` |

**手順**

1. パスワードでサインインし、手段に Email を選ぶ
1. 送信箱から、コードを読む
1. コードを入れる

**検証（合否を判定する）**

- コードのメールが届く
- **戻り先へリダイレクトする**（サインインできた）
- `auth_time` の Cookie が書かれている（セッションの初期化）

## RT-294.30 外部ログインの戻りの口（ExternalLoginCallback）は、失敗を 500 にせず、サインインもしない

| | |
|---|---|
| 観点 | **外部プロバイダ（Google など）は E2E で動かせない**ので、**この口は 1 度も叩いていなかった。****失敗の口だけは叩ける**（プロバイダのエラー、外部ログインの Cookie が無い）。 |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29430_外部ログインの戻りの失敗は500にしない` |

**手順**

1. GET /Account/ExternalLoginCallback?remoteError=access_denied
1. GET /Account/ExternalLoginCallback

**検証（合否を判定する）**

- /Account/ExternalLoginCallback?remoteError=access_denied : **サインイン画面へ戻すか、失敗の画面を出す**（500 にしない）
- /Account/ExternalLoginCallback : **サインイン画面へ戻すか、失敗の画面を出す**（500 にしない）
- **サインインしていない**（保護された画面は開かない）

## RT-294.31 ID 連携の受け口（OIDC の Redirect エンドポイント・SAML2 の ACS）は、連携を始めていない要求をエラー画面で断る

| | |
|---|---|
| 観点 | **受け口の失敗の経路を叩いていなかった。****連携を始めた記録（セッションの state・上流）が無ければ、上流の応答を受け取らない。** |
| 根拠 | #294（E2E の拡充）/ #253 |
| テスト | `RT29431_ID連携の受け口は始めていない要求を断る` |

**手順**

1. GET /Account/IDFederationRedirectEndPoint?code=dummy&state=dummy
1. GET /Account/IDFederationRedirectEndPoint?error=access_denied&state=dummy
1. GET /Account/IDFederationAssertionConsumerService?SAMLResponse=dummy&RelayState=dummy

**検証（合否を判定する）**

- /Account/IDFederationRedirectEndPoint?code=dummy&state=dummy : HTTP 200（500 にならない）
- /Account/IDFederationRedirectEndPoint?code=dummy&state=dummy : **エラー画面になる**（サインインしない）
- /Account/IDFederationRedirectEndPoint?error=access_denied&state=dummy : HTTP 200（500 にならない）
- /Account/IDFederationRedirectEndPoint?error=access_denied&state=dummy : **エラー画面になる**（サインインしない）
- /Account/IDFederationAssertionConsumerService?SAMLResponse=dummy&RelayState=dummy : HTTP 200（500 にならない）
- /Account/IDFederationAssertionConsumerService?SAMLResponse=dummy&RelayState=dummy : **エラー画面になる**（サインインしない）
- **サインインしていない**（保護された画面は開かない）

## RT-294.32 既に使われている利用者名でサインアップすると、画面にエラーを出し、利用者を作らない

| | |
|---|---|
| 観点 | **利用者の作成（`CreateAsync`）が失敗する経路を通していなかった**（`AddErrors` が 1 度も通っていなかった）。**確認待ちのメアドの登録し直し（RT-294.4）とは別の経路である**（利用者名の重複は、作成で断られる）。 |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29432_使われている利用者名ではサインアップできない` |

**手順**

1. 同じ利用者名・別のメアドでサインアップする

**検証（合否を判定する）**

- **サインアップの画面を出し直し、エラーを出す**
- **先の利用者のメアドは変わらない**
- **別のメアドの利用者は作られない**

## RT-294.33 メアドの確認・パスワードのリセットは、パラメタが無い・code が違えば、通さない（パスワードは変わらない）

| | |
|---|---|
| 観点 | **RT-294.6 / .7 は「利用者が居ない」経路だけ**で、**パラメタが無い・code が違う・入力が合わない経路は通していなかった。** |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29433_パラメタが無いかcodeが違えば確認もリセットも通さない` |

**手順**

1. GET /Account/EmailConfirmation
1. GET /Account/EmailConfirmation?userId=dc3a7341-a51f-4156-bc9c-2ce1b7886dc1&code=bogus
1. GET /Account/ResetPassword
1. POST /Account/ResetPassword（code が違う）
1. POST /Account/ResetPassword（確認の入力が合わない）

**検証（合否を判定する）**

- /Account/EmailConfirmation : HTTP 200（500 にならない）
- /Account/EmailConfirmation : **エラー画面になる**
- /Account/EmailConfirmation?userId=dc3a7341-a51f-4156-bc9c-2ce1b7886dc1&code=bogus : HTTP 200（500 にならない）
- /Account/EmailConfirmation?userId=dc3a7341-a51f-4156-bc9c-2ce1b7886dc1&code=bogus : **エラー画面になる**
- /Account/ResetPassword : HTTP 200（500 にならない）
- /Account/ResetPassword : **エラー画面になる**
- code が違う : **リセットの画面を出し直し、エラーを出す**
- 確認の入力が合わない : **リセットの画面を出し直し、エラーを出す**
- **パスワードは変わらない**（元のパスワードで入れる）

## RT-294.34 パスワードの失念を続けて送っても、リセットのメールは 1 通だけ（画面は同じ）

| | |
|---|---|
| 観点 | **`MailResendIntervalSeconds` の絞り（C-31）を、パスワードの失念で確かめていなかった**（`SendConfirmEmailForPasswordReset` の絞りの分岐が通っていなかった）。**画面は変えない**ので、**数えられるのは送信箱だけ**である。 |
| 根拠 | #294（E2E の拡充 / C-31） |
| テスト | `RT29434_リセットのメールは続けて送らない` |

**手順**

1. パスワードの失念を送る
1. パスワードの失念を送る

**検証（合否を判定する）**

- (1) **確認の画面になる**（入力欄もエラーも無い）
- (2) **確認の画面になる**（入力欄もエラーも無い）
- **リセットのメールは 1 通だけ**

## RT-294.35 2FA の途中でなければ、コードの 2FA の口（手段の選択・コードの入力・プッシュの状態）は通さない

| | |
|---|---|
| 観点 | **RT-294.10 は TOTP・回復コードの画面（GET）だけ**で、**コードの 2FA の口と、POST・プッシュの状態の口は、2FA の途中でない要求を通していなかった。** |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29435_2FAの途中でなければコードの口は通さない` |

**手順**

1. GET /Account/SendCode?rememberMe=false
1. GET /Account/VerifyCode?provider=Email&rememberMe=false&rememberBrowser=false
1. POST /Account/SendCode
1. POST /Account/VerifyCode
1. GET /Account/TwoFactorPushStatus
1. POST /Account/LoginWithTwoFactorAuthenticator?rememberMe=false
1. POST /Account/LoginWithTwoFactorAuthenticatorRecoveryCode

**検証（合否を判定する）**

- /Account/SendCode?rememberMe=false : HTTP 200
- /Account/SendCode?rememberMe=false : **エラー画面になる**
- /Account/VerifyCode?provider=Email&rememberMe=false&rememberBrowser=false : HTTP 200
- /Account/VerifyCode?provider=Email&rememberMe=false&rememberBrowser=false : **エラー画面になる**
- POST /Account/SendCode : **エラー画面になる**（コードを送らない）
- POST /Account/VerifyCode : **リダイレクトしない**（サインインしない）
- GET /Account/TwoFactorPushStatus : **承認されていない**（`approved` が false）
- POST /Account/LoginWithTwoFactorAuthenticator?rememberMe=false : **エラー画面になる**
- POST /Account/LoginWithTwoFactorAuthenticatorRecoveryCode : **エラー画面になる**
- **サインインしていない**（保護された画面は開かない）

## RT-294.36 2FA のコードのメールが送れなければ、手段の選択の画面を出し直し、文言を出す（500 にしない）

| | |
|---|---|
| 観点 | **コードの送信に失敗する経路（#214 の catch）を通していなかった。****送信の失敗は、IsDebug のサイトが特定のドメイン宛てで起こす**（RT-294.14 と同じ）。 |
| 根拠 | #294（E2E の拡充）/ #214 |
| テスト | `RT29436_2FAのコードを送れなければ選び直しになる` |

**手順**

1. パスワードでサインインし、手段に Email を選ぶ

**検証（合否を判定する）**

- **手段の選択の画面を出し直し、文言を出す**（コードの入力へ進まない）

## RT-294.37 パスワードを続けて間違えると、ロックアウトの画面になり、正しいパスワードでも入れない（確認済み・確認待ちとも）

| | |
|---|---|
| 観点 | **パスワードのサインインでロックアウトする経路を通していなかった**（RT-294.11 は TOTP）。**確認待ちの利用者は、別の経路で失敗を数える**（C-33。`AccessFailedAsync`）。**確認待ちは、上限に達した次の要求でロックアウトの画面になる**（確認済みは、達した要求で）。 |
| 根拠 | #294（E2E の拡充 / C-33） |
| テスト | `RT29437_パスワードを続けて間違えるとロックアウトになる` |

**手順**

1. 確認済み : ロックアウトするまで、違うパスワードを送る（上限 20 回 ＋ 1）
1. 確認待ち : ロックアウトするまで、違うパスワードを送る（上限 20 回 ＋ 1）

**検証（合否を判定する）**

- 確認済み : **ロックアウトの画面になる**
- 確認済み : **正しいパスワードでも、ロックアウトの画面になる**
- 確認待ち : **ロックアウトの画面になる**
- 確認待ち : **正しいパスワードでも、ロックアウトの画面になる**

## RT-294.38 自己テストの結果画面のボタン（UserInfo・リフレッシュ・照会・取り消し）が動き、取り消したトークンは照会で無効になる

| | |
|---|---|
| 観点 | **自己テストは結果画面までしか通していなかった**（`OAuth2AuthorizationCodeGrantClient2` が 1 度も通っていなかった）。**画面のボタンは、トークン・UserInfo・照会・取り消しの各エンドポイントを、サイト自身が叩く。** |
| 根拠 | #294（E2E の拡充） |
| テスト | `RT29438_自己テストの結果画面のボタンが動く` |

**手順**

1. 自己テストを通し、結果画面まで進む
1. 「GetUserClaims」を押す
1. 「IntrospectAccess」を押す
1. 「Refresh」を押す
1. 「IntrospectRefresh」を押す
1. 「RevokeAccess」を押す
1. 「IntrospectAccess」を押す
1. 「RevokeRefresh」を押す
1. 「IntrospectRefresh」を押す

**検証（合否を判定する）**

- UserInfo : **`sub` が返る**
- 照会（access_token）: **有効**
- リフレッシュ : **新しい access_token が画面に出る**
- 照会（refresh_token）: **有効**
- **取り消した access_token は、照会で無効**
- **取り消した refresh_token は、照会で無効**

## RT-294.39 自己テストの受け口は、fragment・form_post の値を画面に出し、検証できない JARM はエラー画面で断る（500 にしない）

| | |
|---|---|
| 観点 | **自己テストの Implicit の受け口（`OAuth2ImplicitGrantClient`）を 1 度も叩いていなかった。****叩いたら、自己テストを始めていない要求の JARM で 500 になった**（net48 版は 302）。**JARM の検証に失敗したら先へ進めない**（#294 の B7）。 |
| 根拠 | #294（E2E の拡充 / B7） |
| テスト | `RT29439_自己テストのImplicitの受け口は検証できないJARMを断る` |

**手順**

1. 値なし（fragment で返る場合。値は画面のスクリプトが読む）
1. state ＋ 値（form_post・query で返る場合）
1. 検証できない JARM : GET /Account/OAuth2ImplicitGrantClient?response=not.a.jwt
1. 検証できない JARM : GET /Account/OAuth2AuthorizationCodeGrantClient?response=not.a.jwt

**検証（合否を判定する）**

- 値なし : HTTP 200（画面を出す）
- state あり : **受け取った値を画面に出す**
- /Account/OAuth2ImplicitGrantClient?response=not.a.jwt : **エラー画面になる**（値を使わない。500 にしない）
- /Account/OAuth2AuthorizationCodeGrantClient?response=not.a.jwt : **エラー画面になる**（値を使わない。500 にしない）

## RT-294.40 プッシュの 2FA（MobileApp）で、端末が承認すると、待っているブラウザのサインインが完了する

| | |
|---|---|
| 観点 | **プッシュの 2FA の成功の経路を、E2E で通していなかった**（RT-213.1 は `/2fa_result` の失敗の口だけ）。**端末の役は、送信箱（`FcmOutbox`）を読んで `/2fa_result` を叩くテストがする。** |
| 根拠 | #294（E2E の拡充）/ #213 |
| テスト | `RT29440_プッシュの2FAで端末が承認するとサインインできる` |

**手順**

1. パスワードでサインインし、手段に MobileApp を選ぶ
1. 端末の役 : 送信箱から、プッシュ通知のコードを読む
1. 端末の役 : `/2fa_result` で承認する
1. ブラウザの役 : 承認の状態を問い合わせる

**検証（合否を判定する）**

- **端末を登録した利用者には、手段に MobileApp が出る**
- **登録した端末へ、コードのプッシュ通知が届く**
- 承認の前 : **`approved` は false**
- 承認の後 : **`approved` が true で、戻り先が返る**
- **サインインが完了している**（保護された画面が開く）

## RT-294.41 **normal の登録のクライアントは、Device グラントでも refresh_token を受け取り、それで更新できる**

| | |
|---|---|
| 観点 | **以前は refresh_token を作って保存するだけで、応答に入れていなかった**（**使われない行が溜まり、機器は期限が切れるたびに利用者の承認からやり直していた**）。**device の登録には、従来どおり発行しない**（ClientModePolicy の表。EX-4.3）。 |
| 根拠 | RFC 8628 §3.5 / RFC 6749 §5.1 / #294 |
| テスト | `RT29441_Deviceグラントでrefresh_tokenが返る` |

**手順**

1. 機器 : POST /device_authz
1. 利用者 : /device_verify で許可する
1. 機器 : grant_type=device_code でトークンを取る
1. その refresh_token で更新できる

**検証（合否を判定する）**

- access_token が返る
- refresh_token が返る
- normal の登録のトークンは device を名乗らない
- 更新で access_token が返る

## RT-294.42 **DPoP で縛ったトークンを /introspect で照会すると、`cnf` の中に `jkt` が返る**

| | |
|---|---|
| 観点 | **リソース サーバは照会の `cnf.jkt` を見て、証明の鍵と突き合わせる**（RFC 9449 §6.2）。**以前は `jkt` を返していなかった**ので、**照会で確かめるリソース サーバは、縛りに気付けなかった**（mTLS の `x5t#S256` だけ入っていた）。 |
| 根拠 | RFC 7662 §2.2 / RFC 7800 §3.1 / RFC 9449 §6.2 / #294 |
| テスト | `RT29442_DPoPで縛ったトークンの照会でcnfのjktが返る` |

**手順**

1. 証明を添えて、認可コードを交換する
1. 発行先の資格情報で照会する

**検証（合否を判定する）**

- active が true
- cnf.jkt が、証明の鍵の指紋と一致する

## RT-294.43 **CIBA を、`/ciba_authz` から `/token` まで `client_assertion`（private_key_jwt）で通せる**

| | |
|---|---|
| 観点 | **FAPI-CIBA は、クライアント認証に private_key_jwt か mTLS を求める。****以前は `/ciba_authz` は `client_assertion` を受けるのに、`/token` は読まなかった**ので、**利用者が承認した後で `invalid_client` になっていた。** |
| 根拠 | CIBA Core §7.1 / §10.1 / RFC 7523 §2.2 / #294 |
| テスト | `RT29443_CIBAをprivate_key_jwtで最後まで通せる` |

**手順**

1. 利用者 : 認証デバイスを登録する
1. クライアント : client_assertion で POST /ciba_authz
1. 利用者 : 認証デバイスで許可する
1. クライアント : client_assertion で POST /token

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末
- access_token が返る

## RT-294.44 **発行していない auth_req_id でポーリングすると、`invalid_grant` が返る**

| | |
|---|---|
| 観点 | **以前は内部の状態名（`not_found`）を、そのまま error に入れていた**（仕様に無い値で、RP は意味を読めない）。**Device グラントは #199 で直してあった**ので、それに揃えた。 |
| 根拠 | CIBA Core §11 / RFC 6749 §5.2 / #294 |
| テスト | `RT29444_CIBAの知らないauth_req_idはinvalid_grant` |

**検証（合否を判定する）**

- HTTP 400
- error が invalid_grant

## RT-294.45 **JWT Bearer グラントに壊れた assertion を渡しても、HTTP 500 にしない**

| | |
|---|---|
| 観点 | **以前は `Split('.')[1]`・`dic[iss]`・登録の無い鍵の復号を、確かめずに行っていた**ので、**外から来た値で 500 に落とせた**（他の口は #241 で直してあった）。 |
| 根拠 | RFC 7523 §3.1 / RFC 6749 §5.2 / #241 / #294 |
| テスト | `RT29445_JWTBearerの壊れたassertionで500にしない` |

**手順**

1. JWT でない値
1. iss が文字列でない JWT
1. 登録されていない iss

**検証（合否を判定する）**

- HTTP 400 か 401（500 にしない）
- error が返る
- HTTP 400 か 401（500 にしない）
- error が返る
- HTTP 400 か 401（500 にしない）
- error が返る

## RT-294.46 **scope を省いたトークン要求でも、HTTP 500 にしない**（client_credentials / password / JWT Bearer）

| | |
|---|---|
| 観点 | **scope は OPTIONAL である**（RFC 6749 §4.3.2 / §4.4.2）。**以前は null の `Split` で 500 になっていた**（client_credentials は、上の方では null を守っていた）。 |
| 根拠 | RFC 6749 §3.3 / §4.3.2 / §4.4.2 / RFC 7523 §2.1 / #294 |
| テスト | `RT29446_scopeを省いてもトークンが取れる` |

**手順**

1. client_credentials
1. password
1. JWT Bearer（assertion にも scope を入れない）

**検証（合否を判定する）**

- HTTP 200
- access_token が返る
- HTTP 200
- access_token が返る
- HTTP 200
- access_token が返る

## RT-294.47 **CIBA の request が、payload がオブジェクトでない・iss が文字列でない JWT でも、HTTP 400 で返す**

| | |
|---|---|
| 観点 | **以前は Base64URL の復号だけを守っていて、その後の JSON の読み取りで 500 になっていた。** |
| 根拠 | CIBA Core §13 / RFC 6749 §5.2 / #241 / #294 |
| テスト | `RT29447_CIBAの壊れたrequestで500にしない` |

**手順**

1. payload が配列の JWT
1. iss がオブジェクトの JWT

**検証（合否を判定する）**

- HTTP 400
- HTTP 400

## RT-294.48 **他のクライアントが出した refresh_token は、消費せずに断る**（持ち主はその後も使える）

| | |
|---|---|
| 観点 | **以前は消費（ローテーション）してから、発行先が違うと断っていた。****持ち主が次に使うと「使用済みの再提示」と見なされ、一族ごと失効した**（#188 の段階 3）。 |
| 根拠 | RFC 6749 §6 / RFC 9700 §4.14 / #294 |
| テスト | `RT29448_他のクライアントのrefresh_tokenは消費せずに断る` |

**手順**

1. 持ち主（MVC_Sample）が refresh_token を得る
1. 他のクライアント（TestClient）が出す
1. 持ち主は、その後も更新できる

**検証（合否を判定する）**

- error が invalid_grant
- access_token が返る

## RT-294.49 **revoke / introspect の認証方法は、トークン エンドポイントと同じ一覧を広告する**

| | |
|---|---|
| 観点 | **#239 から、revoke / introspect も private_key_jwt と mTLS で通る**のに、**広告は秘密の 2 つのままだった**（広告を見て方法を選ぶ RP は、使えないと判断する）。**一覧は 1 か所（`TokenEndpointAuthMethods`）から作る。** |
| 根拠 | RFC 8414 §2 / RFC 7009 §2.1 / RFC 7662 §2.1 / #294 |
| テスト | `RT29449_Discoveryが受け付ける認証方法を広告する` |

**検証（合否を判定する）**

- token_endpoint_auth_methods_supported に none（パブリック）が在る
- revocation_endpoint_auth_methods_supported が token_endpoint_auth_methods_supported から none を除いたもの
- introspection_endpoint_auth_methods_supported が token_endpoint_auth_methods_supported から none を除いたもの
- request_object_signing_alg_values_supported に RS256 が在る

## RT-294.50 **client_credentials のトークンは、クライアントと同じ名前の利用者が居ても、その利用者に結び付かない**

| | |
|---|---|
| 観点 | **以前は ClientName と同じ名前の利用者を引き、居ればその利用者の sub にしていた。****ClientName はラベル**（登録の時点の所有者の利用者名）なので、**名前を付け替えた後に同じ名前を取った別の利用者に、トークンが結び付いた**（S3）。**client_credentials は資源所有者の居ないトークン**である。 |
| 根拠 | RFC 6749 §4.4 / #294 |
| テスト | `RT29450_client_credentialsのsubは同じ名前の利用者に結び付かない` |

**手順**

1. 管理者 : クライアントと同じ名前の利用者を作る
1. クライアント : client_credentials でトークンを取る
1. /userinfo は、その利用者のメアドを返さない

**検証（合否を判定する）**

- sub はクライアント名
- 利用者のメアドを返さない

## RT-294.51 **fapi2 のクライアントが、PKCE と client_assertion（private_key_jwt）を併用して、認可コードを引き換えられる**

| | |
|---|---|
| 観点 | **FAPI 2.0 は、PKCE と、private_key_jwt か mTLS の両方を求める。****以前は code_verifier が在ると、client_assertion を見ずに PKCE だけで認証した**ので、**証明が PKCE になり、fapi2 の登録は通らなかった**（N1）。 |
| 根拠 | FAPI 2.0 Security Profile §5.3.2.1 / RFC 7636 / RFC 7523 §2.2 / #294 |
| テスト | `RT29451_PKCEとprivate_key_jwtを併用できる` |

**手順**

1. PKCE（S256）で認可コードを取る
1. code_verifier と client_assertion を送って交換する
1. 違う code_verifier では、client_assertion が正しくても通らない

**検証（合否を判定する）**

- access_token が返る
- access_token を返さない
- error は invalid_grant（RFC 7636 §4.6。F1）

## RT-294.52 **認証の方法を明示したクライアントは、PKCE だけでは認可コードを引き換えられない**（`none` を明示したクライアントは引き換えられ、秘密では認証できない）

| | |
|---|---|
| 観点 | **RFC 6749 §4.1.3 は、コンフィデンシャル クライアントの認証を MUST としている。****以前は code_verifier が在り client_secret が無ければ、登録に関わらず PKCE だけで通した**（C-40）。**登録が空のクライアントは、従来どおり PKCE だけで通す**（既定の挙動を変えない）。 |
| 根拠 | RFC 6749 §4.1.3 / RFC 7591 §2（token_endpoint_auth_method）/ #294 |
| テスト | `RT29452_PKCEだけの引き換えは明示していないクライアントだけ` |

**手順**

1. client_secret_basic を明示したクライアント : PKCE だけでは通らない
1. 同じクライアント : client_secret ＋ PKCE なら通る
1. none を明示したクライアント : PKCE だけで通る
1. none を明示したクライアント : 秘密では認証できない

**検証（合否を判定する）**

- invalid_client
- access_token が返る
- access_token が返る
- invalid_client

## RT-294.53 **scope を省いた認可要求（OAuth 2.0 の code）でも、HTTP 500 にしない**

| | |
|---|---|
| 観点 | **scope は省略できる**（RFC 6749 §3.3）。**以前は null の `Split` で 500 になっていた**（N2）。 |
| 根拠 | RFC 6749 §3.3 / §4.1.1 / #294 |
| テスト | `RT29453_scopeを省いた認可要求で500にしない` |

**検証（合否を判定する）**

- HTTP 500 にならない
- code が返る

## RT-294.54 **client_assertion の aud は、トークン エンドポイントの URL のほか、issuer でもよい**（配列は、500 にせず invalid_client で断る）

| | |
|---|---|
| 観点 | **FAPI 2.0 は、issuer を aud として受けることを求める**（RFC 7523 §3 も issuer を認める）。**以前はトークン エンドポイントの URL との完全一致だけ**だったので、**issuer を入れる FAPI 2.0 のクライアントは invalid_client になった**（N4）。**配列の aud は、上流（`JwtAssertion.Verify`）が文字列として読むので受けられない**（**以前は HTTP 500** だった）。 |
| 根拠 | RFC 7523 §3 / FAPI 2.0 Security Profile §5.3.2.1 / RFC 7519 §4.1.3 / #294 |
| テスト | `RT29454_client_assertionのaudにissuerを受ける` |

**手順**

1. aud = issuer
1. aud = トークン エンドポイント
1. aud = 他の値
1. aud = [issuer]（配列）

**検証（合否を判定する）**

- 認証が通る（HTTP 200）
- 認証が通る（HTTP 200）
- invalid_client（500 にしない）
- invalid_client（500 にしない）

## RT-294.55 **登録の grant_types に implicit が無いクライアントの Hybrid（code id_token）の要求は、同意の前に unauthorized_client で断る**

| | |
|---|---|
| 観点 | **認可エンドポイントで発行する経路は、発行の時点（`CheckClientMode`）で grant_types を見ていた**が、**要求の検査では見ていなかった**ので、**利用者に同意させた後で server_error になっていた。****動的登録は組み合わせを揃えるが、構成ファイル・画面の登録は揃っているとは限らない。****code は従来どおり /token で見る**（#307 の段階 1。`RT-307.7`）。 |
| 根拠 | RFC 7591 §2（grant_types）/ RFC 6749 §4.1.2.1 / #294 |
| テスト | `RT29455_grant_typesにimplicitが無ければHybridは同意の前に断る` |

**検証（合否を判定する）**

- 同意画面を出さない
- unauthorized_client

## RT-294.56 **poll の CIBA は、client_notification_token も binding_message も無い request で受け付ける**

| | |
|---|---|
| 観点 | **client_notification_token は ping / push のときだけ REQUIRED、binding_message は OPTIONAL**（CIBA Core §7.1）。**この実装は poll だけを扱う**のに、**以前は両方を必須にしていた**ので、**標準の poll のクライアントは invalid_request で断られた**（N5）。 |
| 根拠 | CIBA Core §7.1 / #294 |
| テスト | `RT29456_pollのCIBAはclient_notification_tokenを要らない` |

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- auth_req_id が返る
- プッシュ通知が送られる（auth_req_id を載せて）
- 宛先は、登録した端末

## RT-294.57 **PAR に預ける Request Object の client_id が、認証したクライアントと違えば、invalid_request_object で断る**

| | |
|---|---|
| 観点 | **RFC 9126 §2.1 は、Request Object の client_id が認証したクライアントであることを求める。****以前は iss だけを照合し、検証と保存は中の client_id で行っていた**ので、**別のクライアントの名義で、預けた要求を作れた**（C-41）。 |
| 根拠 | RFC 9126 §2.1 / RFC 9101 §6.3 / #294 |
| テスト | `RT29457_PARのRequestObjectのclient_idを照合する` |

**検証（合否を判定する）**

- invalid_request_object
- request_uri を返さない

## RT-294.58 **code_verifier が合わなければ、invalid_grant で断る**（PKCE だけでも、client_secret と併せても）

| | |
|---|---|
| 観点 | **RFC 7636 §4.6 は、code_verifier の不一致を invalid_grant とする。****以前は invalid_client で返していた**ので、**クライアントは「資格情報が違う」のか「code_verifier が違う」のかを区別できなかった**（F1）。 |
| 根拠 | RFC 7636 §4.6 / RFC 6749 §5.2 / #294 |
| テスト | `RT29458_合わないcode_verifierはinvalid_grant` |

**手順**

1. PKCE だけ（TestClient_31。none）
1. client_secret ＋ PKCE（TestClient_30。client_secret_basic）
1. 秘密が違えば、従来どおり invalid_client

**検証（合否を判定する）**

- invalid_grant
- invalid_grant
- invalid_client

## RT-294.59 **/ros に預ける Request Object の client_id が、署名したクライアント（iss）と違えば、預からない**

| | |
|---|---|
| 観点 | **RFC 9101 §6.3 は、Request Object の client_id が要求したクライアントであることを求める。****以前は署名（iss）だけを確かめていた**ので、**自分の鍵で署名した Request Object を、別のクライアントの名義で預けられた**（PAR は C-41 で直した。F5）。 |
| 根拠 | RFC 9101 §6.3 / #294 |
| テスト | `RT29459_rosのRequestObjectのclient_idを照合する` |

**手順**

1. client_id が他のクライアント
1. client_id が署名したクライアント（従来どおり預かる）

**検証（合否を判定する）**

- request_uri を返さない
- request_uri を返す

## RT-294.60 認証アプリの登録画面を開いただけでは、TOTP は登録されない（コードを確かめてから登録される）

| | |
|---|---|
| 観点 | **以前は登録画面（GET）を開いただけで、鍵を保存していた。****そのため、コードを確かめていなくても、管理画面は TOTP を登録済みと出し、サインインの手段にも認証アプリが出ていた。****鍵は TempData に置き、コードを確かめてから保存する**ようにした。**間違えて出し直すときは、同じ鍵を出す。** |
| 根拠 | #294（ManageController.*.cs のレビュー B10） |
| テスト | `RT29460_登録画面を開いただけではTOTPは登録されない` |

**手順**

1. 利用者を作り、2FA を有効にする（認証アプリは、まだ登録しない）
1. 認証アプリの登録画面を開く
1. 管理画面と、サインインの手段を見る
1. 間違ったコードを送る
1. 正しいコードを送る

**検証（合否を判定する）**

- 管理画面は、TOTP を登録済みと出さない
- サインインの手段に、認証アプリが出ない
- エラーの文言が出る
- 出し直した画面の鍵は、最初と同じ
- 間違えた後も、管理画面は TOTP を登録済みと出さない
- 回復コードの画面へ進む
- 管理画面は、TOTP を登録済みと出す

**観測（判定しない）**

- サインインの手段

## RT-294.61 メアドの変更で、いまと同じメアドは断られ、他の利用者のメアドは、新しいメアドと同じ画面になる

| | |
|---|---|
| 観点 | **変わったかどうかを、利用者名と比べていた**（「利用者名＝メアド」だった頃の名残。#151）。**いまと同じメアドを送っても、何も言わずに画面を出し直していた。****他の利用者のメアドを送ると、やはり何も言わずに出し直していた**ので、**そのメアドが使われていることが、画面から分かった。****いまのメアドと比べ、同じなら文言を出し、他の利用者のメアドなら送らずに確認の画面を出す**ようにした。 |
| 根拠 | #294（ManageController.*.cs のレビュー B7） / ManageController.ChangeEmail |
| テスト | `RT29461_同じメアドは断られ他の利用者のメアドは区別されない` |

**手順**

1. 使い捨ての利用者を 2 人作る
1. いまと同じメアド（大文字にしたもの）を送る
1. 他の利用者のメアドを送る
1. メアドは変わっていない

**検証（合否を判定する）**

- 入力の画面が出し直される
- エラーの文言が出る
- HTTP 200（確認の画面）
- 新しいメアドを送ったときと同じ、確認の画面になる
- メアドは元のまま

**補足**

- **パスワードの確認は、2FA を有効にした利用者が必ず失敗していた**（サインインそのもので確かめていた）。**メアドの変更は、設定によらず確かめるようになった**（`RT-294.68`）。

## RT-294.62 利用者名を変えると、WebAuthn の資格情報も新しい名前へ移り、元の名前には残らない

| | |
|---|---|
| 観点 | **資格情報は利用者名で持っている**（`FIDO2Data.UserName` と `StoredCredential.UserId`）。**以前は利用者名を変えても、資格情報を移していなかった。****本人は自分の資格情報を使えなくなり、資格情報は元の名前に残っていた。****名前を変えるときに、資格情報も移す**ようにした（`FIDO.DataProvider.RenameUser`）。 |
| 根拠 | #294（ManageController.*.cs のレビュー S1） / ManageController.ChangeUserName |
| テスト | `RT29462_利用者名を変えると資格情報も移る` |

**手順**

1. 一覧を開く（種データが入っている）
1. 利用者名を変える
1. 変えた後の一覧
1. 元の名前で利用者を作り直しても、資格情報は付いていない

**検証（合否を判定する）**

- 1 件以上ある（前提）
- 資格情報が、新しい名前に付いて来る
- 元の名前に残った資格情報

## RT-294.63 管理画面でサインインし直しただけでは、auth_time は新しくならない（max_age の再認証が効く）

| | |
|---|---|
| 観点 | **以前は、管理画面の操作のたびにサインインし直し、auth_time を「いま」にしていた。****資格情報を確かめない操作（2FA の有効化など）でも新しくなる**ので、RP が `max_age` で求めた再認証が、行われないまま通っていた。**auth_time を書くのは、資格情報を確かめた所だけ**にした（パスワードの再確認など）。 |
| 根拠 | OIDC Core §2 auth_time / §3.1.2.1 / #294（ManageController.*.cs の 2 回目のレビュー S1） |
| テスト | `RT29463_管理画面の再サインインではauth_timeを新しくしない` |

**手順**

1. サインインし、2FA を有効にしておく（手順 2 で、パスワードを確かめて無効にするため）
1. パスワードを確かめて 2FA を無効にし、すぐに max_age=2 で認可リクエストを送る
1. 2FA を有効にし（サインインし直すだけで、資格情報は確かめない）、すぐに max_age=2 で送る

**検証（合否を判定する）**

- パスワードを確かめた直後は、再認証を求めない（先へ進む）
- 再認証を求める（同意画面にも、認可コードにも進まない）

## RT-294.64 2FA の無効化は、パスワードを確かめる（無い・間違いなら無効にしない）

| | |
|---|---|
| 観点 | **以前は、セッションさえあれば 2FA を無効にできた**（電話番号の削除・外部ログインの解除も同じ）。**パスワードの再確認を求める**ようにした。**電話番号の削除・外部ログインの解除も、同じ補助（`VerifyPasswordAsync`）で確かめる**（電話番号は SMS が、外部ログインは上流が要るので、E2E では 2FA の無効化で測る）。 |
| 根拠 | #294（ManageController.*.cs の 2 回目のレビュー） |
| テスト | `RT29464_2FAの無効化はパスワードを確かめる` |

**手順**

1. パスワードを送らずに無効にする
1. 間違ったパスワードで無効にする
1. 正しいパスワードで無効にする

**検証（合否を判定する）**

- 無効化のフォームに、パスワードの入力欄がある
- 2FA は有効のまま
- 2FA は有効のまま
- 2FA が無効になる

## RT-294.65 認証アプリの未確定の鍵は、同じブラウザで後からサインインした利用者に使われない

| | |
|---|---|
| 観点 | **未確定の鍵は TempData（Cookie）に置く**（RT-294.60）。**TempData はサインアウトしても残る**ので、**以前は、同じブラウザで後からサインインした利用者に、前の利用者が見た鍵を出していた**（そのまま登録すると、前の利用者がコードを作れる）。**鍵を利用者の id と組にして置き、id が合うときだけ使う**ようにした。 |
| 根拠 | #294（ManageController.*.cs の 2 回目のレビュー） |
| テスト | `RT29465_未確定のTOTPの鍵はほかの利用者に使われない` |

**手順**

1. 利用者 A で、認証アプリの登録画面を開く（登録はしない）
1. 同じブラウザで利用者 B としてサインインし直し、登録画面を開く
1. A の鍵で作ったコードを、B の登録に送る

**検証（合否を判定する）**

- B には、A に出した鍵を出さない
- 登録されない

## RT-294.66 認証アプリを登録した後は、登録画面を開いても鍵を出さない（管理の画面へ戻す）

| | |
|---|---|
| 観点 | **以前は、登録済みの鍵を登録画面に何度でも出していた**（共有鍵と QR コード）。**セッションさえあれば、認証アプリと同じコードを作れるようになった。****登録済みなら、登録画面は出さずに管理の画面へ戻す。** 登録し直すときは、リセットを通す。 |
| 根拠 | #294（ManageController.*.cs の 3 回目のレビュー S1） |
| テスト | `RT29466_登録済みのTOTPの鍵は出さない` |

**手順**

1. 登録画面を開く（GET）
1. 登録の POST を直接送る

**検証（合否を判定する）**

- 管理の画面へ戻す
- 鍵を出さない
- 受けずに、管理の画面へ戻す

## RT-294.67 回復コードの再発行と、認証アプリのリセットは、パスワードを確かめる（無い・間違いなら行わない）

| | |
|---|---|
| 観点 | **以前は、セッションさえあれば、新しい回復コードを画面に出せ、認証アプリを外せた。****回復コードは、それだけで 2FA を通れる。****どちらもパスワードを確かめる**ようにした。 |
| 根拠 | #294（ManageController.*.cs の 3 回目のレビュー S2） |
| テスト | `RT29467_回復コードの再発行とリセットはパスワードを確かめる` |

**手順**

1. 回復コードの再発行 : パスワード無し → 間違い → 正しい
1. 認証アプリのリセット : 間違い → 正しい

**検証（合否を判定する）**

- パスワード無しでは、回復コードを出さない
- 間違ったパスワードでは、回復コードを出さない
- 正しいパスワードなら、回復コードを出す
- 間違ったパスワードでは、認証アプリは登録済みのまま
- 正しいパスワードなら、認証アプリが外れる

## RT-294.68 メアドの変更は、設定によらずパスワードを確かめる（無い・間違いなら確認の画面へ進まない）

| | |
|---|---|
| 観点 | **以前は `RequirePasswordInEditingUserNameAndEmail` が false（既定）だと確かめなかった。****メアドを変えられると、パスワード リセットで乗っ取れる**ので、**メアドの変更だけは、設定によらず確かめる**ようにした（利用者名の変更は、従来どおり設定に従う）。 |
| 根拠 | #294（ManageController.*.cs の 3 回目のレビュー S2） / ManageController.ChangeEmail |
| テスト | `RT29468_メアドの変更はパスワードを確かめる` |

**手順**

1. パスワードを空で送る
1. 間違ったパスワードで送る
1. 正しいパスワードで送る

**検証（合否を判定する）**

- パスワードの入力欄が在る（設定によらず）
- 入力の画面が出し直される（確認の画面へ進まない）
- エラーの文言が出る
- 入力の画面が出し直される（確認の画面へ進まない）
- エラーの文言が出る
- 確認の画面へ進む

## RT-294.69 WebAuthn の資格情報（パスキー）の登録は、パスワードを確かめる（段階 0）

| | |
|---|---|
| 観点 | **以前は、セッションさえあれば資格情報を足せた。****パスキーは、それだけでサインインできる**ので、足した側がずっと入れるようになった。**段階 0（options を作る段）でパスワードを確かめる。** **段階 1 は、段階 0 で Session に置いた options が無いと通らない。** |
| 根拠 | #294（ManageController.*.cs の 3 回目のレビュー S2） |
| テスト | `RT29469_資格情報の登録はパスワードを確かめる` |

**手順**

1. パスワードを空で送る
1. 間違ったパスワードで送る
1. 正しいパスワードで送る

**検証（合否を判定する）**

- options を返さない（status が error）
- challenge を返さない
- options を返さない（status が error）
- challenge を返さない
- options を返す（challenge が在る）

## RT-294.70 管理画面で外したロールは外れる（SystemAdmin を外すと、管理画面が開かなくなる）

| | |
|---|---|
| 観点 | **権限を取り上げられることの確認である。****net10.0 版の mem ストアでは、外しても外れなかった** — Identity Core は正規化した名前（大文字）をストアに渡すが、**ストアは `Name` と突き合わせて見つけられず、何もせずに成功を返していた**（付ける方は #257 で直っていた）。**RT-257.9 は「付ける」しか測っていなかった**ので、見つからなかった。 |
| 根拠 | #294（CmnUserStore.RemoveFromRole。ANALYSIS-IdP.md の C-52） |
| テスト | `RT29470_外したロールは外れる` |

**手順**

1. 管理者が、使い捨ての利用者を SystemAdmin で作る
1. 管理者が、ロールを User だけにする（SystemAdmin を外す）
1. 入り直して、開けなくなる
1. 後片付け : 使い捨ての利用者を削除する

**検証（合否を判定する）**

- 編集できた（一覧へリダイレクトする）
- **一覧が開かない**（SystemAdmin が外れている）
- メニューに導線が出ない
- 削除できた（SystemAdmin を持つかもしれない利用者を残さない）

## RT-294.71 利用者を消したら、その人の refresh_token では access_token を取れない

| | |
|---|---|
| 観点 | **利用者の削除（管理画面・GDPR の削除）は、その人への発行を止めることでもある。****以前は `RefreshTokenDictionary` に利用者の列が無く、更新は利用者を確かめなかった**ので、**消された利用者の access_token を、RP が取り続けられた。** |
| 根拠 | #294（CmnEndpoints.GrantRefreshTokenCredentials。ANALYSIS-IdP.md の C-54） |
| テスト | `RT29471_消された利用者のrefresh_tokenは使えない` |

**手順**

1. 使い捨ての利用者を作り、その人で refresh_token を得る
1. 管理者が、その利用者を消す
1. 消された利用者の refresh_token で更新する

**検証（合否を判定する）**

- 消す前は、更新できる
- invalid_grant で断る
- **access_token を返さない**

**補足**

- **発行済みの access_token は、期限まで残る**（短命なので、ここでは失効させない）。

## RT-294.72 パスワードを変えたら、それより前に発行した refresh_token は使えない（照会も active=false）

| | |
|---|---|
| 観点 | **パスワードを変えるのは、漏れたと思ったときである。****そのとき、漏れた先で取られた refresh_token も止まらなければならない。****SecurityStamp のハッシュを refresh_token に預け、更新と照会で照合する**（パスワードの変更・リセットなど、Identity が SecurityStamp を変える操作で止まる）。 |
| 根拠 | #294（CmnEndpoints.CheckUserOfRefreshToken。ANALYSIS-IdP.md の C-54） |
| テスト | `RT29472_パスワードを変えたら前のrefresh_tokenは使えない` |

**手順**

1. 使い捨ての利用者を作り、その人で refresh_token を得る
1. 本人がパスワードを変える
1. 変える前の refresh_token を照会し、更新する

**検証（合否を判定する）**

- 変える前は、照会が active=true
- **照会に、預けた SecurityStamp のハッシュが出ない**
- 照会が active=false
- 更新は invalid_grant で断る
- **access_token を返さない**

**補足**

- **値は出していない。** 新しいパスワードは構成ファイルの値から作っている（`TESTING.md` 9 節）。

## RT-297.1 クライアント登録の `client_secret` が、暗号化しても往復する

| | |
|---|---|
| 観点 | **user store の秘密を暗号化した**（#297）。**`client_secret` は上流へ送る・画面で再表示する**ので、**元に戻せる形でなければならない**（ハッシュは取れない）。**保存して読み直したときに同じ値が出ること**を測る — **ここが崩れると、クライアント認証が通らなくなる。** |
| 根拠 | #297 / #270 |
| テスト | `RT29701_クライアント登録の秘密が暗号化しても往復する` |

**手順**

1. client_id と client_secret を発行して、登録する
1. 画面を開き直すと、同じ client_secret が出る
1. 後片付け

**検証（合否を判定する）**

- client_secret が入る
- 登録される
- 発行した値と同じである
- 暗号文がそのまま出ていない
- 消せる

## RT-297.2 上流の登録の `client_secret` が、暗号化しても往復する

| | |
|---|---|
| 観点 | **上流の `client_secret` は上流へ送る値**（`/token` のクライアント認証）なので、**必ず平文に戻せなければならない**（#297）。**保存して読み直したときに同じ値が出ること**を測る — **ここが崩れると、上流と連携できなくなる。** |
| 根拠 | #297 / #292 の段階 2 |
| テスト | `RT29702_上流の登録の秘密が暗号化しても往復する` |

**手順**

1. client_secret 付きで足す
1. 編集画面を開くと、同じ client_secret が出る
1. 後片付け

**検証（合否を判定する）**

- 追加できる
- 入れた値と同じである
- 暗号文がそのまま出ていない
- 消せる

**補足**

- **DB に平文が残っていないこと**は、`-UserStoreType sql` で SELECT して確かめる（手順は `TESTING.md`）。**E2E からは DB を見ない**（テストに接続文字列を持たせない。`TESTING.md` 9 節）。

## RT-302.1 発行するトークンのヘッダに `jku` を入れず、`kid` で鍵を引けるようにする

| | |
|---|---|
| 観点 | **`jku` は、検証する側に「ヘッダに書かれた URL を取りに行く」動作を誘う。****鍵の出どころを発行者が自由に指し示せる**ことになり、**検証側の SSRF を誘発しうる**（`ANALYSIS-IdP.md` の D-10）。**標準の経路は `kid` ＋ discovery の `jwks_uri`** である。**消しても他のテストは落ちない**（検証は `kid` で引く）ので、**ここだけが「消えたこと」を測る。** |
| 根拠 | RFC 9068 §2.1 / #302 の段階 1 / D-10 |
| テスト | `RT30201_トークンのヘッダにjkuを入れない` |

**手順**

1. 認可コード フローで access_token と id_token を取る
1. JARM（`response_mode=query.jwt`）の応答も見る

**検証（合否を判定する）**

- access_token のヘッダに `jku` が無い
- access_token のヘッダに `kid` が在る
- access_token の `typ`
- id_token のヘッダに `jku` が無い
- id_token のヘッダに `kid` が在る
- id_token の `typ`
- JARM の response のヘッダに `jku` が無い
- JARM の response のヘッダに `kid` が在る
- JARM の response の `typ`

**補足**

- **`typ` は、出す側と受ける側の両方で効いている。****受ける側**（`CmnAccessToken.VerifyAccessToken`）**は `at+jwt` を期待する**ので、**access_token に `JWT` が付いていると、トークンを使う経路が全部落ちる** — **このケースだけでなく、通し全体が落ちる**のが歯抜けの形である（`TESTING.md`）。
- **配備のとき、発行済みの access_token は検証に通らなくなる**（`typ` が `JWT` のため）。**有効期限が切れるまでの間だけ**で、**`refresh_token` で取り直せば新しい `typ` になる**（`RefreshTokenProvider` は JWS ではない）。

## RT-303.1 `/jwkcerts` が `ETag` と `Cache-Control` を返し、`304` を使える

| | |
|---|---|
| 観点 | **この口は、トークンを検証する相手が必ず読む。****内容は鍵を入れ替えるまで変わらない**のに、**要求ごとにファイルを開いて読み、キャッシュの指示も付けていなかった**（`ANALYSIS-IdP.md` の E-7）。**持ち回らせることで、読む側の往復と、こちらのファイル読み出しを減らす。** |
| 根拠 | RFC 9110 §8.8.3（ETag）/ §13.1.2（If-None-Match）/ #303 |
| テスト | `RT30301_jwkcertsがETagとCacheControlを返す` |

**手順**

1. 1 回目の取得
1. 2 回目の取得（中身と `ETag` が変わらない）
1. `If-None-Match` を付けると `304`（本文なし）

**検証（合否を判定する）**

- HTTP 200
- `ETag` が付く
- `Cache-Control` が `public, max-age=300`
- 本文が JWK Set である（`keys` が在る）
- `ETag` が同じ
- 本文が同じ
- HTTP 304
- 本文を送らない

**補足**

- **覚えているかどうかは、応答からは見えない。****見えるのは `ETag` と `Cache-Control`、そして 304 である。****ファイルの読み出しを減らしたことは、(4) の「追随する」側から裏を取る** — **覚えていなければ追随は自明で、覚えているからこそ測る価値がある。**

## RT-303.2 `JwkSet.json` が変われば、`/jwkcerts` は読み直す（鍵の入れ替えに追随する）

| | |
|---|---|
| 観点 | **覚えたまま返し続けると、鍵を入れ替えても古い鍵を配る。****出す側が新旧 2 本を広告する**作り（#291 / #292 の段階 3）**も、読み直すことが前提**である。**ファイルの最終更新時刻と長さで、変わったかどうかだけを見る**（#303）。 |
| 根拠 | #303 / E-7 / #292 の段階 3 |
| テスト | `RT30302_鍵の入れ替えに追随する` |

**手順**

1. 触る前の `ETag`
1. `JwkSet.json` の末尾に空白を 1 つ足す（鍵は変えない）
1. 戻すと、`ETag` も元に戻る（中身から作っているため）

**検証（合否を判定する）**

- `ETag` が取れる
- `ETag` が変わる（読み直した）
- 本文も新しい（末尾が変わっている）
- `ETag` が 1 回目と同じ

## RT-305.1 Device Authorization Grant : `interval` より短い間隔のポーリングに `slow_down` を返す

| | |
|---|---|
| 観点 | **機器は `interval` を守る義務があるが、守らなくても何も起きなかった**（`ANALYSIS-IdP.md` の D-13。**コードにも「slow_down を検討する」とコメントだけ残っていた**）。**叩き続けられると、`/token` が総当たりの的になる。****`slow_down` は、仕様が用意した断り方**である。 |
| 根拠 | RFC 8628 §3.5（slow_down）/ #305 の段階 1 |
| テスト | `RT30501_Deviceの速すぎるポーリングはslow_down` |

**手順**

1. 機器 : POST /device_authz で device_code を得る
1. 1 回目のポーリング（初回は slow_down にしない）
1. 続けて 2 回目（間隔を守っていない）
1. interval ＋ 1 秒待ってから、3 回目

**検証（合否を判定する）**

- authorization_pending を返す
- slow_down を返す
- トークンは発行しない
- authorization_pending に戻る（要求は生きている）

**観測（判定しない）**

- 応答の interval
  - **機器はこの秒数だけ待つ**（RFC 8628 §3.2）。

**補足**

- **`slow_down` で要求を消していない**ことが、(4) で分かる。**消していたら `invalid_grant` か `expired_token` になる。**

## RT-305.2 CIBA : `interval` より短い間隔のポーリングに `slow_down` を返す

| | |
|---|---|
| 観点 | **CIBA も、クライアントが `/token` を繰り返し叩く。****Device と同じ判定**（`LastPolledAt`）で、**同じ断り方**をする。 |
| 根拠 | CIBA Core §11（slow_down）/ #305 の段階 1 |
| テスト | `RT30502_CIBAの速すぎるポーリングはslow_down` |

**手順**

1. ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）
1. クライアント : CIBA の認証リクエストを送る
1. 1 回目のポーリング（初回は slow_down にしない）
1. 続けて 2 回目（間隔を守っていない）
1. interval ＋ 1 秒待ってから、3 回目

**検証（合否を判定する）**

- 端末の登録 : HTTP 200
- 端末の登録 : 本文は OK
- authorization_pending を返す
- slow_down を返す
- authorization_pending に戻る（要求は生きている）

## RT-305.3 `user_code` を続けて間違えると、その利用者は一定時間断られる

| | |
|---|---|
| 観点 | **機器の `user_code` は、画面から人が打ち込む。****間違えた回数を数えていなかった**ので、**当て続けられた**（`ANALYSIS-IdP.md` の D-13。RFC 8628 §5.2 は制限を要求する）。**断っている間は、正しい `user_code` でも通さない** — **それが「効いている」ことの見え方**である。 |
| 根拠 | RFC 8628 §5.2 / #305 の段階 2 |
| テスト | `RT30503_user_codeを続けて間違えると断られる` |

**手順**

1. 使い捨ての利用者を作る（共用のテスト利用者を断らないため）
1. 機器 : POST /device_authz で user_code を得る
1. 間違った user_code を 20 回送る
1. 正しい user_code を送っても、断られる
1. 5 ＋ 1 秒待つと、また通る

**検証（合否を判定する）**

- 間違いは受け付けない（1 回目）
- 間違いは受け付けない（2 回目）
- 間違いは受け付けない（3 回目）
- 間違いは受け付けない（4 回目）
- 間違いは受け付けない（5 回目）
- 間違いは受け付けない（6 回目）
- 間違いは受け付けない（7 回目）
- 間違いは受け付けない（8 回目）
- 間違いは受け付けない（9 回目）
- 間違いは受け付けない（10 回目）
- 間違いは受け付けない（11 回目）
- 間違いは受け付けない（12 回目）
- 間違いは受け付けない（13 回目）
- 間違いは受け付けない（14 回目）
- 間違いは受け付けない（15 回目）
- 間違いは受け付けない（16 回目）
- 間違いは受け付けない（17 回目）
- 間違いは受け付けない（18 回目）
- 間違いは受け付けない（19 回目）
- 間違いは受け付けない（20 回目）
- 正しい user_code でも通らない
- 待てば通る

**補足**

- **断りは「その利用者」に効く**（`device_verify:<利用者>`）。**間違えた `user_code` では、どの要求を狙ったか分からない**ので、**投入した人で数えている。**

## RT-305.4 クライアント認証を続けて失敗すると、その `client_id` は一定時間断られる

| | |
|---|---|
| 観点 | **`client_secret` は何回でも試せた**（`ANALYSIS-IdP.md` の D-13）。**連続した失敗を数え、上限で断る。****断っている間は、正しい `client_secret` でも通さない。****応答は従来どおり `invalid_client`** で、**断っていること自体は教えない。** |
| 根拠 | #305 の段階 2 / RFC 6749 §5.2（invalid_client） |
| テスト | `RT30504_クライアント認証を続けて失敗すると断られる` |

**手順**

1. 使い捨ての利用者を作り、その利用者でクライアントを登録する
1. 正しい秘密なら通る（断る前の確認）
1. 間違った秘密で 20 回失敗する
1. 正しい秘密でも断られる
1. 5 ＋ 1 秒待つと、また通る

**検証（合否を判定する）**

- HTTP 200
- invalid_client（1 回目）
- invalid_client（2 回目）
- invalid_client（3 回目）
- invalid_client（4 回目）
- invalid_client（5 回目）
- invalid_client（6 回目）
- invalid_client（7 回目）
- invalid_client（8 回目）
- invalid_client（9 回目）
- invalid_client（10 回目）
- invalid_client（11 回目）
- invalid_client（12 回目）
- invalid_client（13 回目）
- invalid_client（14 回目）
- invalid_client（15 回目）
- invalid_client（16 回目）
- invalid_client（17 回目）
- invalid_client（18 回目）
- invalid_client（19 回目）
- invalid_client（20 回目）
- 正しい秘密でも invalid_client
- 待てば HTTP 200

**補足**

- **断りは「`client_id` ＋ 送信元」ごと**である（段階 4）。**他のクライアントも、他の送信元も、影響を受けない**（**このケースは 1 つの送信元から測っている**ので、**送信元ごとに分かれていること自体は `RT-305.7`**）。 **使い捨ての利用者で登録している** — **当時はクライアント登録が 1 人 1 件**で、**共用の利用者で登録すると、`RT-277.1` と登録を奪い合った**（実測で踏んだ。`TESTING.md`）。 **#307 の段階 5-a-1 で 1 人 n 件になったが、使い捨てのままにしている** — **管理画面が扱うのは、その利用者の 1 件**だからである。

## RT-305.5 クライアントごとの上限を超えた要求は 429（Retry-After）になる

| | |
|---|---|
| 観点 | **口に対する要求の回数が、どこにも制限されていなかった**（`ANALYSIS-IdP.md` の D-13）。**段階 2 は「失敗の回数」を数えるが、成功する要求を浴びせる形の負荷は止まらない。****窓の中の要求の回数を数え、超えた分を `429` で断る。****数えるのは口ごと**なので、**ある口の洪水で別の口は止まらない。** |
| 根拠 | #305 の段階 3 / RFC 6585 §4（429 Too Many Requests） |
| テスト | `RT30505_クライアントごとの上限を超えると429` |

**手順**

1. 使い捨ての利用者を作り、その利用者でクライアントを登録する
1. 上限までは通る（1 回目の確認）
1. 上限を超えるまで叩く（10 本ずつ並べて、窓の中で叩き切る）
1. 別の口は止まらない（数えるのは口ごと）
1. 窓が変わると、また通る（最大 23 秒待つ）

**検証（合否を判定する）**

- HTTP 200
- 429 が返る
- HTTP 429
- Retry-After が付く（秒）
- /introspect は 429 にならない
- 待てば HTTP 200

**補足**

- **断りは「口 × クライアント」ごと**である。**他のクライアントも、他の口も、影響を受けない。** **使い捨ての利用者で登録している** — **管理画面が扱うのは、その利用者の 1 件**なので、**共用の利用者で登録すると、同じ `client_id` を他のケースと分け合ってしまう**（実測で踏んだ。**当時は DB 側も 1 人 1 件だった** — **#307 の段階 5-a-1 で、画面だけがこの形になった**）。**窓は固定窓**なので、**境目では瞬間的に上限の 2 倍まで通り得る。**

## RT-305.8 `/token` の `grant_type=password` も、続けて間違えると断られる

| | |
|---|---|
| 観点 | **この口だけ、パスワードの失敗を数えていなかった** — **`SignInManager` を通らず、`VerifyHashedPassword` を直に呼んでいた**ため、**画面のサインインのロックアウトが効かなかった。****クライアント認証の失敗は数えていたが、それはクライアントの秘密の話**であって、**同じ `client_id` の下で利用者名を変えながら試す経路は止まらなかった。****応答は、どの場合も `access_denied` のまま**（**断っていることも、利用者が居るかも、教えない**。`TC-4.2`）。 |
| 根拠 | RFC 6749 §4.3 / #305 の段階 4 |
| テスト | `RT30508_tokenのパスワードも続けて間違えると断られる` |

**手順**

1. 使い捨ての利用者を作る（共用のテスト利用者を断らないため）
1. 正しいパスワードなら通る（断る前の確認）
1. 間違ったパスワードで 20 回失敗する
1. 正しいパスワードでも断られる
1. 5 ＋ 1 秒待つと、また通る

**検証（合否を判定する）**

- access_token が出る
- トークンを出さない（1 回目）
- トークンを出さない（2 回目）
- トークンを出さない（3 回目）
- トークンを出さない（4 回目）
- トークンを出さない（5 回目）
- トークンを出さない（6 回目）
- トークンを出さない（7 回目）
- トークンを出さない（8 回目）
- トークンを出さない（9 回目）
- トークンを出さない（10 回目）
- トークンを出さない（11 回目）
- トークンを出さない（12 回目）
- トークンを出さない（13 回目）
- トークンを出さない（14 回目）
- トークンを出さない（15 回目）
- トークンを出さない（16 回目）
- トークンを出さない（17 回目）
- トークンを出さない（18 回目）
- トークンを出さない（19 回目）
- トークンを出さない（20 回目）
- 正しいパスワードでもトークンが出ない
- 応答は誤パスワードと同じ access_denied
- 待てば access_token が出る

**補足**

- **数えているのは `Users` 表**（`AccessFailedCount` / `LockoutEndDateUtc`）であって、`AuthFailure` 表ではない。 **画面のサインインと同じ数え**なので、**口を変えれば回数が戻る、という抜けが無い。** **利用者名が見つからないときは数えられない**（鍵が無い）— **利用者名を変えながら試す経路は、口ごとのレート制限が頭を打つ**（段階 3）。

## RT-306.1 `redirect_uri` を 2 件登録すると、どちらを指定しても認可コードが取れる

| | |
|---|---|
| 観点 | **以前は 1 本しか登録できなかった**（`ANALYSIS-IdP.md` の D-8）。**開発と本番を 1 つの `client_id` で共存させられず**、**Web とモバイルのような複数のプラットフォームも扱えなかった。****登録は空白区切りの列挙**で、**要求の値は、そのいずれかと完全一致すればよい。** |
| 根拠 | RFC 6749 §3.1.2.2 / OIDC Core §3.1.2.1 / #306 |
| テスト | `RT30601_2件登録するとどちらでも認可コードが取れる` |

**手順**

1. 1 本目（https://localhost:44300/e2e/rt306/a）で認可コードが取れる
1. 2 本目（https://localhost:44300/e2e/rt306/b）でも認可コードが取れる

**検証（合否を判定する）**

- 1 本目で code が返る
- 折り返し先は 1 本目
- 2 本目でも code が返る
- 折り返し先は 2 本目

**補足**

- **区切りは空白である。** **URI に空白は入らない**（RFC 3986 §2）ので曖昧にならない。 **カンマは区切りにしていない** — **`sub-delims` に含まれるので URI に入り得る**（RFC 3986 §2.2）。

## RT-306.2 登録に無い `redirect_uri` は `invalid_request` になる

| | |
|---|---|
| 観点 | **n 件になっても、照合は完全一致のままである。****前方一致にはしていない** — **#263 で `StartsWith` をやめ、`ToLower()` 同士の比較もやめた**（C-10）。**登録の数が増えても、そこは変えていない。** |
| 根拠 | RFC 6749 §3.1.2.3（RFC 3986 §6.2.1 の単純文字列比較）/ #306 |
| テスト | `RT30602_登録に無いredirect_uriは断られる` |

**手順**

1. 登録に無い https://localhost:44300/e2e/rt306/c を送る
1. 1 本目の接頭辞（末尾を削った値）も通らない

**検証（合否を判定する）**

- code を返さない
- 接頭辞でも code を返さない

**補足**

- **登録に無い折り返し先へは、応答を飛ばさない。** **飛ばせると、任意の URL に認可コードを渡せる**ことになる。

## RT-306.3 2 件以上登録しているとき、`redirect_uri` の省略は `invalid_request` になる

| | |
|---|---|
| 観点 | **1 本しか登録できなかった頃は、省略すると登録値がそのまま使われていた。****n 件になると、どれを使うべきか決められない。****RFC 6749 §3.1.2.3 は、複数登録しているなら要求に含めること**としている。**1 件だけの配備では、従来どおり省略できる** — **既存のケースの大半が、その経路で回っている。** |
| 根拠 | RFC 6749 §3.1.2.3 / #306 |
| テスト | `RT30603_2件登録のとき省略は断られる` |

**手順**

1. redirect_uri を送らない

**検証（合否を判定する）**

- code を返さない

**補足**

- **1 件だけ登録している配備は、従来どおり省略できる。** **この分岐は件数で決まる** — **設定は増えていない。**

## RT-307.1 `registration_endpoint` で登録でき、返った `client_id` / `client_secret` で実際に認可コードが取れる

| | |
|---|---|
| 観点 | **登録が「本当に効いている」ことまで測る。****201 と `client_id` が返るだけでは、使える登録になったとは言えない** — **`redirect_uri` が正しい列に入っていなければ、認可要求が通らない。** |
| 根拠 | RFC 7591 §3.1 / §3.2.1（201 Created）/ OIDC DCR 1.0 §2 / #307 |
| テスト | `RT30701_登録でき返った資格情報で認可コードが取れる` |

**手順**

1. redirect_uris を 2 本登録する
1. 返った資格情報で、認可コードを取る

**検証（合否を判定する）**

- HTTP の状態は 201
- client_id が返る
- client_secret が返る
- client_id_issued_at が返る
- client_secret_expires_at は 0（期限なし）
- grant_types の既定は authorization_code
- response_types の既定は code
- redirect_uris に 1 本目が入る
- redirect_uris に 2 本目が入る
- code が返る

**補足**

- **`client_name` は登録しても無視する**（RFC 7591 §3.2.1 が認めている）— **`ClientName` の列は利用者名であり、`Helper.GetClientName` が「登録が在るか」の判定に使っている。** **応答にも入れない**（利用者名を漏らさないため）。

## RT-307.2 トークンが無ければ `401`、scope が足りなければ `403` ＋ `insufficient_scope`

| | |
|---|---|
| 観点 | **この口は、クライアント登録を作れる。****誰でも叩けてはならないし、普通のアクセス トークンでも叩けてはならない。****専用 scope（`client_registration`）は、登録に明記したクライアントにしか出さない** — **他の scope の「登録が無ければ制限しない」とは逆の倒し方である。** |
| 根拠 | RFC 6750 §3.1（invalid_token / insufficient_scope）/ #307 |
| テスト | `RT30702_トークンが無ければ401scopeが足りなければ403` |

**手順**

1. Bearer を付けずに叩く
1. 出来合いでない（偽の）トークンで叩く
1. 専用 scope を持たないトークンで叩く

**検証（合否を判定する）**

- HTTP の状態は 401
- WWW-Authenticate: Bearer が付く
- HTTP の状態は 401
- error は invalid_token
- HTTP の状態は 403
- error は insufficient_scope

**補足**

- **`client_registration` は、登録に明記していなければ出さない。** **「登録が無ければ制限しない」を当てはめると、`scope` を登録していない既存のクライアントが全て、ROPC で登録を作れることになる。**

## RT-307.3 **1 利用者 n クライアント** — 2 件目以降も登録でき、**別々に使え、別々に消せる**

| | |
|---|---|
| 観点 | **段階 1 では 2 件目を `403` ＋ `access_denied` で断っていた。** **絞っていたのは仕様の要求ではなく、器の都合である** — **所有者が `Users.ClientID`（1 枠・NOT NULL・一意索引）だった。** **段階 5-a で `Saml2OAuth2Data.OwnerUserId`（行ごと）へ移したので、縛りが外れた。** **201 が 2 回返るだけでは足りない** — **2 つが本当に別の登録として生きていること**（**資格情報が違い、片方を消してももう片方が動くこと**）**まで測る。** |
| 根拠 | RFC 7591 §3.1 / §3.2.1 / RFC 7592 §2.3 / #307 の段階 5-a |
| テスト | `RT30703_2件目以降も登録でき別々に使える` |

**手順**

1. 1 件目を登録する
1. 同じトークンで 2 件目も登録できる
1. 2 つは別の登録である（資格情報が違う）
1. どちらでも認可コードが取れる（それぞれの折り返し先で）
1. 1 件目を DELETE しても、2 件目は生きている
1. 所有者を消すと、その人の登録は全部消える

**検証（合否を判定する）**

- HTTP の状態は 201
- HTTP の状態は 201
- client_id が違う
- client_secret が違う
- registration_access_token が違う
- 1 件目で code が取れる
- 2 件目で code が取れる
- DELETE は 204
- 2 件目は GET で読める（200）
- 2 件目で、まだ code が取れる
- 1 件目は、もう読めない（401）
- 2 件目も、もう読めない（401）

**補足**

- **`POST` を upsert にはしていない。** **2 回 `POST` すれば、2 件の別の登録になる**（それが n 件である）。**特定の登録を直すのは RFC 7592 の `PUT`**（段階 2）。
- **上限は設けていない**（設定キーも増やしていない）。**洪水はレート制限で受ける**（#305 の段階 3。口の名前 `register`）。
- **管理画面は、まだ 1 件だけを扱う**（段階 5-a-1）。**API から 2 件作った利用者が画面で保存すると、画面が扱う 1 件に寄る** — **一覧にするのは段階 5-a-2。**
- **行が無くなるので `401`**（`404` ではない。RFC 7592 §2.1 の MUST）。**撃ち分けると「在るが触れない」ことが外から分かる**ためである。
- **所有者を書いていなければ、ここで落ちる** — **`OwnerUserId` が空の登録は、利用者を消しても残る**（**種データが、わざとその立場に在る**）。

## RT-307.4 メタデータの誤りは `400`（`invalid_redirect_uri` / `invalid_client_metadata`）

| | |
|---|---|
| 観点 | **知らないメタデータは無視してよい**（RFC 7591 §3.2.1）が、**無視すると黙って弱くなるものは断る。****`jwks_uri` は受け付けるようになった**（#309 の段階 1）が、**読めない URL は、登録のその場で断る** — **受け取って無視すると、`private_key_jwt`（#239）や Request Object（JAR）の検証が、登録したつもりの鍵で通らなくなる。** |
| 根拠 | RFC 7591 §3.2.1 / §3.2.2 / RFC 6749 §3.1.2 / #307 |
| テスト | `RT30704_メタデータの誤りは400になる` |

**手順**

1. redirect_uris が無い
1. redirect_uri にフラグメントが付いている
1. 相対 URI は通らない
1. 読めない jwks_uri は受け付けない（#309 の段階 1）
1. 壊れた software_statement は受け付けない（段階 4）
1. response_types と grant_types が噛み合っていない
1. 専用 scope は、動的登録では付けられない
1. auth（同意画面を出さない）も、動的登録では付けられない
1. どの誤りでも、登録は作られていない

**検証（合否を判定する）**

- HTTP の状態は 400
- error は invalid_redirect_uri
- HTTP の状態は 400
- error は invalid_redirect_uri
- HTTP の状態は 400
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- error は invalid_software_statement
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- error は invalid_client_metadata
- この後で、正しい要求は 201 になる

**補足**

- **この URL には JWK Set が無い**（この配備自身の、存在しないパス）。**登録の口は取りに行って、読めなければ断る**（#309 の決め (B)）。**読める `jwks_uri` を登録して使うところは `RT-309.*`** で測る。
- **自分と同じ強さの scope を、自分で配らせない。** **`client_registration` を動的登録で付けられるようにすると、権限を際限なく増やせる。** **配るのは、管理画面か構成ファイルからだけ**にしてある。
- **同意画面を飛ばすかは、登録を管理する人が決める**（#294）。**自分で `auth` を登録できると、クライアントが決めることになる。**

## RT-307.5 管理 API 専用のアクセス トークンは、scope も有効期限も絞られている

| | |
|---|---|
| 観点 | **配備ぜんたいの `OAuth2AccessTokenExpireTimeSpanFromMinutes`（既定 360 分）では長すぎる** — **この口は、人の操作より CI から叩く想定**で、長く持たせる理由が無い。**scope も混ぜない** — **登録を作れる権限を持ったトークンが、利用者の属性を読む用途でも使い回されると、寿命を短くした意味が薄れる。** |
| 根拠 | RFC 6749 §3.3 / #307 |
| テスト | `RT30705_専用トークンはscopeも有効期限も絞られている` |

**手順**

1. 専用 scope を、他の scope と一緒に要求する
1. 有効期限が、配備ぜんたいの値より短い
1. 応答の expires_in も、絞った期限を言う（#294）

**検証（合否を判定する）**

- scope は専用の 1 本だけ
- 1 時間より短い
- expires_in が exp - iat と一致する（差が 5 秒以内）

**観測（判定しない）**

- exp - iat（秒）

**補足**

- **既定は 300 秒**（`DcrAccessTokenExpireTimeSpanFromSeconds`。**未設定・0 以下なら既定値に倒す**）。**ここで値そのものを突き合わせないのは、配備で変えられる設定だから**である。

## RT-307.6 登録した `response_types` が、認可エンドポイントで効く

| | |
|---|---|
| 観点 | **保存して返すだけにはしない。****登録が「`code` だけ」と言っているのに認可サーバが `token` も通すのでは、登録の意味が無い。****絞りは認可エンドポイントで効く** — **利用者を操作させる前に断る**ため。**`ClientModePolicy`（登録種別で、その経路を許すか）の手前に 1 段置いてある。** |
| 根拠 | RFC 7591 §2（response_types）/ RFC 6749 §4.1.2.1（unauthorized_client）/ #307 |
| テスト | `RT30706_登録したresponse_typesが効く` |

**手順**

1. 登録した response_type（code）は通る
1. 登録に無い response_type（token）は断られる

**検証（合否を判定する）**

- code が返る
- error は unauthorized_client

**観測（判定しない）**

- error_description

**補足**

- **列が空なら絞らない**（#198 と同じ倒し方）。**既存の登録はこの列を持たないので、RFC 7591 §2 の既定（`code`）を当てはめてはならない** — **当てはめると「`code` 以外が通らなくなる」破壊になる。** **既定を書き込むのは、動的登録で作るときだけ。**

## RT-307.7 登録した `grant_types` が、トークン エンドポイントで効く

| | |
|---|---|
| 観点 | **`grant_types` と `response_types` は別物である。****認可エンドポイントは `response_types` を見る**が、**どのグラントでトークンを出すかは `grant_types` で決まる。****`ClientModePolicy`（登録種別 × 証明）の手前に 1 段置いてある** — **`ClientModePolicy` は AS の方針、`grant_types` は RP の申告**であり、**役割が違う。** |
| 根拠 | RFC 7591 §2（grant_types）/ RFC 6749 §5.2（unauthorized_client）/ #307 |
| テスト | `RT30707_登録したgrant_typesが効く` |

**手順**

1. 認可コードは取れる（認可エンドポイントは grant_types を見ない）
1. その code の交換は、unauthorized_client で断られる
1. 登録した grant_type（password）は通る

**検証（合否を判定する）**

- code が返る
- access_token を返さない
- error は unauthorized_client
- access_token が返る

**観測（判定しない）**

- error_description

**補足**

- **列が空なら絞らない。** **通しの大半が、この経路（列を持たない既存の登録）で回っている。**

## RT-307.8 登録した `scope` が、DB に登録したクライアントでも効く

| | |
|---|---|
| 観点 | **これまで、クライアントごとの `scope` の絞りは構成ファイルのクライアントにしか効いていなかった** — **`Helper.GetClientScopes` が構成ファイル（`OAuth2ClientsInformation`）だけを見ていたため、DB に登録したクライアントは「登録が無い」扱いになり、#198 の後半（クライアントごとの絞り）が一切効かなかった**（`scopes_supported` の絞りだけが効いていた）。**#307 の段階 1 で `Scopes` の列を足し、DB も見るようにした。** |
| 根拠 | RFC 7591 §2（scope）/ RFC 6749 §3.3 / #198 / #307 |
| テスト | `RT30708_登録したscopeが効く` |

**手順**

1. scope を openid だけにして登録する
1. 登録に無い scope（email）も一緒に要求する

**検証（合否を判定する）**

- HTTP の状態は 201
- 応答の scope は openid
- 登録した openid は載る
- 登録に無い email は載らない

**観測（判定しない）**

- トークンに載った scope

**補足**

- **断る（`invalid_scope`）のではなく、外す** — **RFC 6749 §3.3 : 認可サーバは、要求されたスコープの一部または全部を無視してよい**（#198 と同じ倒し方）。 **列が空なら絞らない。**

## RT-307.9 `registration_client_uri` を `GET` すると、登録の全体が返る

| | |
|---|---|
| 観点 | **登録の応答は 1 回しか返らない** — **RP が自分の登録を確かめる口が無いと、「登録したつもりの値」と「実際に登録された値」の食い違いに気付けない**（**RFC 7591 §3.2.1 は、サーバが値を拒否・置換してよい**としている）。**`client_secret` は返さない** — **トークンが漏れても、秘密は漏らさない。** |
| 根拠 | RFC 7592 §2.1 / §3 / #307 の段階 2 |
| テスト | `RT30709_登録を読める` |

**手順**

1. 登録する（応答に管理の口と、その鍵が入る）
1. その口を読む

**検証（合否を判定する）**

- HTTP の状態は 201
- registration_access_token が返る（§3 で REQUIRED）
- registration_client_uri が返る（§3 で REQUIRED）
- registration_client_uri は client_id で終わる（絶対 URI）
- HTTP の状態は 200
- client_id は変わらない（§2.1 の MUST）
- redirect_uris が返る
- scope が返る
- grant_types が返る
- registration_client_uri が返る（§3 で REQUIRED）
- registration_access_token が返る（§3 で REQUIRED）
- client_secret は返らない

**補足**

- **提示されたトークンを、そのまま返している** — **保管しているのはハッシュ**なので、**こうでなければ §3 の REQUIRED を満たせない。** **トークンは回さない**（§5 / A.1 は MAY）— **回すと、どちらが有効か取り違えた RP が、管理できなくなる。**
- **`client_id_issued_at` は `GET` では返さない** — **保管していない**（§3.2.1 で任意）。**発行時の `201` だけが返す。**

## RT-307.10 `PUT` で登録を置き換えられ、**新しい値が実際に効く**

| | |
|---|---|
| 観点 | **`200` と新しい値が返るだけでは、効いたことにならない** — **古い `redirect_uri` が通り続けたら、置換できていない。****全置換である**（§2.2 : 省いた項目は消える）ことも、ここで測る。 |
| 根拠 | RFC 7592 §2.2 / RFC 6749 §3.1.2.3 / #307 の段階 2 |
| テスト | `RT30710_PUTで全置換でき置換が実際に効く` |

**手順**

1. redirect_uris = A、scope = openid email で登録する
1. redirect_uris = B、scope = openid に置き換える
1. 新しい redirect_uri（B）で認可コードが取れる
1. 古い redirect_uri（A）は、もう通らない
1. 置換で外した scope（email）は、トークンに載らない

**検証（合否を判定する）**

- HTTP の状態は 200
- redirect_uris が B になる
- redirect_uris から A が消える
- scope が openid になる
- code が返る
- code は返らない
- 置換で残した openid は載る
- 置換で外した email は載らない

**観測（判定しない）**

- error
- トークンに載った scope

**補足**

- **`scope` を省くと、絞りが消える**（**列が空 ＝ 絞らない**。段階 1 の決め）— **§2.2 の「省略は削除要求」に従うと、そうなる。****`client_registration` だけは、明記しても断る**（自己昇格の禁止）。
- **`redirect_uris` は省けない**（OIDC DCR 1.0 §2 で必須）ので、**うっかり全消しにはならない**（`RT-307.13` の (4) が、それを測る）。**`grant_types` / `response_types` を省くと、RFC 7591 §2 の既定（`authorization_code` / `code`）に戻る** ＝ **狭まる。**

## RT-307.11 `DELETE` で登録が消え、**既に出ているアクセス トークンも通らなくなり**、**同じ利用者が登録し直せる**

| | |
|---|---|
| 観点 | **消えたクライアントのトークンが期限まで通ると、払い下げの意味が無い**（RFC 7592 §2.3 : 削除したら、そのクライアントのトークンを無効にすべき）。**`VerifyAccessToken` の「クライアントがまだ在るか」の確認は、効いていなかった** — **`GetClientSecret` は未登録でも `""` を返す**ので、**`!= null` が常に真**だった（**#307 の段階 2 で `Helper.HasClient` にした**）。**段階 1 〜 4 は 1 利用者 1 クライアントだった**ので、**消せないと登録し直せなかった** — **その確認も、ここで一緒に測る**（**段階 5-a-1 で上限は無くなった**）。 |
| 根拠 | RFC 7592 §2.3 / §5 / #307 の段階 2 |
| テスト | `RT30711_DELETEできて登録し直せる` |

**手順**

1. 登録して、そのクライアントのアクセス トークンを取る
1. 消す
1. 既に出ていたアクセス トークンが、もう通らない
1. 2 回目の GET は 401（払い下げたトークンは無効。§5）
1. 消えたクライアントでは、認可コードも取れない
1. 同じ利用者が、登録し直せる

**検証（合否を判定する）**

- 消す前は /userinfo が 200
- HTTP の状態は 204（§2.3 の MUST）
- 本体は空
- /userinfo は 401
- HTTP の状態は 401
- code は返らない
- HTTP の状態は 201

**補足**

- **消すのは登録の行だけ** — **所有者（`Users`）の行は触らない。** **所有者は `Saml2OAuth2Data.OwnerUserId`（登録の行ごと）**なので、**行が消えれば結び付きも一緒に消える**（**管理画面の削除も同じ**）。 **同じ利用者が、何件でも登録できる**（**#307 の段階 5-a-1 で上限が無くなった**）。**同意は落とす**（`ConsentProvider.Revoke`）。
- **段階 1 〜 4 は、所有者が `Users.ClientID`（利用者の行の 1 枠）だった** — **`DELETE` でそこを空にしようとして、`sql` で `500` になった**（**NOT NULL ＋ 一意索引 ＋ 外部キー。`mem` には制約が無く、出なかった**。**この (6) と `RT-307.12` の (6) が捕まえた**）。**段階 5-a-1 で、その列ごと落とした。**
- **外部のリソース サーバが、自前で JWT を検証する場合は止まらない** — **鍵と `exp` だけで通るため**（`/revoke` と同じ限界）。**この IdP の検証を通る口（`/userinfo` ほか）では止まる。**

## RT-307.12 管理 API は、**`registration_access_token` 以外では叩けない**

| | |
|---|---|
| 観点 | **作る権限と、直す権限は別物である**（§2 : クライアントは `registration_access_token` を使うこと）。**段階 1 の専用 scope のアクセス トークンで管理まで出来てしまうと、「作った人」が「他の誰かの登録」を触れる形に近づく。****知らない `client_id` も `401` にする** — **`404` と撃ち分けると、「在るが触れない」ことが外から分かる。** |
| 根拠 | RFC 7592 §2.1 / §5 / RFC 6750 §3.1 / #307 の段階 2 |
| テスト | `RT30712_管理APIの守り` |

**手順**

1. 登録する
1. トークンを付けずに読む
1. 偽のトークンで読む
1. 段階 1 の専用 scope のアクセス トークンでは読めない
1. 知らない client_id は 401（404 ではない）
1. 別の登録のトークンでは触れない

**検証（合否を判定する）**

- HTTP の状態は 401
- WWW-Authenticate が付く（RFC 6750 §3）
- HTTP の状態は 401
- error は invalid_token
- HTTP の状態は 401
- HTTP の状態は 401
- HTTP の状態は 401

**補足**

- **管理画面で作った登録・段階 1 で作った登録には、`registration_access_token` が無い** — **それらは、この口では触れない**（`401`）。**所有者は、管理画面で自分の 1 件を編集・削除できる。**

## RT-307.13 `PUT` のメタデータの誤りは `400` で、**登録は変わらない**

| | |
|---|---|
| 観点 | **全置換の口である**ことが、そのまま危うさになる — **誤った要求が中途まで適用されると、動いていた登録が壊れる。****`client_id` の一致**（§2.2 の MUST）と**`client_secret` を自分で決めさせない**（同）ことも、ここで測る。 |
| 根拠 | RFC 7592 §2.2 / RFC 7591 §3.2.2 / #307 の段階 2 |
| テスト | `RT30713_PUTの誤りは400で登録は変わらない` |

**手順**

1. redirect_uris = A、scope = openid で登録する
1. client_id を入れない
1. 別の client_id を入れる
1. redirect_uris を入れない（§2.2 の「省略は削除」でも、必須は必須）
1. 違う client_secret を入れる
1. 専用 scope を、自分に付けようとする
1. どの誤りでも、登録は変わっていない

**検証（合否を判定する）**

- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- HTTP の状態は 400
- error は invalid_redirect_uri
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 200
- redirect_uris は A のまま
- redirect_uris に B は入っていない
- scope は openid のまま

**補足**

- **読み取り専用の 4 つ**（`registration_access_token` / `registration_client_uri` / `client_id_issued_at` / `client_secret_expires_at`）**は、入っていても無視する** — **§2.2 は「入れるな」と書くが、断ると 「`GET` して直して返す」が成り立たない。**

## RT-307.14 token_endpoint_auth_method=private_key_jwt と jwks を登録すると、その鍵の client_assertion で認証でき、client_secret では認証できない

| | |
|---|---|
| 観点 | **段階 1・2 は、秘密ベースの 2 つしか登録できなかった**（`jwks` は断っていた）。**強い認証方法を使う配備では、API で作ったクライアントを、管理画面で直す手作業が残っていた。****検証する側は #239 / #129 の段階 2 で実装済み**なので、**段階 3 で足したのは「登録を受けて列に入れる」ところだけ**である。**登録された方法は、認証でも効く** — **鍵を登録したクライアントは、秘密では通らない。** |
| 根拠 | RFC 7591 §2 / RFC 7523 §2.2 / RFC 7592 §3 / #307 の段階 3 |
| テスト | `RT30714_private_key_jwtで登録するとその鍵で認証できる` |

**手順**

1. jwks（RSA 1 本）と token_endpoint_auth_method=private_key_jwt で登録する
1. 登録した鍵の client_assertion で、認可コードを交換する
1. （対照）同じクライアントを client_secret で交換すると、通らない

**検証（合否を判定する）**

- HTTP の状態は 201
- 応答の token_endpoint_auth_method は private_key_jwt
- 応答に jwks が返る（登録した鍵）
- client_secret も返る（方法に関わらず発行する）
- HTTP の状態は 200
- access_token が返る
- HTTP の状態は 401
- エラーは invalid_client

**補足**

- **登録された方法でなければ通さない**（段階 3）。**以前は「登録されている資格のどれかで通る」**作りだったので、**鍵を登録しても、秘密でも入れた** ＝ **登録で求めた強さが効かなかった。**
- **`client_secret_basic` と `client_secret_post` は区別しない** — **どちらで来たかを、この層は知らない**（口が同じ形に正規化して渡す）。

## RT-307.15 token_endpoint_auth_method=tls_client_auth と tls_client_auth_subject_dn を登録すると、その証明書で認証できる

| | |
|---|---|
| 観点 | **照合は `x509.Subject` との完全一致**である（RFC 8705 §2.1）。**検証する側は #226 で実装済み**で、**#305 の段階 4 で「登録が空なら通さない」まで入っている。****段階 3 で足したのは、動的登録から DN を登録できるようにしたところだけ。** |
| 根拠 | RFC 8705 §2.1 / §2.1.2 / RFC 7591 §2 / #307 の段階 3 |
| テスト | `RT30715_tls_client_authで登録するとその証明書で認証できる` |

**手順**

1. tls_client_auth と Subject DN を登録する
1. Subject が一致する証明書を添えて交換する（client_secret は送らない）
1. （対照）Subject が違う証明書では、通らない

**検証（合否を判定する）**

- HTTP の状態は 201
- 応答の token_endpoint_auth_method は tls_client_auth
- 応答に tls_client_auth_subject_dn が返る
- access_token が返る
- access_token は返らない

**補足**

- **DN は 1 文字も違ってはならない**（`#263` の `redirect_uri` と同じ厳しさ）。**`tls_client_auth` を登録すると、RFC 8705 §3 の「証明書に縛られたアクセス トークン」も効く**（既存の振る舞い）。

## RT-307.16 認証できない登録は作らせない（材料が無い・鍵が多い・知らない方法・jwks_uri）

| | |
|---|---|
| 観点 | **黙って作ると、クライアントは「登録した方法で認証できる」と考えるが、永久に通らない。** **どれも「無視すると黙って弱くなる／壊れる」もの**なので、**登録の時点で断る**（RFC 7591 §3.2.2 : `invalid_client_metadata`）。 |
| 根拠 | RFC 7591 §2 / §3.2.2 / RFC 7517 §5 / RFC 8705 §2.1.2 / #307 の段階 3 |
| テスト | `RT30716_方法と鍵の誤りは登録の時点で断る` |

**手順**

1. private_key_jwt なのに jwks が無い
1. tls_client_auth なのに tls_client_auth_subject_dn が無い
1. 知らない token_endpoint_auth_method
1. jwks に RSA が 2 本
1. jwks_uri（鍵を URL から引く）は、受け付けない
1. device_code グラント × private_key_jwt

**検証（合否を判定する）**

- HTTP の状態は 400（鍵が無ければ、その方法では認証できない）
- error は invalid_client_metadata
- HTTP の状態は 400（DN が無ければ、照合する相手が無い）
- error は invalid_client_metadata
- HTTP の状態は 400（広告していない方法（既知でない値は拒否する。#224 の段階 2 と同じ方針））
- error は invalid_client_metadata
- HTTP の状態は 400（列は RSA 1 本しか持てない。先頭を採ると、もう一方の鍵で署名したときに失敗する）
- error は invalid_client_metadata
- HTTP の状態は 400（クライアント認証の経路が同期なので、取得を差し込めない（別 Issue））
- error は invalid_client_metadata
- HTTP の状態は 400（RFC 8628 の口は client_assertion を読まないので、永久に認証できない）
- error は invalid_client_metadata

**観測（判定しない）**

- error_description
- error_description
- error_description
- error_description
- error_description
- error_description

**補足**

- **`jwks` と `jwks_uri` を同時に送ることも断る**（RFC 7591 §2 は、どちらか一方としている）。**ここでは `jwks_uri` を単独で送って断られることだけを測った。**

## RT-307.17 PUT で token_endpoint_auth_method を省くと秘密ベースに戻り、jwks は持ち越される

| | |
|---|---|
| 観点 | **`PUT` は全置換**（§2.2 : 省いた項目は「消す要求」）。**方法は、その規則どおり省略で消える** ＝ **秘密ベースに戻る。****鍵と DN だけは持ち越す** — **管理画面から入れた鍵を、`PUT` で消してはならない**（段階 2 の「動的登録で設定できない列」と同じ考え方）。**方法を明記するなら、材料も毎回送ること**（材料が無ければ `400`）。 |
| 根拠 | RFC 7592 §2.2 / §3 / #307 の段階 3 |
| テスト | `RT30717_PUTで方法を省くと秘密に戻るが鍵は消えない` |

**手順**

1. private_key_jwt ＋ jwks で登録する
1. 方法と jwks を省いて PUT する（redirect_uris と client_id だけ）
1. GET で読み直しても、同じである
1. 秘密ベースに戻ったので、client_secret で交換できる

**検証（合否を判定する）**

- HTTP の状態は 200
- token_endpoint_auth_method は client_secret_basic に戻る
- jwks は残っている（省いても消さない）
- GET も client_secret_basic
- GET でも jwks が返る
- access_token が返る

**補足**

- **省略で方法が戻るのは、§2.2 のとおり**である。**ただし「方法だけ戻って、鍵が残る」状態になる** — **鍵は使われなくなるだけで、害は無い**（**認証に使えるのは、登録された方法だけ**）。

## RT-307.18 署名付きの `software_statement` で登録でき、**主張した値が本文（plain JSON）に勝つ**

| | |
|---|---|
| 観点 | **これが機能の要点である。** **ベンダは security に効く項目を statement で固定し**、**配置ごとに変わる項目は本文に書かせる。** **配置側が折り返し先を勝手な所に書き換えても、statement が上書きして効かない。** **201 が返るだけでは足りない** — **どちらの値で登録されたかを、実際の認可要求で確かめる。** |
| 根拠 | RFC 7591 §2.3（MUST take precedence）/ §3.1.1 / #307 の段階 4 |
| テスト | `RT30718_software_statementで登録でき主張が本文に勝つ` |

**手順**

1. 本文は redirect_uris = B、statement は A を主張する
1. statement だけに在る項目は、そのまま使われる
1. 本文だけに在る項目も、そのまま使われる
1. software_statement 自身は、応答に出ない（保管しない）
1. 主張された折り返し先（A）で、実際に認可コードが取れる
1. 本文に書いた折り返し先（B）では、通らない

**検証（合否を判定する）**

- HTTP の状態は 201
- redirect_uris は A（statement が勝つ）
- redirect_uris に B は入らない
- software_id が入る
- scope は本文の値
- software_statement は返らない
- A では認可コードが返る
- B では認可コードが返らない

**補足**

- **食い違っても断らない。** **statement を採り、オペレーション ログに残す**（§2.3 が優先順位を MUST で定めているため）。**上書きされた項目の名前だけを残し、値は書かない。**
- **statement は認可ではない。** **この登録でも、専用 scope のアクセス トークンは要る**（**statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**）。

## RT-307.19 壊れた `software_statement` は `400` ＋ `invalid_software_statement`

| | |
|---|---|
| 観点 | **「読めたが信頼していない」のと「壊れている」のを分ける**（§3.2.2 の 2 つのコード）。**黙って無視してはならない** — **クライアントは「主張した内容で登録された」と考える。** |
| 根拠 | RFC 7591 §2.3 / §3.2.2（invalid_software_statement）/ #307 の段階 4 |
| テスト | `RT30719_壊れたsoftware_statementは400` |

**手順**

1. JWT ではない値
1. 署名が合わない（最後の 1 文字を変える）
1. iss が無い（§2.3 は必須）
1. exp が切れている
1. aud が、この認可サーバではない

**検証（合否を判定する）**

- HTTP の状態は 400（3 つに分かれていても、Base64URL の JSON でなければ読めない）
- error は invalid_software_statement
- HTTP の状態は 400（発行者の証明書で検証して落ちる）
- error は invalid_software_statement
- HTTP の状態は 400（iss が無いと、どの発行者の鍵で検証するかが決まらない）
- error は invalid_software_statement
- HTTP の状態は 400（exp は任意だが、在るなら効かせる（切れた保証を使わせない））
- error は invalid_software_statement
- HTTP の状態は 400（他の認可サーバ向けの statement を、ここで使い回させない）
- error は invalid_software_statement

**観測（判定しない）**

- error_description
- error_description
- error_description
- error_description
- error_description

**補足**

- **`aud` の扱いは、仕様が定めていない。** **在るときだけ `IssuerId` と照合する**（無い statement は通る）。**在るのに見ないと、他の AS へ出した保証がそのまま通る。**
- **`iat` / `nbf` は見ない**（段階 4 の決定）。**`exp` が在れば、それで足りる。**

## RT-307.20 **知らない発行者**の `software_statement` は `400` ＋ `unapproved_software_statement`

| | |
|---|---|
| 観点 | **署名が正しいことと、信頼していることは別である。** **鍵は「発行者ごと」に設定で登録する** — **設定に無い `iss` は、署名が通る鍵で作られていても受けない。** |
| 根拠 | RFC 7591 §3.2.2（unapproved_software_statement）/ #307 の段階 4 |
| テスト | `RT30720_知らない発行者は400` |

**手順**

1. 同じ鍵で署名し、iss だけを設定に無い値にする

**検証（合否を判定する）**

- HTTP の状態は 400（署名は通る鍵だが、その iss を信頼していない）
- error は unapproved_software_statement

**観測（判定しない）**

- error_description

**補足**

- **信頼する発行者を 1 件も設定していない配備では、どの statement もこれになる**（**従来どおり**）。**段階 4 の設定を書いていない配備の振る舞いは、変わっていない。**
- **認可の判定（401 / 403）が先である。** **認可されていない相手には、自分の statement が信頼されているかを教えない** — **信頼一覧の中身を、外から探らせないため。**

## RT-307.21 `PUT`（RFC 7592）でも `software_statement` が効き、**省くと本文が通る**

| | |
|---|---|
| 観点 | **検査は `Validate` の 1 か所**なので、**`POST` と `PUT` で同じ判定になる。****省いたときの振る舞いまで測る** — **statement を保管しない**決めの帰結であり、**`RequireSoftwareStatement` で閉じる穴**だからである。 |
| 根拠 | RFC 7592 §2.2（全置換）/ RFC 7591 §2.3 / #307 の段階 4 |
| テスト | `RT30721_PUTでもsoftware_statementが効く` |

**手順**

1. statement（A を主張）で登録する
1. PUT の本文は B、statement は A を主張する → A のまま
1. 壊れた statement を添えた PUT は 400（登録は変わらない）
1. statement を省いた PUT は、本文が通る（全置換）

**検証（合否を判定する）**

- HTTP の状態は 200
- redirect_uris は A のまま（statement が勝つ）
- B にはならない
- HTTP の状態は 400
- error は invalid_software_statement
- 登録は変わっていない（A のまま）
- HTTP の状態は 200
- redirect_uris は B になる

**補足**

- **(4) は仕様どおりである**（RFC 7592 §2.2 は全置換で、**`software_statement` を省いた要求は「statement 無しの登録」**）。**statement を保管しない**決め（§3.2.1 で任意）の帰結でもある。
- **閉じたい配備は `RequireSoftwareStatement` を true にする** — **`PUT` にも効く**ので、**statement を毎回添えないと `400`** になる。**この E2E は false の配備で測っている**（**true にすると既存の `RT-307.*` が全部落ちる**ため）。

## RT-307.22 **`client_credentials` のトークンで登録でき**、**所有者は「認証したクライアントの所有者」になる**

| | |
|---|---|
| 観点 | **段階 1 〜 5-a は、所有者をトークンの `sub` からしか引けなかった** — **ROPC を開けないと動的登録が使えなかった**（利用者のパスワードが要る）。**CI / IaC から叩くのに、利用者のパスワードを置きたくない。****段階 5-b で、利用者の居ないトークンも受ける** — **作る登録の所有者は、認証したクライアントの所有者**である。 |
| 根拠 | RFC 6749 §4.4 / #307 の段階 5-b |
| テスト | `RT30722_client_credentialsで登録でき所有者はクライアントの所有者` |

**手順**

1. 画面から、専用 scope を持つクライアントを登録する
1. 所有者の利用者名を変える
1. client_credentials で、専用 scope のトークンを取る
1. そのトークンで登録できる
1. 所有者は、認証したクライアントの所有者である

**検証（合否を判定する）**

- 登録できる
- この時点の一覧は 1 件
- 利用者名を変えられる
- access_token が返る
- scope は専用 scope 1 本
- HTTP の状態は 201
- client_id が返る
- その人の一覧は 2 件になる
- 動的登録で作った 1 件が、その人の一覧に出る

**補足**

- **この時点で、登録の `ClientName` は古い名前のまま**である（**ラベルだから**。段階 5-a）。**所有者の鍵は `OwnerUserId`**（`Users.Id`）なので、**切れない。**
- **他の scope と混ぜない** — **ROPC の経路と同じ規則**である（段階 1）。**期限も `DcrAccessTokenExpireTimeSpanFromSeconds`** に絞る。
- **所有者が決まるのは、認証したクライアントが所有者を持っているから**である。**構成ファイル発のクライアントは `owner` 属性**で持つ（`RT-307.23`）。**所有者を持たないクライアントでは断る**（`RT-307.24`）。

## RT-307.23 **構成ファイルの `owner`（利用者名）から、登録の所有者が決まる**

| | |
|---|---|
| 観点 | **構成ファイル発のクライアントは、利用者の行と結び付いていない** — **配備全体のもの**である。**`owner` を 1 属性足して、持ち主を書けるようにした**（#307 の段階 5-b）。**`client_credentials` で叩いたときの所有者**になる。**名前で持つ**のは**設定ファイルは人が書く物**だからで、**利用者名を変えたら設定も直す**必要がある（**登録の表の側は `Users.Id` なので切れない**）。 |
| 根拠 | #307 の段階 5-b / Helper.GetOwnerUserId |
| テスト | `RT30723_構成ファイルのownerから所有者が決まる` |

**手順**

1. `owner` に書かれた利用者を作る
1. client_credentials で、専用 scope のトークンを取る
1. 登録できる
1. 所有者は、`owner` に書かれた利用者である

**検証（合否を判定する）**

- access_token が返る
- scope は専用 scope 1 本
- HTTP の状態は 201
- その人の一覧に出る

**補足**

- **`ClientName` は所有者の利用者名**である（従来どおり）。**`client_name` を要求に書いても無視する**（RFC 7591 §3.2.1 が認めている）。

## RT-307.24 **所有者の決まらないクライアントでは、登録を断る**（`403` ＋ `access_denied`）

| | |
|---|---|
| 観点 | **`client_credentials` のトークンには利用者が居ない**ので、**所有者は認証したクライアントから引く**（#307 の段階 5-b）。**引けないことがある** — **`owner` を書いていない構成ファイルのクライアント**（配備全体のもの）、**`owner` の利用者が居ない**（設定の誤り）、**所有者の無い登録**（種データ）。**そのときは断る** — **誰のものでもない登録を作らない。** |
| 根拠 | #307 の段階 5-b / ClientRegistrationProvider.Register |
| テスト | `RT30724_所有者の決まらないクライアントでは断る` |

**手順**

1. client_credentials で、専用 scope のトークンを取る
1. 登録は断られる

**検証（合否を判定する）**

- トークンそのものは取れる
- HTTP の状態は 403
- error は access_denied
- client_id は返らない

**補足**

- **トークンの発行は通る** — **`scope` は登録に明記してある。****止まるのは `/register` の側**で、**所有者が決まらないため**である。
- **`401` ではない** — **トークンは正しい。****`401` にすると「取り直せ」と読めて、同じ失敗を繰り返させる。**

## RT-307.25 **発行者に許した範囲の外**を主張した `software_statement` は、**`unapproved_software_statement` で断る**

| | |
|---|---|
| 観点 | **段階 4 では「信じるか、信じないか」の 2 択**だった — **信頼した発行者は、何でも主張できた。****提携の範囲を技術的な上限として持てないと、無人の自動登録を許せない**（**人が審査しない道**である）。**発行者の鍵が漏れたときの被害を囲む**意味もある。 |
| 根拠 | RFC 7591 §3.2.2 / #307 の段階 6 |
| テスト | `RT30725_発行者に許した範囲の外は断る` |

**手順**

1. 範囲内の scope は通る
1. 範囲の外の scope を主張すると、断られる
1. 本文（plain JSON）に書いても、同じく断られる
1. PUT（RFC 7592）でも効く

**検証（合否を判定する）**

- HTTP の状態は 201
- 登録された scope は、主張したもの
- HTTP の状態は 400
- error は unapproved_software_statement
- HTTP の状態は 400
- error は unapproved_software_statement
- HTTP の状態は 400
- error は unapproved_software_statement

**観測（判定しない）**

- error_description

**補足**

- **黙って狭めない。** **断る** — **主張が通ったのか削られたのかが、要求した側に分からなくなる**ためである。
- **statement を付けない要求には、この上限は効かない** — **発行者が決まらない**ためである（**`RequireSoftwareStatement` でstatement を必須にすれば、その穴も閉じる**。段階 4）。
- **検査は `Validate` の 1 か所**なので、**`POST` と `PUT` で同じ判定**になる（段階 4 と同じ作り）。

## RT-307.26 **発行者の鍵を入れ替える間、新旧のどちらで署名された `software_statement` でも登録できる**

| | |
|---|---|
| 観点 | **段階 4 は証明書を 1 本しか持てなかった** — **発行者が鍵を替えると、出荷済みのソフトが一斉に登録できなくなる。****入れ替えには、新旧が並ぶ期間が要る**（**鍵のロールオーバー**）。**どちらでもない鍵は通らない**ことも、併せて測る。 |
| 根拠 | #307 の段階 6 / SoftwareStatementIssuer.CerFilePaths |
| テスト | `RT30726_発行者の鍵を入れ替える間は新旧どちらでも通る` |

**手順**

1. 1 本目の鍵で署名した statement は通る
1. 2 本目の鍵で署名した statement も通る
1. どちらでもない鍵で署名した statement は通らない

**検証（合否を判定する）**

- HTTP の状態は 201
- HTTP の状態は 201
- 主張した折り返し先が入る
- HTTP の状態は 400
- error は invalid_software_statement

**補足**

- **試す順は、書いた順**である。**1 本目以外で通ったときは、ログに残す** — **運用者が「古い鍵をいつ消せるか」を判断する材料**になる。
- **`iss` は合っていて、署名だけが合わない**ので **`invalid_software_statement`** である（**知らない発行者なら `unapproved_software_statement`**。`RT-307.20`）。

## RT-307.27 動的登録で作り・読み・直し・消した後も、**保存された登録の行が正しい**

| | |
|---|---|
| 観点 | **`PUT` は全置換**だが、**置き換えるのは動的登録が持つ列だけ**である — **所有者（`OwnerUserId`）や、管理画面から入れた列は持ち越す。** **応答だけを見ても分からない**（所有者は応答に出ない）ので、**所有者の一覧と編集の画面から、行そのものを読む。** |
| 根拠 | RFC 7591 §3.1 / RFC 7592 §2.1〜§2.3 / #307 の段階 2・5-a / #294 |
| テスト | `RT30727_動的登録のCRUDの後も登録の行が正しい` |

**手順**

1. 作る : redirect_uris = A、scope = openid email で登録する
1. 動的登録では設定できない列を、管理画面から入れる
1. 直す : redirect_uris = B、scope = openid に置き換える
1. 読む : 直した値が返る
1. 消す : 一覧から消え、もう読めない
1. 直した登録は、所有者を消すと一緒に消える

**検証（合否を判定する）**

- 所有者の一覧に出る
- 行の redirect_uri は A
- 行の scope は openid email
- HTTP の状態は 200
- 所有者の一覧に、まだ出る（所有者が保たれている）
- 行の redirect_uri は B（置き換わる）
- 行の scope は openid（置き換わる）
- 行の post_logout_redirect_uri は残る（画面から入れた列）
- 行の web_origins は残る（画面から入れた列）
- HTTP の状態は 200
- redirect_uris は B
- scope は openid
- HTTP の状態は 204
- 所有者の一覧から消える
- もう読めない（401）
- 所有者を消すと、もう読めない（401）

**補足**

- **`PUT` は、現行の行を土台にして、動的登録が持つ列だけを置き換える。** **要求の値を土台にしていた頃は、持ち越しを書き忘れた列が消えていた** — **所有者（`OwnerUserId`）がそれで、一覧から外れ、所有者を消しても登録が残った。**
- **所有者が `PUT` で消えていると、ここで `200` が返る** — **所有者で消す仕掛け**（DB は `OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`、`mem` は `CmnUserStore` の削除）が、**空の所有者には効かない**ためである。

## RT-307.28 管理画面で保存しても、**画面に出ない列（EC の公開鍵）は残る**

| | |
|---|---|
| 観点 | **画面の保存は行を丸ごと書き換える**ので、**フォームに欄の無い列は、現行の行から持ち越さないと消える。** **EC の鍵は画面に欄が無い**（動的登録の `jwks` か構成ファイルから入る）。**保存の後で、管理 API から読み直して確かめる。** |
| 根拠 | #307 の段階 3 / #294 / ManageController.AddSaml2OAuth2Data |
| テスト | `RT30728_管理画面で保存しても画面に出ない列は残る` |

**手順**

1. jwks に RSA と EC の鍵を 1 本ずつ入れて登録する
1. 管理画面で redirect_uri を B に直して保存する
1. 管理 API で読み直す

**検証（合否を判定する）**

- 画面には EC の鍵の欄が無い
- HTTP の状態は 200（registration_access_token も残る）
- 画面で直した redirect_uri（B）が返る
- RSA の鍵は残る（画面に欄が在る）
- EC の鍵も残る（画面に欄が無い）

**補足**

- **画面に欄の無い列は、保存のときに現行の行から持ち越す**（`registration_access_token` のハッシュと同じ扱い）。**持ち越していなかった頃は、画面で保存するたびに EC の鍵が消えていた。**

## RT-307.29 登録を消すと、**所有者以外の利用者の同意も消える**（動的登録の `DELETE`・管理画面の削除）

| | |
|---|---|
| 観点 | **同意の表の `ClientID` には外部キーが無い**ので、**登録を消しても同意は残る。** **`DELETE` は所有者の同意だけを、管理画面の削除は 1 件も消していなかった。** **消した後で、利用者ごとの同意の一覧を読み直して確かめる。** |
| 根拠 | RFC 7592 §2.3 / #272 の段階 2 / #294 / ConsentProvider.RevokeByClient |
| テスト | `RT30729_登録を消すと全利用者の同意が消える` |

**手順**

1. 登録 X を作り、所有者（B）と別の利用者（C）が同意する
1. 動的登録の DELETE で X を消し、同意の一覧を読み直す
1. 登録 Y を作って C が同意し、管理画面から Y を消して、同意の一覧を読み直す

**検証（合否を判定する）**

- HTTP の状態は 204
- 所有者（B）の同意は消える
- 別の利用者（C）の同意も消える
- 管理画面から消せる
- 別の利用者（C）の同意も消える

**補足**

- **`DELETE` は、以前は所有者の同意だけを消していた**（`ConsentProvider.Revoke(所有者, client_id)`）。**管理画面の削除は、同意を 1 件も消していなかった。** **どちらも `ConsentProvider.RevokeByClient` で、全利用者の分を消すようにした。**

## RT-308.1 **発行者（ベンダ）の台帳を、画面から足して・直して・消せる**

| | |
|---|---|
| 観点 | **発行者は設定ファイルにしか置けなかった**（#307 の段階 4）。**提携先が増えるたびに配備のファイルを触り、再起動していた。****段階 6 で「許す範囲」（`allowed_scope`）が増えて、台帳としての性格が強くなった**ので、**画面で動かせるようにした**（#308）。 |
| 根拠 | #308 の段階 2 / SoftwareStatementAdminController |
| テスト | `RT30801_画面から発行者を足して直して消せる` |

**手順**

1. 足す
1. 直す
1. 消す

**検証（合否を判定する）**

- 一覧へ戻る（追加の成功）
- 一覧に出る
- 一覧へ戻る（更新の成功）
- 直した表示名が出る
- 直した上限が出る
- 一覧へ戻る（削除の成功）
- 一覧から消える

**補足**

- **鍵（`IssuerKey`）は追加のときだけ入れられる**（PK なので後から変えない）。**編集では hidden で持ち回る。**

## RT-308.2 **DB に入れた発行者**（**証明書を本文で持つ**）**の `software_statement` で、登録が通る**

| | |
|---|---|
| 観点 | **設定ファイルに書くには `.cer` をサーバへ配る必要があった**（#307 の段階 4）。**本文（`CerBody`）で持てるようにした**（#308 の段階 1）ので、**台帳を複製するだけで、提携先を増やせる。****Open棟梁 の X509 の口はファイル パスだけ**なので、**本文からはパラメタ渡しで検証している**（`JWS_*_Param`）。 |
| 根拠 | #308 の段階 1 / SoftwareStatementProvider.JwsFromCerBody |
| テスト | `RT30802_DBに入れた発行者の本文の鍵で登録が通る` |

**手順**

1. 画面から、証明書の本文で発行者を足す
1. その発行者の statement で登録できる
1. 発行者を消すと、同じ statement は通らなくなる

**検証（合否を判定する）**

- 一覧へ戻る（追加の成功）
- HTTP の状態は 201
- 主張した折り返し先が入る
- HTTP の状態は 400
- error は unapproved_software_statement

**補足**

- **`CerFilePath` は空**である（**ファイルを指していない**）。**検証に使うのは、貼った本文だけ。**
- **台帳から消すと、その発行者の保証は、その場で効かなくなる** — **設定ファイルを触って再起動する必要が無い**（これが #308 の値打ち）。

## RT-308.3 **設定ファイルに在る鍵は、画面から足せない**（**同じ鍵なら設定が勝つ**）

| | |
|---|---|
| 観点 | **読み出しは 設定 → DB の順**で、**同じ鍵なら設定が勝つ**（`IdFederationUpstreams` と同じ流儀。#292 の段階 2）。**使われない行を台帳に増やさない**ために、**追加の時点で断る。** |
| 根拠 | #308 の段階 2 / SoftwareStatementAdminController.IsInSetting |
| テスト | `RT30803_同じ鍵なら設定が勝つ` |

**手順**

1. 設定の鍵と同じ鍵では足せない
1. 設定の発行者は、そのまま効いている

**検証（合否を判定する）**

- 一覧へ戻らない（再表示）
- 誤りが出る
- 設定の行は、この画面に出ない

**観測（判定しない）**

- 誤りの文面

**補足**

- **この画面が編むのは user store の行だけ**である。**設定ファイルの行は、画面からは触れない** — **設定を直して再起動する**のが、その行の直し方になる。

## RT-309.1 動的登録で `jwks_uri` を登録でき、**その URL に置いた鍵**の `client_assertion` で `/token` が通る

| | |
|---|---|
| 観点 | **`jwks_uri` は断っていた**（#307 の段階 3）。**受け取って無視すると `private_key_jwt` が黙って通らなくなる**ので、**断る方に倒していた。** **`jwks`（鍵そのもの）だけが使えたため、RP は鍵を入れ替えるたびに登録を直す必要があった** — **`jwks_uri` が在れば、置いてある鍵を替えるだけで済む。** |
| 根拠 | RFC 7591 §2 / RFC 7523 §2.2 / #309 の段階 1 |
| テスト | `RT30901_jwks_uriを登録するとその鍵で認証できる` |

**手順**

1. 相手の JWK Set を、その URL に置く
1. jwks_uri ＋ token_endpoint_auth_method=private_key_jwt で登録する
1. その URL の鍵の client_assertion で、認可コードを交換する
1. jwks と jwks_uri の併記は 400（RFC 7591 §2 の MUST NOT）
1. 読めない jwks_uri は 400（登録のその場で断る）

**検証（合否を判定する）**

- HTTP の状態は 201
- 応答に jwks_uri が返る
- 応答に jwks は返らない（排他）
- HTTP の状態は 200
- access_token が返る
- HTTP の状態は 400
- error は invalid_client_metadata
- HTTP の状態は 400
- error は invalid_client_metadata

**観測（判定しない）**

- jwks_uri

**補足**

- **本来この URL は RP が公開する。** **E2E のクライアントは HTTP サーバを持たない**ので、**静的配信のコンテナ（44305）に置いている**（#309 の決め (H)）。
- **鍵は列に無い** — **この認証は、URL から引いた鍵で通っている。**
- **登録の口は `async` なので、ここでは取りに行って待てる**（決め (B)）。**後から黙って `private_key_jwt` が通らなくなるより、登録のその場で分かる方が良い。**

## RT-309.2 **画面から登録した `jwks_uri`**（**まだ取りに行っていない**）**は、1 回目のクライアント認証で断られ、背景で補充された後は通る**

| | |
|---|---|
| 観点 | **要求の経路ではキャッシュを読むだけ**にしてある（#309 の決め (A)）。**クライアント認証は同期の鎖**で、**そこで取得を待つと net48 で止まる** — **継続が `AspNetSynchronizationContext` へ Post され、その順番を握っているのは待っている自分**だからである。**キャッシュはプロセスの中に在る**ので、**画面から登録した直後・再起動の直後は、空である。****そのときは断って、背景で取り直す**（決め (C)(1)）。 |
| 根拠 | #309 の段階 1 / RFC 7009 §2.1 / RemoteJwkSetStore.RefillInBackground |
| テスト | `RT30902_取りに行っていないjwks_uriは1回目に断られる` |

**手順**

1. 相手の JWK Set を、その URL に置く
1. 画面から、jwks_uri ＋ private_key_jwt で登録する
1. 1 回目のクライアント認証は断られる（キャッシュが空）
1. 背景で補充された後は通る（再試行する）

**検証（合否を判定する）**

- error は invalid_client
- 再試行すると通る
- HTTP の状態は 200（知らないトークンは成功。RFC 7009 §2.2）

**観測（判定しない）**

- jwks_uri
- HTTP の状態
- 通るまでの試行

**補足**

- **この URL は、この回のテストでしか使わない名前にしてある** — **キャッシュはプロセスの中で URL ごと**なので、**他のケースと同じ URL では「空の状態」を測れない。**
- **画面は取りに行かない** — **動的登録の口だけが、登録の前に 1 回取りに行く**（決め (B)）。
- **1 回断られることは、仕様である**（#309 の決め (C)(1)）。**起動時に登録済みの `jwks_uri` を温める形は段階 2** — **温めが間に合わない窓は、どちらにしても残る**ので、**先にこの振る舞いを決めてある。**

## RT-309.3 **同じ `jwks_uri` の中身を入れ替える**と、**`PUT` で読み直して新しい鍵で認証でき、古い鍵では認証できなくなる**

| | |
|---|---|
| 観点 | **これが `jwks_uri` の存在理由**である — **鍵を入れ替えても、登録のメタデータを書き換えずに済む。****登録の時点で 1 回引いて列に焼く形**（起票時の案 (c)）**では、この性質が消える**ので、**「対応した」と言えない。** |
| 根拠 | RFC 7591 §2 / #309 の段階 1 / RemoteJwkSetStore.WarmUpAsync |
| テスト | `RT30903_同じURLの鍵を入れ替えるとPUTで読み直す` |

**手順**

1. RSA の鍵を置いて登録し、その鍵で認証できることを見る
1. 置いてある鍵を EC に入れ替える（登録は触らない）
1. PUT で同じ jwks_uri を出し直すと、読み直す

**検証（合否を判定する）**

- RSA の鍵で通る（error は無い）
- まだ RSA の鍵で通る（キャッシュが効いている）
- HTTP の状態は 200
- 古い鍵（RSA）では通らなくなる
- 新しい鍵（EC / ES256）で通る

**補足**

- **取り直しの下限は 1 分**（`RemoteJwkSetStore.MinRefetchInterval`）。**`kid` を偽った要求を並べれば、外から取得を起こせる**ので、**背景の補充には下限を置いてある。****何もしなくても、最大でその下限ぶんで追随する** — **E2E では 1 分待たない**ので、ここは `PUT` で測る。
- **登録の口は、取り直しの下限を見ない**（**毎回取りに行く**）。**認可が要り**（専用 scope のトークン）**レート制限も掛かっている**ので、**外から叩く経路にはならない。****鍵を入れ替えた相手は、`PUT` でその場で反映できる。**

## RT-309.4 **`software_statement` の中だけで主張された `jwks_uri`** でも登録でき、**その URL の鍵で、1 回目のクライアント認証から通る**

| | |
|---|---|
| 観点 | **段階 1 では断っていた** — **「署名を検証する前に、本文の外の URL へ出て行かない」**という理由だったが、**過剰だった。****同じ呼び出し元は、本文の `jwks_uri` に任意の URL を書ける**（段階 1 で既に取りに行く）ので、**statement の中に書いても、行き先の範囲は変わらない。** **キャッシュは信頼ではない** — **URL → 鍵の対応**でしかなく、**statement の検証が落ちれば登録は作られない**ので、**温めた分は誰にも使われない。** |
| 根拠 | RFC 7591 §2.3 / #309 の段階 2 |
| テスト | `RT30904_statementが主張したjwks_uriでも登録できる` |

**手順**

1. 相手の JWK Set を置き、statement だけが jwks_uri を主張する
1. 1 回目のクライアント認証から通る（登録のときに温めてある）

**検証（合否を判定する）**

- HTTP の状態は 201
- 応答に jwks_uri が返る（statement の値）
- error は無い（1 回目から通る）
- HTTP の状態は 200（知らないトークンは成功。RFC 7009 §2.2）

**補足**

- **段階 1 では `400` ＋ `invalid_client_metadata`（`The jwks_uri could not be read.`）だった** — **本文の値しか温めていなかった**ためである。
- **`jwks` を 1 本も登録していない** — **`private_key_jwt` の「材料」として `jwks_uri` を数えている**（#309 の段階 1）。

## RT-310.1 **`id_token` に `sid` が出る**（OIDC Core §2）。**同じセッション・同じ RP なら、2 回目も同じ値**で、**`refresh_token` で取り直しても同じ**

| | |
|---|---|
| 観点 | **`sid` は「どのセッションか」を言う手段**である（Front-Channel / Back-Channel Logout。#310 の段階 2・3）。**毎回違う値だと、ログアウトを伝える先と結び付かない** — **台帳（`SessionClient`）から引いていることを、ここで押さえる。** |
| 根拠 | OIDC Core §2 / #310 の段階 1 |
| テスト | `RT31001_id_tokenにsidが出て同じセッションでは変わらない` |

**手順**

1. 1 回目の id_token に sid が出る
1. 2 回目の id_token も、同じ sid である
1. refresh_token で取り直しても、同じ sid である

**検証（合否を判定する）**

- id_token に sid が在る
- 2 回目も同じ sid
- 取り直した id_token も同じ sid

**補足**

- **`refresh_token` の経路は、access_token から ClaimsIdentity を組み直して作る**（`CmnAccessToken.AddClaims`）。**そこで `sid` を戻さないと、作り直した `id_token` から消える。**
- **`access_token` にも `sid` が入る** — **`id_token` は access_token のクレーム集合から作られる**ためである（`CmnIdToken.ChangeToIdTokenFromAccessToken`）。**RP ごとに別の値**なので、**RP 同士の突き合わせには使えない。**

## RT-310.2 **同じセッションでも、`sid` は RP ごとに別の値**になる

| | |
|---|---|
| 観点 | **セッション単位で 1 つにすると、`sub` を `pairwise` にしている配備で、2 つの RP が突き合わせたときに同じ利用者だと分かってしまう**（**`sub` を分けた意味が消える**）。**仕様が求めるのは「その RP に出した `id_token` の `sid` と、その RP へ送る `logout_token` の `sid` が同じこと」**なので、**RP ごとに別の値でよい。** |
| 根拠 | OIDC Back-Channel Logout 1.0 §2.4 / OIDC Core §8 / #310 の段階 1 |
| テスト | `RT31002_sidはRPごとに別の値である` |

**手順**

1. 1 つ目の RP に id_token を発行する
1. 2 つ目の RP にも id_token を発行する（同じセッション）

**検証（合否を判定する）**

- 2 つ目の RP にも sid が在る
- 1 つ目と 2 つ目で、sid が違う

**補足**

- **セッションそのものは 1 つである**（Cookie が持つ識別子は同じ）。**台帳（`SessionClient`）が、セッション × クライアントで 1 行**を持ち、**行ごとに別の `sid`** を記録している。**段階 2 では、この表からログアウトを伝える先を引く。**

## RT-310.3 **サインアウトして入り直すと、同じ RP でも `sid` が変わる**

| | |
|---|---|
| 観点 | **`sid` が指すのはセッションであって、利用者でもクライアントでもない。****サインアウトでセッションが終わる**ので、**入り直した後は別のセッション ＝ 別の `sid`** でなければならない（**同じ値が返るなら、それはセッションを識別していない**）。 |
| 根拠 | OIDC Core §2 / #310 の段階 1 |
| テスト | `RT31003_サインアウトして入り直すとsidが変わる` |

**手順**

1. サインアウトの前に id_token を取る
1. サインアウトする（/Account/Logout）
1. 入り直して、同じ RP に id_token を取る

**検証（合否を判定する）**

- サインアウトできた（リダイレクトで返る）
- 入り直した後も sid が在る
- サインアウトの前後で、sid が違う

**補足**

- **サインアウトでは、台帳のその セッションの行も消している**（`SessionClientProvider.DeleteBySession`）。**消えたことは E2E では見えない**（**新しいセッションでは、どの行も引かれない**）。**SQL が通ることは、方言の通しで確かめている。**

## RT-310.4 **Discovery が `backchannel_logout_supported` と `backchannel_logout_session_supported` を広告する**

| | |
|---|---|
| 観点 | **RP は、OP が伝えてくれるかどうかを知る必要が在る。****広告が無ければ、RP は `backchannel_logout_uri` を登録する理由が無い。****`sid` を入れることも広告する** — **RP は `logout_token` の `sid` で、どのセッションを閉じるかを決める。** |
| 根拠 | OIDC Back-Channel Logout 1.0 §3 / #310 の段階 2 |
| テスト | `RT31004_DiscoveryがBackChannelLogoutを広告する` |

**手順**

1. 広告を読む
1. Front-Channel Logout も広告されている（段階 3 で入った）

**検証（合否を判定する）**

- backchannel_logout_supported が true
- backchannel_logout_session_supported が true
- end_session_endpoint も在る（#232 のまま）
- frontchannel_logout_supported が出ている

**補足**

- **Session Management（`check_session_iframe`）は見送った**（third-party cookie を読む仕組みで、現代のブラウザでは効かなくなりつつある）。**広告しないので、RP は使おうとしない。**

## RT-310.5 **`/end_session` でサインアウトすると、`backchannel_logout_uri` を登録した RP に `logout_token` が POST される**（中身も確かめる）。**登録が無い RP には届かない**

| | |
|---|---|
| 観点 | **OP のセッションが終わっても、RP のセッションは残る。****伝えなければ、RP では入ったままになる** — **これが D-1-2 の「他の RP へログアウトを伝えられない」である。****`logout_token` は `id_token` と別のトークン**なので、**`events` が在り、`nonce` が無いことまで見る**（**`id_token` として受け取られると、RP でサインインに使われる恐れが在る**）。 |
| 根拠 | OIDC Back-Channel Logout 1.0 §2.4 / §2.5 / #310 の段階 2 |
| テスト | `RT31005_end_sessionでlogout_tokenが届く` |

**手順**

1. 受け口を登録した RP に、トークンを発行する
1. 受け口を登録していない RP にも、トークンを発行する
1. RP からのログアウト（/end_session）
1. 受け口に logout_token が届く（背景で送られるので待つ）
1. logout_token の中身
1. 登録が無い RP には届いていない

**検証（合否を判定する）**

- id_token に sid が在る（段階 1）
- 2 つ目の RP にもトークンが出た（台帳に 2 行）
- HTTP 302
- セッションが消えている
- 届いた logout_token の数
- aud は、登録した RP の client_id
- iss は、この OP である
- sid は、その RP の id_token と同じ値
- sub も入っている（引けたので）
- jti が在る（使い回しを RP が弾ける）
- events に backchannel-logout が在る
- nonce は入っていない（MUST NOT）
- typ ヘッダは logout+jwt
- kid が在る（id_token と同じ鍵で引ける）
- 登録していない RP 宛ての logout_token が無い

**補足**

- **受信箱を空にしてから測る**（前のケースの通知が混ざらないように）。
- **署名の検証は、ここでは行っていない。** **鍵は `id_token` と同じ**（`kid` も同じ引き方）なので、**`/jwkcerts` で検証できることは `RT-302.*` が押さえている。**
- **再送はしない**（仕様も求めていない）。**届かなかったことはログに残る**（`The back-channel logout notified n of m RPs.`）。

## RT-310.6 **同意画面を出しただけ・拒否された RP には、ログアウトを伝えない**

| | |
|---|---|
| 観点 | **伝える先は「トークンを発行した相手」である。****段階 1 では、認可の口に入った時点で台帳に書いていた**ので、**同意画面を見せただけの相手・拒否された相手も、伝える先に残っていた** — **その RP に「この利用者が来た」ことを教えてしまう。****段階 2 の冒頭で、台帳に書くのを「発行の直前」に移した。** |
| 根拠 | OIDC Back-Channel Logout 1.0 §2.5 / #310 の段階 2 |
| テスト | `RT31006_同意していないRPには伝えない` |

**手順**

1. 拒否する RP の認可要求を出し、同意画面で「拒否」を押す
1. 別の RP には、きちんと発行する（伝える先が 1 つ在る状態にする）
1. サインアウトして、届いた通知を見る

**検証（合否を判定する）**

- 同意画面が出た
- access_denied が返る
- HTTP 302
- 発行した RP には届く
- 拒否した RP には届かない

**補足**

- **受信箱を空にしてから測る**（前のケースの通知が混ざらないように）。
- **同意画面を出した時点では、台帳に行が無い。** **`sid` も、そのとき初めて作られる**（`AddSidClaim` は発行の直前で呼ぶ）。

## RT-310.7 **Discovery が `frontchannel_logout_supported` と `frontchannel_logout_session_supported` を広告する**

| | |
|---|---|
| 観点 | **RP は、どちらの伝え方に対応しているかを知る必要が在る。****受け口を持てない RP**（ブラウザの中だけで動く RP）**は、Front-Channel しか使えない。****`sid` を付けることも広告する** — **RP は `sid` で、どのセッションを閉じるかを決める。** |
| 根拠 | OIDC Front-Channel Logout 1.0 §3 / #310 の段階 3 |
| テスト | `RT31007_DiscoveryがFrontChannelLogoutを広告する` |

**手順**

1. 広告を読む
1. 段階 2 の広告も、そのまま在る
1. Session Management は見送ったので、広告しない

**検証（合否を判定する）**

- frontchannel_logout_supported が true
- frontchannel_logout_session_supported が true
- backchannel_logout_supported が true
- check_session_iframe は出ていない

**補足**

- **Session Management（`check_session_iframe`）は見送った** — **third-party cookie を読む仕組み**で、**現代のブラウザでは効かなくなりつつある。**

## RT-310.8 **`/end_session` が `iframe` の画面を返し、`iss` と `sid` を付けた URL で RP を叩ける**。**登録が無い RP の `iframe` は無い**。**画面の後は、登録された戻り先へ進む**

| | |
|---|---|
| 観点 | **受け口を持てない RP には、ブラウザ経由でしか伝えられない。****`iframe` の URL に `iss` と `sid` が要る** — **Cookie が送られない文脈も在る**ので、**URL だけで「どの OP の・どのセッションか」が分からなければ、RP は閉じるセッションを決められない。** |
| 根拠 | OIDC Front-Channel Logout 1.0 §2 / #310 の段階 3 |
| テスト | `RT31008_end_sessionがiframeの画面を返す` |

**手順**

1. 受け口を登録した RP に、トークンを発行する
1. 受け口を登録していない RP にも、トークンを発行する
1. RP からのログアウト（/end_session）
1. 画面に在る iframe
1. 画面の後に進む先（meta refresh）
1. ブラウザの代わりに、その URL を叩く

**検証（合否を判定する）**

- id_token に sid が在る（段階 1）
- 2 つ目の RP にもトークンが出た（台帳に 2 行）
- リダイレクトではなく、画面が返る（HTTP 200）
- セッションが消えている
- iframe の数
- 登録された frontchannel_logout_uri で始まる
- iss が付いている
- sid は、その RP の id_token と同じ値
- 登録していない RP の iframe は無い
- 登録された post_logout_redirect_uri へ進む
- state も付いている
- 受け口が応える（2xx）
- RP が受け取った回数
- 受け取った sid が、id_token と同じ

**補足**

- **受信箱を空にしてから測る**（前のケースの記録が混ざらないように）。
- **E2E のクライアントは `iframe` を開かない**ので、**画面から URL を取り出して自分で叩いた**（ブラウザの代わり）。**本物の RP は、この要求で自分のセッションを閉じる。**
- **Back-Channel（段階 2）も同時に動く**（登録が在れば）。**この RP には `backchannel_logout_uri` を登録していない**ので、**ここで測っているのは Front-Channel だけ**である。

## RT-310.9 **`/Account/Logout`（OP 主導のサインアウト）でも `iframe` の画面が出る**。**登録が在る RP が 1 つも無ければ、画面は出ない**

| | |
|---|---|
| 観点 | **伝えるのは「OP のセッションが終わるとき」である。****RP から言われたときだけ伝えるのでは、足りない。****一方で、登録している RP が 1 つも無い配備では、画面が増えてはならない** — **応答が変わると、既存の導線が壊れる。** |
| 根拠 | OIDC Front-Channel Logout 1.0 §2 / #310 の段階 3 |
| テスト | `RT31009_Logoutでも画面が出る` |

**手順**

1. 登録が無い RP だけのセッションでは、画面が出ない
1. 登録が在る RP が居れば、画面が出る
1. 画面の後は Home へ進む（RP の指定が無いので）

**検証（合否を判定する）**

- 前提: トークンが出た（台帳に 1 行）
- 従来どおりリダイレクトで返る（HTTP 302）
- 前提: id_token に sid が在る
- 画面が返る（HTTP 200）
- iframe の数
- sid は、その RP の id_token と同じ値
- 進む先が在る
- セッションが消えている

**補足**

- **受信箱を空にしてから測る**（前のケースの記録が混ざらないように）。
- **同じ口を、サインアウトの 5 か所から呼んでいる**（`/Account/Logout` / `/end_session` / `prompt=login` の再認証 / `max_age` の再認証 / 別のアカウントでログイン）。**再認証の経路では、画面の後に同じ認可要求へ戻る**（測っていない）。

## RT-311.1 **Discovery が `dpop_signing_alg_values_supported` を広告する**

| | |
|---|---|
| 観点 | **クライアントは、DPoP が使えるかどうかと、どの `alg` で証明を署名すればよいかを知る必要が在る。****広告が無ければ、クライアントは縛りようが無い。****`none` が入っていてはならない** — **署名の無い証明を受けるなら、鍵を持っている証明にならない。** |
| 根拠 | RFC 9449 §5.1 / #311 の段階 1 |
| テスト | `RT31101_DiscoveryがDPoPを広告する` |

**手順**

1. 広告を読む
1. mTLS の広告は、そのままである

**検証（合否を判定する）**

- dpop_signing_alg_values_supported が在る
- ES256 が入っている
- RS256 が入っている
- none は入っていない
- tls_client_certificate_bound_access_tokens が true

**観測（判定しない）**

- 広告された alg
  - **一覧は `SigningKeys` の表が持つ**（発行・検証・広告が同じ表を見る。#129 の段階 3）。

**補足**

- **2 つの縛り方は、どちらも在ってよい**（RFC 8705 / RFC 9449）。**FAPI 2.0 は、どちらかを必須としている。**

## RT-311.2 **認可コードの `/token` に DPoP の証明を添えると、`token_type` が `DPoP` になり、`access_token` の `cnf.jkt` が鍵の指紋と一致する**

| | |
|---|---|
| 観点 | **これが「持ち主に縛る」の中身**である。**`cnf.jkt` が鍵の指紋でなければ、保護されたリソースは照合できない**（段階 2）。**`token_type` が変わらなければ、クライアントは縛られたことに気付けない。** |
| 根拠 | RFC 9449 §5 / §6 / #311 の段階 1 |
| テスト | `RT31102_認可コードでDPoPに縛れる` |

**手順**

1. 認可コードを取る
1. 証明を添えて交換する
1. access_token の cnf.jkt

**検証（合否を判定する）**

- HTTP 200
- token_type が DPoP
- access_token が返る
- cnf.jkt が、証明の鍵の指紋と一致する
- id_token も返る（OIDC の経路は壊れていない）

**補足**

- **指紋（`jkt`）は RFC 7638 の計算**である。**テスト側でも独立に計算している**（実装のコードは使っていない）。
- **`refresh_token` は、まだ DPoP に縛っていない**（段階 4）。**パブリック クライアントの `refresh_token` を縛ることは RFC 9449 §5 が求めている**ので、**そこで入れる。**

## RT-311.3 **証明が無ければ、従来どおり `bearer`**（`cnf` も無い）。**`refresh_token` の経路でも、証明を添えれば縛れる**

| | |
|---|---|
| 観点 | **既定の挙動を変えないこと**が、この段階の約束である（**DPoP を知らないクライアントは、何もしなくてよい**）。**一方で、縛りたいクライアントは、どのグラントでも縛れる**必要が在る — **`/token` を叩く経路は認可コードだけではない。** |
| 根拠 | RFC 9449 §5 / #311 の段階 1 |
| テスト | `RT31103_証明が無ければbearerのままでrefreshでも縛れる` |

**手順**

1. 証明を添えずに交換する（従来どおり）
1. その refresh_token を、証明を添えて使う

**検証（合否を判定する）**

- token_type が bearer
- cnf が入っていない（縛られていない）
- HTTP 200
- token_type が DPoP
- 取り直した access_token の cnf.jkt が一致する

**補足**

- **縛られていないトークンから、縛られたトークンへ乗り換えられる**（RFC 9449 は禁じていない）。**逆向き（縛られた `refresh_token` を、証明なしで使う）を拒むのは段階 4** である。

## RT-311.4 **壊した証明は `invalid_dpop_proof` で断る**。**断った要求は、`refresh_token` を消費していない**

| | |
|---|---|
| 観点 | **証明を見ずに通すなら、縛りは飾りである。****`htm` / `htu` / `iat` を見ないと、別の口への証明や古い証明が使い回せる**（RFC 9449 §4.3）。**断る前に資格情報を消費してしまうと、クライアントは作り直しもできない** — **だから、証明の検証はグラントの入口で行っている。** |
| 根拠 | RFC 9449 §4.3 / §5 / #311 の段階 1 |
| テスト | `RT31104_壊した証明は断る` |

**手順**

1. 証明なしで refresh_token を取る
1. 壊した証明を、順に投げる
1. 断られた後も、refresh_token はまだ使える

**検証（合否を判定する）**

- typ が JWT → invalid_dpop_proof
- typ が JWT → 400
- htm が違う（GET） → invalid_dpop_proof
- htm が違う（GET） → 400
- htu が別の口 → invalid_dpop_proof
- htu が別の口 → 400
- iat が古い（10 分前） → invalid_dpop_proof
- iat が古い（10 分前） → 400
- jti が無い → invalid_dpop_proof
- jti が無い → 400
- 署名が合わない → invalid_dpop_proof
- 署名が合わない → 400
- 証明なしで使える（消費されていない）
- access_token が返る

**補足**

- **`jwk` に秘密鍵が混ざっている証明**（§4.3）**は、ここでは測っていない** — **ヘッダを後から書き替えると署名が合わなくなり、「署名が合わない」と区別が付かない**ためである（実装では見ている）。
- **`jti` の使い回しは、段階 3 で拒むようにした**（`RT-311.8`）。**ここで投げている証明は、どれも検証を通らない** — **だから `jti` は焼かれず、台帳とは関わりなく断られている。**

## RT-311.5 **`cnf.jkt` で縛ったトークンは、`Authorization: DPoP …` ＋ その鍵で署名した証明（`ath` 付き）を添えれば、`/userinfo` で使える**

| | |
|---|---|
| 観点 | **縛った結果が「使えなくなる」だけでは意味が無い。****正しい持ち主は、これまでと同じことができなければならない。****`ath` は、その証明がこのトークンのためのものだと示す**（§4.2） — **無ければ、別のトークンに付けた証明を使い回せる。** |
| 根拠 | RFC 9449 §7.1 / #311 の段階 2 |
| テスト | `RT31105_縛ったトークンは証明と一緒なら使える` |

**手順**

1. 証明を添えて呼ぶ

**検証（合否を判定する）**

- HTTP 200
- sub が返る（利用者の情報が取れている）

**補足**

- **トークンは、認可コードの `/token` に証明を添えて取ったもの**である（段階 1。`token_type` は `DPoP`）。
- **`ath` は access_token の SHA-256 を BASE64URL したもの**（§4.2）。**`htm` は `GET`、`htu` は広告された `userinfo_endpoint`** である。

## RT-311.6 **縛ったトークンは、出し方を変えると断られる**（`Bearer` で出す／証明なし／`ath` が違う／別の鍵／`htu` が別の口）。**正しい出し方なら、また使える**

| | |
|---|---|
| 観点 | **縛りを「使う側の出し方」で外せてはいけない。****`Bearer` で出せば通るなら、漏えいしたトークンはそのまま使える** — **縛った意味が無くなる。****最後に正しい出し方で通ることまで見る** — **断りが「トークンを壊した」結果ではないことを、ここで押さえる。** |
| 根拠 | RFC 9449 §7.1 / #311 の段階 2 |
| テスト | `RT31106_出し方を変えると断られる` |

**手順**

1. Bearer で出す（スキームを変える）
1. (1-b) Bearer で出すが、正しい証明を添える
1. DPoP スキームだが、証明が無い
1. ath が、別のトークンの指紋
1. 別の鍵（RSA）で署名した証明
1. htu が別の口（/token への証明）
1. 正しい出し方なら、また使える

**検証（合否を判定する）**

- 401
- 401（スキームを見ている）
- 401
- 401
- 401
- 401
- 200

**補足**

- **トークンは、認可コードの `/token` に証明を添えて取ったもの**である（段階 1。`token_type` は `DPoP`）。
- **(4) は「鍵が違う」**のであって、**署名が壊れているのではない** — **証明そのものは正しく、`cnf.jkt` と合わない**だけである。
- **`WWW-Authenticate` のスキームは `Bearer` のまま**である（RFC 9449 §7.1 は `DPoP` を求めている）。**`DPoP-Nonce` を返す段階 4 で直す** — **チャレンジに `algs` と `nonce` を載せるのは、そこで要るため。**

## RT-311.7 **縛っていないトークンは、従来どおり `Bearer` で `/userinfo` が通る**

| | |
|---|---|
| 観点 | **段階 2 の約束は「縛ったものだけを縛る」**ことである。**DPoP を知らないクライアントが、照合を入れた途端に動かなくなってはならない。** |
| 根拠 | RFC 9449 §7.1 / #311 の段階 2 |
| テスト | `RT31107_縛っていないトークンは従来どおり` |

**手順**

1. 証明を添えずにトークンを取る
1. Bearer で /userinfo を呼ぶ
1. 縛っていないトークンを DPoP スキームで出した場合

**検証（合否を判定する）**

- token_type が bearer
- HTTP 200
- sub が返る

**観測（判定しない）**

- 応答
  - **仕様は、この場合を明示していない。** **この実装は通す**（**縛っていないトークンは、縛りを見ない**）。**判定にはしていない。**

## RT-311.8 **一度使った証明は、二度と通らない**（`/userinfo` と `/token` の両方）。**新しい `jti` なら通る。** **検証に通らなかった証明の `jti` は、焼かれない**

| | |
|---|---|
| 観点 | **証明が「正しいこと」だけを見ていると、横から写し取った証明がそのまま通る**（RFC 9449 §11.1）。**縛りは「鍵を持っていること」の確認であって、「証明という文字列を持っていること」の確認ではない。****焼くのは通った証明だけ**でなければならない — **壊した証明を投げるだけで相手の `jti` を使えなくできるなら、それは別の邪魔立てになる。** |
| 根拠 | RFC 9449 §11.1 / #311 の段階 3 |
| テスト | `RT31108_同じ証明は2回目で断られる` |

**手順**

1. 証明を添えて呼ぶ
1. **同じ証明をもう一度** 添えて呼ぶ
1. 新しい `jti` の証明なら、また使える
1. 認可コードを 2 本取り、同じ証明で 2 回 `/token` を叩く
1. 同じ `jti` で、まず壊れた証明（`htu` が別の口）を投げる
1. **同じ `jti`** で、正しい証明を投げる

**検証（合否を判定する）**

- 200
- 401（使い回しは断る）
- 200
- 1 回目は 200
- 1 回目の token_type は DPoP
- 2 回目は invalid_dpop_proof
- 2 回目は 400
- 401（`htu` が合わない）
- 200（焼けるのは通った証明だけ）

**補足**

- **(3) が通ることで、(2) の断りが「使い回し」に対するものだと分かる** — **トークンも鍵も壊れていない。**
- **別の認可コードで叩いている** — **断りの理由はコードではなく、証明の使い回しである。**
- **記録は、検証の最後に行っている** — **先に記録すると、壊した証明を投げるだけで相手の `jti` を奪える。**

## RT-311.9 **別の鍵が同じ `jti` を使っても、互いを塞がない**（**台帳は「鍵 × `jti`」で持つ**）

| | |
|---|---|
| 観点 | **`jti` の値はクライアントが決める。****`jti` だけを台帳の鍵にすると、先に使われた値は他の相手が使えなくなる** — **よく使われる値を先に撃つだけで、相手の要求を断らせられる。****RFC 9449 §11.1 も、証明の公開鍵と組にして持つことを挙げている。** |
| 根拠 | RFC 9449 §11.1 / #311 の段階 3 |
| テスト | `RT31109_台帳は鍵ごとである` |

**手順**

1. 鍵の違う 2 本のトークンを取る（EC と RSA）
1. EC の鍵で、その `jti` を使う
1. **RSA の鍵で、同じ `jti`** を使う
1. EC の鍵で、その `jti` をもう一度

**検証（合否を判定する）**

- 2 本とも取れた
- 200
- 200（鍵が違えば塞がらない）
- 401（同じ鍵なら、やはり断る）

**補足**

- **(3) と (4) を並べることで、台帳が効いていることと、鍵ごとに別であることが、同時に見える。****`jti` だけを鍵にしていたら、(3) が 401 になる。**

## RT-311.10 **認可要求に `dpop_jkt` を付けると、その `code` はその鍵でしか引き換えられない**（別の鍵・証明なしは `invalid_grant`）。**断られた `code` は、正しい鍵でまだ引き換えられる**

| | |
|---|---|
| 観点 | **`code` を盗んで `/token` に持ち込む筋**は、**PKCE が `code_verifier` で塞いでいる所**である。**`dpop_jkt` は、同じ所を鍵で塞ぐ**（RFC 9449 §10） — **`access_token` を縛っても、`code` の段階で奪われては間に合わない。****断るときに `code` を消費してはいけない** — **消費すると、正しい持ち主がやり直せなくなる。** |
| 根拠 | RFC 9449 §10 / #311 の段階 4 |
| テスト | `RT31110_dpop_jktでcodeが鍵に縛られる` |

**手順**

1. `dpop_jkt`（EC の鍵の指紋）を付けて code を取り、EC の証明で引き換える
1. 同じ `dpop_jkt` の code を、**別の鍵（RSA）の証明**で引き換える
1. 同じ code を、**証明なし**で引き換える
1. **その code は、まだ使える**（EC の証明で引き換える）
1. `dpop_jkt` を付けない code は、従来どおり証明なしで引き換えられる

**検証（合否を判定する）**

- HTTP 200
- token_type が DPoP
- cnf.jkt が `dpop_jkt` と一致する
- invalid_grant
- 400
- invalid_grant
- 400
- HTTP 200（断りで消費していない）
- HTTP 200
- token_type は bearer

**補足**

- **`invalid_dpop_proof` ではなく `invalid_grant` で断っている** — **証明そのものは正しく、「この `code` のものではない」**のである。**証明の作りが悪いのか、持ち主が違うのかを、クライアントが区別できる。**
- **デバイス / CIBA の経路には `dpop_jkt` が無い**（**認可要求がブラウザを通らない**ため）。**そこは測っていない。**

## RT-311.11 **縛った `access_token` と一緒に出た `refresh_token` は、同じ鍵でしか使えない**（別の鍵・証明なしは `invalid_grant`）。**ローテーションした後も縛られている**

| | |
|---|---|
| 観点 | **`access_token` だけを縛っても、更新で縛りの無いものに乗り換えられる**なら、**縛りは寿命の分しか効かない**（RFC 9449 §5）。**漏えいして困るのは、むしろ長命な `refresh_token` の方**である。**断るときに消費してはいけない** — **ローテーションの一族ごと失効させては、持ち主が巻き込まれる**（#188 の段階 3）。 |
| 根拠 | RFC 9449 §5 / #311 の段階 4 |
| テスト | `RT31111_refresh_tokenも同じ鍵に縛られる` |

**手順**

1. 証明を添えて code を引き換え、縛られた refresh_token を得る
1. **証明なし**で更新する
1. **別の鍵（RSA）の証明**で更新する
1. **同じ鍵（EC）の証明**で更新する
1. **ローテーションした refresh_token も縛られている**
1. 縛っていない refresh_token は、従来どおり証明なしで使える
1. 縛っていない refresh_token を、**証明を添えて**更新すると、**出てくる refresh_token は縛られている**

**検証（合否を判定する）**

- token_type が DPoP
- invalid_grant
- 400
- invalid_grant
- 400
- HTTP 200（断りで消費していない）
- token_type が DPoP
- cnf.jkt が同じ鍵の指紋
- invalid_grant
- HTTP 200
- token_type は bearer
- 乗り換えられる（token_type が DPoP）
- 乗り換えた先も縛られている（invalid_grant）

**補足**

- **縛っていない `refresh_token` を、証明を添えて使うと、縛られたトークンが出る**（`RT-311.3`）。**その向きは RFC 9449 も禁じていない** — **塞いだのは逆向き（縛られたものを、証明なしで使う）である。****(7) は、乗り換えた先の `refresh_token` にも縛りが付くことを見ている。**

## RT-311.12 **`DPoP` スキームで来た要求を断るときは、`WWW-Authenticate: DPoP` ＋ `algs` で答える**。**`Bearer` で来た要求には、従来どおり `Bearer`**

| | |
|---|---|
| 観点 | **チャレンジは「次はこう出せ」と伝えるもの**である。**`DPoP` で出した相手に `Bearer` と答えては、何を直せばよいか分からない**（RFC 9449 §7.1）。**`algs` は、証明の署名に使える alg** — **クライアントが鍵の種類を選べる。****`Bearer` しか知らない相手に `DPoP` を突き付けない**のも、同じ理由である。 |
| 根拠 | RFC 9449 §7.1 / #311 の段階 4 |
| テスト | `RT31112_チャレンジのスキームがDPoPになる` |

**手順**

1. `DPoP` スキームで、証明を添えずに出す
1. `Bearer` スキームで出す

**検証（合否を判定する）**

- 401
- スキームが DPoP
- `algs` が在る
- `algs` に ES256 が在る
- 401
- スキームは Bearer のまま
- `algs` は入らない

**観測（判定しない）**

- `DPoP-Nonce` ヘッダ（既定では要求しない）
  - **nonce を要求する配備でだけ付く**（`RT-311.13` / `RT-311.14`）。

**補足**

- **両方のスキームを並べて広告はしない。** **できるが、`Bearer` だけを知るクライアントが 2 つ目を読めるとは限らず、得るものが無い。**

# FA. FAPI（クライアント登録ごとに通る経路）

## FA-1.1 client_mode=fapi1 のクライアントは、PKCE(S256) の認可コードだけが通る

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

## FA-1.2 fapi1 の refresh_token は、非対称の証明でだけ使える

| | |
|---|---|
| 観点 | **使えない資格情報は渡さない**（#224 の段階 2）という原則は変わらない。変わったのは前提で、**#239 の段階 3 で refresh_token の行を証明ごとに分けた**（`private_key_jwt` / mTLS なら fapi1 / fapi2 も通す。`client_secret` では通さない）。**FAPI は refresh token を禁じていない**ので、以前のように「fapi1 には発行しない」では、期限が切れるたびに認可からやり直しになる。 |
| 根拠 | RFC 6749 §5.1 / §6 / FAPI 1.0 Advanced / #224 / #239 |
| テスト | `FA0102_fapi1のrefresh_tokenは非対称の証明でだけ使える` |

**手順**

1. 対照 : normal 登録では、refresh_token で更新できる
1. fapi1 で PKCE(S256) のトークンを取る
1. client_secret で更新しようとする（fapi1 には認めない証明）

**検証（合否を判定する）**

- 対照（normal）は更新できる
- refresh_token が発行される（#239 の段階 3 で開いた）
- client_secret では更新できない
- エラーは unauthorized_client

**補足**

- **(1) の対照で、サーバ全体では refresh_token が有効**であることが分かる。fapi1 が更新できないのは**証明の種類**によるもので、登録種別そのものではない（`private_key_jwt` / mTLS なら通る。`RT-239.5` が fapi2 で測っている）。

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

## FA-2.1 client_mode=fapi2 のクライアントは、client_secret でも PKCE でも通らない

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
- エラーは invalid_client（認証の方法を明示した登録は、PKCE だけでは認証しない）

**補足**

- **これは設計どおり。** fapi2 の登録は、証明書（x509）か private_key_jwt を伴う経路でだけ通る（**PKCE との併用は `RT-294.51`**）。**通る側は FA-6.1 で測る**（net10.0 版のみ。net48 版は手動。#226）。

## FA-3.1 client_mode=device のクライアントは、PKCE(S256) の認可コードが通る

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
1. fapi2（TestClient2）は、クライアント認証の段で断られる

**検証（合否を判定する）**

- TestClient3 は device_code を得る
- MVC_Sample は device_code を得る
- TestClient1 は unauthorized_client（400）
- TestClient4 は unauthorized_client（400）
- TestClient2 は invalid_client（401）

**補足**

- **client_secret は正しいものを送っている。** 拒否の理由は認証の失敗ではなく、**登録種別がこのグラントを許さないこと**（だから invalid_client ではなく unauthorized_client）。
- **`TestClient1` / `TestClient4` は方法を明示していない**ので、**`client_secret` で認証が通り、登録種別の判定まで進む**（`unauthorized_client`）。**どちらの道でも、このグラントは使えない。**
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

## FA-5.2 client_mode が既知でない値（fapi_1）のクライアントは、開始（/ciba_authz）で unauthorized_client になる

| | |
|---|---|
| 観点 | **既知でない登録値は、不正な登録として拒否する**（#224 の段階 2）。以前は fapi2 とみなしていた。「一番厳しい種別」に倒す作りは、種別が増えると意味が変わるため、やめた。なお client_mode を書いていない登録は normal で、これには当たらない。 |
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

## FA-6.1 client_mode=fapi2 のクライアントは、mTLS（Subject が一致する証明書）の認可コードで通る

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
- refresh_token が発行される（mTLS で更新できる証明）

**補足**

- **#239 の段階 3 で、mTLS / private_key_jwt なら fapi1 / fapi2 にも開いた。**以前は「証明によらず normal だけ」だったので、発行もされなかった。**実際に更新できることは `FA-6.5` が測る**（#245 の段階 1）。

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

## FA-6.3 client_mode が既知でない値（fapi_1）のクライアントは、Subject が一致する証明書でも通らない

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

## FA-6.5 client_mode=fapi2 のクライアントは、mTLS で refresh_token を使える

| | |
|---|---|
| 観点 | **`ClientModePolicy` の表で、E2E が無かった唯一の行**（`refresh_token × mTLS`。#245 の段階 1）。#239 の段階 3 で **fapi1 / fapi2 にも refresh_token を開いた**が、**開いたのは `private_key_jwt`（`RT-239.5`）と mTLS の 2 つ**で、**mTLS の側は「発行される」ことだけを `FA-6.1` が見ており、実際に更新できるかは測っていなかった。****client_secret では開かない**ことも、ここで対照として見る（FAPI は秘密ベースの認証を認めない）。 |
| 根拠 | RFC 8705 §2.1 / FAPI 2.0 / #239 の段階 3 / #245 の段階 1 |
| テスト | `FA0605_mTLSでrefresh_tokenを使える` |

**手順**

1. mTLS の認可コードで、refresh_token を得る
1. 同じ証明書を提示して更新する
1. （対照）証明書を提示せずに更新すると通らない

**検証（合否を判定する）**

- refresh_token が返る
- 新しいアクセス トークンが返る
- 更新後のトークンにも cnf が載る（証明書に紐づく）
- 更新後も fapi クレームは登録どおり fapi2
- トークンを返さない
- エラーは invalid_client

**補足**

- **fapi2 は client_secret を通さない**ので、証明書が無ければ更新できない（表の `refresh_token × Any → normal` の行には当たらない）。

# 21. OAuth 2.1（許されない経路の抑止）

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

# SA. SAML2（Web Browser SSO）

## SA-1.1 SP-initiated Web Browser SSO が成立する（要求 Redirect / 応答 Redirect）

| | |
|---|---|
| 観点 | **要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある。**署名の対象が違う** — Redirect はクエリ文字列、POST は XML の中。**SP 側の照合（Audience / Recipient / InResponseTo / RelayState）がすべて通ること**を見る（#276 で足した）。 |
| 根拠 | SAML 2.0 Core / Bindings 3.4・3.5 / Web SSO Profile / #275 |
| テスト | `SA0101_Redirect要求とRedirect応答で成立する` |

**手順**

1. 自己テストのボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の照合が、すべて通る

**検証（合否を判定する）**

- IdP のエンドポイントへ送られる
- SP（ACS）へリダイレクトで返る
- 応答のクエリ文字列に SigAlg と Signature が付く
- 応答の XML を復号して読める
- StatusCode は Success
- Assertion を含む
- NameID がある
- Conditions に NotOnOrAfter がある
- NotOnOrAfter を時刻として読める
- 有効期限の幅が 25〜35 分（雛形の 30 分）
- HTTP 200（結果の画面）
- 判定は NORMAL_END
- 照合していない項目が無い
- 画面に「✓ 検証できた」が出る
- 画面に「✓ 一致」が出る
- 画面に「✓ 自分の ACS URL」が出る
- 画面に「✓ 送った要求の ID と一致」が出る
- 画面に「✓ 期限内」が出る
- RelayState が送った state と一致する

**観測（判定しない）**

- XML の中の署名
  - **Redirect Binding では、署名は XML ではなくクエリ文字列に付く**（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。

**補足**

- **NameID と XML は画面に出ているが、ここでは値を報告しない**（利用者を指す値のため）。**有無と照合の結果だけを見る。**

## SA-1.2 SP-initiated Web Browser SSO が成立する（要求 Redirect / 応答 POST）

| | |
|---|---|
| 観点 | **要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある。**署名の対象が違う** — Redirect はクエリ文字列、POST は XML の中。**SP 側の照合（Audience / Recipient / InResponseTo / RelayState）がすべて通ること**を見る（#276 で足した）。 |
| 根拠 | SAML 2.0 Core / Bindings 3.4・3.5 / Web SSO Profile / #275 |
| テスト | `SA0102_Redirect要求とPost応答で成立する` |

**手順**

1. 自己テストのボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の照合が、すべて通る

**検証（合否を判定する）**

- IdP のエンドポイントへ送られる
- 自動送信フォームで返る（action は SP）
- フォームに SAMLResponse がある
- 応答の XML を復号して読める
- StatusCode は Success
- Assertion を含む
- NameID がある
- Conditions に NotOnOrAfter がある
- NotOnOrAfter を時刻として読める
- 有効期限の幅が 25〜35 分（雛形の 30 分）
- XML の中に署名がある
- HTTP 200（結果の画面）
- 判定は NORMAL_END
- 照合していない項目が無い
- 画面に「✓ 検証できた」が出る
- 画面に「✓ 一致」が出る
- 画面に「✓ 自分の ACS URL」が出る
- 画面に「✓ 送った要求の ID と一致」が出る
- 画面に「✓ 期限内」が出る
- RelayState が送った state と一致する

**補足**

- **NameID と XML は画面に出ているが、ここでは値を報告しない**（利用者を指す値のため）。**有無と照合の結果だけを見る。**

## SA-1.3 SP-initiated Web Browser SSO が成立する（要求 POST / 応答 Redirect）

| | |
|---|---|
| 観点 | **要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある。**署名の対象が違う** — Redirect はクエリ文字列、POST は XML の中。**SP 側の照合（Audience / Recipient / InResponseTo / RelayState）がすべて通ること**を見る（#276 で足した）。 |
| 根拠 | SAML 2.0 Core / Bindings 3.4・3.5 / Web SSO Profile / #275 |
| テスト | `SA0103_Post要求とRedirect応答で成立する` |

**手順**

1. 自己テストのボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の照合が、すべて通る

**検証（合否を判定する）**

- 要求の自動送信フォームが返る（HTTP 200）
- フォームに SAMLRequest がある
- SP（ACS）へリダイレクトで返る
- 応答のクエリ文字列に SigAlg と Signature が付く
- 応答の XML を復号して読める
- StatusCode は Success
- Assertion を含む
- NameID がある
- Conditions に NotOnOrAfter がある
- NotOnOrAfter を時刻として読める
- 有効期限の幅が 25〜35 分（雛形の 30 分）
- HTTP 200（結果の画面）
- 判定は NORMAL_END
- 照合していない項目が無い
- 画面に「✓ 検証できた」が出る
- 画面に「✓ 一致」が出る
- 画面に「✓ 自分の ACS URL」が出る
- 画面に「✓ 送った要求の ID と一致」が出る
- 画面に「✓ 期限内」が出る
- RelayState が送った state と一致する

**観測（判定しない）**

- XML の中の署名
  - **Redirect Binding では、署名は XML ではなくクエリ文字列に付く**（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。

**補足**

- **NameID と XML は画面に出ているが、ここでは値を報告しない**（利用者を指す値のため）。**有無と照合の結果だけを見る。**

## SA-1.4 SP-initiated Web Browser SSO が成立する（要求 POST / 応答 POST）

| | |
|---|---|
| 観点 | **要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある。**署名の対象が違う** — Redirect はクエリ文字列、POST は XML の中。**SP 側の照合（Audience / Recipient / InResponseTo / RelayState）がすべて通ること**を見る（#276 で足した）。 |
| 根拠 | SAML 2.0 Core / Bindings 3.4・3.5 / Web SSO Profile / #275 |
| テスト | `SA0104_Post要求とPost応答で成立する` |

**手順**

1. 自己テストのボタンを押す（要求を組み立てて IdP へ）
1. IdP が応答（アサーション）を返す
1. SP の照合が、すべて通る

**検証（合否を判定する）**

- 要求の自動送信フォームが返る（HTTP 200）
- フォームに SAMLRequest がある
- 自動送信フォームで返る（action は SP）
- フォームに SAMLResponse がある
- 応答の XML を復号して読める
- StatusCode は Success
- Assertion を含む
- NameID がある
- Conditions に NotOnOrAfter がある
- NotOnOrAfter を時刻として読める
- 有効期限の幅が 25〜35 分（雛形の 30 分）
- XML の中に署名がある
- HTTP 200（結果の画面）
- 判定は NORMAL_END
- 照合していない項目が無い
- 画面に「✓ 検証できた」が出る
- 画面に「✓ 一致」が出る
- 画面に「✓ 自分の ACS URL」が出る
- 画面に「✓ 送った要求の ID と一致」が出る
- 画面に「✓ 期限内」が出る
- RelayState が送った state と一致する

**補足**

- **NameID と XML は画面に出ているが、ここでは値を報告しない**（利用者を指す値のため）。**有無と照合の結果だけを見る。**

## SA-2.1 /samlmetadata が、entityID・証明書・NameIDFormat・SSO の口を出す

| | |
|---|---|
| 観点 | **SP は、この XML だけを見て IdP に繋ぐ。****entityID が応答の Issuer と違えば、SP の照合が落ちる。****SSO の口が違えば要求が届かず、証明書が違えば署名を検証できない。****E2E が 1 件も無かった口である**（#275）。 |
| 根拠 | SAML 2.0 Metadata 2.4.3（IDPSSODescriptor）/ #275 |
| テスト | `SA0201_メタデータの中身がIdPの設定と揃っている` |

**手順**

1. XML として読める
1. entityID が、OIDC の issuer と同じ値である
1. IDPSSODescriptor に、署名用の証明書がある
1. NameIDFormat を 3 種とも広告している
1. SSO の口が、Redirect と POST の両方にあり、設定と一致する
1. 公開情報なので、許していないオリジンにも開く

**検証（合否を判定する）**

- HTTP 200
- Content-Type
- XML として読める
- entityID = Discovery の issuer
- IDPSSODescriptor がある
- protocolSupportEnumeration
- 署名用の X509Certificate がある
- NameIDFormat の件数
- urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified を広告する
- urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress を広告する
- urn:oasis:names:tc:SAML:2.0:nameid-format:persistent を広告する
- SingleSignOnService の件数
- HTTP-Redirect の Location
- HTTP-POST の Location
- Access-Control-Allow-Origin

**観測（判定しない）**

- WantAuthnRequestsSigned
  - **固定で true を出している**（Open棟梁 の雛形）。**実際は、`jwk_rsa_publickey` を登録していないクライアントの要求は、署名が無くても通る**（`VerifySamlRequest` の「鍵がない場合は、通す」）。**広告と振る舞いが揃っていない**ので、`CONFIGURATION.md` に明記してある。

## SA-2.2 メタデータは、退役させる途中の署名証明書も並べて広告する

| | |
|---|---|
| 観点 | **鍵を入れ替えられること**（#292 の段階 3）。**SP はメタデータをキャッシュする**ので、**1 本だけ広告していると、替えた瞬間に検証できなくなる。****2 本並べておけば、SP がどちらでも検証できる**（**受け取る側は全部試す**。`SAML2Client.VerifyResponseWithReason` の鍵の列を受ける版）。 |
| 根拠 | SAML 2.0 Metadata 2.4.1.1 / #292 の段階 3 |
| テスト | `SA0202_メタデータが退役前の証明書も広告する` |

**手順**

1. メタデータを引く
1. 署名用の KeyDescriptor の本数を見る
1. 1 本目は、いま署名に使っている証明書である

**検証（合否を判定する）**

- HTTP 200
- XML として読める
- 1 本以上ある
- 退役前の証明書も並ぶ（設定が在れば）
- 1 本目と 2 本目は別の証明書である

**観測（判定しない）**

- 広告している署名証明書の本数
  - **`PreviousSigningCerFilePaths` に書いた分だけ増える**（区切りは空白かカンマ）。

## SA-3.1 NameIDPolicy=unspecified は、sub（既定は利用者 ID）を NameID にする

| | |
|---|---|
| 観点 | **`NameIDPolicy` の値で `NameID` の中身が変わる**（`PPIDExtension.GetSubForSAML2`）。**自己テストのボタンは `unspecified` 固定**なので、**ここだけが従来の E2E と重なる**（他の 2 種は未測定だった）。 |
| 根拠 | SAML Core 2.2.2 / 8.3 / #275 |
| テスト | `SA0301_UnspecifiedはsubをNameIDにする` |

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- NameID の Format が echo される
- NameID がある
- メアドではない（既定は public ＝ 利用者 ID）

## SA-3.2 NameIDPolicy=emailAddress は、利用者のメアドを NameID にする

| | |
|---|---|
| 観点 | **メタデータは広告しているのに、E2E が踏んでいなかった**（#275）。**`user.Email` をそのまま入れる**（`GetSubForSAML2`）。**利用者名とメアドは #151 の段階 3 で分かれている**ので、**`unspecified` とは必ず違う値になる。** |
| 根拠 | SAML Core 8.3.2 / #275 |
| テスト | `SA0302_EmailAddressはメアドをNameIDにする` |

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- NameID の Format が echo される
- NameID がメアドの形である

**補足**

- **メアドを NameID にすると、RP に利用者のメアドが渡る。****pairwise（PPID）を使っていても、この指定で素のメアドが出る**ので、**配備のときに意識すること。**

## SA-3.3 NameIDPolicy=persistent は、RP ごとに違う PPID を NameID にする

| | |
|---|---|
| 観点 | **`persistent` は `subject_types` に依らず、必ず PPID になる**（`GeneratePPIDByUserID(iss, user.Id)`）。**同じ利用者でも、RP が違えば値が違う**ので、**RP 同士が突き合わせられない**（OIDC の pairwise と同じ狙い）。**2 つのクライアントで比べる**ことで、それを測る。 |
| 根拠 | SAML Core 8.3.7 / #275 |
| テスト | `SA0303_PersistentはRPごとに違うPPIDをNameIDにする` |

**手順**

1. RP その 1（TestClient_21）
1. RP その 2（TestClient_22）
1. 2 つの RP で、値が違う
1. unspecified とも違う

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- NameID の Format が echo される
- NameID がある
- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- NameID がある
- RP ごとに違う値になる
- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- 同じ RP でも、unspecified とは違う値になる

**補足**

- **`subject_types` を書いていないクライアントでも、`persistent` を指定すれば PPID になる。****OIDC 側の既定（public。#151 の段階 4）とは別の話である。**

## SA-4.1 未サインインの要求はサインイン画面へ送られ、サインイン後にアサーションが返る

| | |
|---|---|
| 観点 | **SP-initiated Web Browser SSO の本来の形**である（Web SSO Profile 4.1.1）。**従来の E2E はすべてサインイン済みから始めていた**ので、**`[Authorize]` のチャレンジを通って戻る経路が未測定だった**（#275）。**送られることだけでなく、戻ってアサーションが返ることまで見る。** |
| 根拠 | SAML 2.0 Web SSO Profile 4.1.1 / #275 |
| テスト | `SA0401_未サインインならサインインさせてからアサーションを返す` |

**手順**

1. 未サインインだと、サインイン画面へ送られる
1. サインインして、同じ要求をもう一度送る
1. 返ったアサーションが、送った要求に対応している

**検証（合否を判定する）**

- まだサインインしていない（測る前提）
- リダイレクトする（302）
- 送り先はサインイン画面
- この時点でアサーションを返さない
- サインインできた
- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- InResponseTo（送った要求の ID）
- Destination（登録した ACS URL）
- Assertion を含む
- NameID がある

**補足**

- **同じ URL をもう一度送っている**（SP が `RelayState` で復帰させる形は測っていない）。**この実装の `Saml2Request` は `ReturnUrl` で戻る**ので、**ブラウザなら、サインインの後に自動で戻る。**

## SA-5.1 AssertionConsumerServiceURL が登録値と違えば、登録値へ Requester を返す

| | |
|---|---|
| 観点 | **要求に書かれた ACS URL をそのまま使うと、任意の URL へアサーションを飛ばせられる。****事前登録の値と完全一致するか、省略されているときだけ通す。****以前は `CreateSamlResponse` が `null` を返していたが、呼び出し側が `== HttpRedirect` で分岐していたため、`null` が POST 側に落ち、`action` も `SAMLResponse` も空の自動送信フォームが返っていた**（#276 の (1)）。 |
| 根拠 | SAML Core 3.2.1 / Web SSO Profile 4.1.4.1 / #276 |
| テスト | `SA0501_ACSURLが登録値と違えば登録値へエラー応答` |

**手順**

1. 登録値と違う ACS URL で、要求を送る
1. 返す先は、要求の値ではなく登録値である
1. StatusCode は Requester である

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- フォームの action
- 要求に書いた URL へは返さない
- SAMLResponse がある（空のフォームではない）
- 応答を読める
- StatusCode
- Destination（応答の宛先）
- InResponseTo（送った要求の ID）
- エラー応答に Assertion を入れない
- NameID を含まない（利用者を指す値を返さない）

**補足**

- **以前は、エラー応答にも Assertion を組み込んでいた**（`CreateSamlResponse` が `CreateResponse` と `CreateAssertion` を常に呼んでいた）。**認証が成立していないのに、認証の主張を返していた**（#278。SAML 2.0 Core 3.2.2 / 4.1.4.2 のとおり、エラー応答は `Status` だけで正当）。

## SA-5.2 未登録の Issuer には、応答せずエラー画面を返す

| | |
|---|---|
| 観点 | **応答を返す先は、事前登録の ACS URL だけ**である。**登録が無ければ、返す先が決まらない**ので、**要求に書かれた URL へは返さない**（SAML Core 3.2.1）。**以前は `action` が空の自動送信フォームが返っていた**（#276 の (1)）。 |
| 根拠 | SAML Core 3.2.1 / #276 |
| テスト | `SA0502_未登録のIssuerにはエラー画面` |

**手順**

1. 未登録の Issuer で、要求を送る

**検証（合否を判定する）**

- 500 にしない
- エラー画面が開く
- 空の自動送信フォームではない

## SA-5.3 壊れた SAMLRequest を送っても、500 にしない

| | |
|---|---|
| 観点 | **外から任意の文字列が来る口である。****base64 でない・XML でない・AuthnRequest でない**ものが来ても、**サーバの例外を見せない。****#241 と同じ観点**（JWT でない値・`iss` の無い JWT で 500 にしない）。 |
| 根拠 | #241 と同じ観点 / #275 |
| テスト | `SA0503_壊れたSAMLRequestでも500にしない` |

**手順**

1. SAMLRequest = （壊れた値 1）
1. SAMLRequest = （壊れた値 2）
1. SAMLRequest = （壊れた値 3）

**検証（合否を判定する）**

- 500 にしない
- エラー画面が開く
- 空の自動送信フォームではない
- 500 にしない
- エラー画面が開く
- 空の自動送信フォームではない
- 500 にしない
- エラー画面が開く
- 空の自動送信フォームではない

**補足**

- **net48 版は `customErrors` が例外を 302 に変える**ので、**500 でないことだけでは足りない**（#272 で踏んだ）。**エラー画面が開くことまで見る。**

## SA-5.4 鍵を登録したクライアントの、署名の無い要求は断る

| | |
|---|---|
| 観点 | **`jwk_rsa_publickey` を登録していれば、署名を検証する。****登録していなければ、署名の無い要求も通す**（`VerifySamlRequest` の「鍵がない場合は、通す」）。**`AuthnRequest` の署名は SAML では任意**で、**応答が事前登録の ACS URL にしか飛ばない**ことで守っている。**登録した場合に、それが効いていること**をここで測る。 |
| 根拠 | SAML Core 3.4 / Web SSO Profile / #275 |
| テスト | `SA0504_鍵を登録したクライアントの署名の無い要求を断る` |

**手順**

1. 署名を付けずに要求を送る
1. StatusCode は Requester である（署名を検証できない）
1. SP の画面が「エラー応答である」と出す

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode
- エラー応答に Assertion を入れない（#278）
- 応答の宛先は自己テストの ACS である
- HTTP 200（結果の画面）
- 判定は ABNORMAL_END
- 理由が「エラー応答である」と出る
- StatusCode が画面に出る

**補足**

- **`TestClient_21` は鍵を登録していない**ので、**同じ要求が `SA-3.*` では通る。** 差は登録だけである。
- **上流（Open棟梁 #598）で 2 つが直っている。****`VerifyByXPath` が `StatusCode` を見るようになり**、**`VerifyResponse` の `out statusCode` が検証の前に設定される**ようになった。**そのため、こちら側に回避を置かずに理由を出せている。**

## SA-6.1 上流の IdP へ SAML2 で委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **下流は自分で認証せず、上流のアサーションを受け取る。****`NameIDFormat=emailAddress` の `NameID` をメアドとして扱い**、**`(上流の EntityID, NameID)` を連携キーに**、下流のアカウントへ結び付ける。**検証鍵は設定で与える**（`IdFederationSaml2CerFilePath`）— **`SpRp_RsaCerFilePath` は、この配備では自分の証明書として読まれている**ため。 |
| 根拠 | SAML 2.0 Web Browser SSO Profile / #286 の段階 2 |
| テスト | `SA0601_SAML2のID連携でサインインできる` |

**手順**

1. 上流でサインインしておく
1. 下流で「SAML2 の ID 連携」を押す
1. 送った AuthnRequest を読む
1. 上流がアサーションを返し、下流の ACS が受け取る
1. 下流にサインインできている

**検証（合否を判定する）**

- 上流にサインインできる
- サインイン画面に SAML2 の導線が出ている
- 上流の SSO へ送られる
- SAMLRequest を読める
- NameIDFormat に emailAddress を要求する
- IsPassive は付けない（上流が画面を出してよい）
- 上流が下流の ACS を指す
- 応答が読める
- StatusCode が Success
- NameIDFormat が emailAddress
- NameID がメアドである
- ACS がサインインさせる（リダイレクトする）
- 下流にサインインできている

**観測（判定しない）**

- 上流の Issuer
  - **期待値は設定の `IdFederationSaml2IssuerId`**（下流が照合する）。
- 下流の画面に出るメアド
  - **上流の `NameID` と同じになる**（`NameID` をメアドとして受け取るため）。

## SA-6.2 二度目の SAML2 の ID 連携でも、同じ下流アカウントになる

| | |
|---|---|
| 観点 | **連携キーは `(上流の EntityID, NameID)`** である。**1 度目と 2 度目で通る枝が違う**（作る／結ぶ ⇔ 結び付けを引く）ので、**同じ利用者に着くことを測る。** |
| 根拠 | #286 の段階 2 / RT-140.5 と同じ観点 |
| テスト | `SA0602_二度目の連携でも同じ利用者になる` |

**手順**

1. 上流でサインインしておく
1. 1 度目の ID 連携
1. もう一度、ID 連携を行う

**検証（合否を判定する）**

- 1 度目でサインインできる
- 2 度目もサインインできる
- 2 度目も同じ利用者（メアドが一致）
- NameID が毎回同じ

**観測（判定しない）**

- 1 度目のメアド

## SA-6.3 上流にセッションが無ければ、SAML2 の ID 連携は成立しない

| | |
|---|---|
| 観点 | **下流は、上流のアサーションを受け取るだけ**である。**`IsPassive` を送らないので、上流はサインイン画面を出す**（#287 と同じ考え方）。**そこを通らないかぎりアサーションは返らない**ので、**下流はサインインしない。** |
| 根拠 | SAML 2.0 Web Browser SSO Profile / #286 の段階 2 |
| テスト | `SA0603_上流が未サインインなら連携は成立しない` |

**手順**

1. 上流にサインインせずに、下流で「SAML2 の ID 連携」を押す

**検証（合否を判定する）**

- 上流の SSO へは送られる
- アサーションは返らない（下流の ACS を指さない）
- 上流は自分のサインイン画面へ送る
- 下流はサインインしない

**観測（判定しない）**

- 上流が返した画面
  - **サインイン画面である**（`IsPassive` を送っていないため、**上流は認証の UI を出せる**）。

## SA-6.4 SAML2 の ID 連携が、アサーションの属性（mail / uid / email_verified）を使う

| | |
|---|---|
| 観点 | **段階 4 で、メアド・利用者名・`email_verified` を属性で運べるようになった**（#286）。**下流は「属性 → `NameID`」の順でメアドを決める**ので、**上流が属性を出していれば、そちらが使われる。****`email_verified` を上流が言うようになった**ため、**既存アカウントへの結び付けを、`NameID` の形で代用しなくてよい。** |
| 根拠 | SAML Core 2.7.3.1 / #286 の段階 4 |
| テスト | `SA0604_ID連携がアサーションの属性を使う` |

**手順**

1. 上流でサインインして、ID 連携を 1 回通す
1. 上流のアサーションに属性が入っている
1. 下流は、属性のメアドで利用者を引いている

**検証（合否を判定する）**

- 連携が成立する（サインインさせる）
- AttributeStatement がある
- メアドの属性（mail）がある
- 利用者名の属性（uid）がある
- email_verified の属性が true
- 下流の画面に出るメアドが、属性のメアドと一致

**観測（判定しない）**

- NameID と属性のメアドの関係
  - **この上流は `emailAddress` の `NameID` を返す**ので、**同じ値になる。****属性の方を使っていることは `SA-7.2` と合わせて読むこと**（`persistent` の `NameID` でも属性からメアドが取れる）。

**補足**

- **`Transient` の `NameID` は受けない**（段階 4）— **毎回変わる値を連携キーにできない**（SAML Core 8.3.8）。

## SA-6.5 署名を壊した AuthnRequest は、上流が弾く

| | |
|---|---|
| 観点 | **(2)（下流 → 上流の `AuthnRequest`）の署名が検証されていること**（#293 の段階 2）。**上流に `jwk_rsa_publickey` を登録していなければ、`VerifySamlRequest` は「鍵がない場合は、通す」経路に入る**ので、**壊した署名でも通ってしまう** — **それを落とすのがこのケースである。****製品が署名した本物の要求の、署名だけを 1 バイト変えて送る**ので、**配備を壊さずに歯抜けが測れる**（段階 4）。 |
| 根拠 | SAML 2.0 Bindings 3.4.4.1 / #275 / #293 の段階 2 |
| テスト | `SA0605_署名を壊したAuthnRequestを上流が弾く` |

**手順**

1. 上流でサインインしておく（署名の検証まで進ませるため）
1. 下流に、本物の AuthnRequest を作らせる（送る手前で止める）
1. 署名だけを 1 バイト変えて送る
1. 上流が弾く

**検証（合否を判定する）**

- 下流は AuthnRequest に署名している
- 壊したのは署名だけである
- 上流が応答を返す（画面で止まらない）
- StatusCode
- エラー応答に Assertion を入れない（#278）
- 下流にサインインさせない

**観測（判定しない）**

- SigAlg
  - **実際に使ったアルゴリズム**（Open棟梁 #604 の追随）。

**補足**

- **このケースが通らなくなったら、まず登録を見ること**（`store/docker-compose.yml` の `jwk_rsa_publickey`）。**鍵が無いと「通す」ので、`Success` が返って落ちる。**

## SA-6.6 上流が署名証明書を 2 本広告していても、SAML2 の ID 連携ができる

| | |
|---|---|
| 観点 | **鍵の入れ替え中の上流と連携できること**（#292 の段階 3。#291 の残件）。**メタデータに `KeyDescriptor` が 2 本以上並ぶ**とき、**どれで署名されたかは応答から分からない**（**SAML2 の署名に `kid` に当たるものが無い**）。**だから受け取る側は全部試す** — **最初の 1 本しか見ていなかった頃は、ここで落ちていた。** |
| 根拠 | SAML 2.0 Metadata 2.4.1.1 / #291 / #292 の段階 3 |
| テスト | `SA0606_上流が証明書を2本広告していても連携できる` |

**手順**

1. 上流のメタデータが、2 本広告していることを見る
1. 上流でサインインして、連携する
1. 署名を検証して、サインインできている

**検証（合否を判定する）**

- 上流は 2 本以上広告している
- 応答が読める
- StatusCode が Success
- ACS がサインインさせる（リダイレクトする）
- 下流にサインインできている

**補足**

- **鍵の順が入れ替わっても通る**ことは、歯抜けで測った（上流の 1 本目を「署名に使っていない証明書」にすると、**2 本目で検証して通る**。`TESTING.md`）。

## SA-7.1 アサーションが、メアド・利用者名・email_verified を属性で返す

| | |
|---|---|
| 観点 | **`NameID` だけでは、メアドと利用者名を運べない**（#286 の段階 4）。**OIDC 側のクレームに 1 対 1 で対応させた属性**を出す（`mail` ⇔ `email`、`uid` ⇔ `preferred_username`、`email_verified` ⇔ `email_verified`）。**`urn:oid:…` は X.500/LDAP Attribute Profile** であり、**他の IdP（Shibboleth / ADFS など）とも合う。** |
| 根拠 | SAML Core 2.7.3.1 / SAML V2.0 prof-attr-x500 / #286 の段階 4 |
| テスト | `SA0701_アサーションが属性でメアドと利用者名を返す` |

**手順**

1. 名前の付け方（FriendlyName / NameFormat）

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- StatusCode
- InResponseTo（送った要求の ID）
- AttributeStatement がある
- メアドの属性（mail）が、サインインした利用者のメアド
- 利用者名の属性（uid）が、サインインした利用者名
- email_verified の属性（種データの利用者は確認済み）
- メアドの属性に FriendlyName と NameFormat がある
- メアドの FriendlyName
- メアドの NameFormat
- 利用者名の FriendlyName
- 利用者名の NameFormat
- email_verified の NameFormat（標準の属性ではないので basic）

**観測（判定しない）**

- 属性の件数
  - **3 件**（`mail` / `email_verified` / `uid`）。**この E2E は `Name` だけを鍵にする**ので、**製品側（`FriendlyName` も鍵に入れる）より少ない。**

**補足**

- **署名は応答の全体に対して行う**ので、**属性も署名の対象に入っている**（`SA-1.*` が署名を測っている）。

## SA-7.2 NameIDPolicy=persistent でも、属性でメアドと利用者名が分かる

| | |
|---|---|
| 観点 | **これが段階 4 の目的である。****`Persistent`（PPID）の `NameID` はメアドではない**ので、**段階 3 までは、その配備と ID 連携できなかった**（`NameID` をメアドとして扱っていた）。**属性が在れば、`NameID` が何であっても利用者を引ける。** |
| 根拠 | SAML Core 8.3.7 / #286 の段階 4 |
| テスト | `SA0702_persistentでも属性でメアドが分かる` |

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- StatusCode
- InResponseTo（送った要求の ID）
- NameID の Format が echo される
- NameID はメアドではない（PPID）
- それでも、属性のメアドは利用者のメアドである
- 属性の利用者名も取れる

**補足**

- **下流（SP）側の口は、属性 → `NameID` の順でメアドを決める**（`IDFederationAssertionConsumerService`）。**この要求の形でも ID 連携が成立する**という意味である。**ただし、下流が送る要求は `emailAddress` のまま**なので（#286 の決め事）、**`SA-6.*` はそちらを測っている。**

# CN. コンテナ配備（疎通と配備固有）

## CN-1.1 コンテナの Discovery が返り、`issuer` が構成の `IssuerId` と一致する

| | |
|---|---|
| 観点 | **コンテナは `appsettings.json` と compose の環境変数で構成される**（#284）。**`issuer` は待ち受けている URL とは別の値**（`IssuerId`）であり、**compose が上書きしている**ので、**重ね読みが効いていなければ合わない。** |
| 根拠 | #281 / #284 |
| テスト | `CN0101_Discoveryが返りissuerが構成と一致する(containerKey: "downstream")` |

**手順**

1. Discovery を引く
1. issuer が構成の IssuerId と一致する

**検証（合否を判定する）**

- JSON が返る
- issuer が一致する

## CN-1.2 上流コンテナと下流コンテナの `issuer` が違う

| | |
|---|---|
| 観点 | **ハイブリッド構成では、2 つの IdP が建つ**（#281）。**同じ `iss` を名乗ると、連携キー `(iss, sub)` の意味が曖昧になる。****`IssuerId` は URL に依らない固定値**なので、**設定で分けるしかない。** |
| 根拠 | #281 |
| テスト | `CN0102_上流と下流のissuerが違う` |

**手順**

1. 両方の issuer を引く
1. 違う値である

**検証（合否を判定する）**

- 上流の issuer が取れる
- 下流の issuer が取れる
- issuer が違う

## CN-1.3 `jwkcerts` が鍵を返す（マウントした署名鍵まで読めている）

| | |
|---|---|
| 観点 | **署名鍵はイメージに入れず、ホストの `C:\root\files\resource` をマウントしている**（#250 の段階 2）。**資源のパスは 19 件を環境変数で振り替えており、1 つでも漏らすと、その設定を使った瞬間に落ちる。****`jwkcerts` が返れば、少なくとも署名鍵までは届いている。** |
| 根拠 | #250 の段階 2 / #284 |
| テスト | `CN0103_jwkcertsが鍵を返す(containerKey: "downstream")` |

**手順**

1. jwkcerts を引く

**検証（合否を判定する）**

- 鍵が 1 つ以上ある

## CN-1.4 `/Ping` が応答する（死活監視の口）

| | |
|---|---|
| 観点 | **`IsLockedDownTestEndpoints` でも閉じない口である**（`CONFIGURATION.md` 11 節の注意 3）。**コンテナを監視するなら、ここを見ることになる。** |
| 根拠 | #219 / #284 |
| テスト | `CN0104_Pingが応答する(containerKey: "downstream")` |

**手順**

1. /Ping を叩く

**検証（合否を判定する）**

- HTTP 200 が返る

## CN-1.5 上流コンテナと下流コンテナの署名鍵が違う

| | |
|---|---|
| 観点 | **脚ごとに鍵を分けられること**（#293 の段階 1）。**同じ鍵だと、(3)（上流 → 下流の応答）の検証鍵を(4)（下流 → SPRP）の鍵と取り違えても通ってしまう** — **取り違えが露見しない。****compose が上流だけ `RsaPfxFilePath` / `JwkSetFilePath` を`*_Upstream` に向けている**ので、**その上書きが効いていなければ同じになる。** |
| 根拠 | #293 の段階 1 |
| テスト | `CN0105_上流と下流の署名鍵が違う` |

**手順**

1. それぞれの jwkcerts から、RSA の kid を読む
1. 両方の samlmetadata から、署名証明書を読む

**検証（合否を判定する）**

- 上流の RSA 鍵が取れる
- 下流の RSA 鍵が取れる
- kid が違う
- 2 つ目の上流の kid も違う
- 上流の署名証明書が取れる
- 下流の署名証明書が取れる
- 署名証明書が違う

**観測（判定しない）**

- 上流の RSA kid
  - **`JwkSetFilePath`（`JwkSet_Upstream.json`）が出どころ**である。
- 下流の RSA kid
  - **既定（`JwkSet.json`）のまま**である。
- 2 つ目の上流の RSA kid
  - **`JwkSet_Upstream2.json` が出どころ**である（#292 の段階 1）。

## CN-2.1 コンテナで、種データの利用者でサインインできる

| | |
|---|---|
| 観点 | **`mem` なので、作り直すたびに種データが作られる**（`CreateData`）。**サインインできることは、画面・ビュー・メールの雛形・DataProtection の鍵まで届いていることを意味する**（どれもマウントか設定で与えている）。 |
| 根拠 | #250 の段階 2 / #264 / #284 |
| テスト | `CN0201_種データの利用者でサインインできる(containerKey: "downstream")` |

**手順**

1. サインインする（利用者名は構成から。パスワードは出さない）
1. 保護された画面が開く

**検証（合否を判定する）**

- サインインできた
- `/Manage/Index` が開く

## CN-3.1 自己テストの `ClientCredentialsFlow` が通る（折り返しが届いている）

| | |
|---|---|
| 観点 | **サーバが自分自身を呼ぶ**ので、**コンテナの中から届く宛先が要る**（#250）。**`OAuth2ContainerizatedAuthSvrEPRootURI` に HTTP のループバックを与えている**（HTTPS にすると、コンテナの中でホストの開発用証明書を検証できない）。**この設定が欠けると、画面は出るのに結果が `ABNORMAL_END` になる。** |
| 根拠 | #250 / #284 |
| テスト | `CN0301_自己テストのclient_credentialsが通る(containerKey: "downstream")` |

**手順**

1. サインインして、自己テストのボタンを押す
1. 応答に access_token がある
1. トークンが空でない

**検証（合否を判定する）**

- 応答に access_token がある
- トークンが空でない

**補足**

- **値は出さない。** 有無と長さだけを見る（`TESTING.md` 9 節）。**折り返しが届いていなければ、ここが空になる。**

## CN-4.1 上流コンテナと下流コンテナが、同じ名前の Cookie を発行しない

| | |
|---|---|
| 観点 | **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、**ポートを分けても Cookie は分かれない。** **名前で分けるしかない**（#255）。**掛かっていないものが 1 つでもあると、そこだけが奪い合いになる** — **#282 の AntiForgery がそれだった。** |
| 根拠 | RFC 6265 §8.5 / #250 の段階 4 / #255 / #282 |
| テスト | `CN0401_上流と下流で同じ名前のCookieを発行しない` |

**手順**

1. それぞれサインインして、発行された Cookie の名前を集める
1. 名前が 1 つも重なっていない

**検証（合否を判定する）**

- 上流が Cookie を発行する
- 下流が Cookie を発行する
- 重なる名前が無い

**補足**

- **値は出さない。** 名前だけを見る（`TESTING.md` 9 節）。**`SessionTimeOut` だけは除いている** — **Open棟梁 の定数で、設定で分けられない**が、**雛形は `FxSessionTimeOutCheck` を `off` にしているので読まれない**（`CONFIGURATION.md` 11 節）。

## CN-5.1 下流コンテナから上流コンテナへ委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **コンテナ 2 つだけでハイブリッド IdP 構成が取れること**（#281）。**ブラウザが行く先（`authorize`）とサーバが呼ぶ先（`token` / `userinfo`）を分けた設定が効いていなければ、`code` の後で止まる。****どちらも「同じイメージの別の配備」**なので、**ここで出るのは配備の差である。** |
| 根拠 | OIDC Core §3.1 / #140 / #281 / #284 |
| テスト | `CN0501_コンテナ2つでID連携できる` |

**手順**

1. 上流コンテナでサインインしておく（この経路の確認を 1 本に絞るため）
1. 下流コンテナで「ID連携でサインイン」を押す
1. 上流が認可応答（form_post）を返す
1. 下流コンテナにサインインできている

**検証（合否を判定する）**

- 上流にサインインできる
- 上流の認可エンドポイントへ送られる
- prompt は付けない（上流が画面を出してよい）
- code が返る
- 保護された画面が開く

**補足**

- **`token` / `userinfo` はコンテナ内の宛先（`http://upstream:8080`）で呼ばれる**（#281）。**届いていなければ、この画面は開かない。**

## CN-5.2 コンテナ 2 つの構成でも、二度目の連携で同じ利用者になる

| | |
|---|---|
| 観点 | **連携キーは `(iss, sub)`**（#140 の段階 3）。**下流コンテナは `IssuerId` を上流と分けている**（#281）が、**連携キーに使うのは上流の `iss`** なので、分けても同じ利用者になる。**毎回新しいアカウントが作られないこと**を見る。 |
| 根拠 | #140 の段階 3 / #281 / #284 |
| テスト | `CN0502_二度目の連携でも同じ利用者になる` |

**手順**

1. 上流でサインインして、1 回目の連携を通す
1. もう一度、同じ経路を通す
1. 同じ利用者である

**検証（合否を判定する）**

- 1 回目でサインインできる
- 1 回目と 2 回目が同じ利用者

## CN-5.3 下流コンテナから上流コンテナへ SAML2 で委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **コンテナ 2 つだけで、SAML2 のハイブリッド IdP 構成が取れること**（#293 の段階 3）。**`CN-5.1` / `CN-5.2` は OIDC** なので、**SAML2 の脚はここで初めてコンテナを通る。****上流は下流と別の RSA 鍵を持つ**（#293 の段階 1）ので、**(3) を上流の鍵で検証できていなければ、この一巡は通らない。** |
| 根拠 | SAML 2.0 Web Browser SSO Profile / #286 / #281 / #293 の段階 3 |
| テスト | `CN0503_コンテナ2つでSAML2のID連携ができる` |

**手順**

1. 上流コンテナでサインインしておく（SAML の口は同意を通らない）
1. 下流コンテナで「SAML2 の ID 連携」を押す
1. 上流がアサーションを返し、下流コンテナの ACS が受け取る
1. 下流コンテナにサインインできている

**検証（合否を判定する）**

- 上流にサインインできる
- サインイン画面に SAML2 の導線が出ている
- 上流の SSO へ送られる
- 上流が下流の ACS を指す
- 応答（`SAMLResponse`）が読める
- StatusCode が Success
- 応答の Issuer は上流である
- (2) 下流 → 上流の AuthnRequest に署名が載っている
- (3) 上流 → 下流の Response に署名が載っている
- ACS がサインインさせる（リダイレクトする）
- 保護された画面が開く

**観測（判定しない）**

- 下流コンテナの画面に出るメアド
  - **上流の属性（`mail`）から受け取る**（#286 の段階 4）。

**補足**

- **上流が `AuthnRequest`（(2)）を検証できなければ Success は返らない**（#293 の段階 2。上流は登録値 `jwk_rsa_publickey` で検証する）。**下流が応答（(3)）を検証できなければ ACS がサインインさせない**（鍵は上流のメタデータから引く。#291）。**上流のメタデータは、コンテナの中から届く宛先で引いている**（`http://upstream:8080/samlmetadata`。**`https://localhost:44301` はコンテナの中から届かない**。#250 で実測）。

## CN-5.4 2 つ目の上流（鍵も issuer も違う OP）へ OIDC で委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **上流を n 件登録できること**（#292 の段階 1）。**上流 2 は、上流 1 とも下流とも別の RSA 鍵**で、**別の `issuer`** を名乗る — **`id_token` の検証鍵を、相手ごとに引けていなければ通らない**（#289 / #290）。**「鍵の違う OP と連携できる」ことは、ここで初めて測れる**（#289 の完了コメントに残した限界）。 |
| 根拠 | OIDC Core §3.1 / #289 / #290 / #292 の段階 1 |
| テスト | `CN0504_2つ目の上流とOIDCで連携できる` |

**手順**

1. 2 つ目の上流でサインインしておく
1. 下流で「ID 連携でサインイン」を、上流 2 を指して押す
1. 上流 2 が認可応答を返し、下流が id_token を検証する
1. 下流にサインインできている

**検証（合否を判定する）**

- 2 つ目の上流にサインインできる
- 上流 2 の認可エンドポイントへ送られる
- code が返る
- 保護された画面が開く

**補足**

- **上流 2 の鍵は `http://upstream2:8080/jwkcerts` から引いている**（`IdFederationUpstreams__upstream2__jwk_set_uri`。#290）。**引けなければ、設定の `.cer`（`SHA256RSA_Upstream2.cer`）に倒れる。****上流 1 の鍵では、どちらも検証できない。**

## CN-5.5 2 つ目の上流へ SAML2 で委譲して、下流にサインインできる

| | |
|---|---|
| 観点 | **SAML2 でも上流を n 件登録できること**（#292 の段階 1）。**メタデータの `entityID` は上流ごとに照合する**（#291）ので、**相手を取り違えれば、メタデータの値は使われない。****署名鍵も上流 2 のもの**であり、**上流 1 の鍵では検証できない。** |
| 根拠 | SAML 2.0 Web Browser SSO Profile / #291 / #292 の段階 1 |
| テスト | `CN0505_2つ目の上流とSAML2で連携できる` |

**手順**

1. 2 つ目の上流でサインインしておく
1. 下流で「SAML2 の ID 連携」を、上流 2 を指して押す
1. 上流 2 がアサーションを返し、下流の ACS が受け取る
1. 下流にサインインできている

**検証（合否を判定する）**

- 上流 2 の SSO へ送られる
- 応答が読める
- StatusCode が Success
- 応答の Issuer は上流 2 である
- ACS がサインインさせる（リダイレクトする）
- 保護された画面が開く

## CN-5.6 上流が違っても、同じ（検証済みの）メアドなら、同じ下流の利用者に結び付く

| | |
|---|---|
| 観点 | **連携キーは `(iss, sub)`**（#140 の段階 3）なので、**上流ごとに別の行**になる。**行が無い初回は、メアドで既存アカウントを探し、検証済みなら結ぶ**（#151 の段階 3 / #140 の段階 1）。**結果として、2 つの上流から来た同じ人は、同じ下流の利用者になる。****上流が 1 件のときは測れなかった**（#292 の段階 1）。 |
| 根拠 | #140 の段階 1・3 / #151 の段階 3 / #292 の段階 1 |
| テスト | `CN0506_上流が違っても同じメアドなら同じ利用者になる` |

**手順**

1. 上流 1 で連携して、下流の利用者名を読む
1. 上流 2（別の iss・別の鍵）で連携して、下流の利用者名を読む
1. 同じ利用者に結び付いている（アカウント リンク）
1. 二度目の連携でも、同じ利用者のままである

**検証（合否を判定する）**

- 上流 1 の連携でサインインできる
- 上流 2 の連携でサインインできる
- 上流 1 と上流 2 で同じ利用者
- 2 回目も同じ利用者

**補足**

- **結び付けの守りは「メアドが検証済みであること」**である（#140 の段階 1。`Sts.AccountLink.CheckLinkToExistingUser`）。**検証済みでなければ結ばず、理由を画面とログに出す。****上流が増えるほど、この守りが効いている必要がある。**

## CN-6.1 `/MultiPurposeAuthSite/...` では開かない（コンテナは root 配信である）

| | |
|---|---|
| 観点 | **コンテナは `UsePathBase` を呼んでいないので root で配信する**（#250 の段階 2）。**Visual Studio は `/MultiPurposeAuthSite` の仮想アプリ**であり、**「VS と同じ設定」のうち、ここだけは同じにできない**（#281 で決めた）。**どちらの形なのかを取り違えると、`redirect_uri` の照合が合わなくなる**ので、**root 配信であることを固定する。** |
| 根拠 | #250 の段階 2 / #281 / #284 |
| テスト | `CN0601_仮想ディレクトリ付きのパスでは開かない(containerKey: "downstream")` |

**手順**

1. 仮想ディレクトリ付きのパスを叩く
1. 開かない（404。リダイレクトもしない）
1. root のパスなら開く

**検証（合否を判定する）**

- HTTP 404 である
- `/Account/Login` は開く

## CN-6.2 同意の記録が無いクライアントは、`prompt=none` で `consent_required` になる

| | |
|---|---|
| 観点 | **上流は `mem` なので、作り直すと同意の記録が消える**（#280）。**`prompt=none` では UI を出せない**ので、**記録が無ければ `consent_required` を返すのが正しい**（OIDC Core §3.1.2.6）。**どのテストも「許可」を押さない専用のクライアント**で測る（他のクライアントは `CN-5` が同意を記録してしまう）。 |
| 根拠 | OIDC Core §3.1.2.6 / #272 の段階 2 / #280 / #284 |
| テスト | `CN0602_同意の記録が無ければconsent_requiredになる` |

**手順**

1. 専用のクライアント（同意を押さない）を構成から引く
1. サインインして、prompt=none で認可を要求する
1. consent_required が返る

**検証（合否を判定する）**

- `redirect_uri` が登録されている
- リダイレクトで返る
- error が consent_required

**補足**

- **同意画面を出さないのが肝である。** `prompt=none` は「UI を出すな」であり、**記録が無いときに黙って code を出してはならない**（#272 の段階 2 ＝ C-3）。

## CN-6.3 未登録の `client_id` では認可せず、エラーの画面が出せる

| | |
|---|---|
| 観点 | **プロトコルの確認はホスト側で済んでいる。****ここで見たいのは「コンテナでエラーの画面が出せること」**である — **ビューや資源のパスが届いていなければ、ここが 500 になる。** |
| 根拠 | #284 |
| テスト | `CN0603_未登録のclient_idでは認可しない(containerKey: "downstream")` |

**手順**

1. 未登録の client_id で認可を要求する
1. code は出ない。500 でもない

**検証（合否を判定する）**

- code が出ない
- 500 ではない

# UI. ブラウザでしか測れないもの（描画・JavaScript）

## UI-1.1 WebAuthn の削除画面で、チェックを入れたか外したかが見て分かる

| | |
|---|---|
| 観点 | **`class="form-control"` を付けると、Bootstrap 5 の `appearance: none` で**標準の描画が消える**（#277 の段階 6 で踏んだ）。**入れても外しても同じ空の箱**になり、**選べたかどうかが分からない。****値の往復は正しかった**ので、**HttpClient では見えない不具合**だった。 |
| 根拠 | #277 の段階 6 / Bootstrap 5 の .form-control |
| テスト | `UI0101_チェックの有無が見て分かる` |

**手順**

1. サインインして、削除の画面を開く
1. 入れる前と、入れた後を見比べる

**検証（合否を判定する）**

- チェックボックスが出ている
- チェックボックスが見えている
- 入れた後の見た目が、入れる前と違う

**観測（判定しない）**

- 使っているブラウザ
- appearance
  - **`appearance: none` それ自体は不具合ではない。****Bootstrap 5 の `.form-check-input` も `none` にしたうえで、印を自分で描いている**（**実測 : `none` のまま (2) は通る**）。**不具合だったのは `.form-control`** で、**標準の描画を消すだけで、代わりを描かなかった。****だから「見た目が変わるか」を測る**（原因ではなく、結果を測る）。

**補足**

- **選べること自体は HttpClient 側で測っている**（`RT-277.3`）。**ここで測るのは、選べたかどうかが画面から分かること**だけである。

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
- 認証したユーザのトークンである（email）
- sub が返る

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

