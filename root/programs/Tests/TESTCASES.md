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

## RT-C10.1 管理画面の自己テストの折り返し先は、登録されているクライアントでだけ使える

| | |
|---|---|
| 観点 | **`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**管理画面の「トークンを取る」の折り返し先と完全一致する `redirect_uri` は、**その client_id にその URI が登録されているかを見ずに通っていた。****`IsLockedDownTestEndpoints` の対象外**なので、**本番でも閉じられなかった。****`test_self_code_manage` を記号にして登録値で表せるようにし、分岐を消した。****登録どおりの照合だけになり、例外は無くなった。** |
| 根拠 | RFC 6749 §3.1.2.3 / ANALYSIS-IdP.md の C-10 |
| テスト | `RTC1001_自己テスト用の折り返し先も登録と突き合わせる` |

**手順**

1. 登録していないクライアントが、この折り返し先を指定する
1. 登録しているクライアントが、同じ折り返し先を指定する

**検証（合否を判定する）**

- 記号が解決できている（管理画面の口を指している）
- 認可コードを発行しない
- その URI へリダイレクトしない
- 認可コードを発行する

**観測（判定しない）**

- 応答
  - **redirect_uri が照合できないときは、その URI へエラーも返さない**（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。
- 応答
  - **登録値として表せるようにしたので、通常の照合で通る**（分岐は要らない）。

**補足**

- **(1) が、消した分岐そのものである。**分岐が在った間は、**登録済みのどのクライアントでもこの URI を宛先にできた。**
- **(2) は、消したことで機能が壊れていないことを見ている。****管理画面の「トークンを取る」は、この記号を登録しておく必要がある**（新規登録の既定）。**動作確認の後は、自分の RP の折り返し先に書き換える。**

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
| 観点 | **この認可サーバが発行する alg は `SigningKeys.SupportedAlgs`** で、`jwkcerts` と Discovery も、その一覧から作っている。**以前は、知らない alg を RS256 として扱っていた**（C-8）。**関門は 3 つ**で、**発行しない alg は即、拒否**し、**発行する alg でも、鍵（kty / crv）が合わなければ拒否**し（#129 の段階 3）、**鍵まで合っても、署名が合わなければ拒否**する（#129 の段階 4）。 |
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

- **C-8 で「受ける alg」を固定した**（#129 の段階 1）。**段階 2 で RS384 / RS512 を足した**ので、**ここが通ることが、その証拠**になる。**受ける集合は `CmnAccessToken.SupportedAlgs` の 1 か所**で、**Discovery の `id_token_signing_alg_values_supported` も、そこから作っている。**

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
- **`kty` だけで判定していると、ここが通ってしまう**（どちらも `kty=EC`）。**`crv` まで突き合わせる**ようにした（`CmnAccessToken.IsSameKeyType`）。**実害が出る前に入れた**（ES384 / ES512 を発行し始めるのと同じ段階）。

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

1. 上流でサインインしておく（下流は prompt=none で委譲する）
1. 下流で「ID連携でサインイン」を押す
1. 上流が認可応答（form_post）を返す
1. 下流の Redirect エンドポイントへ渡す

**検証（合否を判定する）**

- 上流にサインインできる
- 上流の認可エンドポイントへ送られる
- PKCE(S256) を付けて要求する
- prompt=none で要求する（画面を出させない）
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
| 観点 | **下流は prompt=none で委譲する。** 上流が黙って認証できないときに**勝手にサインインさせてしまっては、委譲の意味が無い。****上流が画面を出すか login_required を返すかは #254 の論点**で、**どちらでも下流はサインインしない。** |
| 根拠 | OIDC Core §3.1.2.1 / §3.1.2.6 / #140 / #254 |
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
- Front-Channel Logout は広告しない

**観測（判定しない）**

- 広告された URL
  - 設定キー OAuth2EndSessionEndpoint（既定 /end_session）で決まる。

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
- 確認すればログアウトする（HTTP 302）
- サインアウトされた

**観測（判定しない）**

- 戻り先
  - **この配置の TestClient には post_logout_redirect_uri の登録が無い**ため、RP へは戻さず確認画面になる（§3 の MUST）。雛形（`_appsettings.json` / `_app.config`）には `test_self_logout` を足したので、当て直せば戻るようになる。

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

1. 認可コード フローで refresh_token を得る（client_secret で交換）
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

1. トークンを得る
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

1. トークンを得る
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

- **Redirect Binding は、クエリ文字列そのものが署名の対象**である（`SigAlg` が `RSAwithSHA1` のときだけ検証する。従来どおり）。

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
1. （対照）絞っていないクライアントは、ES256 でも通る

**検証（合否を判定する）**

- トークンが返る
- トークンが返らない
- トークンが返る（登録を書かなければ従来どおり）

**補足**

- **絞るのは「受ける側」だけ**である。**発行する側（`id_token_signed_response_alg`）は #129 の段階 2 で入っており、別の項目。**
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

**検証（合否を判定する）**

- 認可コードは発行されない
- 同じ URL へ戻される（再認証の経路）
- サインイン画面へ送られる
- 認可コードが返る（印が効いている）

**補足**

- **印が無いと、ここで永久に送り返す。** `max_age=0` でも同じことが起きるので、**#247 で入れた印（`re_auth_at`）をそのまま使っている。**
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

# FA. FAPI（クライアント登録ごとに通る経路）

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

## FA-6.5 oauth2_oidc_mode=fapi2 のクライアントは、mTLS で refresh_token を使える

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

**観測（判定しない）**

- エラー応答に Assertion が入るか
  - **いまの実装は、エラー応答にも Assertion を組み込む**（`CreateSamlResponse` が `CreateResponse` と `CreateAssertion` を常に呼ぶため）。**仕様としては、エラー応答にアサーションは要らない。****直すなら別 Issue**（この Issue の範囲では、返す先と StatusCode を測る）。

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

**検証（合否を判定する）**

- HTTP 200（自動送信フォーム）
- SAMLResponse がある
- StatusCode

**補足**

- **`TestClient_21` は鍵を登録していない**ので、**同じ要求が `SA-3.*` では通る。** 差は登録だけである。

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

