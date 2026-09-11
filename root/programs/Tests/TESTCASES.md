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

## TC-3.2 トークン応答に Cache-Control: no-store が付く

| | |
|---|---|
| 観点 | トークンを含む応答は、中間キャッシュやブラウザ履歴に残してはならない。RFC 6749 は **Cache-Control: no-store と Pragma: no-cache** を MUST としている。 |
| 根拠 | RFC 6749 §5.1（successful response）/ §5.2（error response） |
| テスト | `TC0302_トークン応答のキャッシュ制御` |

**手順**

1. POST /token で正常にトークンを取得し、応答ヘッダを見る

**検証（合否を判定する）**

- この応答にトークンが含まれている（前提の確認）

**観測（判定しない）**

- Cache-Control
  - RFC 6749 §5.1 は no-store を MUST としている。
- Pragma
  - RFC 6749 §5.1 は no-cache を MUST としている。HTTP/1.0 の後方互換のためのもの。

**補足**

- **この 2 つは現状 MUST を満たしていない。** 判定を NG にすると他の検証が実行されなくなるため、ここでは観測にとどめ、別途 Issue として扱う。

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
  - OIDC Core §5.3.3 は 401 と WWW-Authenticate を求める（#196）。

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

**観測（判定しない）**

- 旧が再び提示された後も、新は使えるか
  - BCP は、使用済みの refresh_token が再び提示されたら、**どちらが正規か分からないので、有効な方も失効させる**ことを勧めている。

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
  - RFC 7662 §2.3 は、認証に失敗したら 401 を返すとしている（#196）。

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

**観測（判定しない）**

- token_type
  - 見つかった種類が入る。RFC 7662 §2.2 の token_type は Bearer などの型を指すので、意味がずれている。

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

- この実装は scope を assertion の中から読む。RFC 7523 §2.1 では、scope はトークン要求のパラメタである。

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

- **HTTP ステータス自体は 200 のまま**である（RFC 6749 §5.2 は 400 / 401 を求める）。これは #196 で別途扱う。

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
- unsupported_grant_type で拒否される

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

# 保留中のテストケース（Skip）

**未修正だと分かっている項目は、期待する動作を書いたうえで Skip にしている。**
消さずに残すのは、直したときに Skip を外すだけで検証できるようにするため。

**実行されないため、上の一覧には現れない。**
観点・根拠・手順はテスト コードにある。

| テスト | Skip の理由（Issue 番号・実測日・実測結果） |
|---|---|
| `RT187_04_未知のresponse_typeはunsupported_response_typeでリダイレクトする` | 未修正。実測（2026/09/09, net10.0）では、リダイレクトではなくエラー画面（HTTP 200）になる。 |

