# AccountController の設計メモ

対象：両アプリの `Controllers/AccountController*.cs`（partial の全ファイル）

| ファイル | 担うこと |
|---|---|
| `AccountController.cs` | 本体（マネージャー、共通処理） |
| `AccountController.Authorize.cs` | 認可エンドポイント（max_age・prompt・同意、Response Mode / JARM）、Device AuthZ の確認画面 |
| `AccountController.SignIn.cs` / `SignUp.cs` / `TwoFactor.cs` | サインイン・サインアウト、利用者登録、2FA |
| `AccountController.ExternalLogin.cs` / `IdFederation.cs` / `Saml2.cs` | 外部ログイン、ID 連携（OIDC / SAML2）、SAML2 の IdP |
| `AccountController.SelfTest.cs` / `Helper.cs` | 自己テスト、種データなどの補助 |

**今の仕様は、ソースのコメントを見ること。**
ここには、段階ごとの決定と経緯（「前はどうだったか」「なぜ変えたか」）を残す。
ソースには Issue 番号だけを残してある（`（#310）` など）。段階の番号は、ここで引く。

## 認可エンドポイント（`Authorize.cs`）

### #247（max_age）

- **max_age の判定を CommonLibrary（`CmnEndpoints.CheckAuthTime`）へ移した。** bool では「再認証」「login_required」「invalid_request」を区別できなかった
- **要求の検証（`ValidateAuthZReqParam`）を先に行うようにした。**
  以前は `max_age` の判定が先で、超過すると `valid_redirect_uri` も `err` も空のまま、文面の無いエラー画面になっていた（`ANALYSIS-IdP.md` の A-12）
- **net10.0 版のサインアウトは `SignInManager.SignOutAsync()` にした。**
  `HttpContext.SignOutAsync()`（スキーム指定なし）では、Cookie（Identity.Application）が消えず、次の要求でも認証済みのままだった（実測）。
  net48 版は `SignOut(DefaultAuthenticationTypes.ApplicationCookie)` とスキームを指定しているため、net10.0 版だけの症状だった

### #254（`[AllowAnonymous]`）

- **#247 で足したのは「セッションは在るが古い」場合だけだった。**
  「セッションが無い」場合は、`[Authorize]` がコードに入る前にサインイン画面へ飛ばしていたので、`prompt=none` に `login_required` を返せなかった
- **`[Authorize]` を外し、未認証のときの扱いをメソッドの中で決めた**（net48 版は `HttpUnauthorizedResult`、net10.0 版は `ChallengeResult`）

### #229（クエリ文字列）

- **net10.0 版は、以前 `GetEncodedUrl` から生のまま取り出していた**ため、パーセント エンコードされた `request_uri`（`urn:...` のコロン）を取りこぼしていた。
  net48 版は `Request.QueryString`（デコード済み）で読んでおり、そちらに合わせた

### #272 の段階 2 / D-6（同意の記録）

- **以前は「`prompt=none` なら無条件に同意を飛ばす」だった**（C-3）。
  セッションが生きていれば、どのクライアントも無音で認可を取れた
- **同意を記録する（`ConsentProvider`）ようにして、「以前に同意済みか」で判定できるようにした。** 記録が無く `prompt=none` なら `consent_required`
- **拒否（E-6）を足した。** 以前は拒否できず、`access_denied` を返す経路も無かった。拒否は記録しない（利用者が気を変えられなくなる）
- **`prompt=login` で再認証する**ようにした。`max_age` の再認証と同じ経路（印を残してサインアウトし、同じ URL に戻す）を使う。
  `prompt=none` との併記は、段階 1 で `invalid_request` にしてある

### #310（OP のセッションと、ログアウトの通知）

| 段階 | 内容 |
|---|---|
| 段階 1 | OP のセッションの識別子（Cookie）を作り、サインアウトで終わらせる（`ClearOpSession`） |
| 段階 2 | Back-Channel Logout（サーバから POST）。`sid` を台帳（`SessionClientProvider`）に書く。`EnsureOpSession` で送り返す |
| 段階 3 | Front-Channel Logout（`iframe`）。`FrontChannelLogoutView` |

- **`AddSidClaim` を呼ぶ位置を、「code / token を実際に作る直前」へ移した（段階 2）。**
  以前は認可の経路の分岐より手前で呼んでいたので、同意画面を出しただけの相手・拒否された相手の行まで台帳に残り、
  段階 2 で「トークンを一度も受けていない RP へログアウトを伝える」ことになった
- **`EnsureOpSession` で、Cookie を置いてから同じ URL へ送り返すようにした（段階 2）。**
  Cookie が無いまま 2 本の認可要求が同時に来ると、別々の識別子ができ、残らなかった方の行は掃除まで残り、「もう居ないセッション」の通知先として生き続けた
- **Front-Channel の画面は、伝える先が無ければ出さない（段階 3）。** 登録している RP が無い配備では、従来どおりリダイレクトで終わる（応答も変わらない）

### net48 版への取り込み（#294）

- **net10.0 版で整理した `Authorize.cs` のコメントと if の構造を、net48 版へ取り込んだ。**
  未認証・再認証の分岐を「状態で分けてから、`prompt=none` かで分ける」形にした（判定の結果は変わらない）
- **net48 版の `AddAuthTimeClaim` は、認証時刻 Cookie が無いと例外になっていた**（`Request.Cookies[...].Value`）。
  net10.0 版と同じく、無ければ最小値で埋めるようにした（`?.Value`）

## ID 連携・外部ログイン（`IdFederation.cs` / `ExternalLogin.cs` / `Saml2.cs`）

### #140（ID 連携の安全性）

- **段階 1：上流の `email_verified` を見る。** メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない。
  新規作成で、以前は言い値に関わらず `EmailConfirmed = true` を入れていた
- **段階 3：PKCE（S256）を付け、`state` を 32 文字にした**（10 文字では短い）。
  以前は `code_verifier` に `""` を渡しており、PKCE を使っていないのに PKCE のオーバーロード（`client_secret_post`）を選んでいた
- **段階 3：認可応答の `iss` を検証する**（RFC 9207）
- **段階 3：連携キーを (issuer, sub) にした。** 以前は独自の `userid` クレームを鍵にしていたため、相手が汎用認証サイトに限られていた（`userid` は独自スコープ）

### #151（利用者名とメアド）

- **段階 1：`user:` で `ApplicationUser` から直に取れるものは、二重に持たない**
- **段階 3：利用者の鍵をメアドにした。** 以前は `RequireUniqueEmail` で「メアド」か「上流の識別子」かを選んでいた
  - 既存アカウントに結ぶとき、以前は「鍵が上流の識別子」の場合に備えて、メアドを突き合わせていた（メアドで引くので不要になった）
  - 新規作成で、以前は `uid` を利用者名にしてから、メアドを後で入れ直していた（利用者名とメアドを別に渡すようにした）
  - サインイン画面の Email 欄は「利用者名またはメアド」の入力になった。欄の名前は、ビュー・リソース・E2E・ID 連携の `login_hint` に波及するため変えていない
  - 入力された値を、そのまま `login_hint` として上流へ渡す
- **段階 3：利用者登録で、利用者名とメアドの両方を受け取る。** 以前はどちらか一方を `uid` に潰していた（画面には両方在ったのに）
- **段階 3：メアドの検証を必ず伴う。** 以前は「メアド無し」の配備があり、そのときは約款画面・サインイン画面へ直行し、`EmailConfirmed` を直に `true` にしていた
- **段階 4：新規に作るときの利用者名**（`preferred_username` → メアドの `@` より前）

### #286（ID 連携の整理）

- **段階 1：SAML2 の応答の検証で、鍵と期待 Issuer を引数にした**（検証の本体は #246 で両アプリから寄せ、#294 で Open棟梁 の `SAML2Client.VerifyResponseWithReason` へ移した）
- **段階 2：OIDC の開始（`StartIdFederationByOidc`）と、利用者の結び付け（`SignInByIdFederationOidc`）をメソッドに分けた。**
  以前はサインイン画面の分岐と `IDFederationRedirectEndPoint` に直書きしていたので、SAML2 側と並べて読めず、「protocol の往復」と「利用者の結び付け」が 1 つのメソッドに混ざっていた。
  自分の認可エンドポイントを組み立てていた行は落とした
- **段階 2：SAML2 の `NameID`（`Persistent`）は、上流が署名して主張した主体の識別子として扱うと決めた。** この段階では、`Persistent` の `NameID` を返す上流とは繋げなかった
- **段階 4：SAML2 で、メアド・名前・`email_verified` の 3 つを属性から受け取れるようにした**（Open棟梁 の `SAML2Attributes`）。
  無ければ、従来どおり `emailAddress` の `NameID` をメアドとして扱う。`Transient` の `NameID` は受けない
- **段階 5：`aud` は呼び出し側で確認する**

### #291 / #292（複数の上流）

- **#292 の段階 1：上流を複数持てるようにした。** どの上流へ送ったかを Session に控え、戻ってきたときに引く。Session が切れていれば既定（先頭の 1 件）で、1 件の配備では従来どおり
- **#292 の段階 3：鍵のロールオーバー。** 検証鍵はメタデータ → 設定の `.cer` の順で集め、2 本以上並ぶときは全部渡して試させる
- **#292 の段階 4-a：RelayState の扱いを、両アプリに同文で置かない**
- **id_token の検証鍵の選び方**：段階 2 で上流の discovery → `jwks_uri` → `kid`（ロールオーバーに追随）、段階 1 で設定の `.cer`（引けなかったときの受け皿）。どちらも無ければ従来どおり渡さない

### SAML2 の IdP（`Saml2.cs`）

- **#276：エラー応答を作れないときは、エラー画面を返す。** 以前は `null` を返しており、MVC のアクションから `null` を返すと 500 になった
- **`CreateSaml2Response` を 3 分岐にした。** 以前は `== HttpRedirect` の 2 分岐だったので、`null` が POST 側に落ち、`action` も `SAMLResponse` も空の自動送信フォームが返っていた

## サインイン・登録・2FA（`SignIn.cs` / `SignUp.cs` / `TwoFactor.cs`）

- **#294：WebAuthn のサインインの失敗を記録する。** 以前は画面へ返すだけだった
- **#292 の段階 1：サインイン画面から委譲する上流は `IdpKey` で選ぶ。** 空なら既定（先頭の 1 件）で、従来の押し方と同じ結果になる
- **#310 の段階 1〜3：サインアウト（`LogOff` / `EndSession`）で OP のセッションを終わらせ、伝える先があれば Front-Channel の画面を挟む。** 伝える先が無ければ、従来どおり直に戻る
- **#214：2FA のコード送信の失敗を、処理されない例外にしない。** 以前は例外がそのまま出て、原因の分からないエラー画面になっていた

## 自己テスト・補助（`SelfTest.cs` / `Helper.cs`）

- **#246：FAPI2 の自己テストのトークン交換を `private_key_jwt` にした。**
  以前は `client_secret` を空で送り、クライアント証明書（TB）が付くことを前提にしていたが、
  自己テストのクライアントは `ClientCertPfxFilePath` が設定されていなければ証明書を添えない。
  設定が無い配置では `/token` が 401（`invalid_client`）になり、自己テストが結果画面まで通らなかった（`/ros` でも `/par` でも同じ）
- **#310 の段階 2 / 3：Back-Channel / Front-Channel Logout の受け口（自己テスト）を足した**
- **#246 の項目 3：SAML2 のアサーションを画面に出す（自己テストの ACS）。** 以前は `?ret=認証完了（nameId=…）` / `?ret=認証失敗` という URL に移るだけで、どこで落ちたのかが分からず、読み取った属性も XML も捨てていた
- **#294：自己テストの ACS（`AssertionConsumerService`）を `Saml2.cs` から移した。** `Saml2.cs` は IdP の口だけを持つ
- **#264：E2E 専用のクライアント登録を、利用者の登録（`saml2OAuth2Data`）に寄せた。**
  以前は `test.ps1 -Launch` が環境変数で差し込んでいたが、net48 版は一覧ごと 1 本の環境変数で渡すため、件数に上限があった（#262 で踏んだ。IIS Express が起動するのに全要求が 500 になる）
- **#307 の段階 5-a：クライアントごとの利用者を作らなくなった。**
  以前は外部キー（`Saml2OAuth2Data.ClientID` → `Users.ClientID`）を満たすためだけに、クライアント 1 件につき利用者 1 人を作っていた。
  所有者を `Saml2OAuth2Data.OwnerUserId` へ移し、その外部キーを落としたので、要らなくなった（[ClientRegistrationProvider.md](ClientRegistrationProvider.md) の段階 5-a）
- **#277 の段階 7：WebAuthn の資格情報の種。** 初期化済みでも、テスト用の種はまき直す
- **#260：テスト用の利用者名に接尾辞を付けられる**（`TestUserSuffix`。空なら付けない＝従来どおり）

## #305（認証の失敗の数え方）

- **段階 2：Device AuthZ の確認画面で、続けて間違えている利用者を断る**（RFC 8628 §5.2）
