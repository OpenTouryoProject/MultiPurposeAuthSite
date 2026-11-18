# 品質の羅針盤（QUALITY.md）

**どこを・何で・どれだけ確かめるか**を、汎用認証サイトについて決めた文書。人が決め、エージェントが従う。

- **共通の決まりは [`QUALITY.common.md`](QUALITY.common.md)**（OpenTouryoCodingAgentAssets の配布物。ここでは直さない）。**節の番号は同じ**で、本書には各節の汎用認証サイトの中身だけを書く
- **エージェントは、変更の前に本書と `QUALITY.common.md` を読む**（[`AGENTS.md`](AGENTS.md) から参照し、`CLAUDE.md` から読み込んでいる）
- 方針の経緯と、Open棟梁 との共通部分は Wiki の
  [品質の羅針盤（方針案）](https://github.com/NetDevInfraWGinOSSConsortium/NetDevInfraWiki/wiki/OTR_QualityCompass)。
  導入は [#315](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/315)
  （Open棟梁 は [OpenTouryo#640](https://github.com/OpenTouryoProject/OpenTouryo/issues/640)）。
  共通と固有に分けたのは OpenTouryoCodingAgentAssets#21

> **人は個々の変更を細かく見るより、羅針盤を決める役を担う。**
> エージェントは、作業がどの名前空間に当たるかを本書で引き、その重みで確かめ、報告する。

## このリポジトリの値

`QUALITY.common.md` の「このリポジトリの値」は、この表を指す。

| 項目 | 値 |
|---|---|
| 検出器の置き場所 | `root`（`CheckExpectationChange.ps1`・`rules.common.psd1`・`rules.psd1`） |
| 判定の用例の置き場所 | `root/files/tools/ExpectationGuard.Tests`（製品のソースの隣を避けて、道具の置き場所に置く） |
| 入れ直しのコマンド | `<アセット>\install\install.ps1 -TargetRoot <このリポジトリ> -IncludeQualityGuard -QualityGuardPath root -QualityGuardTestsPath root/files/tools/ExpectationGuard.Tests`（`-Product` は付けない。`AGENTS.md`・`CLAUDE.md` はこのリポジトリが持つ） |
| 宛先のブランチ（段 3 で検査する PR の宛先） | `develop`・`master`（[`expectation-change.yml`](.github/workflows/expectation-change.yml)） |
| 必須のチェック | `expectation-change`・`testcases-regenerated` |
| 共有の作業ブランチ | `5th_agent` など（ほかの人・セッションも push する。メッセージを書き直さない） |
| 変更のレビュー役（4 節） | [`quality-reviewer`](.claude/agents/quality-reviewer.md)（`model: sonnet`。#347。Open棟梁 と同じ形。OpenTouryo#680） |
| 回帰テストの名前 | `RT-<Issue>`（`TestReport` の識別子） |

### 一次情報

**本書には方針と表だけを置く。** 手順は各文書が一次情報である。

| 内容 | 一次情報 |
|---|---|
| 検証の手順・回す範囲 | [`root/CHEATSHEET.md`](root/CHEATSHEET.md) 1 節、[`root/TESTING.md`](root/TESTING.md) |
| コーディング規約 | [`root/CODING.md`](root/CODING.md) |
| テストケース | [`Tests/TESTCASES.md`](root/programs/Tests/TESTCASES.md)（生成物。一次情報はテスト コード） |
| カバレッジの値と、届いていない箇所 | [`Tests/COVERAGE.md`](root/programs/Tests/COVERAGE.md) |
| セキュリティの指摘の扱い | [`AGENTS.md`](AGENTS.md)「セキュリティの指摘は、公開される前に確認を取る」、[`Security.ja.md`](Security.ja.md) |

---

## 1. 品質マップ

**単位**：名前空間。接頭辞 `MultiPurposeAuthSite.` は省略する（フォルダは `root/programs/CommonLibrary/` の下。`Controllers` は両版のサイトの下）。

| 名前空間 | リスク | 正の根拠 | 検証の手段 | 人が必ず見る箇所 |
|---|---|---|---|---|
| `TokenProviders` | **高** | OAuth2 / OIDC の RFC・仕様 | E2E（両版）、**適合性テスト**（2 節） | 検証を省く分岐、トークンの紐付け、既定値の変更 |
| `Extensions.Sts` | **高** | 拡張仕様（FAPI・CIBA・JAR・PAR・DPoP・Logout・Discovery など） | E2E（両版）、**適合性テスト**（2 節） | 同上。**OpenTouryo のアセンブリの更新** |
| `SamlProviders` | **高** | SAML2 の仕様（OASIS） | E2E（両版） | 署名の対象と消費する要素の一致。**OpenTouryo のアセンブリの更新** |
| `Controllers` | **高** | OAuth2 / OIDC・SAML2 の仕様、[`ANALYSIS-IdP.md`](root/programs/ANALYSIS-IdP.md) | E2E（両版。net48 と net10.0 の差）、**適合性テスト**（2 節。net10.0 版） | サインイン・同意・CSRF、既定値の変更 |
| `Extensions.FIDO` | **高** | WebAuthn・FIDO の仕様 | E2E（両版） | 署名の検証、チャレンジの扱い |
| `Util.Sts`・`Util.IdP` | **中〜高** | 呼び出し元の仕様 | E2E（両版） | クライアントの解決、鍵の扱い |
| `Password` | **中〜高** | パスワードのハッシュの方式 | E2E（両版） | 既定のアルゴリズム、既存のハッシュの互換性 |
| `Data` | **中〜高** | 各 DBMS の文法 | E2E（`mem`・`sql`・`ora`・`npg`）、`CompareDdl.ps1` | DDL の変更（配備済みの DB）、SQL の組み立て、3 方言の一致 |
| `Manager`・`Co` | 中 | [`CommonLibrary/ANALYSIS.md`](root/programs/CommonLibrary/ANALYSIS.md) | E2E（両版） | 設定の既定値（`Co`）の変更 |
| `Network`・`Notifications`・`Entity`・`ViewModels`・`Log` | 中〜低 | — | E2E（両版） | 外への送信先、例外の扱い |
| `Util.Test` | 低（**製品の経路に無い**） | — | E2E が使う | **製品の経路から呼ばれるようにならないか**（例外は、`IsDebug` か `SeedsTestData` で閉じた 1 行のフック。`TestOutbox`・`TestClients.RegisterInStore`） |
| ツール（`CommandLineTools`）・`DesignNotes` | 低 | — | ビルド | 原則として見ない |

- **OpenTouryo のアセンブリ（`OpenTouryoAssemblies`）を更新するときは、E2E を通す。**
  検証の中身（DPoP の `htu`、大文字小文字の比べ方、SAML2 の `SigAlg`、JARM の `error` の応答など）がそちらにあるため、
  ソースの差分に現れないまま振る舞いが変わる（OpenTouryo#642〜#644 が実例）
- 検証の手段の具体（どのスクリプトを、どの引数で回すか）は [`AGENTS.md`](AGENTS.md)「検証は、変更の届く範囲で決める」と [`root/CHEATSHEET.md`](root/CHEATSHEET.md) 1 節による

---

## 2. 正の定義

- **根拠**：`TestReport` の `basis`（`TESTCASES.md` の「根拠」）に書く。書き方は 7 節
- **観測の扱い**
  - 検証（`Verify`・`VerifyEqual`）は、外れればテストは落ちる。観測（`Observe`）は記録する。**判定しない**
  - **Open棟梁 との違い：こちらの観測は落ちない。** サイトは外から叩く対象で、仕様が幅を持つ項目を合否に混ぜると「通った」の意味が薄まるため
  - **単体テスト（`Tests/UnitTests`）に観測は無い。** 判定できる値だけを書き、`[Basis]` に根拠を書く（7 節。Open棟梁 の `[Observation]` は流用しない。#324）
  - **落ちない代わりに、前回の実行と比べて差分を報告する**（`2_RunAllTests.ps1` が [`CompareObservations.ps1`](root/CompareObservations.ps1) を呼ぶ。報告書の末尾と画面に出る）。
    **判定はせず、合否にも関わらない。** 変わってよいかは人が判断する
  - **前回の値はコミットしない**（`Result` に置く）。配備ごとの値や、サインイン中の利用者の名前を含む画面の文面が入るため
- **外部の基準を、最終的な正とする。** 適合性テスト（OpenID Foundation の Conformance Suite。`ANALYSIS-IdP.md` の D-14。**#350 で入れた**）。
  回し方・プラン・結果の読み方は [`TESTING.md`](root/TESTING.md) 5 節「適合性テスト」と [`container/CTS/README.md`](container/CTS/README.md)
  - **いつ回すか**：**(1) リリースの前に、全プランを回す。(2) 適合性テストで見つかった不適合を直す Issue では、`fixed` の前に、そのプランを回す。**
    **普段の作業（`fixing`・ほかの `fixed`）では回さなくてよい**（Conformance Suite のコンテナがメモリを使い、全プランで 2〜3 時間かかる。E2E の通しには入れない）
  - **結果の扱い**：落ちたものは、**環境（Conformance Suite の設定・自動操作）の不足か、OP の不適合かを仕分け**、不適合は原因ごとに Issue にする（セキュリティの弱点の疑いなら、公開する前に人に聞く。[`AGENTS.md`](AGENTS.md)）。
    **結果（`container/CTS/out/`）はコミットしない**（配備ごとの値と、テスト利用者のパスワード・クライアントの秘密鍵を含む）
  - **自動では回せないモジュールがある**（利用者が拒否する操作など。`container/CTS/README.md`）。**REVIEW（画面の写し）は、人が見て合否を付ける**
  - **相手は net10.0 版だけ**（判定の大半は `CommonLibrary` で共通。両版の差は E2E が測る）

---

## 3. 期待値の変更と、その承認

### 期待値の変更に当たるもの

**TESTCASES.md ではなく、テスト コードの差分で見る。** TESTCASES.md は生成物で、作り直しには E2E の実行が要るためである。

| 対象 | 期待値の変更に当たるもの |
|---|---|
| テスト（`root/programs/Tests/**/*.cs`） | テストの削除（`[Fact]`・`[Theory]`・`[SkippableFact]`・`[SkippableTheory]`・`[InlineData]`・`[MemberData]` などの行の削除） |
| | Skip の追加（`Skip.If(`・`Skip.IfNot(`・`Skip =`・`SkipException(`） |
| | 検証の削除（`.Verify(`・`.VerifyEqual(` の行の削除。`Observe` への移動を含む。`UnitTests` の下では `Assert.`・`[Basis(` の行の削除も） |
| | 根拠の変更（`Report` の `basis` が、識別子ごとに変わった・消えた） |

- Skip の正当な使い方：DB やコンテナが無い、片方の版だけの機能
- **仕組みのファイル**には、共通のものに加えて `TestReport.cs` が当たる（`rules.psd1` が足した）。`Verify` が落ちなくなれば、すべてのテストが通るからである

### このリポジトリの規則（#335）

| ファイル（`root/`） | 持ち主 | 中身 |
|---|---|---|
| `rules.psd1` | このリポジトリ | このリポジトリの規則（テストの属性・Skip・`Verify` と単体テストの `Assert.`・`[Basis(` の削除・`Report` の `basis`・`TESTCASES.md`・`TrailerRequirements`） |

- 写し（本体・共通の規則・判定の用例・フック・突き合わせ役）は `QUALITY.common.md` 3 節の表のとおり。Open棟梁 も同じ本体を写して使う（OpenTouryo#657）
- **要確認**の範囲（`rules.psd1` の `ReviewScope`）は書かない＝リポジトリ全体（`DiffScope` はテストの範囲で、要確認には使わない）
- **置き換えの前後で、導入の後の全コミット（62 件）の判定が同じ**であることを確かめた（PowerShell 7・5.1。#335）
- 段 2 の有効化・PR の前の確かめ・CI で止まったときは `QUALITY.common.md` 3 節。CI で止まったときに外さない必須のチェックは、「このリポジトリの値」の 2 つ

### TESTCASES.md の作り直しの漏れ

**CI では作り直さず、検出だけ行う**（作り直しには DB・コンテナが要る）。
同じワークフローのジョブ `testcases-regenerated` が、**テストの文面**（`TestReport` に渡す文面とメソッド名）**が変わったのに `TESTCASES.md` が変わっていない** PR を落とす。
手元では、`root` で `.\CheckExpectationChange.ps1 -Range develop..HEAD -CheckGenerated`
（**`-CheckTestCases` から改名した**。#335。共通の本体では、生成物の確認は規則の `GeneratedRules` で決まる）。

- **通しの既定から外れるテスト**（`-ShortLifetimes` などの特別な構成）は原本に載らない。
  そのときは、コミットのトレーラーに `TestCases-Unchanged: <理由>` と書く

---

## 4. レビューの観点

**名前空間に応じて、次を確かめる。** どの名前空間でも見る観点は `QUALITY.common.md` 4 節にある。

### OIDC / OAuth2（`TokenProviders`・`Extensions.Sts`・`Controllers`）

- [ ] `state`・`nonce`、`redirect_uri` の完全一致、PKCE
- [ ] トークンの紐付け（mTLS・DPoP）、クライアントとトークン・コードの紐付け。
  **トークンを作る経路（`ProtectFromPayload` / `CreateFromClaims`）で、縛り（`cnf`）が揃っているか** —
  **client_credentials・ROPC・device_code だけ、証明書に縛っていなかった**（#346。`RT-346.7`・`.8`）。
  **縛る証明書は、認証で確かめたものか**（クライアント認証を通らない経路では、提示されただけの証明書が残る）。
  **トークンを出す口は、トークン エンドポイントだけではない** — **認可エンドポイントの Implicit・Hybrid も access_token を出す。**
  **強制（送信者の拘束の必須など）を、出すすべての口で揃えたか**（#346。`RT-346.9`）
- [ ] **縛る鍵を受け取る口が複数あるとき、すべてを見ているか。**
  **PAR では、`dpop_jkt` と `DPoP` ヘッダのどちらでも `code` を縛る**（RFC 9449 §10.1 の MUST。両方が来たら一致を確かめる）。
  **`dpop_jkt` だけを見て、ヘッダを捨てていた**（#365。`RT-365.1`・`.2`）
- [ ] **縛るかどうかが、クライアントの種別で変わらないか。**
  **RFC 9449 §5 は、公開クライアントの `refresh_token` だけを DPoP の鍵に縛る**（秘密を持つクライアントは、クライアント認証で縛られている）。
  **種別によらず縛ると、鍵を作り直したクライアントが更新できなくなる**（#367。`RT-311.11`）。
  **入れ替え（ローテーション）も同じ** — **FAPI 2.0 は入れ替えないことを求める**（#367。`RT-367.1`）
- [ ] `alg` の固定（`none` を受けない）、`aud`・`iss`・`exp` の確認
- [ ] **出す JWT のヘッダの `kid` は、署名した鍵（`jwks_uri` に載る鍵）の `kid` か。**
  **Nested JWT（JWE の中の JWS）では、暗号化に使うクライアントの鍵の `kid` と取り違えやすい**（#352。`RT-352.1`）。
  **自己テスト（サーバとクライアントを兼ねる）では気付けない。** RP として、`kid` で `jwks_uri` から鍵を引いて確かめる
- [ ] **出す JWT の `alg` は、登録（`id_token_signed_response_alg`）に従っているか。** **形（JWS / JWE）や経路ごとに、alg を決める箇所が分かれていないか** —
  **暗号化した id_token の中の JWS だけ、登録にかかわらず ES256 だった**（#355。`RT-355.1`）。
  **JARM の応答は、登録で選べず RS256 に固定だった**（#370。`RT-370.5`）。
  **登録が無いときの既定が、プロファイル（FAPI は RS256 を認めない）に合うか**も見る。
  **既定を変えるなら、相手（Open棟梁 で作った RP・同梱の自己テストのクライアント）がその alg を検証できるか**も見る（**Open棟梁 の RP 側の検証が、暗号化しない ES256 を受けなかった**ので、#370 では FAPI の登録の既定を ES256 にするのを見送り、**OpenTouryo#695 で直ってから変えた**。#394。`RT-394.1`）。
  **見送ったときは、相手の側の Issue と、直ったら何をするかを、コードのコメントと文書に残す**（#370 の見送りは、Open棟梁 の更新の知らせで拾えた）
- [ ] **受ける JWT（Request Object など）の alg は、鍵の種類と食い違っていないか。プロファイルが認めない alg を受けていないか。**
  **Request Object を RS256 でしか検証できず、FAPI の RP の ES256 を断っていた。一方で FAPI の登録の RS256 は受けていた**（#370。`RT-370.1`〜`.4`）。
  **受ける alg を変えたら、その alg で作っている既存のテスト（と自己テストのクライアント）が、測りたい理由より先に alg で断られていないか**も見る。
  **受ける JWT ごとに、alg の扱いがそろっているか**も見る — **Request Object は PS256 を受けて FAPI の RS256 を断るのに、`client_assertion` と CIBA の要求は PS256 を受けなかった**（#395。`RT-395.1`・`.2`）。
  **鍵の種類（`kty`）で alg を決める版の `Verify` は、PS256 を通せない**（RSA の鍵は RS256 に決まる）。**ヘッダの alg を受けてよいと決めてから、その alg と鍵から検証鍵を作る**（OpenTouryo#664 の `JWS` を受ける版）
- [ ] **応答の数値（`expires_in`・`interval` など）を、JSON の文字列にしていないか**（RFC 6749 §5.1「Numerical values are included as JSON numbers」）。
  **`Dictionary<string, string>` で応答を作ると、数値が文字列になる**（#294・#353。`RT-294.75`・`RT-353`）。
  **E2E の `JsonResponse.String` は数値も文字列にして返す**ので、型は `KindOf` で見る
- [ ] **値の無いクレームを、空文字列・null で返していないか**（OIDC Core 1.0 §5.3.2。名前ごと省く）。
  **利用者の値をそのまま足すと、持っていない項目が `""` で出る**（#354。`RT-354.1`）。**`*_verified` も、値が無ければ出さない**。
  **受け付けているものを、Discovery で広告しているか**（逆に、広告して受けないものが無いか）— **`response_mode=jwt` を受けていたのに、`response_modes_supported` に載せていなかった**（JARM §2.3.4。#379。`RT-379.1`）。
  **応答の形（クエリ・フラグメント・JARM）ごとに、値の無いパラメタの扱いが揃っているか** — **クエリは省いていたが、JARM は要求に無い `state` を `"state": null` で載せていた**（#378。`RT-378.1`）
- [ ] **登録で受けた URL の中身を、確かめずに識別に使っていないか**（`sector_identifier_uri` は、中身に `redirect_uris` がすべて在ることを確かめてから、pairwise の Sector に使う。OIDC Registration 1.0 §5）。
  **以前は確かめずに受け、値を捨てていた**（#364。`RT-364.2`）。**受けた値を黙って捨てる**のも、利用者には「効いている」と読める
- [ ] **プロファイルが資源に求める応答のヘッダを付けているか**（FAPI 1.0 Baseline §6.2.1 の 11 の `x-fapi-interaction-id`）。
  **外から来た値をヘッダ・ログに返すなら、形を確かめているか**（UUID の形でなければ使わない。#384。`RT-384.1`）
- [ ] **仕様の「だけ」を「も」と読んでいないか**（FAPI 2.0 の `aud` は issuer だけ。#323）。登録の種別で規定が変わらないか。
  **プロファイルの強制を 1 つの登録種別に入れたら、ほかの種別の同じ規定も見る** — **S256 の PKCE を fapi2 には必須にした（#366）が、fapi1 の PAR（FAPI 1.0 Advanced §5.2.2 の 18）には入れていなかった**（#383。`RT-383.1`）。**原典が経路を限るなら、その経路だけにする**（fapi1 は PAR の要求だけ）。
  **逆に、プロファイルが一般の仕様より強く求めるものを、一般の規則のまま通していないか** — **OIDC Core では任意の `nonce` を、FAPI 1.0 Baseline は `openid` の要求に必須とする。fapi1 の `response_type=code` を `nonce` 無しで通していた**（#382。`RT-382.1`）。
  **強制を足したら、同じ登録で別の理由の拒否を測っているテストが、新しい強制で先に断られて「通って」いないか**（**断る理由まで確かめる**）— **fapi1 に JARM を必須にすると、`RT-382.1` の `nonce` 無しの要求は JARM の確かめで先に断られ、理由を見ないテストは通ったままだった**（#381。`error_description` で理由を確かめるようにした）。
  **同じパラメタを、外（フォーム）と中（Request Object）の両方で見ているか** — **PAR はフォームの `request_uri` を断っていたが、Request Object の中の `request_uri` は見ていなかった**（RFC 9126 §2.1。#380。`RT-380.1`）。
  **同じ規定を、受ける口ごとに入れたか** — **Request Object の寿命の上限（60 分）を PAR・`/ros` の FAPI の登録には入れた（#336）が、CIBA の署名した要求には入れていなかった**（#388。`RT-388.1`）
- [ ] **受ける値が、口（エンドポイント）ごとの仕様で変わらないか。** **CIBA の口では、クライアント認証の `aud` に CIBA の URL も受ける**（CIBA Core 1.0 §7.1 の MUST）。
  **判定が口を問わず、トークン エンドポイントの URL と issuer だけを受けていた**（#371。`RT-371.1`〜`.3`）。
  **広げるなら、その口の分だけにする** — 使い捨てにしていない値（クライアント認証の JWT の `jti`）は、全部の口で受けると、別の口に流用できる
- [ ] **根拠の仕様が、後の RFC で更新・置き換えられていないか**（rfc-editor.org の「Updated by」）。
  **RFC 10070**（2026 年 11 月）**は、クライアント認証の `aud` を issuer の唯一の値に限り、トークン エンドポイントの URL を禁じ（§4）、PAR の口の URL を外した（§5）** —
  **#371 で RFC 9126 §2 に従って足した PAR の口の URL も、改訂で外れていた**（#398。`RT-398.1`・`RT-371.2`）。**#397 は改訂を確かめずに、置き換えられた節を根拠に起票した**。
  **適合性テスト（Conformance Suite）も、改訂より古い規定で確かめていることがある**（#397・#398）
- [ ] **値が無いときに、検証を飛ばしていないか**（`nonce`・`aud`・署名など）
- [ ] **引き換えの値（`code`・`auth_req_id`・`device_code`）を、出したクライアントと照合してから、状態を返したり、記録を書き換え・消したりしているか。**
  **CIBA・Device は、照合の前に状態を返し、承認済みの記録と認可コードを消していた**ので、値を知る別のクライアントが先に引くと、正規のクライアントが結果を受け取れなかった（#387。`RT-387.1`・`.2`）。
  **トークンが出ないことだけでなく、正規のクライアントの続きが壊れないこと**まで見る
- [ ] 失効したトークン・使用済みのコードを、受けていないか。
  **同時に来た要求で、2 回使えないか**（読んでから使用済みにするのではなく、**使用済みにできた 1 つだけが引き換える**。#332）

### SAML2（`SamlProviders`）

- [ ] 署名の対象と、消費する要素の一致（XSW）
- [ ] リプレイ（`InResponseTo`・`ID`）、`Audience`、有効期限（`NotBefore` / `NotOnOrAfter`）
- [ ] **広告（メタデータ）と振る舞いが揃っているか**（`WantAuthnRequestsSigned="true"` を広告しながら、鍵を登録していない SP の署名の無い要求を通していた。#400。`RT-400.1`）。**テストが「通る」前提に頼っていないか**（要求を直に送る E2E の多くが、署名の無い要求を送っていた）
- [ ] **Redirect Binding の送り先の URL にクエリ文字列をつなぐとき、送り先が既にクエリを持っていないか**（SAML Bindings §3.4.4.1。**常に `?` でつないでいた**。#393。`AppendQueryTests`）。**同じ組み立てが、ID 連携の要求と IdP の役の応答の両方にあった**
- [ ] **`Audience` は SP の entityID か**（SAML Profiles §4.1.4.2）。**ACS URL を入れていた・ACS URL と照合していた**（#389。`RT-389.1`）。**IdP の役で入れる値と、SP の役で照合する値を、両方そろえて変える**（片方だけ変えると、自己テスト・ID 連携が通らない）
- [ ] **SP の役で送る署名した要求に、送り先の `Destination` を入れているか**（SAML Bindings §3.4.5.2・§3.5.5.2 の MUST）。
  **自己テストと ID 連携の `AuthnRequest` に入れていなかった**（Open棟梁 の従来の版。OpenTouryo#693 で `[Obsolete]`。#391。`RT-391.1`・`SA-6.1`）。
  **IdP の役で受けた要求の `Destination` を、受けた口の URL と照合しているか**（在れば照合し、違えば捨てる。SAML Core 3.2.1。署名した要求には必須）。
  **送る側だけ直して、受ける側を照合していなかった**（#392。`RT-392.1`・`.2`）。
  **OpenTouryo のアセンブリを更新したら、`CS0618`（`[Obsolete]`）の警告が増えていないかを見る** — **入れ替えで増えた警告は、上流が直し方を示している**
- [ ] **応答に入れる値のうち、外（要求を送る側・利用者）が決められるものの形を確かめているか。** **部品は値を文字列の置換で埋め込む**（Open棟梁 の `SAML2Bindings.CreateResponse`・`CreateAssertion`）。
  **要求の `ID`（`InResponseTo`）と、EmailAddress の形式の NameID（利用者のメアド）で、署名する応答の構造を変えられた**（#390。`RT-390.1`〜`.3`）。
  **要求から取った値は、署名の検証に失敗したエラー応答にも入る**ので、鍵を登録した SP でも当たる

### Web のセキュリティ（`Controllers`）

- [ ] CSRF（状態を変える要求）、同意の確認を飛ばせないか
- [ ] オープン リダイレクト、認可の確認（他人の資源に触れないか）
- [ ] **読めない入力で 500 にしないか。** NUL 文字を含むフォームは、**net10.0 だけが例外で断る**（#331）
- [ ] **預けた JSON（Request Object など）の値を、型を確かめずに `(string)` で読んでいないか。** **配列・オブジェクトは、預けた後の別の口（`/authorize`）で例外になる** — **PAR・`/ros` は `dpop_jkt`・`nonce`・`state` などの型を見ずに預かり、PAR そのものか `/authorize` が 500 になっていた**（#377。`RT-377.1`）。**預かる口で断り、読む側は例外にしない。** **1 つ見つけたら、同じ JSON から読むほかの値も見る**（本文は `dpop_jkt` だけを挙げていた）。**型を `JTokenType.String` だけで見ない** — 既定の読み方は、日付の形の文字列を `Date` にする（OpenTouryo#662。#377 の別モデルのレビュー。`RT-377.1`）。**預けて読み直す JSON は、日付に変えない読み方（`JwtUtil.TryParseObjectAsIs`）で読む** — **預けた `state` が `/authorize` の応答で書き換わっていた**（#403。`RT-403.1`）。**時差付きの値で測るなら、手元の機械と違う時差にする**（同じ時差では書き換わらない）

### DB（`Data`）

- [ ] パラメタ化できる値を、パラメタにしているか
- [ ] **3 方言（SQL Server・Oracle・PostgreSQL）と `mem` で、同じ意味になるか**
- [ ] **`mem` に無い制約（外部キーなど）に当たらないか。`mem` だけの通しでは見つからない**（#327）
- [ ] **`mem` は、利用者の物をすべての要求で共有する。** ストアの一覧（`MemoryStoreList`）の外で、ロックなしに書き換える一覧を足していないか（#325・#331）
- [ ] **外部キーの子の列に、その列が先頭のインデックスがあるか。無いと親の削除が全件走査になり、デッドロックする**（#329。`UserStoreDdlTests`）
- [ ] DDL を変えたなら、配備済みの DB への手順を書いたか
- [ ] **読んだ値で書き戻していないか。** 並行した要求の更新が消える、使い捨ての値を 2 回使える（#316）
- [ ] **読み取りの失敗を「無い」として返していないか。** パスワードの誤りと見分けが付かず、ロールを読めないままサインインできる（#331）。
  **投げ直すなら、DB が受け付けない入力（NUL 文字、列の幅を大きく超える値）で 500 にならないか。**
  **利用者に限らず、外から来た値（コード・トークン・`client_id`、画面のフォーム、管理画面の `key` など）で引く口すべて**である。
  **net48 版は、例外をエラー画面への 302 にする**ので、状態コードだけでは見つからない（ACCESS ログの `OnException` を見る）。
  Oracle は 4000 文字を超える文字列のパラメタを例外にする（`mem` には幅が無いので、`mem` の通しでは見つからない）。
  **ただし「無い」が「通す」になる口（使用済みの記録・失敗の数え）では、引かずに「無い」としない**（#331）
- [ ] **更新の結果を見ているか。競合で負けたとき、失敗のまま返していないか**（#331）。
  同じ利用者の行は、無関係な更新（サインインの数え、別の端末）でも書き換わる。**読み直して、変えた項目だけを当て直す**（`UpdateWithRetryAsync`）。
  **失敗を null で返す API**（`GenerateNewTwoFactorRecoveryCodesAsync`）**も、結果である**（#331）。
  **子の行を書いてから利用者の行を更新する API**（`AddLoginAsync`・`AddClaimAsync`・`RemoveLoginAsync`）は、**行は書けているのに競合で失敗を返す**（ID 連携がエラー画面で終わった。#331 の `RT-294.23`）

### 全般（汎用認証サイトの補足）

- [ ] **net48 と net10.0 で、同じ振る舞いになるか**（片方だけ直していないか）
- [ ] テストが変更した分岐を通っているかは、[`COVERAGE.md`](root/programs/Tests/COVERAGE.md) の手順で測り、HTML で行を見る
- [ ] 見つかった型の横展開は、別のエンドポイントに残っていないかで見る
- [ ] **テストが、時間の窓（ロックアウト・`max_age`・レート制限の窓・ポーリングの間隔）の中で終わる前提に立っていないか。**
  通しの負荷で応答が遅くなると落ちる（#325・#331）。**窓に対して、何往復を何秒で済ませる前提か**を見る。
  **打ち切りは回数ではなく時間で決める**（`RT-305.5`）。
  **窓を過ぎてから確かめた結果は、合否に使わず数え直す**（ロックアウト。`LockoutWindow`）
- [ ] **ブラウザのテスト（`Tests/WebUI`）で、操作の後に、待たない API（`CountAsync` など）で画面を読んでいないか。**
  **読み込みの状態の通知（`WaitForLoadStateAsync`・`WaitForURLAsync`）ではなく、測る要素が現れるのを待つ**（#325・#331。`UI-1.1`）

### レビュー役（汎用認証サイトの補足）

- **指摘の再現の方法**は、`RT-<Issue>` にできるかで書く
- **終了の条件**（`QUALITY.common.md` 4 節）を回数で決めないのは、#294 で、2 回目のほうが項目の多いファイルがあったため
- レビュー役を回すのは、[`AGENTS.md`](AGENTS.md)「完了の前に、別モデルのレビューを回す」。回し方は `QUALITY.common.md` 4 節「サブエージェントで回す」
- 見つけた問題がセキュリティの弱点なら、[`AGENTS.md`](AGENTS.md)「セキュリティの指摘は、公開される前に確認を取る」による

---

## 5. フィードバックの輪

- `QUALITY.common.md` 5 節のとおり。回帰テストの名前は「このリポジトリの値」（`RT-<Issue>`）
- `Found-By:` を導入の前のコミットへ遡って数えるなら、Wiki の集計で行う（コミットは書き換えない）

---

## 6. 計測

リリースごとに見る（Wiki の「開発基盤の KPI と KGI」の「AI 駆動開発の品質の指標」）。共通の指標は `QUALITY.common.md` 6 節。汎用認証サイトでは、次も見る。

- 品質マップの単位で、根拠の種類（**外部の仕様 / Issue / リポジトリの前提**）の割合（7 節。数え方は下の「根拠の種類」）
- 品質マップの単位で、E2E のカバレッジ（[`COVERAGE.md`](root/programs/Tests/COVERAGE.md)。**判定には使わない**）
- **適合性テストの、プランごとの PASSED・FAILED の数**（リリースの前に回したもの。2 節）と、**起票した不適合の数・直した数**。
  **FAILED には、自動では回せないモジュールと、1 つの不適合で止まったモジュールも含まれる**ので、数だけで比べず、仕分けた結果と並べて見る

### 根拠の種類（初回の基準。[`CountBasis.ps1`](root/CountBasis.ps1)。2026/11/01）

**E2E はサイトを外から叩くので、テストと名前空間は 1 対 1 に対応しない。** そのため、品質マップの名前空間ではなく、テストの群で数える。
外部の仕様と Issue の両方を挙げる根拠は、外部の仕様に数える。**根拠の内容が正しいかは、この数では分からない。**

| 群 | テスト | 外部の仕様 | うち節あり | Issue | リポジトリの前提 |
|---|---:|---:|---:|---:|---:|
| SM | 6 | 4（67%） | 4（100%） | 1（17%） | 1（17%） |
| TC | 20 | 20（100%） | 20（100%） | 0（0%） | 0（0%） |
| EX | 42 | 42（100%） | 42（100%） | 0（0%） | 0（0%） |
| RT | 361 | 278（77%） | 260（94%） | 83（23%） | 0（0%） |
| FA | 14 | 12（86%） | 9（75%） | 2（14%） | 0（0%） |
| 21 | 2 | 2（100%） | 2（100%） | 0（0%） | 0（0%） |
| SA | 22 | 20（91%） | 18（90%） | 2（9%） | 0（0%） |
| CN | 17 | 6（35%） | 4（67%） | 11（65%） | 0（0%） |
| UI | 1 | 0（0%） | 0 | 1（100%） | 0（0%） |
| 計 | 485 | 384（79%） | 359（93%） | 100（21%） | 1（0%） |

---

## 7. 期待値の根拠の書き方

**`TestReport` の `basis` に書く。** `basis` は必須の引数なので、有無ではなく**種類**を見る。
単体テスト（`Tests/UnitTests`）は `[Basis("...")]` に書く。**無いテストは `BasisRequiredTests` が落とす。**

```csharp
TestReport r = this.Report("EX-2.7",
    "何を確かめるテストか",
    "観点（何が満たされていれば良いのか）",
    "RFC 7009 §2.1 / #322");
```

- 根拠の種類（外部の仕様・Issue・リポジトリの前提）と書き方の例は `QUALITY.common.md` 7 節。外部の仕様は `RFC 7009 §2.1`、`OIDC Core 1.0 §3.1.2.1` のように**節まで書く**
- 導入のときの節番号の確認（2026/11/01）：節を挙げた 142 種のすべてと SAML の節について、原典に節があり、見出しがテストの題と合うかを見た。
  疑わしいものは本文まで読み、誤り 7 件を直した。**全件の本文を読んだわけではない**
- **`basis` を変えるのは期待値の変更**（3 節）

---

## 8. エージェント向けチェックリスト

共通の項目は `QUALITY.common.md` 8 節。汎用認証サイトでは、次も確かめる。

- [ ] テストを足したなら、判定できない値は `Observe` にしたか（2 節・7 節）
- [ ] テストの文面を変えたなら、`TESTCASES.md` を作り直したか（3 節）
- [ ] リスクが「高」の名前空間を `fixed` で変えたなら、`quality-reviewer` を回し、`Reviewed-with: quality-reviewer (<モデル ID>)` を書いたか（4 節）
- [ ] 適合性テストで見つかった不適合を直したなら、`fixed` の前に、そのプランを回したか（2 節）
