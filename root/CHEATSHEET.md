# チートシート

**手順だけを並べたもの。** 理由・詳細・落とし穴の背景は、各項のリンク先が一次情報。

> ここは**意図的に二重管理**している。手順は「思い出すため」に転記し、
> **判断が要ることは書かない。** 迷ったらリンク先を読むこと。

---

## 0. ワンライナー集

**断りの無いものは `root` で実行する**（`cd root`）。詳しくは右端の節。

### 検証する

| やりたいこと | コマンド | 節 |
|---|---|---|
| 全部を通しで（ビルド → E2E。両版を起動する） | `.\0_RunAll.ps1` | 1 |
| ビルドだけ（両版） | `.\1_BuildAll.ps1` | 1 |
| 片方だけビルドする（クリーンを省いて速く） | `.\1_BuildAll.ps1 -Only net10.0 -SkipClean` | 1 |
| 指定できるステップ名を見る | `.\1_BuildAll.ps1 -List` | 1 |
| 警告の内訳を出す（**警告が増えていないかを見る**） | `.\1_BuildAll.ps1 -Only net -SkipClean -WarnDetail` | [`BUILDING.md`](BUILDING.md) 3 節 |
| OpenTouryo のアセンブリを取り直す | `.\1_BuildAll.ps1 -Libs Force` | 5 |
| E2E を両版で通す（サイトを起動 → テスト → 停止） | `.\2_RunAllTests.ps1 -Launch` | 1 |
| 起動済みのサイトを叩く | `.\2_RunAllTests.ps1` | 1 |
| 一部だけ回す | `.\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RequestObjectTests"` | 1 |
| net10.0 版だけ起動して回す（net48 版の分は Skip） | `.\2_RunAllTests.ps1 -Launch -NoNetFx` | [`TESTING.md`](TESTING.md) 1 節 |
| ブラウザで測るもの（`UI-n.n`）を外す | `cd programs\Tests; .\test.ps1 -Launch -NoWebUI` | 1 |
| **テストを足した・変えた**ので、テストケースの原本を作り直す | `.\2_RunAllTests.ps1 -Launch -UpdateTestCases` | [`TESTING.md`](TESTING.md) 10 節 |
| サイトのコード カバレッジを測る | `.\2_RunAllTests.ps1 -Launch -Coverage` | [`TESTING.md`](TESTING.md) 1 節 |

### 特別な構成で回す（`-Filter` と併せて使う。`-UpdateTestCases` は付けない）

| やりたいこと | コマンド | 節 |
|---|---|---|
| 有効期限（`RT-188`）を、寿命を短くして回す | `.\2_RunAllTests.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"` | 1 |
| DPoP の nonce（`RT-311.13` / `.14`）を回す | `.\2_RunAllTests.ps1 -Launch -DPoPNonce -Filter "FullyQualifiedName~DPoPNonceTests"` | [`TESTING.md`](TESTING.md) 5 節 |
| Implicit を閉じた配備（`RT-314`）を回す | `.\2_RunAllTests.ps1 -Launch -NoImplicit -Filter "FullyQualifiedName~ImplicitDisabledTests"` | [`TESTING.md`](TESTING.md) 5 節 |
| net48 版でも mTLS（`FA-6`）を回す（証明書の準備・後片付けが要る） | `.\SetupNetFxMtls.ps1 -Action Prepare` → （管理者）`-Action Trust` → `.\2_RunAllTests.ps1 -Launch -NetFxMtls` → （管理者）`-Action Cleanup` | 1 |
| 証明書の準備ができているかを見る | `.\SetupNetFxMtls.ps1 -Action Check` | 1 |
| DB のストアで回す（`sql` / `ora` / `npg`。`Container\Store\` の DB コンテナを起動・停止する） | `.\2_RunAllTests.ps1 -Launch -UserStoreType sql` | [`TESTING.md`](TESTING.md) 1 節 |
| 別ホストの DB を指す（`Container\Store\` のコンテナを起動しない） | `.\2_RunAllTests.ps1 -Launch -UserStoreType sql -NoStoreContainer -ConnectionString <接続文字列>` | [`TESTING.md`](TESTING.md) 1 節 |

### テストのスタブ（MPAS を IdP として起動する。`Container\Stub\` で実行する）

**Open棟梁 などのクライアント（RP / SP）のテストから使う。** 流れと設定値は 10 節。

| やりたいこと | コマンド | 節 |
|---|---|---|
| **最初に 1 回**（と、MPAS を更新したとき）: publish と証明書の書き出し | `cd ..\Container\Stub; .\1_PublishStub.ps1` | 10.1 |
| パラメタのファイルを作る（写して直す） | `copy .env.sample my-stub.env` | 10.2 |
| **起動する** | `docker compose --env-file my-stub.env up -d --build` | 10.1 |
| 起動を確かめる（200 と JSON が返ればよい） | `curl.exe -s https://localhost:44310/.well-known/openid-configuration` | 10.1 |
| **まっさらに戻す**（利用者・同意・セッションが消える） | `docker compose --env-file my-stub.env restart` | 10.1 |
| **止めて消す** | `docker compose --env-file my-stub.env down` | 10.1 |
| ログを見る | `docker compose --env-file my-stub.env logs -f`（アプリのログは `Container\Stub\logs\`） | 10.6 |
| 証明書を作り直す（期限切れなど） | `.\1_PublishStub.ps1 -NewCertificate` | 10.1 |
| **他のリポジトリから起動する**（パラメタのファイルは使う側に置く） | `docker compose -f C:\MultiPurposeAuthSite\Container\Stub\docker-compose.yml --env-file <絶対パス> up -d --build` | 10.5 |
| 2 つ目を同時に起動する（`.env` のポート・URL・`iss` を変える） | `docker compose -p mpas-stub2 --env-file stub2.env up -d --build` | 10.5 |
| 動いているスタブを見る | `docker ps --filter "label=com.docker.compose.project=mpas-stub"` | — |

### E2E 用のコンテナ（`Container\E2E\` / `Container\Store\`。このリポジトリのテストが使う）

| やりたいこと | コマンド | 節 |
|---|---|---|
| ID 連携の IdP 群（上流・上流 2・下流）と jwks を作り直して起動する（publish → `up -d --build`） | `..\Container\E2E\1_DockerComposeUp.bat` | [`TESTING.md`](TESTING.md) 1 節 |
| IdP 群を**一旦止める**（`start` で戻せる） | `cd ..\Container\E2E; docker compose stop` | — |
| IdP 群を**消す** | `..\Container\E2E\2_DockerComposeDown.bat` | — |
| E2E 用の DB に DDL を流し込む（DB は起動しない。通しでは `test.ps1` が起動・停止する） | `..\Container\Store\1_DockerComposeUp.bat` | [`TESTING.md`](TESTING.md) 1 節 |
| DB を**一旦止める**（コンテナもボリュームも残す。`start` で戻せる） | `cd ..\Container\Store; docker compose --profile postgres --profile sqlserver --profile oracle stop` | — |
| DB を**消す**（**`down -v` でボリュームも消える**。E2E 用なので作り直せる） | `..\Container\Store\2_DockerComposeDown.bat` | — |
| 動いているコンテナを見る | `docker ps --filter "label=com.docker.compose.project=mpas-e2e"`（DB は `mpas-store`） | — |

### その他

| やりたいこと | コマンド | 節 |
|---|---|---|
| 3 つの RDB の DDL を突き合わせる（差があれば終了コード 1） | `.\CompareDdl.ps1` / `.\CompareDdl.ps1 -Detail` | [`CONFIGURATION.md`](CONFIGURATION.md) 7 節 |
| 失敗したビルド・テストのログを読む | `programs\Tests\E2ETests\Result` の `net48.log` / `net10_0.log` / `E2ETests.log` / `MpasSite.out.log` | 2 |
| net10.0 版を Kestrel で起動する（**先に 4 節の環境変数を設定する**。ルート URI と待ち受け URL を揃えるため） | `cd programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore; dotnet run --urls https://localhost:44300` | 4 |
| 未コミットの変更を見る（**報告の直前に取り直す**） | `git status --porcelain` | [`../AGENTS.md`](../AGENTS.md) |
| Issue を見る | `gh issue view <番号> --repo OpenTouryoProject/MultiPurposeAuthSite` | 7 |

---

## 1. 検証（変更したら必ず）

```powershell
cd root
.\0_RunAll.ps1                  # ビルド → テスト
```

個別に回す。

```powershell
.\1_BuildAll.ps1                # ビルドだけ
.\1_BuildAll.ps1 -List          # 対象の一覧
.\1_BuildAll.ps1 -Only net10.0 -SkipClean
.\1_BuildAll.ps1 -WarnDetail    # 警告の内訳

.\2_RunAllTests.ps1 -Launch     # サイトを起動 → テスト → 停止
.\2_RunAllTests.ps1             # 起動済みのサイトを叩く
```

1 件だけ試す。

```powershell
cd root\programs\Tests
.\test.ps1 -Launch -Filter "FullyQualifiedName~RequestObjectTests"
```

合否の読み方 → [`BUILDING.md`](BUILDING.md) 3 節 / [`TESTING.md`](TESTING.md) 5 節

### 有効期限（`RT-188`）は、寿命を短くして回す

```powershell
cd root
.\2_RunAllTests.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"
```

**`-Filter` と併せて使う**（寿命が短いので他のテストは落ちる）。**`-UpdateTestCases` は付けない**（原本が壊れる）。

### ブラウザで測るもの（`UI-n.n`）だけを回す

```powershell
cd root\programs\Tests
.\test.ps1 -Launch -NoNetFx -Filter "FullyQualifiedName~Tests.WebUI"
```

**既定の通しにも入っている**（**ブラウザが無ければ Skip** する。動かしたくなければ `-NoWebUI`）。
**ブラウザの入れ方** : `bin\Debug\net10.0\playwright.ps1 install chromium`、または Chrome / Edge。
詳細 → [`TESTING.md`](TESTING.md) 5 節「`UI-n.n`（ブラウザで測るもの）」

### mTLS（`FA-6`）を net48 版でも回す

```powershell
cd root
.\SetupNetFxMtls.ps1 -Action Prepare   # 通常の PowerShell
.\SetupNetFxMtls.ps1 -Action Trust     # **管理者**
.\2_RunAllTests.ps1 -Launch -NetFxMtls # 通常の PowerShell
.\SetupNetFxMtls.ps1 -Action Cleanup   # **管理者**。必ず行う
```

**`Prepare` は管理者で実行しない**（証明書が別の利用者のストアに入り、テストから見えない）。
詳細 → [`TESTING.md`](TESTING.md) 5 節「mTLS（`FA-6`）と、net48 版の `-NetFxMtls`」
背景 → [`TESTING.md`](TESTING.md) 5 節

### net48 版の mTLS（`FA-6`）だけ、準備が要る

**net10.0 版は、通常の通しで測っている**（`-Launch` がテスト専用のフックを読ませる）。
**net48 版は、証明書を用意したうえで `-NetFxMtls` を付けたときだけ測る。**

1. 準備（**管理者の PowerShell**。テスト用 CA と証明書 2 枚を作り、CA を信頼されたルートへ）

```powershell
$ca = New-SelfSignedCertificate -Subject 'CN=MPAS E2E Test CA' `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -TextExtension @('2.5.29.19={critical}{text}ca=true') `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(7)

foreach ($cn in 'mpas-e2e-mtls-client', 'mpas-e2e-mtls-other') {
    New-SelfSignedCertificate -Subject "CN=$cn" -Signer $ca `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(7) | Out-Null
}

$cer = Join-Path $env:TEMP 'mpas-e2e-ca.cer'
Export-Certificate -Cert $ca -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Remove-Item $cer
```

2. 実行（通常の PowerShell でよい）

```powershell
cd root
.\2_RunAllTests.ps1 -Launch -NetFxMtls
```

3. 後片付け（**管理者の PowerShell**。**必ず行う。**信頼されたルートに残さない）

```powershell
$subjects = 'CN=MPAS E2E Test CA', 'CN=mpas-e2e-mtls-client', 'CN=mpas-e2e-mtls-other'
Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\My |
    Where-Object { $subjects -contains $_.Subject } | Remove-Item
```

**5.1 / 7 のどちらでも回る**（実測済み。2026/09/23）。背景 → [`TESTING.md`](TESTING.md) 5 節

## 2. ログの置き場所

**すべて 1 か所に出る。** `root\programs\Tests\E2ETests\Result`（`.gitignore` 済み）。

| ファイル | 中身 |
|---|---|
| `net48.log` / `net10_0.log` / `Clean__*.log` | ビルド（ステップごと。`-v:d` の全出力） |
| `E2ETests.log` | `dotnet test` の画面出力 |
| `E2ETests.trx` | テスト結果の XML。**合否はこれで判定する** |
| `MpasSite.out.log` / `MpasSite.err.log` | `-Launch` で起動したサイトの出力 |

**「サイトが応答しません」と出たら、まず `MpasSite.out.log`。**
`Now listening on: ...` があればサイトは正常で、原因は叩く側にある。

保存先は `-OutputDir` で変えられる。実行の最後にもパスが表示される。

> **クリーンすると、前回の `*.log` は消える。**
> `2_DeleteFile.bat` が `root\programs` 配下の `*.log` を再帰削除するため
> （`.trx` は残る）。**失敗したログを読む前に、建て直さないこと。**

## 3. バッチを直接使う

```
root\programs\0_ExecAllBat.bat             通し（クリーン → net48 → net10.0）
root\programs\10_MultiPurposeAuthSite.bat      net48 だけ
root\programs\10_MultiPurposeAuthSiteCore.bat  net10.0 だけ
root\programs\1_DeleteDir.bat              packages / obj / bin ... を消す
root\programs\2_DeleteFile.bat             *.suo / *.user / *.bak ... を消す
```

構成 → [`BUILDING.md`](BUILDING.md) 4 節

## 4. サイトを起動する

Visual Studio（IIS Express）が素直。既定は `https://localhost:44300/MultiPurposeAuthSite`。

コマンドラインから Kestrel で。

```
cd root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore
set ASPNETCORE_ENVIRONMENT=Development
set appSettings__OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44300
set appSettings__OAuth2ClientEndpointsRootURI=https://localhost:44300
dotnet run --urls https://localhost:44300
```

テストのついでに立てるなら、**2 つとも立ててくれる。**

```
root\programs\Tests\test.ps1 -Launch     net10.0 : 44300 / net48 : 44302
```

**構成のルート URI と待ち受け URL を揃えること。https で動かすこと。**
理由 → [`CONFIGURATION.md`](CONFIGURATION.md) 5 節

## 5. 初回の準備

```
1. OpenTouryo のアセンブリ
   4. のビルドで自動取得される（無ければ取得する）
   取り直す  : cd root && .\1_BuildAll.ps1 -Libs Force
   手で入れる: root\programs\3_BuildLibsAtOtherRepos.bat
               （または OpenTouryo を clone してビルドし、mpas_dev.bat で複写）

2. 設定ファイルを作る（どちらも .gitignore 済み）
   programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\_appsettings.json → appsettings.json
   programs\MultiPurposeAuthSite\MultiPurposeAuthSite\_app.config              → app.config

3. 証明書を配置する
   root\files\resource\X509 → 設定ファイルのパスへ

4. 建てる
   cd root && .\1_BuildAll.ps1
```

詳細 → [`CONFIGURATION.md`](CONFIGURATION.md)

## 6. コードを書く前に

| 見るもの | 場所 |
|---|---|
| 投稿規約（コメント量、git-flow、PR の粒度） | [`../Contributing.ja.md`](../Contributing.ja.md) |
| エージェント固有の制約 | [`../AGENTS.md`](../AGENTS.md) |
| ファイル形式ごとの約束 | [`CODING.md`](CODING.md) |
| 領域ごとの構成 | 各フォルダの `ANALYSIS.md` |
| 適合上の穴の一覧 | [`programs/ANALYSIS-IdP.md`](programs/ANALYSIS-IdP.md) |
| 本番へ切り替えるときに見るもの | [`CONFIGURATION.md`](CONFIGURATION.md) 11 節 |

**ファイル ヘッダの更新者名は、Claude Code なら「玄人 幸道」。**

## 7. GitHub

```
gh issue list   --repo OpenTouryoProject/MultiPurposeAuthSite
gh issue view   <番号> --repo OpenTouryoProject/MultiPurposeAuthSite
gh issue create --repo OpenTouryoProject/MultiPurposeAuthSite --title <title> --body-file <path>
gh issue comment <番号> --repo OpenTouryoProject/MultiPurposeAuthSite --body-file <path>
```

**エージェントは、投稿前に文面を提示して承認を得る。** 本文は `--body-file` で渡す。
テンプレート（`.github/ISSUE_TEMPLATE/`）は `--body-file` と併用しても効かないので、
**読んで、その構成に沿って書く。**

## 8. よく踏む落とし穴

| 症状 | 原因 | 見るもの |
|---|---|---|
| net48 が「パッケージがありません」 | `packages` を消した。`packages.config` は `nuget.exe restore` が要る | [`BUILDING.md`](BUILDING.md) 6 節 |
| net48 だけ「型が無い」 | `NetFxLibrary.csproj` に `<Compile Include>` を足し忘れた | [`CODING.md`](CODING.md) 2 節 |
| 片方の構成だけコンパイルが通らない | `DefineConstants` に条件シンボルを書き落とした | [`CODING.md`](CODING.md) 2 節 |
| `-Only` で片方だけ建てると復元がおかしい | `CommonLibrary` の `obj` は 2 つの csproj で共有 | [`BUILDING.md`](BUILDING.md) 7 節 |
| 自己テスト（FAPI2 / CIBA）が HTTP 500 | 待ち受け URL と構成のルート URI が違う | [`CONFIGURATION.md`](CONFIGURATION.md) 5 節 |
| http だと認可でエラー画面 | Cookie が `SameSite=None`。http では保持されない | [`CONFIGURATION.md`](CONFIGURATION.md) 5 節 |
| テストが全件 Skip なのに緑に見える | サイトが起動していない。**成功 0 件は NG にしてある** | [`TESTING.md`](TESTING.md) 5 節 |
| **net10.0 でログインはできるのに保護された画面へ進めない** | **前の起動の認証クッキーが残っている**（下の注記） | この節の下 |
| **画面が例外になる（`[Display]` を付けた項目）** | `.resx` に足して **`.Designer.cs` を直していない**。実行時に反射で探すので、**ビルドでは分からない** | [`CODING.md`](CODING.md) 2 節 |
| 差分がファイル全体になった | 改行コードを変えた（CRLF / LF が混在している） | [`CODING.md`](CODING.md) 3 節 |
| bat で `'xxx' は…認識されていません` | 非 ASCII による解析ずれ | [`CODING.md`](CODING.md) 4 節 |
| ps1 が 5.1 で落ちる / 表がずれる | BOM 無し、または 7 専用の引数、`Format-Table` | [`CODING.md`](CODING.md) 5 節 |
| `*.bak` の控えが消えた | `2_DeleteFile.bat` の削除対象 | [`BUILDING.md`](BUILDING.md) 10 節 |

### 古い認証クッキーが残っていると、ログインできなくなる（net10.0）

**症状**: ログインの POST は **302**（＝認証は成功している）のに、
`[Authorize]` の画面（`/authorize`、`/Manage/Index` など）でログイン画面に戻される。

**原因**: 前の起動で発行された `.AspNetCore.Identity.Application` が残っている。
**`UserStoreType = mem` では、デバッグを停止・再開するたびに利用者が消え、
Data Protection の鍵も作り直される**ので、古いクッキーはもう照合できない。

**直し方**: F12 → Application → Storage → **「Clear site data」**。

**測れない理由を知っておくこと。**

- **net48 版では起きない。** 別プロセス・別名のクッキー（`.AspNet.ApplicationCookie`）
- **E2E でも起きない。** 毎回まっさらな `CookieContainer` で始めるうえ、
  **`HttpClient` は `SameSite` / `Secure` の規則を適用しない**。
  **ブラウザでしか出ない不具合は、E2E が緑でも残る**

> **ブラウザに古い状態が残っていて、コードは正しいのに動かない**類は、
> 認証デバイス側でも起きている（[`programs/authentication_device/CHEATSHEET.md`](programs/authentication_device/CHEATSHEET.md) 7 節）。
> **まず Clear site data を試す。**

## 9. エージェントとして守ること

**一次情報は [`../AGENTS.md`](../AGENTS.md)。** ここは要点だけ。

- **git 操作をしない。** `add` / `commit` / `push` / `checkout` / `switch` / `branch` / `reset` / `restore` / `stash`
  - 参照系（`status` / `diff` / `log` / `show` / `ls-files` / `blame`）は自由
- **状態を報告する直前に、必ず取り直す。** 前のターンの出力や記憶から書かない
- **GitHub への投稿は、文面を提示して承認を得てから。** 投稿後は URL を報告する
- **秘密を転記しない。** 設定の変更は雛形側に書く
- **回さなかった検証は、「回していない」と報告する。** どこまで回すかの目安は [`../AGENTS.md`](../AGENTS.md)
- ヘッダの更新者は **「玄人 幸道」**

## 10. テストのスタブとして MPAS を使う（`Container\Stub\`）

**Open棟梁 などのクライアント（RP / SP）のテストで、相手の IdP として MPAS を起動する。**
**中身は net10.0 版の MPAS そのもの**（応答を偽装するスタブではない）。OAuth2 / OIDC / SAML2 の IdP として動く。
一次情報 → [`../Container/Stub/README.md`](../Container/Stub/README.md)

**前提** : Docker（compose v2）、.NET 10 SDK、`C:\root\files\resource`（[`Readme.ja.md`](Readme.ja.md) の手順）、
OpenTouryo のアセンブリ（`.\1_BuildAll.ps1` が取得する）。

### 10.1 流れ

```powershell
cd Container\Stub                                     # リポジトリのルートから
.\1_PublishStub.ps1                                   # 最初に 1 回（MPAS を更新したら、もう一度）
copy .env.sample my-stub.env                          # パラメタ（10.2）
copy appsettings.Stub.sample.json my-stub.json        # クライアントの登録（10.3）。my-stub.env の STUB_SETTINGS で指す
docker compose --env-file my-stub.env up -d --build   # 起動
curl.exe -s https://localhost:44310/.well-known/openid-configuration   # 200 と JSON が返ればよい

# ……ここでクライアントのテストを回す（10.4 の値を RP / SP に設定する）……

docker compose --env-file my-stub.env restart         # まっさらに戻す（テストの間で状態を消したいとき）
docker compose --env-file my-stub.env down            # 止めて消す
```

- **自分のファイルは `my-` で始める**（`.gitignore` 済み。テスト用の秘密を書いてもコミットされない）
- **状態は残らない**（`UserStoreType=mem`）。**再起動で、利用者・同意・セッション・管理画面で足した登録が消える**
- **`--env-file` は、どのコマンドにも同じものを付ける**（付けないと既定値で解釈される）
- **MPAS のコードを更新したら、`1_PublishStub.ps1` からやり直す**（`--build` でイメージに入る）
- **証明書はホストの開発用証明書**なので、同じホストのテストなら警告なしで信頼される。作り直すなら `-NewCertificate`

### 10.2 パラメタ（`.env`）

**書いていないキーは既定値になる。** **相対パスは `Container\Stub\` から見たもの。**

| キー | 既定 | 変えるとき |
|---|---|---|
| `STUB_PORT` | `44310` | ポートが塞がっているとき・2 つ目を起動するとき |
| `STUB_PUBLIC_URL` | `https://localhost:44310` | **`STUB_PORT` を変えたら、必ずこれも変える** |
| `STUB_ISSUER` | `https://localhost:44310` | **RP の期待する `issuer` に合わせる** |
| `STUB_SETTINGS` | `./appsettings.Stub.sample.json` | **自分のクライアントを登録した JSON を指す**（10.3） |
| `STUB_ADMIN_UID` / `STUB_ADMIN_PWD` | テスト用の値 | 管理画面を使うとき |
| `STUB_TEST_USER_PWD` | テスト用の値 | テスト利用者のパスワードを変えるとき |
| `STUB_LOCKDOWN_TEST_ENDPOINTS` | `false` | 自己テストの画面などを閉じるなら `true` |
| `STUB_CERT_DIR` / `STUB_CERT_ENV_FILE` | `./cert` / `./cert/cert.env` | 自分の証明書を使うとき（README 4 節） |
| `STUB_RESOURCE_DIR` | `C:/root/files/resource` | リソースを別の場所に置いたとき |

**値はテスト専用にすること**（管理者・テスト利用者・`client_secret`）。

### 10.3 クライアントを登録する（JSON）

**`appsettings.json` と同じ書き方。** 雛形の値に重ねて効き、**書いたキーだけが変わる。**

```json
{
  "appSettings": {
    "OAuth2ClientsInformation": {
      "57ab0000000000000000000000000001": {
        "client_secret": "<テスト用の秘密>",
        "redirect_uri_code": "https://localhost:5001/signin-oidc",
        "redirect_uri_token": "-",
        "client_name": "MyTestRP"
      }
    }
  }
}
```

| 項目 | 書くこと |
|---|---|
| キー（`client_id`） | **32 桁の 16 進** |
| `redirect_uri_code` | 認可コード フローの戻り先。**RP の値と 1 文字も違ってはならない** |
| `redirect_uri_token` | Implicit の戻り先（使わなければ `-`） |
| `redirect_uri_saml` | SAML2 の ACS（使わなければ書かない） |
| `client_name` | 名前（**他のクライアントと重ねない**） |

**既存の `appsettings.json` を丸ごと渡してもよい。** `.env` に、そのパスを書く。

```
STUB_SETTINGS=C:/MultiPurposeAuthSite/root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json
```

**公開 URL・`iss`・管理者は JSON では変えられない**（環境変数の方が強い）。**`.env` で変える。**
**`UserStoreType`（常に `mem`）・リソースのパス・`DataProtectionKeyPath` も、JSON に書いても変わらない**（README 3 節）。

### 10.4 RP / SP に設定する値

| 項目 | 値（既定のとき） |
|---|---|
| Authority / Issuer | `https://localhost:44310`（`STUB_ISSUER`） |
| Discovery | `https://localhost:44310/.well-known/openid-configuration`（**各エンドポイントはここから引く**） |
| `client_id` / `client_secret` | 10.3 で登録した値 |
| `redirect_uri` | 10.3 で登録した値と同じもの |
| サインインする利用者 | `super_tanaka@example.com` / `tanaka@example.com`（パスワードは `STUB_TEST_USER_PWD`） |

### 10.5 他のリポジトリから使う・複数起動する

```powershell
# **パラメタのファイルは、使う側のリポジトリに置いてよい。** その中のパスは絶対パスで書く
docker compose -f C:\MultiPurposeAuthSite\Container\Stub\docker-compose.yml --env-file C:\work\my-repo\mpas-stub.env up -d --build
docker compose -f C:\MultiPurposeAuthSite\Container\Stub\docker-compose.yml --env-file C:\work\my-repo\mpas-stub.env down

# **同じホストで 2 つ目**: -p でプロジェクト名を、.env で STUB_PORT / STUB_PUBLIC_URL / STUB_ISSUER を分ける
docker compose -p mpas-stub2 --env-file stub2.env up -d --build
docker compose -p mpas-stub2 --env-file stub2.env down
```

**E2E 用のコンテナ（44301〜44305）とは、ポートもプロジェクト名も別**なので、同時に動かせる。

### 10.6 困ったとき

| 症状 | 原因・直し方 |
|---|---|
| `up` が「port is already allocated」 | **ポートが使われている。** `STUB_PORT` と `STUB_PUBLIC_URL` を変える |
| RP が「issuer が違う」と言う | **`STUB_ISSUER` が RP の期待と違う**（末尾の `/` の有無も見る） |
| 認可でエラー画面になる | **`redirect_uri` が登録値と違う**（10.3）。または `client_id` が 32 桁の 16 進でない |
| トークンの取得が 401 | **`client_secret` が違う** |
| サインインで画面に戻される | **パスワードが `STUB_TEST_USER_PWD` と違う** |
| 別のコンテナで動く RP から届かない | **`localhost:44310` はそのコンテナ自身を指す**（証明書の名前も合わない）。README 6 節 |
| MPAS を直したのに振る舞いが変わらない | **`1_PublishStub.ps1` を回していない**（`--build` だけでは古い成果物が入る） |
| 起動直後に応答しない | **起動中。** `docker compose --env-file my-stub.env logs -f` で `Now listening on` を待つ |
| 原因が分からない | `docker compose --env-file my-stub.env logs`、アプリのログは `Container\Stub\logs\` |

**net48 版の振る舞いは再現しない**（中身は net10.0 版）。**任意のエラー応答は返せない**（本物の IdP なので、同意の拒否・`prompt=none`・期限切れなど、自然に出るものだけ）。
