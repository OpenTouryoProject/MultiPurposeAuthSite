# チートシート

**手順だけを並べたもの。** 理由・詳細・落とし穴の背景は、各項のリンク先が一次情報。

> ここは**意図的に二重管理**している。手順は「思い出すため」に転記し、
> **判断が要ることは書かない。** 迷ったらリンク先を読むこと。

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
