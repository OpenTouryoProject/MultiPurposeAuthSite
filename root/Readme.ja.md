# 汎用認証サイト — セットアップとビルド

**ここが、ビルドの入口です。**

汎用認証サイト（Multi-purpose Authentication Site）は、ASP.NET Identity と JSON Web Token（JWT）による
OAuth 2.0 / OpenID Connect の IdP および STS です。製品の概要は[リポジトリ直下の Readme.ja.md](../Readme.ja.md) を参照してください。

このファイルの英語版は[こちら](README.md)から。

本書は**環境を用意してビルドが通るまで**を扱います。
引数・判定基準・バッチごとの役割は各文書が一次情報で、ここには転記しません
（転記すると、両方を直さないかぎりズレます）。

- コーディング エージェントで開発する場合は、先に [AGENTS.md](../AGENTS.md) を読んでください。
- 手順だけを引きたい場合は [CHEATSHEET.md](CHEATSHEET.md) が早いです。

## 前提ツールのインストール

- **Visual Studio**（または MSBuild と .NET SDK）。
  MSBuild は `vswhere` で解決するため、**Community 以外（Professional / Enterprise / Build Tools）でも構いません**
  → [BUILDING.md](BUILDING.md) 5 節
- **.NET 10.0 SDK**。net10.0 版に要ります
- **IIS Express**。net48 版を動かすときだけ要ります（無ければ、その分のテストは Skip されます）

**`dotnet build` だけでは net48 版は建ちません** → [BUILDING.md](BUILDING.md) 10 節

DBMS は、ビルドには要りません。`UserStoreType` を `mem` にすればメモリ上のストアで動きます
→ [CONFIGURATION.md](CONFIGURATION.md) 7 節

## 初回の準備

### 1. OpenTouryo のアセンブリ（自動）

本リポジトリは Open棟梁 のアセンブリを参照してビルドします。
`.gitignore` 済みで clone 直後はありませんが、**ビルドが面倒を見ます。**

```powershell
cd root
.\1_BuildAll.ps1              # 無ければ取得してから建てる
.\1_BuildAll.ps1 -Libs Force  # Open棟梁 側を更新したとき、取り直す
.\1_BuildAll.ps1 -Libs None   # 取得しない
```

取得は `develop` の ZIP を取得してビルドし、`OpenTouryoAssemblies` へ複写します。
**取得の前に ZIP キャッシュ（`Temp.zip` / `Temp`）を消します**（古い版を掴み続けないため）。
取得が成功したら、そのキャッシュも片付けます（失敗したときは、原因を見るため残します）。

手で用意することもできます。`root\programs\3_BuildLibsAtOtherRepos.bat`（タグ `03-20`）を
実行するか、Open棟梁 を別途 clone してビルドし、`mpas_dev.bat` で複写します。

### 2. 設定ファイルを作る

雛形から複写して作ります。**どちらも `.gitignore` 済み**で、実際の資格情報を含みます。

| 雛形 | 作るもの |
|---|---|
| `programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\_appsettings.json` | `appsettings.json` |
| `programs\MultiPurposeAuthSite\MultiPurposeAuthSite\_app.config` | `app.config` |

中身の意味は [CONFIGURATION.md](CONFIGURATION.md)。**設定ファイルが無いと実行できません**
（ビルドは通ります）→ [BUILDING.md](BUILDING.md) 10 節

### 3. 証明書を配置する

`root\files\resource\X509` の pfx / cer を、設定ファイルが指すパスへ置きます
→ [CONFIGURATION.md](CONFIGURATION.md) 8 節

## プログラムのビルド

```powershell
cd root
.\1_BuildAll.ps1
```

`1_BuildAll.ps1` は、ビルド バッチ（`root\programs\*.bat`）を呼び、
**出力を解析して合否を出す**ラッパーです。バッチ自身は MSBuild の終了コードを伝播せず、
末尾で入力待ちになるため、そのままでは合否が取れません → [BUILDING.md](BUILDING.md) 2 節

| 見たいもの | 一次情報 |
|---|---|
| 引数（`-Only` `-List` `-Configuration` `-SkipClean` `-WarnDetail` など） | [BUILDING.md](BUILDING.md) 1 節 |
| 合否の判定基準（エラーと警告の扱い） | [BUILDING.md](BUILDING.md) 3 節 |
| どのバッチが何を建てるか | [BUILDING.md](BUILDING.md) 4 節 |
| 既知の警告 | [BUILDING.md](BUILDING.md) 8 節 |

**バッチを直接実行してもビルドできます。** 通しは `root\programs\0_ExecAllBat.bat`
（クリーン → net48 → net10.0）、個別は `10_MultiPurposeAuthSite*.bat` です。

**`Release` でも建ててください。** 構成を変えたときに、`Debug` でしか通らない状態になりがちです
→ [BUILDING.md](BUILDING.md) 5 節

## ビルド後の検証

ビルドと E2E テストは、`root` にあるスクリプトで行えます。**いずれも終了コードで合否が分かります。**

```powershell
cd root
.\0_RunAll.ps1          # 下記 2 本をまとめて実行
```

| スクリプト | 内容 |
|---|---|
| `1_BuildAll.ps1` | 全ビルド。エラーと警告を集約して判定する |
| `2_RunAllTests.ps1` | E2E テストを実行する。net10.0 版と net48 版の両方に同じテストを流す |

2 本は個別に実行することもできますが、**実行順は固定**です（テストは動いているサイトを叩くため、
ビルドが前提になります）。**ビルドが NG なら、テストは実行しません。**

**サイトの起動は既定で行います**（`-Launch` が既定で ON）。
起動し忘れると「全件 Skip」になり、合否として読めなくなるためです。
起動済みのサイトを使うなら `-Launch:$false`、net48 版を測らないなら `-NoNetFx` を渡します。

手順と判定基準は [TESTING.md](TESTING.md)（1 節 使い方 / 5 節 判定基準 / 8 節 前提条件）、
テストの構成と足し方は [programs/Tests/README.md](programs/Tests/README.md) を参照してください。

**ログは 1 か所に出ます。** `root\programs\Tests\E2ETests\Result`（`.gitignore` 済み）
→ [CHEATSHEET.md](CHEATSHEET.md) 2 節

## 文書の一覧

| 文書 | 内容 |
|---|---|
| [BUILDING.md](BUILDING.md) | ビルドの実行と判定 |
| [TESTING.md](TESTING.md) | E2E テストの実行と判定 |
| [CONFIGURATION.md](CONFIGURATION.md) | 設定ファイルの扱い |
| [CODING.md](CODING.md) | ファイル形式ごとの約束（改行コード、ヘッダ、bat / ps1 の書き方） |
| [CHEATSHEET.md](CHEATSHEET.md) | 手順だけを並べたもの |
| [../AGENTS.md](../AGENTS.md) | 開発エージェントが守ること |
| [../Contributing.ja.md](../Contributing.ja.md) | 投稿規約（コメント量、git-flow、PR の粒度） |
| [programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md](programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md) | IdP としての適合性と、対応状況の一覧 |
