# CODING.md — コーディング規約

対象: `root/programs` 配下（C# / bat / ps1 / Markdown）
配置: `root`

**既存コードに合わせること。**

> **一次情報は本書ではない。**
>
> | 内容 | 一次情報 |
> |---|---|
> | コメント量、クロスコンパイル方針、git-flow、PR の粒度 | [`../Contributing.ja.md`](../Contributing.ja.md) |
> | エージェント固有の制約（git 操作、GitHub 操作、秘密の扱い） | [`../AGENTS.md`](../AGENTS.md) |
> | 各領域の構成と落とし穴 | 各フォルダの `ANALYSIS.md` |
>
> 本書は、そこに書かれていない**ファイル形式ごとの約束**を扱う。

---

## 1. ファイル ヘッダ

`.cs` の冒頭は、Apache License のブロックとクラス ヘッダを持つ。**新規追加時も付ける。**

```csharp
//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
// ...
#endregion

//**********************************************************************************
//* クラス名        ：CmnIdToken
//* クラス日本語名  ：CmnIdToken
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/02/12  西野 大介         新規
//*  2026/09/07  玄人 幸道         nonce無しでもid_tokenを発行するよう修正（#183）
//**********************************************************************************
```

**変更履歴はヘッダの履歴だけ継続する**（`Contributing.ja.md`）。
コード中に「修正の開始・終了」を書かない。

### 更新者名

| 変更した人 | 「更新者」に書く名前 |
|---|---|
| メンテナ | 西野 大介 |
| **Claude Code（エージェント）** | **玄人 幸道** |

**既存行の名前を流用しない。** 誰が入れた変更かを後から追えるようにするため。
エージェントの作業と人の作業を混ぜて記録すると、レビューの重み付けができなくなる。

「玄人 幸道」は「西野 大介」と**表示幅が同じ**なので、
既存行のパディング（名前の後ろに半角空白 9 個）をそのまま使えば桁が揃う。

Git のコミット著者は人であり、これとは別。**エージェントは git 操作をしない**（`AGENTS.md`）。

## 2. クロスコンパイル

**net48 と net10.0 は別系列**なので、条件付きコンパイルで分ける。

```csharp
#if NETFX
    // net48
#else
    // net10.0
#endif
```

| シンボル | 定義するプロジェクト | 使用箇所（`CommonLibrary`） |
|---|---|---|
| `NETFX` | `NetFxLibrary.csproj` | `#if NETFX` が 71 箇所 |
| `NETCORE` | `NetCoreLibrary.csproj` | `#if NETCORE` が 5 箇所 |

**`#if NETFX` を主に使う。** `#if NETCORE` は、Core にしか無いものを足すときだけ。

### ソースの出し入れは csproj が違う

| | 形式 | ファイルの指定 |
|---|---|---|
| `NetFxLibrary.csproj` | 旧形式 | **`<Compile Include>` を 1 本ずつ明記**（84 個） |
| `NetCoreLibrary.csproj` | SDK 形式 | 既定で全部入り、**`<Compile Remove>` で除外** |

**ファイルを追加したら、両方に反映が要る。**
`NetFxLibrary.csproj` に `Include` を足し忘れると、
net10.0 では通るのに net48 でだけ「型が無い」になる。

### 構成ごとにシンボルを書き落とさない

**`DefineConstants` は構成（Debug / Release）ごとに別々に書く。** 片方に書き忘れられる。

```xml
<PropertyGroup Condition=" '$(Configuration)|$(Platform)' == 'Debug|AnyCPU' ">
  <DefineConstants>TRACE;DEBUG;NETFX</DefineConstants>
<PropertyGroup Condition=" '$(Configuration)|$(Platform)' == 'Release|AnyCPU' ">
  <DefineConstants>TRACE;NETFX</DefineConstants>
```

> **実際に踏んだ。** `NetFxLibrary.csproj` の Release に `NETFX` が無く、
> `#else`（Core 側）が採られてコンパイルが通らなかった。
>
> ```
> Co/Config.cs(49,28): error CS0234: 'Configuration' が名前空間 'Microsoft.Extensions' に存在しません
> Data/CmnUserStore.cs(59,17): error CS0234: 'AspNetCore' が名前空間 'Microsoft' に存在しません
> ```
>
> ビルド バッチが `BUILD_CONFIG=Debug` 固定だったため、長く露見しなかった。
> `1_BuildAll.ps1 -Configuration Release` を入れて初めて出た。**修正済み。**

`CommandLineTools` の net 版は、Debug / Release の両方に `NET` を持っている。そちらが手本。

## 3. 改行コードは混在している

**`root/programs` の `.cs` は、ファイルごとに CRLF と LF が混ざっている。**

| 例 | 改行 |
|---|---|
| `CommonLibrary/TokenProviders/CmnAccessToken.cs` | CRLF |
| `CommonLibrary/TokenProviders/CmnIdToken.cs` | CRLF |
| `CommonLibrary/TokenProviders/CmnEndpoints.cs` | **LF** |
| `MultiPurposeAuthSiteCore/.../AccountController.cs` | **LF** |

**変えてはならない。** 改行を変えると git がファイル全体を差分として扱い、レビューできなくなる。
`Contributing.ja.md` も「IDE や Editor によりインデントが変更されるような不要な修正もコミットしない」と定めている。

スクリプトで複数行を置換するときは、対象ファイルの改行を検出してから組み立てる。

```python
nl = "\r\n" if "\r\n" in txt else "\n"
```

> **置換文字列に `nl` を埋め込んだうえで、さらに `.replace("\n", nl)` を掛けないこと。**
> CRLF のファイルで `"\r\n".replace("\n", "\r\n")` は `"\r\r\n"` になり、**ファイル全体が差分**になる。

確認は `git diff --numstat` の行数で行う。
**`git show HEAD:<path>` は blob を LF 正規化して出すので、改行の比較には使えない。**

`sed -i` は行中の置換なら改行を保つので安全。複数行にまたがるときだけ注意する。

## 4. bat ファイル

**重要な bat は、非 ASCII を一切書かない。** コメントも英語にする。

cmd.exe はバッチを**バイト オフセットで読み進める**ため、非 ASCII があると
コンソールのコード ページ次第で文字境界がずれ、
**`@rem` コメントの途中から先がコマンドとして実行される**ことがある。

- **BOM は緩和にはなるが、保証ではない**（対話コンソールで再現することがある）
- **`chcp 65001` を中に書くと、むしろ悪化する。** 途中でコード ページが変わる分、条件が増える
- **非対話（`cmd /c`）では再現しない。** 手元で確認しても気付けない

`z_Common.bat` は**すべてのビルド バッチが呼ぶ**ので、純 ASCII にしてある。
先頭に `NOTE: keep this file pure ASCII.` と理由が書いてある。

| 非 ASCII の役割 | 対処 |
|---|---|
| コメント・`echo` | **ASCII 化する**（重要な bat では必須） |
| 外部プログラムへ渡す**引数** | 消せない。コンソールのコード ページに合わせて符号化する |

純 ASCII なら BOM は不要（差分ノイズになるだけ）。
**日本語を書き足すときは、BOM の有無を確認すること。**

現状、`root/programs` の bat は次のとおり。

| ファイル | 非 ASCII |
|---|---|
| `z_Common.bat` / `0_ExecAllBat.bat` / `10_*.bat` / `2_DeleteFile.bat` | **無し** |
| `1_DeleteDir.bat` / `z_Common2.bat` / `3_BuildLibsAtOtherRepos*.bat` | 有り（コメントのみ） |

## 5. ps1 ファイル

**Windows PowerShell 5.1 と PowerShell 7 の両方で動くこと。**

開発時は `pwsh`（7）で確認しがちだが、利用者は `powershell.exe`（5.1）で実行する。

| 事象 | 原因 | 対処 |
|---|---|---|
| 構文エラー・文字化け（`繧ｵ繧､繝`） | 5.1 は BOM 無しの `.ps1` を **ANSI（Shift_JIS）**として読む | **UTF-8 BOM ＋ CRLF** で保存する |
| `Get-Content` の結果が違う | 既定エンコードが 5.1 は ANSI、7 は UTF-8 | **`-Encoding UTF8`** を明示する |
| 自己署名証明書の HTTPS が叩けない | **API ごとに、動く版が違う**（下の表） | 版で分岐する |
| `-File` で単体起動したときだけ `Join-Path` が落ちる | **`[CmdletBinding()]` があると、5.1 は `param()` の既定値を評価する時点で `$PSScriptRoot` が空** | パスの既定値は `param()` に書かず、本体で決める |
| 表の見出し・罫線・データがずれる | 5.1 の `Format-Table` は**桁数ではなく文字数**で幅を決める（全角は 1 文字で 2 桁） | `SummaryTable.ps1` の `Write-SummaryTable` を使う |

> **1 行目は実際に踏んだ。** `test.ps1` だけ BOM 無しで作ってしまい、
> 5.1 から `0_RunAll.ps1` を実行すると日本語コメントが化けて
> **クォートの対応が壊れ、構文エラーになった。**
> ここに書いてある落とし穴を、この文書を書いた本人が踏んでいる。
> **`.ps1` を足したら、必ず 5.1 でも構文検査すること。**

### `$PSScriptRoot` を `param()` の既定値で使わない

**実測（Windows PowerShell 5.1 / PowerShell 7）。**

| スクリプトの形 | 5.1 `-File` | 7 `-File` |
|---|---|---|
| `param(...)` だけ | 入る | 入る |
| **`[CmdletBinding()]` ＋ `param(...)`** | **空** | 入る |

```
Join-Path : Cannot bind argument to parameter 'Path' because it is an empty string.
```

**`0_RunAll.ps1` から `&` で呼ぶ分には呼び出し元の値が見えるため表面化しない。**
単体で `-File` 起動したときだけ落ちるので、通しの確認では見つからない。

```powershell
# 悪い
[CmdletBinding()]
param([string]$OutputDir = (Join-Path $PSScriptRoot "logs"))

# 良い
[CmdletBinding()]
param([string]$OutputDir)

if (-not $OutputDir)
{
    $OutputDir = Join-Path $PSScriptRoot "logs"
}
```

### 自己署名証明書の HTTPS（5.1 / 7 で API を分ける）

**同じ書き方で両方は通らなかった。** 開発用証明書の Kestrel に対する実測。

| 方法 | 5.1 | 7 |
|---|---|---|
| `Invoke-WebRequest` | **NG** | OK（`-SkipCertificateCheck`） |
| `HttpWebRequest` ＋ `ServicePointManager` のコールバック | **OK** | NG |
| `HttpWebRequest` ＋ 個別のコールバック | － | NG |
| `HttpClient` ＋ コールバック | **NG** | OK |

- 5.1 の NG : `接続が切断されました: 送信時に、予期しないエラーが発生しました。`
- 7 の NG : `The SSL connection could not be established`

**生の `SslStream` は 5.1 でも TLS 1.2 / 1.3 の両方で成功する。TLS そのものの問題ではない。**
`-UseBasicParsing` / `-Proxy $null` / `-DisableKeepAlive` のいずれでも変わらなかった。

原因を追うより、**それぞれで通ることを確認した方法を使う。**

```powershell
if ($PSVersionTable.PSVersion.Major -ge 6)
{
    $res  = Invoke-WebRequest -Uri $url -TimeoutSec 5 -SkipCertificateCheck
    $code = [int]$res.StatusCode
}
else
{
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12

    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Timeout = 5000
    $res  = $req.GetResponse()
    $code = [int]$res.StatusCode
    $res.Close()
}
```

```powershell
# 集計表は Format-Table ではなく、桁数を自前で数える整形を使う
. (Join-Path $PSScriptRoot "SummaryTable.ps1")
Write-SummaryTable $results
```

その他。

- **要素 1 個の配列は、返した時点でスカラーに展開される。** そのまま `[0]` を取ると
  **文字列の 1 文字目**になる。関数の戻り値を添字で使うなら `@()` で受ける
- **`$PSScriptRoot` で組み立てる。** ダブル クリック起動でカレントに依存しないようにする
- **`Read-Host` で締める**のは、ダブル クリックする最上位（`0_RunAll.ps1`）だけ。
  途中のスクリプトに入れると、通しで回せなくなる
- **例外を握り潰さない。** 再試行する `catch` でも**最後の理由は残す。**
  時間切れになったとき、理由が無いと原因が分からない
- **子プロセスの出力はファイルへ残す**（`-RedirectStandardOutput` / `-RedirectStandardError`）。
  「応答しません」だけでは、落ちたのか起動中なのかも分からない
- **待ち時間は回数ではなく実時間で測る。** 接続拒否は即座に返るが、
  起動中は `Timeout` まで待つため、回数だと上限が数倍変わる
- **変更したら 5.1 でも実行して確かめること**

```powershell
# 構文検査
powershell.exe -NoProfile -Command "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('root\1_BuildAll.ps1',[ref]$null,[ref]$e); $e"

# 通し（5.1 / 7 の両方で）
powershell.exe -NoProfile -File "root\0_RunAll.ps1" -SkipClean
pwsh           -NoProfile -File "root\0_RunAll.ps1" -SkipClean

# **単体でも起動してみること。** 通しでは表面化しない不具合がある
powershell.exe -NoProfile -File "root\1_BuildAll.ps1" -List
powershell.exe -NoProfile -File "root\2_RunAllTests.ps1" -Launch
```

### 書式

`SummaryTable.ps1` は OpenTouryo リポジトリからの移植。**あちらと足並みを揃える。**
コメント ベースのヘルプ（`.SYNOPSIS` / `.NOTES` の更新履歴）は `.cs` のヘッダと同じ流儀で書く。

## 6. `ANALYSIS.md` と `ANALYSIS-IdP.md`

**点在する分析のスナップショットではなく、対応状況の一覧を兼ねる。**

指摘した項目を修正したら、同じコミット（または直後）で次を行う。

- 見出しの末尾に `— **✅ 修正済み（#182）**` を付ける。`★最優先` などの優先度表記は外す
- **本文の記述は消さない。** 「何が問題だったか」を残したまま印を付ける
- 修正前のコード引用には `// 修正前: <パス>` と明記する。**行番号は修正で動くので書かない**
- 本文中の「現在こうなっている」という断定が偽になったら、そこも直す
- ロードマップの表と、0 節の「対応状況」の件数も更新する

**誤検出だったものは `⚠️ 誤検出（#Issue）` にして、理由を残す。** 消さない。

**ずれた文書は、次に読む人が「まだ直っていない」と誤認する材料になる。**

## 7. 秘密を書かない

`app.config` / `appsettings.json` の内容を、
**コード・コメント・コミット メッセージ・Issue 本文・報告に転記しない。**

設定の変更は雛形（`_app.config` / `_appsettings.json`）側に書く。
詳細は [`CONFIGURATION.md`](CONFIGURATION.md) 6 節。

テストの出力にトークンを出さない。キー名とエラーだけを出す
（[`TESTING.md`](TESTING.md) 9 節）。
