# BUILDING.md — ビルドの実行と判定

対象: `root/programs`（net48 版 / net10.0 版）
配置: `root`

本書は、**どう実行し、どう合否を判定するか**を扱う。
「何をビルドするか」の正はビルド バッチ（`root/programs/*.bat`）にあり、
`root/*.ps1` はそれを呼んで結果を集約するだけである。

> **一次情報は本書ではない。** 迷ったら次を見ること。
>
> | 内容 | 一次情報 |
> |---|---|
> | 各プロジェクトの構成 | 各フォルダの `ANALYSIS.md` |
> | 設定ファイルの扱い | [`CONFIGURATION.md`](CONFIGURATION.md) |
> | テストの実行と判定 | [`TESTING.md`](TESTING.md) |
> | bat / ps1 の書き方 | [`CODING.md`](CODING.md) |
> | 手順だけ知りたい | [`CHEATSHEET.md`](CHEATSHEET.md) |

---

## 1. 使い方

```powershell
cd root
.\0_RunAll.ps1                  # ビルド → テストの通し
.\1_BuildAll.ps1                # ビルドだけ
.\1_BuildAll.ps1 -List          # 対象の一覧（**ここが一次情報**）
.\1_BuildAll.ps1 -Only net10.0 -SkipClean
.\1_BuildAll.ps1 -WarnDetail    # 警告の内訳を出す
```

バッチを直接ダブル クリックしてもよい。その場合は `root/programs` の
`0_ExecAllBat.bat`（通し）または `10_MultiPurposeAuthSite*.bat`（個別）を使う。

| 引数 | 意味 |
|---|---|
| `-Configuration` | `Debug`（既定）/ `Release`。`BUILD_CONFIG` としてバッチへ渡る |
| `-Only` | ステップ名またはバッチ名の部分一致で絞る |
| `-List` | `-Only` に指定できる名前を出して終わる |
| `-SkipClean` | クリーン処理を省略する |
| `-WarnDetail` | 警告を種類ごとに集計して出す |
| `-IgnoreErrors` | 既知のエラーとして合否から外す正規表現。**除外分は別枠で必ず表示する** |
| `-OutputDir` | ログの保存先。既定は `%TEMP%\MpasBuildLogs` |

## 2. なぜラッパーが必要か

バッチをそのまま回しても、合否が取れない。

- **各バッチは MSBuild の終了コードを伝播しない。** `%ERRORLEVEL%` を見ていない
- **末尾に `pause` がある。** 対話入力を待って止まる
- **`-v:d`（詳細）で出力が膨大。** 目視で error を探すのは現実的でない

`1_BuildAll.ps1` は、`0_ExecAllBat.bat` と同じ `echo. | call` 方式で stdin を与えて実行し、
出力を解析して判定する。

## 3. 判定基準

### エラーと警告の抽出

**ASCII のコード部分だけで判定する。**

```
: error CS1002:
: error MSB4226:
: error :            ← コードを伴わない形式もある（NuGet の restore 失敗など）
[ERROR]              ← z_Common.bat が MSBuild 未検出時に出す独自形式
```

**日本語の文言では判定しない。** 「ビルドに成功しました」はロケールで変わるうえ、
コード ページの食い違いで化けることがある。コード部分は ASCII なので、化けても合否は変わらない。

同じ指摘が複数プロジェクトから重複して出るため、**行の重複を除いて**数える。
このため件数は MSBuild が最後に出すサマリと一致しない（MSB3277 のように 1 件で何行も出る警告がある）。
**増減を見る目安**として使う。

### 合否

| 表示 | 意味 |
|---|---|
| `OK` | 除外後のエラーが 0 件 |
| `NG` | 除外後のエラーが 1 件以上 |
| `見送り` | `-SkipClean`、または nuget.exe が無くてクリーンを飛ばした |
| `バッチ無し` | 呼ぶバッチが存在しない |

**`見送り` は失敗に数えない。** ただし**黙って飛ばさず、必ず表に残す。**
飛ばしたことが見えないと「通った」と読めてしまう。

終了コードは、NG が 0 件なら `0`、1 件以上なら `1`。

### `-Only` が空振りしたら止める

1 件も選ばれないまま進むと「全ステップ OK」と表示される。
**打ち間違いが緑になる**のが最も悪いので、一致 0 件は `exit 1` にしてある。

## 4. ビルドの構成

`root/programs` にあるバッチ。

| バッチ | 役割 |
|---|---|
| `0_ExecAllBat.bat` | 通し。クリーン → net48 → net10.0 |
| `1_DeleteDir.bat` | `packages` `obj` `bin` `bld` `Temp` `Build` `PrecompiledWeb` `.vs` を再帰的に削除 |
| `2_DeleteFile.bat` | `*.suo` `*.user` `*.tmp` `*.log` `*.bak` `*.skrold` を削除 |
| `3_BuildLibsAtOtherRepos.bat` | OpenTouryo を ZIP で取得してビルドし、`OpenTouryoAssemblies` へ複写 |
| `3_BuildLibsAtOtherReposInTimeOfDev.bat` | 同上（開発時用） |
| `10_MultiPurposeAuthSite.bat` | net48 版（CommandLineTools ＋ MultiPurposeAuthSite） |
| `10_MultiPurposeAuthSiteCore.bat` | net10.0 版（CommandLineToolsCore ＋ MultiPurposeAuthSiteCore） |
| `z_Common.bat` | 共通処理。**すべてのビルド バッチが最初に呼ぶ** |
| `z_Common2.bat` | `z_Common.bat` の devenv 版。**未使用**（バッチ内の注記を参照） |

> **`2_DeleteFile.bat` は OpenTouryo では `1_DeleteFile.bat`。**
> `0_ExecAllBat.bat` がその名前で呼んでいたため、削除ステップが**空振りしていた**。
> 現在は正しい名前を呼ぶ。

## 5. `z_Common.bat` が解決するもの

OpenTouryo の `root/programs/CS/z_Common.bat` の移植。**足並みを揃えること。**

| 解決するもの | 内容 |
|---|---|
| `BUILDFILEPATH` | MSBuild.exe。**vswhere で解決**するので、Community 以外（Professional / Enterprise / BuildTools）でも見つかる |
| `NUGET_MSBUILD` | `nuget.exe restore` に渡す `-MSBuildPath`。指定しないと SSMS 同梱の MSBuild を掴むことがある |
| `NUGET_EXE` | `nuget.exe`。まず自分の隣、無ければ PATH |
| `VisualStudioVersion` | **vswhere から取得**する。固定値だと、別の VS しか無い環境で `MSB4226` になる |
| `COMMANDLINE` | `/p:Configuration=... /p:DebugType=... -v:d` |

**見つからなければ `exit /b 1` で止める。** 空のまま進むと `/p:Configuration=...` 自体が
コマンドとして実行され、原因が分かりにくい。

`BUILD_CONFIG` と `DEBUG_TYPE` は `if not defined` で、**呼び出し側が先に設定していればそれを尊重する。**
`1_BuildAll.ps1 -Configuration Release` はこれを使っている。

> **このファイルは純 ASCII にすること。** 理由は [`CODING.md`](CODING.md) 4 節。

## 6. nuget.exe と packages.config

**net48 版の Web アプリは `packages.config` を使う。**

```
root/programs/MultiPurposeAuthSite/MultiPurposeAuthSite/packages.config
```

`packages.config` は **MSBuild の `-t:Restore` では復元できない。** `nuget.exe restore` が要る。
このため `root/programs/nuget.exe` をリポジトリに置いてある（OpenTouryo と同じ）。

一方 `CommonLibrary/NetFxLibrary.csproj` は `PackageReference` なので、
そちらは MSBuild の Restore が要る。**両方を回す。**

```
%NUGET_EXE% restore "...sln" %NUGET_MSBUILD%     ← packages.config
%BUILDFILEPATH% %COMMANDLINE% /t:Restore "...sln" ← PackageReference
%BUILDFILEPATH% %COMMANDLINE% "...sln"            ← ビルド
```

> **かつて、この最後の行が無かった。** ビルド行に `/t:Restore` が付いていたため、
> net48 のソリューションは**復元されるだけで一度もビルドされていなかった。**

### nuget.exe を失うと復旧できない

`1_DeleteDir.bat` は `packages` も消す。nuget.exe が無い状態でこれを回すと、
**net48 版はそこから復元できなくなる。**

`1_BuildAll.ps1` は nuget.exe が見つからないとき、**クリーンを見送る**。
`10_MultiPurposeAuthSite.bat` は警告を出して続行する（`packages` が既にあれば通るため）。

## 7. `CommonLibrary` の `obj` は共有されている

```
root/programs/CommonLibrary/
    NetFxLibrary.csproj    ← net48   （旧形式、Compile Include を明記）
    NetCoreLibrary.csproj  ← net10.0 （SDK 形式、Compile Remove で除外）
    obj/                   ← **共有**
    bin/netfx/, bin/netcore/  ← こちらは分かれている
```

`obj/project.assets.json` は 1 つしかない。**後から復元した方が上書きする。**

net10.0 を建てた直後に net48 を建てると、`project.assets.json` が net10.0 のものになっている。
そのため net48 側では**必ず先に Restore を回す**（6 節）。

`1_BuildAll.ps1` は net48 → net10.0 の順で回すので、通しで使うぶんには意識しなくてよい。
`-Only` で片方だけ建てるときに踏む。

## 8. 既知の警告

**エラーは 0 でなければならないが、警告は残っている。**

| ターゲット | 警告の行数（重複除去後） |
|---|---|
| net48 | 45 前後 |
| net10.0 | 39 前後 |

主なもの。

| コード | 内容 |
|---|---|
| `MSB3277` | アセンブリの版の競合（`Microsoft.Data.SqlClient` 6.0 / 7.0 など）。OpenTouryo アセンブリと NuGet パッケージの食い違い |
| `CS1685` | `System.ObsoleteAttribute` が複数アセンブリで定義されている（net48 の ASPNETCOMPILER） |
| `CS1702` | `System.Memory` の版の想定一致 |

`-WarnDetail` で種類ごとの件数と代表例が出る。
**同じ種類は、たいてい 1 か所の対処でまとめて消える。**

## 9. 実行結果の例

クリーン ビルド（`nuget.exe` あり）。

```
構成 : Debug
=== Clean (dir) ===
  OK  エラー 0 / 警告 0  (6.5 秒)
=== Clean (file) ===
  OK  エラー 0 / 警告 0  (0.5 秒)
=== net48 ===
  OK  エラー 0 / 警告 45  (126.8 秒)
=== net10.0 ===
  OK  エラー 0 / 警告 39  (58.9 秒)

================ サマリ ================

ステップ     結果 エラー 既知 警告    秒
------------ ---- ------ ---- ---- -----
Clean (dir)  OK        0    0    0   6.5
Clean (file) OK        0    0    0   0.5
net48        OK        0    0   45 126.8
net10.0      OK        0    0   39  58.9

  所要時間 : 3.2 分
  ログ     : C:\Users\...\AppData\Local\Temp\MpasBuildLogs

  全ステップ OK
```

## 10. 落とし穴

### OpenTouryo のアセンブリが要る

`root/programs/OpenTouryoAssemblies/Build_net48` と `Build_netcore100` を参照している。
**`.gitignore` 済みなので、clone しただけでは無い。**

`3_BuildLibsAtOtherRepos.bat` で取得するか、OpenTouryo を別途 clone してビルドし、
`mpas_dev.bat` で複写する。

### `dotnet build` 単体では net48 は建たない

net48 版は旧形式の csproj と ASPNETCOMPILER を使うため、**MSBuild でしか建たない。**
`dotnet build` は net10.0 版と `Tests/` 用。

### 設定ファイルが無いと実行できない

ビルドは通るが、起動には `appsettings.json` / `app.config` が要る。
どちらも `.gitignore` 済み。雛形（`_appsettings.json` / `_app.config`）から作る。
詳細は [`CONFIGURATION.md`](CONFIGURATION.md)。

### `*.bak` は消える

`2_DeleteFile.bat` の対象に `*.bak` が入っている。
手元の控えをリポジトリ内に置くと、クリーン時に消える。
