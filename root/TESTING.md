# TESTING.md — E2E テストの実行と判定

対象: `root/programs/Tests`
配置: `root`

本書は、**どう実行し、どう合否を判定するか**を扱う。
テストそのものの設計方針と個々のテストの説明は
[`programs/Tests/README.md`](programs/Tests/README.md) が一次情報。

> **一次情報は本書ではない。** 迷ったら次を見ること。
>
> | 内容 | 一次情報 |
> |---|---|
> | **各テストが何を確かめるのか** | [`programs/Tests/TESTCASES.md`](programs/Tests/TESTCASES.md) |
> | テストの方針・構成・未修正項目 | [`programs/Tests/README.md`](programs/Tests/README.md) |
> | 適合上の穴の一覧 | [`programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md`](programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md) |
> | ビルド | [`BUILDING.md`](BUILDING.md) |
> | 設定と起動 URL | [`CONFIGURATION.md`](CONFIGURATION.md) |

---

## 1. 使い方

```powershell
cd root
.\2_RunAllTests.ps1 -Launch     # サイトを起動 → テスト → 停止
.\2_RunAllTests.ps1             # 起動済みのサイトを叩く
.\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RequestObjectTests"
```

1 件だけ試すときは、下の層を直接叩いてもよい。

```powershell
cd root\programs\Tests
.\test.ps1 -Launch -Filter "FullyQualifiedName~Issue186"
```

| 引数 | 意味 |
|---|---|
| `-Launch` | net10.0 版を起動してからテストし、終わったら停止する |
| `-Url` | `-Launch` のときに待ち受ける URL。既定 `https://localhost:44300` |
| `-Filter` | `dotnet test` の `--filter` |
| `-Configuration` | `Debug`（既定）/ `Release` |
| `-OutputDir` | TRX とログの保存先。既定は `programs\Tests\E2ETests\Result`（`.gitignore` 済み） |
| `-UpdateTestCases` | テストケースの原本（`programs\Tests\TESTCASES.md`）を作り直す |

## 2. 構造

**3 層になっている。** OpenTouryo が `root/programs/*.ps1` から `CS/*.bat` を呼ぶのと同じ形。

```
root/2_RunAllTests.ps1          呼び出しと集計（TRX を読む）
  └ programs/Tests/test.ps1     どう起動して、どう流すか
      └ dotnet test → E2ETests  xUnit
```

分けてある理由。

- `test.ps1` は **`Tests` フォルダから直接叩ける入口**になる。1 件だけ流すときに使う
- `2_RunAllTests.ps1` は**集計だけ**を持つ。起動方法が変わっても、こちらは影響を受けない

## 3. テストは外から叩く

テストはアプリを **HTTP で外から叩く。** 実装側のクラス（`CmnEndpoints` / `Helper` など）を参照しない。

JWT のデコードも Request Object の署名も、テスト側で独立に実装している。
**同じコードで作って同じコードで読むと、型や値の誤りを検出できない**ためである。

このため、**サイトが動いていることが前提**になる。

## 4. 起動する URL を合わせる（重要）

**サイトは、構成ファイルに書かれた URL で待ち受けている必要がある。**

アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
サーバ自身が `OAuth2AuthorizationServerEndpointsRootURI` へ **HTTP で折り返す。**
叩き先と構成が食い違うと、その折り返しが接続不能になり **HTTP 500** になる。

**https で動かすこと。**
認証まわりの Cookie は `SameSite=None` で発行されるため、**http では保持されない。**
`max_age` を使うフロー（FAPI2）は `auth_time` Cookie を見るので、http だとエラー画面になる。

Visual Studio（IIS Express）で起動する分には、構成ファイルのままなので食い違わない。
`-Launch` は、環境変数で両者を揃えてから Kestrel を起動する。

```
appSettings__OAuth2AuthorizationServerEndpointsRootURI
appSettings__OAuth2ClientEndpointsRootURI
```

詳細は [`CONFIGURATION.md`](CONFIGURATION.md)。

## 5. 判定基準

### 識別子

テストには識別子が付いている。**原本と報告は、これで突き合わせる。**

| 接頭辞 | 対象 | 置き場所 |
|---|---|---|
| `TC-n.n` | 基本テストケース（OAuth 2.0 / OIDC の基本的な検証項目） | `Tests/Basic/` |
| `SM-n` | 疎通（テスト基盤そのものの確認） | `Tests/SmokeTests.cs` |
| `RT-<Issue>.n` | 個別 Issue の回帰（`RT-186.2` なら #186 の 2 番目） | `Tests/*.cs` |

報告書の一覧と詳細は、この順（TC → SM → RT）に並ぶ。

### 報告は 2 つに分かれている

**説明と結果を混ぜない。**

| | 場所 | いつ変わるか |
|---|---|---|
| **原本**（何を・何を根拠に確かめるのか） | `programs\Tests\TESTCASES.md` | **テストを変えたときだけ**。リポジトリに入れる |
| **報告**（その回に何が起きたか） | `Result\E2ETests.report.md` | 実行のたび。`.gitignore` 済み |

観点・根拠・手順は実行しても変わらないので、毎回刷り直さない。
報告は「検証・観測の期待と実測」だけを持ち、冒頭から原本へリンクする。

**妥当性を評価するときは、両方を渡すこと。**

原本はテストの記録から生成する。**テスト コードが一次情報**である。

**`Skip` にしているテストは実行されないので、記録が出ない。**
そのぶんは「保留中のテストケース」として、`Skip` の理由から別枠で載る。
このため **`Skip` の理由は「未修正」で始め、Issue 番号・実測日・実測結果を書く**

```powershell
.\2_RunAllTests.ps1 -Launch -UpdateTestCases
```

### net48 版を測る

**net48 版は IIS Express で立てる。** `app.config` の
`OAuth2AuthorizationServerEndpointsRootURI` が
`https://localhost:44300/MultiPurposeAuthSite` なので、
**その仮想パスで待ち受けている必要がある**（Kestrel では仮想ディレクトリを作れない）。

Visual Studio から起動すれば、そのまま合う。
コマンドラインから立てる場合は、`applicationhost.config` を用意する。

```
"C:\Program Files\IIS Express\iisexpress.exe" /config:<applicationhost.config> /site:<サイト名>
```

サイトには 2 つのアプリケーションを持たせる。

| 仮想パス | 物理パス | 役目 |
|---|---|---|
| `/` | 空のフォルダ | net10.0 版の到達性判定を 404 にし、そちらを Skip させる |
| `/MultiPurposeAuthSite` | `programs\MultiPurposeAuthSite\MultiPurposeAuthSite` | net48 版の本体 |

バインドは `https` の `*:44300:localhost`。
44300〜44399 は IIS Express の開発用証明書が http.sys に登録済みなので、そのまま使える。

> **`.vs` を消すと `applicationhost.config` も消える。**
> `1_DeleteDir.bat` の削除対象に `.vs` が入っているため、
> クリーン後は Visual Studio で開き直すか、自分で用意する。

### 取り違えは検出する

**net48 版と net10.0 版は、既定ではどちらも同じ URL で構成されている。**
片方しか動いていないのに、両方の到達性判定が通ってしまう。

そのままだと**同じアプリを 2 回測って「両方 OK」と報告する。**（実際にやった）

このため、応答ヘッダで**どちらのアプリが応答したのか**を確かめている。

| | 見分け方 |
|---|---|
| net48 | `X-AspNet-Version` が付く |
| net10.0 | `Server: Kestrel` |

期待と食い違う場合は、そのターゲットを Skip して理由を残す。

```
net10.0版 (MultiPurposeAuthSiteCore) のはずの https://localhost:44300/MultiPurposeAuthSite に、
net48版（ASP.NET Framework）が応答しました。同じURLで構成されているため取り違えます。
片方を別のURLにするか、順番に実行してください。
```

報告書にも、測った相手が残る。

```
対象: net48版 (MultiPurposeAuthSite) (https://localhost:44300/MultiPurposeAuthSite)
      / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0）
```

### 両方を同時に測る

**報告書（`E2ETests.report.md`）は 1 回の実行で上書きされる。**
net48 版を測った後に net10.0 版を測れば、net48 版の結果は残らない。
**両方の結果を 1 枚に残したいなら、同じ実行で測る。**

既定では両者が同じ URL を指していて取り違えるので、**net10.0 版をずらす。**

```
> .\2_RunAllTests.ps1 -Launch -Url https://localhost:44301
```

`-Url` は Kestrel の待ち受け URL であると同時に、
構成ファイルの `OAuth2AuthorizationServerEndpointsRootURI` /
`OAuth2ClientEndpointsRootURI` の上書き（環境変数）と、
テスト側の `MPAS_CORE_BASEURL` にも渡される。
**3 つが揃っていないと、サーバが自分自身へ戻る経路（FAPI2 の自己テストなど）が壊れる。**

net48 版は `app.config` の URI（`44300/MultiPurposeAuthSite`）から動かせないので、
**ずらすのは net10.0 版の方。**

| 対象 | 待ち受け | 立て方 |
|---|---|---|
| net48 | `https://localhost:44300/MultiPurposeAuthSite` | IIS Express（先に起動しておく） |
| net10.0 | `https://localhost:44301` | `-Launch` が起動・停止する |

この形で実行すると 94 件（47 × 2）が測られ、報告書の「叩いた先」に両方が並ぶ。

```
| 叩いた先 | net48版 (MultiPurposeAuthSite) (https://localhost:44300/MultiPurposeAuthSite)
            / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0）<br>
            net10.0版 (MultiPurposeAuthSiteCore) (https://localhost:44301)
            / 応答: net10.0（Kestrel） |
```

**この行は `-Url` の値ではなく、実際に応答したアプリから作る。**
引数を書き写すだけでは、測れていない対象まで「叩いた」ことになってしまう。

### TRX を読む

コンソールの集計行（`テストの合計数: ...`）は**ロケールで変わる。**
TRX（XML）の `outcome` は `Passed` / `Failed` / `NotExecuted` で固定なので、こちらを読む。

`test.ps1 -TrxPath` が出力先を受け取る。`2_RunAllTests.ps1` がそれを渡している。

### 合否

| 条件 | 判定 |
|---|---|
| 失敗 0 件、かつ**成功 1 件以上** | `OK`（終了コード `0`） |
| 失敗 1 件以上 | `NG`（`1`） |
| **成功 0 件** | `NG`（`1`） |
| TRX が出ていない | `NG`（`1`）。テストの起動そのものに失敗している |

**成功 0 件を NG にしているのが肝。**
サイトを起動し忘れると全件 Skip になり、「失敗 0 件」で緑に見えてしまう。
それがいちばん危ない。

### Skip は失敗ではない

テストは net10.0 版と net48 版の**両方に同じものを流す**（`[SkippableTheory]` ＋ `AllTargets`）。
クロスコンパイルで下位互換版を維持しているので、
**「片方だけ直っている」状態を検出できること**を最優先にしている。

起動していない対象は Skip する。net48 版は IIS Express での手動起動が前提で、
常に動いているとは限らないため、そこで落とさない。

**Skip は 2 種類ある。混ぜて数えると、どちらも見えなくなる。**

```
  Skip 30 件の内訳
        28  netfx          ← そのサイトが起動していないだけ（環境）
         2  (対象なし)     ← 未修正と分かっている項目（仕様）
```

`2_RunAllTests.ps1` は、テスト名の `targetKey: "..."` で切り分けて内訳を出す。

## 6. 未修正の項目の扱い

**未修正だと分かっている項目は、期待する動作を書いたうえで `Skip` にする。**
消さずに残すのは、直したときに `Skip` を外すだけで検証できるようにするため。

`Skip` の理由には、**Issue 番号・実測日・実測結果**を書く。

```csharp
[SkippableTheory(Skip = "未修正（#197）。実測（2026/09/09, net10.0）では、"
    + "誤った redirect_uri を送ってもトークンが発行される。")]
```

現在 `Skip` にしているものは
[`programs/Tests/README.md`](programs/Tests/README.md) の「未修正の項目」にある。

## 7. 実行結果の例

```
================ サマリ ================

対象     結果 成功 失敗 Skip   秒
-------- ---- ---- ---- ---- ----
E2ETests OK     28    0   30 42.3

  Skip 30 件の内訳
        28  netfx
         2  (対象なし)

  所要時間 : 0.7 分
  TRX      : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.trx
  ログ     : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.log

  全テスト OK
```

## 8. 前提条件

| 前提 | 備考 |
|---|---|
| ビルド済み | `1_BuildAll.ps1`、または Visual Studio |
| 設定ファイル | `appsettings.json` / `app.config`。テストは**ここから資格情報を読む** |
| `UserStoreType` | `mem` を想定。テスト ユーザは初回アクセスで作られ、再起動で消える |
| 証明書 | `SpRp_RsaPfxFilePath` の pfx。Request Object の署名に使う |

**net10.0 版と net48 版は、既定では同じ URL で構成されている。同時には測れない。**
取り違えは検出して Skip する（5 節「取り違えは検出する」）。
片方を別の URL にするか、順番に実行する。

## 9. 秘密情報を出さない

`TestUserPWD` / `client_secret` / pfx のパスワードは、
実行時に**アプリ自身の構成ファイルから読み出す。** テスト側は値を持たない。

`client_id` も直書きしない。環境ごとに違う（`CreateClientsIdentity.exe` で生成する）ので、
`client_name`（`TestClient` / `MVC_Sample` など）から引く。

**テストの出力にトークンや秘密情報を書かないこと。**
`JsonResponse.ToString()` はキー名とエラーだけを出す。

```
HTTP 200 / keys=[access_token, expires_in, id_token, refresh_token, token_type] / error=-
```

## 10. テストを足すとき

1. `programs/Tests/E2ETests/Tests/` に置く。ファイル ヘッダは既存に合わせる（[`CODING.md`](CODING.md)）
2. `TargetTestBase` を継承し、`[SkippableTheory]` ＋ `[MemberData(nameof(AllTargets))]` にする
   - net10.0 版でしか成立しないものだけ `CoreOnly` を使う
3. `client_id` は `Flows.Registration(client, KnownClients.XXX)` で引く
4. **未修正の挙動を見つけたら、期待する動作を書いて `Skip`。** Issue を起こして番号を書く
5. `ANALYSIS-IdP.md` にも反映する（あちらが適合上の穴の一覧）
