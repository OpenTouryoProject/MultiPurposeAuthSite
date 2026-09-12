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
.\2_RunAllTests.ps1 -Launch     # 2 つのサイトを起動 → テスト → 停止
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
| `-Launch` | **net10.0 版と net48 版の両方**を起動してからテストし、終わったら停止する |
| `-Url` | net10.0 版（Kestrel）の待ち受け URL。既定 `https://localhost:44300` |
| `-NetFxUrl` | net48 版（IIS Express）の待ち受け URL。既定 `https://localhost:44302` |
| `-NoNetFx` | net48 版を起動しない。その分は Skip される |
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
`-Launch` は、**構成ファイルを書き換えずに、環境変数で上書きしてから**起動する。

```
OAuth2AuthorizationServerEndpointsRootURI
OAuth2ClientEndpointsRootURI
FcmOutboxDirectory
```

`FcmOutboxDirectory` は、プッシュ通知の送信箱（テスト用）。サイトは FCM に送らず、ここにファイルを書く。
テストは `MPAS_CORE_FCM_OUTBOX` / `MPAS_NETFX_FCM_OUTBOX` で場所を受け取り、認証デバイスの代わりに読む（CIBA の `EX-8`）。

Open棟梁 の `GetConfigParameter` は、`appSettings` の `FxContainerization` が `ON` のとき
**設定ファイルより環境変数を優先する**（net48 / net10.0 の両方）。
**キー名がそのまま環境変数名になる。** 接頭辞は付かない。

このため、**net48 版を `app.config` の URL に置く必要がない。**
別のポートへ寄せられるので、2 つのサイトを同時に立てても衝突しない。

> **環境変数は、子プロセスの起動時に写される。**
> 2 つのサイトへ別々の URL を渡せるのは、この性質による。
> 起動の直前に書き換えること。後から変えても、動いている側には効かない。

詳細は [`CONFIGURATION.md`](CONFIGURATION.md)。

## 5. 判定基準

### 識別子

テストには識別子が付いている。**原本と報告は、これで突き合わせる。**

| 接頭辞 | 対象 | 置き場所 |
|---|---|---|
| `SM-n` | 疎通（テスト基盤そのものの確認） | `Tests/SmokeTests.cs` |
| `TC-n.n` | 基本テストケース（OAuth 2.0 / OIDC の基本的な検証項目） | `Tests/Basic/` |
| `EX-n.n` | 拡張仕様（Revocation / Introspection / Device / Hybrid / response_mode / JWT Bearer / CIBA） | `Tests/Extended/` |
| `RT-<Issue>.n` | 個別 Issue の回帰（`RT-186.2` なら #186 の 2 番目） | `Tests/Issues/` |

報告書の一覧と詳細、原本は、この順（**SM → TC → EX → RT**）に並ぶ。

**土台から順に並べる。**
SM が倒れていれば、TC の合否は読む意味がない。
サイトに届いていない・サインインできていない、という話であって、
**仕様に適合しているかどうか以前**だからである。
同じ理由で、拡張（EX）は基本（TC）の上に乗っている。
TC が倒れている状態の EX は、拡張の問題なのか土台の問題なのかを判断できない。RT も同じ。

先に出る群が倒れていたら、**後ろは読まずに原因を潰す。**

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

### net48 版も同時に測る

**`-Launch` は 2 つのサイトを立てる。** 1 回の実行で 94 件（47 × 2）を測る。

| 対象 | 待ち受け | 立て方 |
|---|---|---|
| net10.0 | `https://localhost:44300` | Kestrel（ビルド済みの `MultiPurposeAuthSite.exe`） |
| net48 | `https://localhost:44302` | IIS Express |

> **`dotnet run` は使わない。**
> アプリを子プロセスとして起動するため、親（`dotnet`）を止めてもアプリが残り、
> 次回の起動がポートを奪われる。ビルド済みの exe を直接起動すれば、
> 止めた時点で確実に終わる。

**報告書は 1 回の実行で上書きされる。**
別々に測ると、後から測った方しか残らない。**両方を残したいなら、同じ実行で測る。**

net48 版は ASP.NET なので Kestrel では動かない。`test.ps1` は IIS Express の雛形

```
%ProgramFiles%\IIS Express\config\templates\PersonalWebServer\applicationhost.config
```

を読み、サイト 1 つ分を書き換えて `Result\applicationhost.config` に出す。

- 物理パス : `programs\MultiPurposeAuthSite\MultiPurposeAuthSite`
- バインド : `https` の `*:44302:localhost`
- 44300〜44399 は IIS Express の開発用証明書が http.sys に登録済みなので、そのまま使える

**仮想ディレクトリは作らない。**
待ち受け URL は環境変数で構成へ反映されるので（4 節）、
`/MultiPurposeAuthSite` の下に置く必要がない。アプリはサイト直下に置く。

立てられないときは、**理由を出してその対象を Skip する。** 失敗にはしない。

| 状況 | 見るところ |
|---|---|
| `-NoNetFx` を付けた | 意図的に測らない |
| IIS Express が無い | `%ProgramFiles%\IIS Express\iisexpress.exe` |
| net48 版がビルドされていない | `1_BuildAll.ps1`（`bin\MultiPurposeAuthSite.dll`） |

> **`.vs` を消すと、Visual Studio 用の `applicationhost.config` は消える。**
> `1_DeleteDir.bat` の削除対象に `.vs` が入っているため。
> `test.ps1` が使うのは自前で作る方なので、こちらは影響を受けない。

### 取り違えは検出する

**net48 版と net10.0 版は、構成ファイルの既定ではどちらも同じ URL を指している。**
`-Launch` は別のポートへ寄せるが、手で立てた場合や `testsettings.json` で
URL を指定した場合は、**同じ URL を 2 回測ることが起こり得る。**

そのままだと**同じアプリを 2 回測って「両方 OK」と報告する。**（実際にやった）

このため、応答ヘッダで**どちらのアプリが応答したのか**を確かめている。

| | 見分け方 |
|---|---|
| net48 | `X-AspNet-Version` が付く |
| net10.0 | `Server: Kestrel` |

期待と食い違う場合は、そのターゲットを Skip して理由を残す。

```
net10.0版 (MultiPurposeAuthSiteCore) のはずの https://localhost:44302 に、
net48版（ASP.NET Framework）が応答しました。同じURLで構成されているため取り違えます。
片方を別のURLにするか、順番に実行してください。
```

報告書の「叩いた先」も、**`-Url` の値ではなく、実際に応答したアプリ**から作る。
引数を書き写すだけでは、測れていない対象まで「叩いた」ことになってしまう。

```
| 叩いた先 | net10.0版 (MultiPurposeAuthSiteCore) (https://localhost:44300)
            / 応答: net10.0（Kestrel）
            net48版 (MultiPurposeAuthSite) (https://localhost:44302)
            / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0） |
```

個々のテストの記録にも残る。

```
対象: net48版 (MultiPurposeAuthSite) (https://localhost:44302)
      / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0）
```

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
E2ETests OK    220    0    1 146.7

  Skip 1 件の内訳
         1  (対象なし)

  対象ごとの Skip は、そのサイトが起動していないだけのことが多い。
  (対象なし) は、未修正として Skip 指定しているもの（Tests\README.md）。

  所要時間 : 2.4 分
  TRX      : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.trx
  ログ     : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.log
  報告書   : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.report.md
  原本     : C:\MultiPurposeAuthSite\root\programs\Tests\TESTCASES.md

  全テスト OK
```

## 8. 前提条件

| 前提 | 備考 |
|---|---|
| ビルド済み | `1_BuildAll.ps1`、または Visual Studio |
| 設定ファイル | `appsettings.json` / `app.config`。テストは**ここから資格情報を読む** |
| `UserStoreType` | `mem` を想定。テスト ユーザは初回アクセスで作られ、再起動で消える |
| 証明書 | `SpRp_RsaPfxFilePath` の pfx。Request Object の署名に使う |
| `FxContainerization` | `ON`。**待ち受け URL の上書きに要る**（4 節）。雛形には入っている |
| IIS Express | net48 版を測るときだけ。無ければその分が Skip される |

**構成ファイルの既定では、net10.0 版と net48 版は同じ URL を指している。**
`-Launch` は環境変数で別のポートへ寄せるので、**同時に測れる。**
手で立てるときは、片方を別の URL にすること。
取り違えは検出して Skip する（5 節「取り違えは検出する」）。

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
