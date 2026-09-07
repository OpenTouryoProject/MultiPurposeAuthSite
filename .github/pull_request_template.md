<!--
**このテンプレートは任意です。** 不要な見出しは消してください。
小さな変更なら、要約 1 行でも構いません。

1 つの "プルリクエスト" に複数のタスクを混ぜないでください（Contributing.ja.md）。
-->

## 概要

<!-- 何を変えたか。関連する Issue があれば `#123` のように書いてください。 -->

## 変更内容

<!--
ファイル単位ではなく、**変更の意図**の単位で。

  ・net48 と net10.0 の両方に効くか
    → 実装の多くは CommonLibrary に在り、**直すと両系統に効きます**
  ・設定キーを増減したか
    → _appsettings.json と _app.config の両方を直したか
  ・エンドポイントを増減したか
    → net10.0 の Startup.cs と、net48 の App_Start/RouteConfig.cs / WebApiConfig.cs の両方
  ・DDL を変えたか
    → sqlserver / oracle / pstgrs の 3 方言すべて
-->

## 検証

<!--
**本リポジトリに CI はありません。結果を貼ってください。**

  dotnet build root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore.sln
  dotnet build root/programs/CommandLineTools/CommandLineToolsCore.sln
  root/programs/10_MultiPurposeAuthSite.bat        … net48。**Debug 構成で**

エラー 0 に加えて、**警告が増えていないこと**を確認してください。
CommonLibrary を直した場合は、**net48 / net10.0 の両方**を通してください。

文書だけの変更なら「不要」と書いてください。
-->

## 利用者への影響

<!--
**無いなら「無し」と書いてください。** 空欄だと、確認したのか未確認なのか分かりません。

  ・既定の挙動が変わるか
  ・**RP（クライアント）側の追随が必要か**（応答形式・パラメタ名・エラー コードの変更など）
  ・設定ファイルの追記が必要になるか
  ・DDL の適用が必要になるか
-->

## チェック

<!-- 該当するものだけで構いません。 -->

- [ ] 実ファイル（`app.config` / `appsettings.json`）ではなく、
      テンプレート（`_app.config` / `_appsettings.json`）を直した
- [ ] **秘密情報を差分に含めていない**
- [ ] 新規 `.cs` にヘッダ コメント（Apache License ＋ クラス名・日本語名・更新履歴）を付けた
- [ ] 既存 `.cs` の更新履歴に 1 行追記した
- [ ] net48 側は `<Compile Include>` / `<Content Include>` を csproj に追記した
      （旧形式 csproj のため、置くだけでは含まれません）
- [ ] 文言はリソース（`CommonLibrary/Resources`）に置いた

---

<!--
**master 宛の PR は、レビュー 1 名の承認が必要です。**
develop 宛には必須チェックはありません。

セキュリティに関する修正は、公開の PR ではなく
Private vulnerability reporting から作れる private fork で進めてください（SECURITY.md）。
-->
