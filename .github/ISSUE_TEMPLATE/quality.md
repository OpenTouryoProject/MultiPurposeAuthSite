---
name: 品質改善
about: リファクタリング、規約整備、CI・セキュリティの整備、文書の整理
labels: quality improvement
---

<!--
書けるところだけで構いません。**このテンプレートは任意です。**
不要な見出しは消してください。

「調査 → 実装 → 検証」の型で書くと追いやすくなります。
実施済みの内容を記録として起票する場合も、この型で構いません。
-->

## 概要

<!-- 何を、なぜ直すか。 -->

## 現状

<!--
**実測した値を書いてください。** 「多い」「遅い」ではなく件数や秒数で。
推測と事実を混ぜないこと。

各領域の現状は ANALYSIS.md にまとめてあります。重複して書く必要はありません。

  root/programs/CommonLibrary/ANALYSIS.md
  root/programs/MultiPurposeAuthSiteCore/ANALYSIS.md
  root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md   … IdP のプロトコル適合性
  root/programs/MultiPurposeAuthSite/ANALYSIS.md
  root/programs/CommandLineTools/ANALYSIS.md
  root/programs/authentication_device/ANALYSIS.md
-->

## 対応

<!-- 何をするか。複数の案があるなら、選んだ理由も。 -->

## 検証

<!--
**本リポジトリに CI はありません。** 手元で通した結果を貼ってください。

.NET 10 側:

  dotnet build root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore.sln
  dotnet build root/programs/CommandLineTools/CommandLineToolsCore.sln

net48 側（MSBuild が必要。**Debug 構成で**）:

  root/programs/10_MultiPurposeAuthSite.bat

前提として、Open棟梁のアセンブリを先に用意しておく必要があります。
  root/programs/3_BuildLibsAtOtherReposInTimeOfDev.bat（または mpas_dev.bat）

**エラー 0 に加えて、警告が増えていないこと**を確認してください。
現状の基準は MultiPurposeAuthSiteCore/ANALYSIS.md 9.1 節にあります。

CommonLibrary を直した場合は、**net48 / net10.0 の両方**をビルドしてください。
SQL を直した場合は、sqlserver / oracle / pstgrs の 3 方言すべてを確認してください。

文書だけの変更なら「不要」と書いてください。
-->

## 利用者への影響

<!--
**無いなら「無し」と書いてください。** 空欄だと、確認したのか未確認なのか分かりません。
あるなら、リリース ノートから参照できるように具体的に。
-->
