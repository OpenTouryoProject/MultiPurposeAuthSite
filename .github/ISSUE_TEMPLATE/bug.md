---
name: 不具合
about: 動かない・想定と違う挙動を報告する
labels: bug
---

<!--
書けるところだけで構いません。**このテンプレートは任意です。**
不要な見出しは消してください。

セキュリティに関する問題は、ここではなく Private vulnerability reporting へ。
→ SECURITY.md / Security.ja.md
-->

## 現象

<!-- 何が起きるか。エラー メッセージがあれば、そのまま貼ってください。 -->

## 環境

| | |
|---|---|
| バージョン | <!-- 例: develop (コミット ハッシュ) / 02-00 --> |
| 構成要素 | <!-- CommonLibrary / MultiPurposeAuthSiteCore / MultiPurposeAuthSite / CommandLineTools / authentication_device --> |
| ターゲット | <!-- net48 / net10.0。**両者は共通ライブラリを使う別アプリ**であり、片方にしか無い問題があり得ます --> |
| UserStoreType | <!-- mem / sql / ora / npg --> |

## 再現手順

<!--
1.
2.
3.
-->

## 期待する動作

## OAuth2 / OIDC の場合

<!--
プロトコルの問題なら、次も書いてください。設定で挙動が変わります。

  ・フローと grant_type / response_type / response_mode
  ・関係する設定（Enable*GrantType、EnableOpenIDConnect など）
  ・クライアントの subject_types / oauth2_oidc_mode
  ・リクエストとレスポンスの実際の値（**トークンや client_secret は伏せてください**）

**報告の前に、既知かどうかを確認してください。**
  ・root/programs/MultiPurposeAuthSiteCore/ANALYSIS-IdP.md
  ・SECURITY.md の「Already known」
-->

## 調べたこと

<!-- 原因の見当や、切り分けの結果があれば。無くても構いません。 -->
