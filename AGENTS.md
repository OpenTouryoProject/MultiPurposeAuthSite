# プロジェクト ポリシー
アプリケーション・フレームワーク

https://github.com/OpenTouryoProject/OpenTouryo/

を使用した

https://github.com/OpenTouryoProject/MultiPurposeAuthSite

の開発エージェント用。

**プロジェクト共通の投稿規約は [Contributing.ja.md](Contributing.ja.md) に従う。**
コメント量の目安、クロスコンパイルと下位互換の方針、ブランチ運用（git-flow）、
"プルリクエスト" の粒度は、人もエージェントも同じ規約による。
本書は、そこに書かれていない**エージェント固有の制約**を扱う。

### Git 操作は行わない（状態を変える操作をしない）

**成果物の検収は人が行う。** エージェントは作業結果をワーキング ツリーに残すところまでを担当し、
Git 操作は人が手動で行う。

したがって、指示がない限り次を実行してはならない。

- `git add` / `commit` / `push`（検収前・未レビューの変更を確定・送信しない）
- `git checkout` / `switch` / `branch` / `reset` / `restore` / `stash`（人の作業状態や未保存の作業を壊す）

**参照系は制限しない。** 何を変更したかを正確に報告するために必要なため、次は自由に実行してよい。

- `git status` / `diff`（`--cached` 含む）/ `log` / `show` / `ls-files` / `check-ignore` / `blame`

作業が完了したら**何を変更したかを報告するに留める**。コミットの要否とタイミングは人が判断する。

**状態を報告する直前に、必ず取り直すこと。** 前のターンの出力や記憶から書かない。

```
git status --porcelain                      # 未コミットの変更
gh issue view <番号> / gh pr view <番号>    # Issue / PR の状態
gh api ...                                  # 設定・アラートの状態
```

**人はエージェントの報告とは独立にコミットし、Issue や PR を操作する。**
数ターン前の状態は、高い確率で古い。
**古い一覧を出すと「まだ残っている」と誤認させ、検収の判断材料そのものが誤りになる。**

参照系は制限していないので、回数を惜しむ理由はない。
**0 件なら「ワーキング ツリーはクリーン」と書く。前回の一覧を再掲しない。**

<!--
  補足（執筆者向け）:
  インストラクションは「文脈」であって強制力を持たない。上記は遵守されやすい書き方に
  しているが、確実に阻止したい場合は仕組み側で塞ぐ必要がある。
    - Claude Code : PreToolUse フックで Bash(git commit:*) 等を deny する
    - 各プロダクト: 同等の機構があればそれを使う
-->

### GitHub 操作は gh で行う

Issue の調査・起票・コメントは、**`gh` コマンドで実行してよい**（ブラウザ操作を人に依頼しない）。
上記の「Git 操作は行わない」はワーキング ツリーとコミット履歴に対する制約であり、
GitHub 側のやり取りは対象外。

```
gh issue view <番号> --repo OpenTouryoProject/MultiPurposeAuthSite
gh issue list --repo OpenTouryoProject/MultiPurposeAuthSite
gh issue comment <番号> --repo OpenTouryoProject/MultiPurposeAuthSite --body-file <path>
gh issue create --repo OpenTouryoProject/MultiPurposeAuthSite --title <title> --body-file <path>
```

ただし**公開リポジトリへの投稿は取り消しにくい**ため、次を守ること。

- **投稿前に文面を提示し、承認を得てから実行する。** 承認なしに投稿しない
- 本文は一時ファイルに書き、`--body-file` で渡す（改行・記号の欠落を避ける）
- 投稿後は URL を報告する

**テンプレートは自動では適用されない。読んで、その構成に沿って書くこと。**

`gh issue create` / `gh pr create` の `--template` は「エディタで編集する前提の
開始テキスト」であり、**`--body-file` と併用すると本文で上書きされる。**
エージェントは `--body-file` を使うため、テンプレートは効かない。

```
.github/ISSUE_TEMPLATE/bug.md          不具合
.github/ISSUE_TEMPLATE/enhancement.md  機能追加・改善
.github/ISSUE_TEMPLATE/quality.md      品質改善（リファクタリング・規約・CI・文書）
.github/pull_request_template.md       PR
```

**テンプレートは任意**（`blank_issues_enabled: true`）だが、
**「利用者への影響」は、無いなら「無し」と明記する。**
空欄だと、確認したのか未確認なのかが読み手に分からない。
