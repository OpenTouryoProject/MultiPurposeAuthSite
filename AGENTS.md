# プロジェクト ポリシー
アプリケーション・フレームワーク

https://github.com/OpenTouryoProject/OpenTouryo/

を使用した

https://github.com/OpenTouryoProject/MultiPurposeAuthSite

の開発エージェント用。

環境のセットアップ・ビルド・検証の手順は [root/Readme.ja.md](root/Readme.ja.md) を参照。
本書は、その上で**エージェントが守るべきこと**と、**どの文書を見るか**を示す。

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

### セキュリティの指摘は、公開される前に確認を取る

`SECURITY.md` / `Security.ja.md` のとおり、**セキュリティの問題は公開の Issue に書かない。**
報告は **Private vulnerability reporting**（非公開の security advisory）で行う。

**見落としやすいのは、文書経由で公開されることである。**
`ANALYSIS.md` / `ANALYSIS-IdP.md` は公開ファイルであり、**コミットした時点で公開になる。**
未修正の弱点をそこに書くことは、公開の Issue に書くのと同じ効果を持つ。
**「記録として書いただけ」は、公開しない理由にならない。**

したがって、**未修正**のセキュリティ上の弱点を見つけたら、次の順で進める。

1. **まず人に報告する。** どこに書くか（公開の文書 / 非公開の advisory）を決めるのは人である
2. 合意を得るまで、**攻撃の手順や再現の具体を、ワーキング ツリーのファイルに書かない。**
   書いてよいのは「どの関数で、どの確認が抜けているか」まで
3. 非公開の advisory の番号（`GHSA-…`）は、**公開ファイルに書かない。** 存在そのものが分かるため
4. 公開の Issue として起票してよいかは、**文面を見せて承認を得る**（この節の上の規約と同じ）

**修正と同じコミットに入るなら、`ANALYSIS` に書いてよい。** その時点で攻撃は成立しないため、
これまでどおり「✅ 修正済み（#Issue）」として記録する。

### 検証は、変更の届く範囲で決める

**検証は目的ではなく、壊していないことを確かめる手段である。**
**全部回すのは「安全」ではない。遅いだけのことがある。**
逆に、**変更が実行されるコードに届いていないなら、通しを回しても何も分からない。**

**入口は [`root/Readme.ja.md`](root/Readme.ja.md) である。**
前提の準備とスクリプト（`root\*.ps1`）は、そこから辿れる。
手順だけを引くなら [`CHEATSHEET.md`](root/CHEATSHEET.md) 1 節、合否の読み方は
[`BUILDING.md`](root/BUILDING.md) 3 節・[`TESTING.md`](root/TESTING.md) 5 節が一次情報である。
**本書にコマンドは書かない。** 転記すると、両方を直さないかぎりズレる。

| 変更 | 目安 |
|---|---|
| 文書（`.md`）のみ | **回さなくてよい** |
| `CommonLibrary/` | **net48 / net10.0 の両方をビルド**（両アプリが使う）＋ E2E の通し |
| どちらかのアプリだけ | そのアプリのビルド ＋ E2E の通し |
| E2E テストのコード | E2E の通し。**テストを足したり変えたりしたら、原本も作り直す**（[`TESTING.md`](root/TESTING.md) 10 節） |
| `.ps1` | **変更したら実行する。** 構文エラーは読んでも分からず、5.1 と 7 で振る舞いが違う（[`CODING.md`](root/CODING.md) 5 節） |

**E2E は、net48 版と net10.0 版の両方に同じテストを流す。**
片方を起動せずに通しても、**その分は Skip として数えられる**ので「通った」ことにはならない。
両方を測るには、サイトを起動する指定（`-Launch`）で回す。

**エラー 0 だけでなく、警告が増えていないことも見る**（[`BUILDING.md`](root/BUILDING.md) 3 節）。

**迷ったら通しでよい。** ただし**迷っていないのに通すのは、ただの浪費である。**

**回さなかったなら、そう報告する。** 「検証済み」と書かない。
**回していないのに回したように読める報告が、一番危い。**
検収する人は、何が確かめられていないかを知っている必要がある。
