# DesignNotes（設計メモ）

**ソースのコメントには、今の仕様と、その理由だけを書く。**
**段階ごとの決定と経緯（「前はどうだったか」「なぜ変えたか」）は、ここに置く。**

維持補修で「なぜこうなっているのか」を辿るための記録である。
コードを読むだけなら、ここを読む必要は無い。

## 一覧

| ファイル | 対象のソース | 主な Issue |
|---|---|---|
| [ClientRegistrationProvider.md](ClientRegistrationProvider.md) | `CommonLibrary/Extensions/Sts/ClientRegistrationProvider.cs` | #307 / #309 / #310 / #294 |
| [AccountController.md](AccountController.md) | 両アプリの `Controllers/AccountController*.cs`（partial の全ファイル） | #140 / #151 / #247 / #272 / #286 / #292 / #310 |

## 書き方

- **1 ソース（またはクラス）に 1 ファイル**。ファイル名はクラス名にする
- **段階（Issue の段階）ごとに節を立てる**。各節には「決めたこと」「理由」「前はどうだったか」を書く
- **今の仕様の説明は、ソースに置く**（ここに写さない。写すと両方を直さない限りズレる）
- ソースの冒頭の `/* */` から、対応するファイルへの参照を 1 行入れる
