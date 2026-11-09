# コンテナの定義

**テストのためのコンテナを、用途別に置いてある**（#318。もとは `store\` と `stub\`）。
**どれも MPAS の配備用ではない**（パスワードや秘密はテスト用の固定値）。

| ディレクトリ | 何 | compose のプロジェクト名 | 起動 |
|---|---|---|---|
| `Store\` | **E2E 用の UserStore の DB**（SQL Server・Oracle・PostgreSQL） | `mpas-store` | **通しでは `test.ps1` が、使う 1 つだけを起動・停止する**（`-UserStoreType` が `mem` 以外のとき） |
| `E2E\` | **ID 連携の E2E で使う IdP 群**（上流・上流 2・下流）と、**`jwks_uri` を配る nginx** | `mpas-e2e` | **`1_PublishIdP.ps1`（用意）→ `2_DockerComposeUp.bat`（起動）→ `3_DockerComposeDown.bat`（停止）**（#340） |
| `Stub\` | **他のリポジトリ（Open棟梁 など）のテストから使う IdP のスタブ** | `mpas-stub` | **`1_PublishStub.ps1`（用意）→ `2_DockerComposeUp.bat`（起動）→ `3_DockerComposeDown.bat`（停止）**。`Stub\README.md` |
| `CTS\` | **適合性テスト（OpenID Foundation の Conformance Suite）と、その相手の OP**（#350。`ANALYSIS-IdP.md` の D-14） | `mpas-cts` | **`..\E2E\1_PublishIdP.ps1`（OP の用意。E2E と共用）→ `2_DockerComposeUp.bat`（起動）→ `RunTestPlan.ps1`（プランを回す）→ `3_DockerComposeDown.bat`（停止）**。`CTS\README.md` |
| `Common\` | **E2E と Stub が共用する設定**（`mpas-common.env`、`LogConf.xml`）と、**成果物の新しさの確認**（`CheckPublishFreshness.ps1`。#340） | — | — |

**E2E と Stub は、同じ作法である**（#340）。

| | |
|---|---|
| **用意**（`1_Publish*.ps1`） | publish と証明書。**`appsettings.json` は雛形に差し替える**（手元の秘密をイメージに入れない）。**MPAS を直したら、先にこれ** |
| **起動**（`2_DockerComposeUp.bat`） | `up -d --build`。**手元の `appsettings.json` は起動時にマウントする。** **成果物がソースより古ければ警告する**（起動は止めない） |
| **停止**（`3_DockerComposeDown.bat`） | `down`（状態は残らない。鍵とログはホストに残る） |

**プロジェクト名は、各 `docker-compose.yml` の `name:` で決めてある**（フォルダ名に依らない）。
**E2E のテストは、この名前（ラベル）でコンテナを探す**（`ContainerTargets`）。

**手順は `root\TESTING.md` 1 節**、コマンドだけなら `root\CHEATSHEET.md` 0 節を見ること。

## バッチ（`*.bat`）は純 ASCII（#342）

**バッチの `echo` とコメントは英語で書く**（`root\CODING.md` 4 節）。
cmd は、バッチをコンソールのコード ページで読む。**日本語の Windows の既定（932）では、UTF-8 の日本語が化け、
`rem` の途中から先がコマンドとして実行されることもある**（`cmd /c` では再現しない）。
**日本語の説明は、ここ（と各 `README.md`）に書く。**

| バッチ | 補足 |
|---|---|
| `Store\1_DockerComposeUp.bat` | **DDL を写してから**（`0_CopyInitSql.ps1`。古いスキーマのまま起動しないため。#250 の段階 1）**DB は起動しない。** 3 つの DB には profiles が付いているので `up -d` では何も起動しない。**使う 1 つだけを名前で起動する**（3 つ同時だと、VM がメモリを使い切って固まることがある）。**Oracle の初回の起動は数分かかる** |
| `Store\2_DockerComposeDown.bat` | **profiles を 3 つとも並べて `down -v` する。** 並べないと `down` の対象から外れてコンテナが残る（実測）。**`--remove-orphans` では消えない**（profiles の付いたサービスは orphan 扱いにならない） |
| `E2E\2_DockerComposeUp.bat`・`Stub\2_DockerComposeUp.bat` | **`--build` を付ける**（#294。付けないと、publish した成果物がイメージに入らない）。起動の前に、成果物の新しさを確かめる（`Common\CheckPublishFreshness.ps1`） |
| `E2E\3_DockerComposeDown.bat`・`Stub\3_DockerComposeDown.bat` | **状態は残らない**（`UserStoreType=mem`）。**DataProtection の鍵（`keys*\`）とログ（`logs*\`）はホストに残る** |
| `Stub\2_DockerComposeUp.bat`・`Stub\3_DockerComposeDown.bat` | パラメタのファイルが無ければ、**終了コード 1** で止まる。**括弧の中で `exit /b` しない**（`cmd /c` から呼ぶと、終了コードが 0 になることがある） |
