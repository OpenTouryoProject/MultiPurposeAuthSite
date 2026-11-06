# コンテナの定義

**テストのためのコンテナを、用途別に置いてある**（#318。もとは `store\` と `stub\`）。
**どれも MPAS の配備用ではない**（パスワードや秘密はテスト用の固定値）。

| ディレクトリ | 何 | compose のプロジェクト名 | 起動 |
|---|---|---|---|
| `Store\` | **E2E 用の UserStore の DB**（SQL Server・Oracle・PostgreSQL） | `mpas-store` | **通しでは `test.ps1` が、使う 1 つだけを起動・停止する**（`-UserStoreType` が `mem` 以外のとき） |
| `E2E\` | **ID 連携の E2E で使う IdP 群**（上流・上流 2・下流）と、**`jwks_uri` を配る nginx** | `mpas-e2e` | **`1_PublishIdP.ps1`（用意）→ `2_DockerComposeUp.bat`（起動）→ `3_DockerComposeDown.bat`（停止）**（#340） |
| `Stub\` | **他のリポジトリ（Open棟梁 など）のテストから使う IdP のスタブ** | `mpas-stub` | **`1_PublishStub.ps1`（用意）→ `2_DockerComposeUp.bat`（起動）→ `3_DockerComposeDown.bat`（停止）**。`Stub\README.md` |
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
