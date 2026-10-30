@echo off
rem **docker compose（v2）**。-v でボリュームも消す（E2E 用なので作り直せる方がよい）
rem
rem   **profiles を 3 つとも並べる。** DB には profiles が付いているので、
rem   **並べないと down の対象から外れ、コンテナが残る**（実測で確認した）。
rem   **--remove-orphans では消えない**（profiles の付いたサービスは orphan 扱いにならない）。
docker compose --profile postgres --profile sqlserver --profile oracle down -v
