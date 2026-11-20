**相手（RP）の JWK Set を置く場所**（#309 の段階 1）。

**`jwks` コンテナが、ここを `http://localhost:44305/` で配る。**
**中身は E2E が書いて、同じテストの中で消す**（`Infrastructure/JwksUri`）。
**`.json` は追跡しない**（`.gitignore`）。

**`/redirect/<名前>` は、`/<名前>` へ 302 で送る**（#405。`RT-405.1`。`JwksUri.RedirectUrl`）。設定は `container/E2E/jwks-nginx.conf`（変えたら `docker compose -p mpas-e2e restart jwks`）。
