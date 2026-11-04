**相手（RP）の JWK Set を置く場所**（#309 の段階 1）。

**`jwks` コンテナが、ここを `http://localhost:44305/` で配る。**
**中身は E2E が書いて、同じテストの中で消す**（`Infrastructure/JwksUri`）。
**`.json` は追跡しない**（`.gitignore`）。
