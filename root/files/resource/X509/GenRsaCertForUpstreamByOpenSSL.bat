@echo off
rem **上流 IdP 用の RSA 鍵を作る**（#293 の段階 1）。
rem   **下流（この配備）と別の鍵にするため**に在る。
rem   **ハイブリッド IdP の E2E で、上流コンテナだけがこの鍵を使う**
rem   （store/docker-compose.yml の upstream で RsaPfxFilePath を向け替えている）。
rem
rem **GenRsaCertByOpenSSL.bat と違い、対話で聞かない**（subject と pfx のパスワードを決め打ち）。
rem   **E2E と開発用の鍵**なので、**本番では使わないこと**（パスワードもここに書いてある）。
rem
rem 出力 : SHA256RSA_Upstream.cer / SHA256RSA_Upstream.pfx（パスワードは test）

openssl genrsa -out upstream-private-key.pem 2048
openssl req -new -key upstream-private-key.pem -subj "/CN=x" -out upstream.csr
openssl x509 -in upstream.csr -days 365000 -req -signkey upstream-private-key.pem -out SHA256RSA_Upstream.cer
openssl pkcs12 -export -inkey upstream-private-key.pem -in SHA256RSA_Upstream.cer -passout pass:test -out SHA256RSA_Upstream.pfx

del upstream-private-key.pem
del upstream.csr

rem **作り直したら、上流の JwkSet も作り直すこと。**
rem   CommandLineTools/CreateJwkSetJson を、上流の設定（RsaCerFilePath と JwkSetFilePath）で 1 回回す。
rem   出力 : resource/MultiPurposeAuthSite/JwkSet_Upstream.json
