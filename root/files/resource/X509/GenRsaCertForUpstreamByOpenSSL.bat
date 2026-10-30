@echo off
rem **上流 IdP 用の RSA 鍵を作る**（#293 の段階 1 / #292 の段階 1）。
rem   **下流（この配備）と別の鍵にするため**に在る。
rem   **ハイブリッド IdP の E2E で、上流コンテナだけがこの鍵を使う**
rem   （Container/E2E/docker-compose.yml の upstream で RsaPfxFilePath を向け替えている）。
rem
rem **GenRsaCertByOpenSSL.bat と違い、対話で聞かない**（subject と pfx のパスワードを決め打ち）。
rem   **E2E と開発用の鍵**なので、**本番では使わないこと**（パスワードもここに書いてある）。
rem
rem **引数で接尾辞を渡せる**（#292 の段階 1。上流が n 件になるため）。
rem   引数なし : SHA256RSA_Upstream.cer / .pfx
rem   Upstream2 : SHA256RSA_Upstream2.cer / .pfx
rem
rem 使い方 : GenRsaCertForUpstreamByOpenSSL.bat [接尾辞]（pfx のパスワードは test）

setlocal
set NAME=%1
if "%NAME%"=="" set NAME=Upstream

openssl genrsa -out %NAME%-private-key.pem 2048
openssl req -new -key %NAME%-private-key.pem -subj "/CN=x" -out %NAME%.csr
openssl x509 -in %NAME%.csr -days 365000 -req -signkey %NAME%-private-key.pem -out SHA256RSA_%NAME%.cer
openssl pkcs12 -export -inkey %NAME%-private-key.pem -in SHA256RSA_%NAME%.cer -passout pass:test -out SHA256RSA_%NAME%.pfx

del %NAME%-private-key.pem
del %NAME%.csr
endlocal

rem **作り直したら、その上流の JwkSet も作り直すこと。**
rem   CommandLineTools/CreateJwkSetJson を、上流の設定（SpRp_RsaCerFilePath と JwkSetFilePath）で 1 回回す。
rem   出力 : resource/MultiPurposeAuthSite/JwkSet_<接尾辞>.json
