@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Create the RSA key for an upstream IdP (#293 step 1 / #292 step 1), so that it differs from
rem this deployment (downstream). In the hybrid IdP E2E, only the upstream containers use it
rem (container/E2E/docker-compose.yml points RsaPfxFilePath / RsaCerFilePath to it).
rem
rem Unlike GenRsaCertByOpenSSL.bat, it does not ask (the subject and the pfx password are fixed).
rem This key is for E2E and development only. Do not use it in production (the password is written here).
rem
rem Usage: GenRsaCertForUpstreamByOpenSSL.bat [suffix]   (pfx password: test)
rem   no argument : SHA256RSA_Upstream.cer / .pfx
rem   Upstream2   : SHA256RSA_Upstream2.cer / .pfx   (#292 step 1: there can be n upstreams)

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

rem After recreating it, recreate the JwkSet of that upstream as well:
rem   run CommandLineTools/CreateJwkSetJson once with the upstream settings
rem   (RsaCerFilePath and JwkSetFilePath; before #339, SpRp_RsaCerFilePath).
rem   Output: resource/MultiPurposeAuthSite/JwkSet_<suffix>.json
