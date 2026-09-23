@echo off
rem クライアント証明書（mTLS 用）を作り直す。
rem
rem   ・出来上がるのは _SHA256RSAClientCert.cer / _SHA256RSAClientCert.pfx
rem     （既存を壊さないよう、先頭に _ が付く。確認してから名前を変えて置き換える）
rem   ・パスワードは test（構成ファイルの SpRp_ClientCertPfxPassword と同じ）
rem   ・Subject は、クライアント登録の tls_client_auth_subject_dn と一致させること
rem     （雛形では TestClient1 / TestClient2 の値）
rem   ・PKCS#12 の暗号化は古い方式に揃える。net48（.NET Framework）で読めるようにするため
rem
rem 詳細は CONFIGURATION.md 8 節。

where openssl >nul 2>&1
if errorlevel 1 (
    echo openssl が PATH にありません。
    echo OpenSSL を入れるか、Git 同梱のもの（mingw64 の bin）に PATH を通してから実行してください。
    exit /b 1
)

set SUBJECT=/CN=MPAS Test Client
set DAYS=36500
set PASSWORD=test

openssl req -x509 -newkey rsa:2048 -sha256 -days %DAYS% -nodes ^
  -keyout _client-private-key.pem -out _SHA256RSAClientCert.cer ^
  -subj "%SUBJECT%" -addext "extendedKeyUsage=clientAuth" -addext "basicConstraints=CA:FALSE"

openssl pkcs12 -export -inkey _client-private-key.pem -in _SHA256RSAClientCert.cer ^
  -out _SHA256RSAClientCert.pfx -passout pass:%PASSWORD% ^
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1

del _client-private-key.pem

openssl x509 -in _SHA256RSAClientCert.cer -noout -subject -dates
