# ##################################################################################################
# MPAS のスタブを動かすコンテナ（#294）
#
#   **作りは store\app\Dockerfile と同じ**（ホストビルド型。publish 済みの成果物を写すだけ）。
#   **違うのは中身の appsettings.json** — **雛形（_appsettings.json）である**（1_PublishStub.ps1 が入れる）。
#   **開発者の手元の appsettings.json（秘密を含む）は、イメージに入れない。**
#
#   **リソース（署名鍵など）はイメージに入れず、compose がマウントする**（store\ と同じ理由）。
# ##################################################################################################

FROM mcr.microsoft.com/dotnet/aspnet:10.0

WORKDIR /app

# **publish 済みの成果物を写す**（1_PublishStub.ps1 が用意する）
COPY publish/ ./

# **log4net の構成だけは差し替える**（雛形は Windows のパスを書いているため）。
#   1_PublishStub.ps1 が store\app\LogConf.xml を写して置く（二重に持たない）。
COPY LogConf.xml ./
RUN mkdir -p /app/logs

# HTTPS だけで待ち受ける。証明書は compose がマウントして環境変数で渡す
EXPOSE 8081

ENTRYPOINT ["dotnet", "MultiPurposeAuthSite.dll"]
