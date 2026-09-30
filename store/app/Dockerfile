# ##################################################################################################
# ハイブリッド IdP の**上流側**を動かすコンテナ（#250 の段階 2）
#
#   **下流（連携する側）はホストで動かす**（Visual Studio / test.ps1 -Launch）。
#   **このコンテナは上流（連携される側）だけを受け持つ。**
#
#   **ホストビルド型である。** `3_PublishUpstream.ps1` が publish した成果物を写すだけ。
#   コンテナ内ビルド型にしなかったのは、**Open棟梁 のアセンブリを HintPath で参照している**ため
#   （`root/programs/OpenTouryoAssemblies/Build_netcore100`）。
#   コンテナの中で建てるには、そこまで持ち込む必要がある。**必要になったら足す。**
#
#   **PathBase は無い**（`UsePathBase` を呼んでいない）ので、**root で配信する**。
#   Visual Studio の仮想ディレクトリ（/MultiPurposeAuthSite）とは形が違う。
#
#   **リソース（C:\root\files\resource）はイメージに入れず、compose がマウントする。**
#   署名鍵（X509 の pfx、JwkSet.json）を含むため、**イメージに焼くべきではない。**
#   中身は Readme.ja.md の手順でホストに用意されているものを、そのまま使う。
# ##################################################################################################

FROM mcr.microsoft.com/dotnet/aspnet:10.0

WORKDIR /app

# **publish 済みの成果物を写す**（3_PublishUpstream.ps1 が用意する）
COPY publish/ ./

# **log4net の構成だけは差し替える**（雛形は Windows のパスを書いているため）。
#   雛形の "C:\root\files\..." は Linux では区切り文字と見なされず、
#   **その名前のファイルが /app に出来てしまい、読めない。**
#   これは **/app/logs に出す**（compose が store/logs にマウントする）。
COPY LogConf.xml ./
RUN mkdir -p /app/logs

# HTTPS だけで待ち受ける。証明書は compose がマウントして環境変数で渡す
EXPOSE 8081

ENTRYPOINT ["dotnet", "MultiPurposeAuthSite.dll"]
