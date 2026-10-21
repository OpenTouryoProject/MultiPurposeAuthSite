<#
.SYNOPSIS
    E2E テストを実行する。必要なら対象のサイトを起動してから実行する。

.DESCRIPTION
    テストは「動いているサイト」を HTTP で叩く。したがって、実行前に
    テスト対象が起動している必要がある。

    -Launch を付けると、**net10.0 版と net48 版の両方を起動**し、
    テストの後に停止する。

      net10.0 版 : Kestrel        既定 https://localhost:44300
      net48 版   : IIS Express    既定 https://localhost:44302

    ** なぜ URL を合わせる必要があるか **

    アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、サーバ自身が
    「構成ファイルに書かれた URL」へ HTTP で折り返す。
    叩き先と構成が食い違うと、その折り返しが接続不能になり HTTP 500 になる。

    また、認証まわりの Cookie は SameSite=None で発行されるため、
    ** http では保持されない。** max_age を使うフロー（FAPI2）は
    auth_time Cookie を見るので、https で動かす必要がある。

    ** どうやって合わせるか **

    構成ファイルを書き換えずに、**環境変数で上書きする。**
    Open棟梁 の GetConfigParameter は、appSettings の FxContainerization が
    ON のとき、設定ファイルより環境変数を優先する（net48 / net10.0 の両方）。

      OAuth2AuthorizationServerEndpointsRootURI
      OAuth2ClientEndpointsRootURI

    キー名がそのまま環境変数名になる（接頭辞は付かない）。
    このため、**net48 版を app.config の URL に置く必要はない。**
    別ポートへ寄せられるので、net10.0 版と URL が衝突しない。

.PARAMETER UserStoreType
    サイトが使う UserStore の種類（mem / sql / ora / npg）。既定は mem。

    ** 既定を mem のままにしている理由 **

    sql / ora / npg は、対応する DBMS が動いていることが前提になる。
    既定を変えると、DBMS の無い環境で E2E が回らなくなる。

    ** 切り替えるときに要るもの **

    接続文字列。-ConnectionString で渡すか、環境変数で渡す。

      sql : MPAS_CONNSTR_SQL   （キー名 ConnectionString_SQL）
      ora : MPAS_CONNSTR_ODP   （キー名 ConnectionString_ODP）
      npg : MPAS_CONNSTR_NPS   （キー名 ConnectionString_NPS）

    **スクリプトに既定値を書かない。** 書いたものは事実上の資格情報になる。

    ** 事前に要ること **

    対象の DBMS に、空のデータベース（スキーマ）と
    files/resource/MultiPurposeAuthSite/Sql/<dbms>/Create_UserStore.sql の実行。
    ロール・管理者・テスト ユーザは、**初回の /Account/Login でサイトが作る**
    （CreateData が Roles の件数で初期化済みかを判定する）。

    ** net48 は npg を選べない **

    Npgsql の参照が #if NETCORE で囲まれているため、net48 版は PostgreSQL を使えない。
    -UserStoreType npg のときは、net48 版を起動しない（その分は Skip）。

.PARAMETER ConnectionString
    -UserStoreType が mem 以外のときに使う接続文字列。
    省略した場合は、上記の環境変数から読む。

.PARAMETER NoStoreContainer
    **store\ の DB コンテナを、起動も停止もしない。**

    既定では、-UserStoreType が mem 以外のとき、**接続文字列が store\ の
    ポート（1434 / 1522 / 5433）を指していれば、その DB コンテナを起動し、
    終わったら停止する**（3 つ同時に起動するとメモリを使い切るため。
    store\docker-compose.yml の「メモリの節約」）。

    **自分が起動したものだけを止める。** 既に起動していれば、そのまま残す。

    **接続文字列が store\ のポートを指していなければ、何もしない**
    （手動確認の LocalServicesOnDocker は既定ポートなので、自動で対象外になる）。
    このスイッチは、それでも触らせたくないときに使う。

.PARAMETER Launch
    net10.0 版と net48 版を起動してからテストする。

.PARAMETER Url
    net10.0 版が待ち受ける URL（既定 https://localhost:44300）。

.PARAMETER NetFxUrl
    net48 版が待ち受ける URL（既定 https://localhost:44302）。
    44300〜44399 は IIS Express の開発用証明書が http.sys に登録済み。

.PARAMETER NoNetFx
    net48 版を起動しない。その分のテストは Skip される。

.PARAMETER NetFxMtls
    net48 版でも mTLS のテスト（FA-6）を回す（#226）。**準備が要る**（TESTING.md「net48 版の mTLS」）。
    IIS Express にクライアント証明書を要求させ（sslFlags="Ssl, SslNegotiateCert"）、
    テストは CurrentUser\My に用意した証明書を使う。
    IIS は信頼できない証明書をアプリより前で 403.16 として断るので、
    **発行元（テスト用 CA）を、コンピューターの信頼されたルートに入れておく必要がある**（管理者権限）。
    付けなければ、FA-6 は net10.0 版だけを測る（net48 版のケースは作らない。Skip にもならない）。

.PARAMETER ShortLifetimes
    **有効期限のテスト（RT-188）専用。** 認可コード・Request Object・refresh_token の寿命を
    ごく短くしてサイトを起動する（#188）。

    **-Filter と併せて使うこと。** 寿命が短いので、他のテストは落ちる。
      .\test.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"

    付けなければ、有効期限のテストはケースを作らない（Skip にもならない）。

.PARAMETER DPoPNonce
    **DPoP の nonce のテスト（RT-311.13 / RT-311.14）専用。**
    **nonce を要求する設定（EnableDPoPNonce）でサイトを起動する**（#311 の段階 4）。

    **-Filter と併せて使うこと。** **nonce を知らない証明は全部断られる**ので、
    他の DPoP のテストは落ちる。
      .	est.ps1 -Launch -DPoPNonce -Filter "FullyQualifiedName~DPoPNonceTests"

    付けなければ、nonce のテストはケースを作らない（Skip にもならない）。

.PARAMETER NoWebUI
    ブラウザで測るもの（`Tests/WebUI`。識別子 UI-n.n）を走らせない。
    既定では走らせる（ブラウザが無ければ Skip する）。

.PARAMETER Filter
    dotnet test の --filter に渡す式。

.PARAMETER LogDir
    サイトの起動ログ（MpasSite.*.log / IisExpress.*.log）の出力先。
    既定は E2ETests\Result（.gitignore 済み）。

.PARAMETER TrxPath
    テスト結果を TRX（XML）でも書き出す先。
    上位の ..\..\2_RunAllTests.ps1 が集計に使う。

    コンソール出力の集計行（"テストの合計数: ..."）はロケールで変わるため、
    機械で読むときはこちらを使う。

.EXAMPLE
    .\test.ps1 -Launch
    .\test.ps1 -Launch -NoNetFx
    .\test.ps1 -Filter "FullyQualifiedName~RequestObjectTests"
    .\test.ps1 -Launch -NetFxMtls -Filter "FullyQualifiedName~MtlsTests"
    .\test.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"

.EXAMPLE
    # SQL Server のストアで回す（接続文字列は環境変数から）
    $env:MPAS_CONNSTR_SQL = 'Data Source=localhost;Initial Catalog=UserStore;User ID=sa;Password=***;'
    .\test.ps1 -Launch -UserStoreType sql

.EXAMPLE
    # PostgreSQL のストアで回す（net48 版は自動的に Skip される）
    .\test.ps1 -Launch -UserStoreType npg -ConnectionString 'HOST=localhost;DATABASE=UserStore;USER ID=postgres;PASSWORD=***'
#>
[CmdletBinding()]
param(
    [switch] $Launch,
    [ValidateSet('mem', 'sql', 'ora', 'npg')]
    [string] $UserStoreType = 'mem',
    [string] $ConnectionString,
    [switch] $NoStoreContainer,
    [string] $Url = 'https://localhost:44300',
    [string] $NetFxUrl = 'https://localhost:44302',
    [switch] $NoNetFx,
    [switch] $NetFxMtls,
    [switch] $ShortLifetimes,
    [switch] $DPoPNonce,
    [switch] $NoWebUI,
    [string] $Filter,
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',
    [string] $TrxPath,
    [string] $LogDir
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# パスの既定値は、param() ではなく本体で決める
# ------------------------------------------------------------------
# **$PSScriptRoot を param() の既定値で使わない。**
# [CmdletBinding()] を付けたスクリプトを Windows PowerShell 5.1 で
# -File 起動すると、既定値を評価する時点では $PSScriptRoot が空で、
#   Join-Path : Cannot bind argument to parameter 'Path' because it is an empty string.
# になる（[CmdletBinding()] が無ければ入る。PowerShell 7 では両方とも入る）。
#
# 0_RunAll.ps1 から & で呼ぶ分には呼び出し元の値が見えるため表面化せず、
# **単体で -File 起動したときだけ落ちる。**
# ------------------------------------------------------------------

if (-not $LogDir) {
    $LogDir = Join-Path $PSScriptRoot 'E2ETests\Result'
}

# ------------------------------------------------------------------
# store\ の DB コンテナ（#305 の後）
# ------------------------------------------------------------------
# **DB を 3 つ同時に起動すると、Docker の VM がメモリを使い切って固まることがある。**
#   **使うストアの DB だけを、テストの間だけ起動する**
#   （store\docker-compose.yml の「メモリの節約」。方針は LocalServicesOnDocker の CHEATSHEET）。
#
# **自分が起動したものだけを止める。** **人が自分で上げていた DB は、そのまま残す。**
#
# **対象かどうかは、接続文字列のポートで決める**（store\ は +1 にしてある）。
#   **既定ポート（＝ 手動確認の LocalServicesOnDocker）なら、触らない。**

$script:StoreDir = Join-Path `
    (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'store'

function Get-StorePortFromConnStr
{
    param([string] $UserStoreType, [string] $ConnStr)

    if (-not $ConnStr) { return $null }

    #  **方言ごとに書き方が違う。**
    #    sql : Data Source=localhost,1434
    #    ora : Data Source=localhost:1522/FREEPDB1
    #    npg : PORT=5433
    switch ($UserStoreType)
    {
        'sql' { if ($ConnStr -match 'Data\s*Source\s*=\s*[^;,]+,\s*(\d+)') { return [int] $Matches[1] } }
        'ora' { if ($ConnStr -match 'Data\s*Source\s*=\s*[^;:]+:\s*(\d+)')  { return [int] $Matches[1] } }
        'npg' { if ($ConnStr -match '(?i)(^|;)\s*PORT\s*=\s*(\d+)')         { return [int] $Matches[2] } }
    }

    return $null
}

function Test-StorePort
{
    param([int] $Port)

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async  = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $opened = $async.AsyncWaitHandle.WaitOne(1000)

        if ($opened) { $client.EndConnect($async) }

        $client.Close()
        return $opened
    }
    catch {
        return $false
    }
}

function Invoke-StoreDocker
{
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $DockerArgs)

    #  **store\ で実行する。** compose のプロジェクト名をフォルダ名（store）に合わせるため。
    #  **profiles が付いたサービスは、名前を明示すれば起動できる**（--profile は要らない）。
    Push-Location $script:StoreDir
    try {
        return (& docker @DockerArgs 2>&1 | Out-String)
    }
    finally {
        Pop-Location
    }
}

function Start-StoreContainer
{
    param([string] $Service, [int] $Port, [string] $Name)

    if (Test-StorePort -Port $Port) {
        Write-Host ("  {0} は既に起動しています（このテストでは止めません）。" -f $Name) -ForegroundColor Yellow
        return $false
    }

    Write-Host ("  {0} のコンテナを起動します（docker compose up -d {1}）..." -f $Name, $Service) `
        -ForegroundColor Cyan

    #  **起動した時刻を控える**（ログを「ここから後」だけ見るため）。
    #    **docker compose logs は、再起動をまたいで前回の分も残る** —
    #    **前回の "done." を見て即座に先へ進んでしまった**（実測で踏んだ）。
    #    **2 秒戻す**のは、ホストとデーモンの時計のずれを見込んで。
    $script:StoreSince = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $out = Invoke-StoreDocker 'compose' 'up' '-d' $Service

    if ($LASTEXITCODE -ne 0) {
        throw ("DB コンテナの起動に失敗しました（{0}）。`n{1}" -f $Service, $out)
    }

    return $true
}

function Wait-Store
{
    param([string] $Service, [int] $Port, [string] $Name,
          [string] $Since, [int] $TimeoutSeconds = 900)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    Write-Host ("  {0} が使えるようになるのを待ちます..." -f $Name) -ForegroundColor Cyan

    while ((Get-Date) -lt $deadline) {

        switch ($Service)
        {
            'oracle' {
                #  **healthcheck を見る**（compose の healthcheck は oracle にだけ在る）。
                #    **ポートが開いても、DB はまだ初期化中のことがある。初回は数分かかる。**
                $id = (Invoke-StoreDocker 'compose' 'ps' '-q' $Service).Trim()

                if ($id) {
                    $health = (& docker inspect $id --format '{{.State.Health.Status}}' 2>&1 | Out-String).Trim()

                    if ($health -eq 'healthy')   { Write-Host '    使えます。' -ForegroundColor Green; return }
                    if ($health -eq 'unhealthy') { throw ("{0} が unhealthy になりました。" -f $Name) }
                }
            }

            'sqlserver' {
                #  **ポートが開いただけでは足りない。**
                #    **init/0_start-up.sh は sqlservr と並行に走る**ので、
                #    **DDL が流れ終わる前にテストを始めると落ちる。**
                #    **しかも 1_Create_UserStore.sql は破壊的で、起動の度に
                #    UserStore を DROP して作り直す** — **待たないと、サイトの初期化と衝突する。**
                #
                #  **ログは「起動した時刻から後」だけを見る**（$Since）。
                #    **docker compose logs は再起動をまたいで残る**ので、
                #    **全部を見ると前回の "done." で通ってしまう**（実測で踏んだ）。
                #    **自分で起動していないとき（$Since が空）は、ポートだけを見る。**
                if (Test-StorePort -Port $Port) {

                    if (-not $Since) {
                        Write-Host '    使えます（既に起動していたので、ログは見ません）。' -ForegroundColor Green
                        return
                    }

                    $log = Invoke-StoreDocker 'compose' 'logs' '--since' $Since $Service

                    if ($log -match 'done\.') { Write-Host '    使えます。' -ForegroundColor Green; return }
                    if ($log -match 'did not accept logins') {
                        throw ("{0} がログインを受け付けませんでした。" -f $Name)
                    }
                }
            }

            default {
                #  **postgres は、初期化 SQL が終わってから外の接続を受ける**
                #    （公式イメージの entrypoint が、初期化中は Unix ソケットだけで動かす）。
                #    **ポートが開けば、DDL は流れ終わっている。**
                if (Test-StorePort -Port $Port) { Write-Host '    使えます。' -ForegroundColor Green; return }
            }
        }

        Start-Sleep -Seconds 5
    }

    throw ("{0} が {1} 秒以内に使える状態になりませんでした。" -f $Name, $TimeoutSeconds)
}

function Stop-StoreContainer
{
    param([string] $Service, [string] $Name)

    Write-Host ("  {0} のコンテナを停止します（docker compose stop {1}）..." -f $Name, $Service) `
        -ForegroundColor Cyan

    $null = Invoke-StoreDocker 'compose' 'stop' $Service
}

# ------------------------------------------------------------------
# UserStore の切り替え（#207）
# ------------------------------------------------------------------
# 設定ファイルは書き換えない。**環境変数で上書きする**（FxContainerization=ON）。
# キー名がそのまま環境変数名になるので、ConnectionString_* を直接渡せる。
#
# **接続文字列の既定値は持たない。** 引数か環境変数で受ける。
#
# **Service / Port は store\docker-compose.yml のもの**（#305 の後）。
#   **接続文字列がこのポートを指していれば、その DB コンテナを都度 起動・停止する。**
#   **指していなければ触らない**（手動確認の LocalServicesOnDocker は既定ポート）。
$storeKeys = @{
    'sql' = @{ Key = 'ConnectionString_SQL'; Env = 'MPAS_CONNSTR_SQL'; Name = 'SQL Server'; Service = 'sqlserver'; Port = 1434 }
    'ora' = @{ Key = 'ConnectionString_ODP'; Env = 'MPAS_CONNSTR_ODP'; Name = 'Oracle';     Service = 'oracle';    Port = 1522 }
    'npg' = @{ Key = 'ConnectionString_NPS'; Env = 'MPAS_CONNSTR_NPS'; Name = 'PostgreSQL'; Service = 'postgres';  Port = 5433 }
}

$storeConnKey = $null
$storeConnStr = $null

# **都度 起動・停止する DB コンテナ**（#305 の後。mem のときと、対象外のときは $null）。
$storeService = $null
$storePort    = $null
$storeStarted = $false

if ($UserStoreType -ne 'mem') {

    $info = $storeKeys[$UserStoreType]
    $storeConnKey = $info.Key

    # 引数が優先。無ければ環境変数。
    $storeConnStr = $ConnectionString
    if (-not $storeConnStr) {
        $storeConnStr = [Environment]::GetEnvironmentVariable($info.Env)
    }

    if (-not $storeConnStr) {
        throw ("-UserStoreType {0}（{1}）には接続文字列が要ります。" -f $UserStoreType, $info.Name) `
            + "`n  -ConnectionString で渡すか、環境変数 $($info.Env) に設定してください。" `
            + "`n  **スクリプトに既定値は持たせていません**（資格情報になるため）。"
    }

    Write-Host ("UserStore : {0}（{1}）" -f $UserStoreType, $info.Name) -ForegroundColor Cyan
    Write-Host ("  接続文字列は {0} として渡します（内容は表示しません）。" -f $storeConnKey)

    # **store\ の DB コンテナを、都度 起動・停止するか**（#305 の後）。
    #   **接続文字列から読めたポートが store\ のものなら、対象にする。**
    #   **読めない（＝ 既定ポート）/ 違う番号なら、別の DBMS を指している**ので触らない。
    if (-not $NoStoreContainer) {

        $foundPort = Get-StorePortFromConnStr -UserStoreType $UserStoreType -ConnStr $storeConnStr

        if ($foundPort -eq $info.Port) {
            $storeService = $info.Service
            $storePort    = $info.Port
            Write-Host ('  DB コンテナ : {0}（ポート {1}）を、このテストの間だけ起動します。' -f $storeService, $storePort) -ForegroundColor Cyan
        }
        elseif ($null -eq $foundPort) {
            Write-Host '  接続文字列にポートがありません（既定ポート）。' -ForegroundColor Yellow
            Write-Host '    store\ の DB ではないと判断し、コンテナは触りません。' -ForegroundColor Yellow
        }
        else {
            Write-Host ('  接続文字列のポートは {0} で、store\ の {1} ではありません。' -f $foundPort, $info.Port) -ForegroundColor Yellow
            Write-Host '    コンテナは触りません。' -ForegroundColor Yellow
        }
    }

    # **net48 は PostgreSQL を選べない。** Npgsql の参照が #if NETCORE で囲まれている。
    if ($UserStoreType -eq 'npg' -and -not $NoNetFx) {
        Write-Host '  net48 版は PostgreSQL を使えないため、起動しません（その分は Skip）。' -ForegroundColor Yellow
        $NoNetFx = $true
    }
}

$programs = Split-Path -Parent $PSScriptRoot
$csproj   = Join-Path $PSScriptRoot 'E2ETests\E2ETests.csproj'
$coreDir  = Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore'
$netFxDir = Join-Path $programs 'MultiPurposeAuthSite\MultiPurposeAuthSite'
$iisExe   = Join-Path $env:ProgramFiles 'IIS Express\iisexpress.exe'
$iisTmpl  = Join-Path $env:ProgramFiles 'IIS Express\config\templates\PersonalWebServer\applicationhost.config'

# ------------------------------------------------------------------
# 起動を待つ
# ------------------------------------------------------------------
# **開発用の自己署名証明書を通す方法を、5.1 と 7 で分ける。**
# 同じ書き方で両方を通せなかった。この環境で実測した結果は次のとおり。
#
#   方法                                    5.1   7
#   --------------------------------------  ----  ----
#   Invoke-WebRequest                       NG    OK  （7 は -SkipCertificateCheck）
#   HttpWebRequest + ServicePointManager    OK    NG
#   HttpWebRequest + 個別のコールバック     -     NG
#   HttpClient + コールバック               NG    OK
#
#   5.1 の NG : 「接続が切断されました: 送信時に、予期しないエラーが発生しました。」
#
# **5.1 の証明書検証コールバックは、コンパイルしたデリゲートにすること**（#226）。
# スクリプト ブロックだと、クライアント証明書のネゴシエーション時に別スレッドから呼ばれ、実行できない。
#   7   の NG : 「The SSL connection could not be established」
#
# 生の SslStream は 5.1 でも 1.2 / 1.3 の両方で成功するので、
# **TLS そのものの問題ではない。**
# 版差の原因を追うより、それぞれで通ることを確認した方法を使う。
# **software_statement の発行者（#307 の段階 4）。**
#   **E2E は、この iss で statement に署名する**（RT-307.18 〜 .21）。
#   **署名鍵は SpRp_RsaPfxFilePath**（JwsSigner.SignRS256）なので、
#   **サイトには、その対の .cer を「発行者の検証鍵」として渡す。**
#
#   **雛形の既定は空**（＝ software_statement を受け付けない）なので、
#   **テストでは、ここで渡して有効にする。**
#   **渡さないと RT-307.18 〜 .21 は Skip になる**（-Launch でないときも同じ）。
$script:SoftwareStatementIssuerKey = 'e2e_vendor'
$script:SoftwareStatementIssuer    = 'https://vendor.opentouryo.com'
# **証明書は 2 本渡す**（#307 の段階 6 の (D)）。
#   **発行者の鍵の入れ替えを測るため** — **新旧を並べた状態**を作る。
#   **1 本目** : `SpRp_RsaPfxFilePath` の対（**既存の `RT-307.18` 〜 `.21` が使う**）
#   **2 本目** : `RsaPfxFilePath` の対（**`RT-307.26` が、こちらで署名する**）
#   **区切りは空白**（`PreviousSigningCerFilePaths` と同じ流儀）。
#
#   **`SHA256RSAClientCert.cer` は使えない** — **リポジトリには在るが、
#   配備側（C:/root/files/resource/X509）に配られていない**（実測で踏んだ）。
#   **サイトが読むのは配備側**なので、**配られているものから選ぶこと。**
$script:SoftwareStatementCer       = 'C:/root/files/resource/X509/SHA256RSA_Client.cer ' `
    + 'C:/root/files/resource/X509/SHA256RSA_Server.cer'
$script:SoftwareStatementAlg       = 'RS256'

# **発行者に許す範囲**（#307 の段階 6 の (A)）。
#   **既存のケースが登録するのは `openid` と `openid email` だけ**（実測で確かめた）なので、
#   **上限はそこまでに絞る** — **広く取ると「範囲の外」が無くなり、`RT-307.25` が測れない。**
#   **grant_types は、既存のケースが登録する 3 つを含める**
#   （`authorization_code` / `refresh_token` / device_code）。
$script:SoftwareStatementAllowedScope = 'openid email'
$script:SoftwareStatementAllowedGrantTypes =
    'authorization_code refresh_token urn:ietf:params:oauth:grant-type:device_code'


# **テストで使うクレームの対応付け（#230）。**
#   キーはクレーム名（address.<副フィールド> と書くと address オブジェクトを組み立てる）、
#   値は UnstructuredData の中のキー（usd1 / usd2 は /Manage/AddUnstructuredData で入れられる）
#   または user:<項目>。**両サイトへ同じ内容を差し込む**（RT-230 が参照する）。
$script:UserClaimsMapping = [ordered]@{
    # **画面（usd1 / usd2）から入れた値を測る分**（#230。RT-230.*）。
    #   **ここは標準クレームの名前に変えない。** 管理画面で入れられるのは この 2 欄だけなので、
    #   変えると「画面から入れた値が返る」経路を測れなくなる（#261 の判断）。
    'name'                = 'usd1'
    'address.locality'    = 'usd2'
    # **ApplicationUser から直に取る分**（#151 の段階 1）。
    'preferred_username'  = 'user:UserName'
    # **仕込んだ標準クレームを測る分**（#261。2 人目の利用者の UnstructuredData）。
    #   キー名とクレーム名が同じなので、対応付けは素直に 1 対 1 になる。
    'given_name'          = 'given_name'
    'family_name'         = 'family_name'
    'nickname'            = 'nickname'
    'profile'             = 'profile'
    'picture'             = 'picture'
    'website'             = 'website'
    'gender'              = 'gender'
    'birthdate'           = 'birthdate'
    'zoneinfo'            = 'zoneinfo'
    'locale'              = 'locale'
    'updated_at'          = 'updated_at'
    'address.formatted'   = 'address.formatted'
    'address.street_address' = 'address.street_address'
    'address.region'      = 'address.region'
    'address.postal_code' = 'address.postal_code'
    'address.country'     = 'address.country'
}

# **テスト利用者の接尾辞（#260）。**
#   **2 つのサイトを同時に立てるので、DB ストアでは 1 つの DB を共有する。**
#   分けないと、**同じ利用者の DeviceToken / UnstructuredData を書き換え合って**
#   間欠で落ちる（RT-230.* / RT-233.* / EX-8.*）。
#   **mem では各サイトが自前のストア（プロセス内）を持つので、もともと起きない。**
#
#   サイト側は appSettings の TestUserSuffix として読み（種データの名前に付く）、
#   テスト側は MPAS_<対象>_TESTUSER_SUFFIX として読む（同じ値を見る）。
#   **上流（ID フェデレーションの IdP）には渡さない。** 別の DB なので分ける必要が無く、
#   渡すと「上流に居ない利用者」でサインインしようとして落ちる。
$script:TestUserSuffixCore  = '_core'
$script:TestUserSuffixNetFx = '_netfx'

# **client_credentials から動的登録を叩くクライアント（#307 の段階 5-b）。**
#   **ROPC を開けずに `/register` を叩く経路**を測るために渡す。
#
#   | | |
#   |---|---|
#   | **`…Dcr` の方** | **`scope` に専用 scope ＋ `owner`**（**所有者が決まる**） |
#   | **`…DcrNoOwner` の方** | **`scope` だけ。`owner` が無い**（**所有者が決まらない** → `403`） |
#
#   **net10.0 にだけ渡す。** **net10.0 は「節」として読む**ので
#   **クライアントを 1 件ずつ足せる**が、**net48 は 1 本の JSON 文字列**で、
#   **足すと既存のクライアントを全て置き換えてしまう。**
#   **net48 では `RT-307.23` / `.24` を Skip する**（`RT-307.15` と同じ作法）。
#
#   **所有者は、この測定のための専用の利用者**（`e2e_dcr_owner` ＋ 接尾辞）。
#   **テストが作って、終わったら消す** — **種データの利用者を使わない**
#   （**他のケースと登録を奪い合わないため**。#305 の段階 3 で踏んだ所）。
#   **接尾辞を付けるのは、サイトごとに利用者を分けているため**（#260）。
$script:DcrCcClientId          = 'e2e307dcc100000000000000000000aa'
$script:DcrCcClientSecret      = 'e2e_307_5b_dcr_cc_secret_do_not_use_in_production'
$script:DcrCcNoOwnerClientId   = 'e2e307dcc200000000000000000000bb'
$script:DcrCcNoOwnerSecret     = 'e2e_307_5b_dcr_cc_noowner_secret_do_not_use'


# **ID フェデレーションの下流として振る舞うための設定（#250 の段階 5）。**
#   上流は store\ のコンテナ（https://localhost:44301）で、**test.ps1 の管理外**である
#   （建っていなければ、連携のテストは Skip される）。
#
#   **redirect_uri はクライアント 1 件に 1 つ**なので、**下流ごとに別のクライアント**を使う。
#   登録は store\docker-compose.yml にある（上流に環境変数で差し込んでいる）。
#
#   **上流のエンドポイント（IdFederation{Authorize,Token,UserInfo}Endpoint）は上書きしない。**
#   構成ファイルが既に 44301 を指しており、**テストはその値を読んで上流を探す**ため、
#   ここで上書きすると、両者がずれたときに気付けなくなる。
$script:IdFederationClients = @{
    'core'  = @{
        ClientId = 'e2e1c0de0000000000000000000000c1'
        Secret   = 'E2E_dY3kQ8pR6tW1vZ4xA7bN0mS5jL2hG9fC'
    }
    'netfx' = @{
        ClientId = 'e2e1c0de0000000000000000000000f2'
        Secret   = 'E2E_qP7wE2rT5yU8iO1pA4sD6fG9hJ3kL0zX'
    }
}

<#
.SYNOPSIS
    ID フェデレーションの下流として振る舞う設定を、環境変数に置く（#250 の段階 5）。
.PARAMETER TargetKey
    core / netfx
.PARAMETER SiteUrl
    そのサイトが待ち受ける URL（redirect_uri の組み立てに使う）
#>
function Set-IdFederationEnv
{
    param(
        [Parameter(Mandatory)][string] $TargetKey,
        [Parameter(Mandatory)][string] $SiteUrl
    )

    $c = $script:IdFederationClients[$TargetKey]

    $env:OAuth2AndOidcClientID = $c.ClientId
    $env:OAuth2AndOidcSecret = $c.Secret

    # **E2E の下流は root で配信する**（VS の /MultiPurposeAuthSite とは形が違う）
    $env:IdFederationRedirectEndpoint = $SiteUrl.TrimEnd('/') + '/Account/IDFederationRedirectEndPoint'

    # **上流の id_token の検証鍵**（#289 の段階 1）。
    #   **上流は別の鍵を使う**（#293 の段階 1）ので、**上流の .cer を指す。**
    #   **通常は discovery から引く**ので、これは引けなかったときの倒れ先である。
    $env:IdFederationOidcDiscoveryUrl = 'https://localhost:44301/.well-known/openid-configuration'
    $env:IdFederationOidcCerFilePath = 'C:/root/files/resource/X509/SHA256RSA_Upstream.cer'

    # **SAML2 の ID 連携**（#286 の段階 2）。
    #   **上流の SSO の口**と、**自分の ACS**（上流の redirect_uri_saml に登録した値）と、
    #   **期待する上流の Issuer**と、**上流の署名証明書**。
    #   **同じ client_id を使う**（上流は Issuer = http://<client_id> で SP を引く）。
    #   **メタデータの URL**（#291）。**口と証明書は、ここから引く。**
    $env:IdFederationSaml2MetadataUrl = 'https://localhost:44301/samlmetadata'
    $env:IdFederationSaml2RequestEndpoint = 'https://localhost:44301/saml2request'
    $env:IdFederationSaml2ResponseEndpoint = $SiteUrl.TrimEnd('/') + '/Account/IDFederationAssertionConsumerService'
    $env:IdFederationSaml2IssuerId = 'https://ssoauth.opentouryo.com'
    $env:IdFederationSaml2CerFilePath = 'C:/root/files/resource/X509/SHA256RSA_Upstream.cer'

    # **user store の秘密を暗号化する鍵**（#297）。
    #   **既定の通しを「暗号化した状態」で回す**（`RT-297.*` が、その往復を測る）。
    #   **値はテスト用**で、**出力しない**（他の秘密と同じ扱い。`TESTING.md` 9 節）。
    $env:UserStoreSecretPassword = 'E2E_SecretBox_8rJ2vQ5mZ1xK'

    # **/jwkcerts のキャッシュ**（#303。E-7）。
    #   **既定の通しを「キャッシュ有効」で回す**（`RT-303.1` が Cache-Control / ETag / 304 を測る）。
    #   **短くしてある**（鍵を入れ替える周期より短いこと。`CONFIGURATION.md`）。
    $env:JwkSetCacheMaxAgeSeconds = '300'

    # **認証の失敗を数える**（#305 の段階 2）。
    #   **上限を高くしてある**（`RT-305.3` / `RT-305.4` は、この回数だけ失敗させて断りを測る）。
    #   **低くすると通しが壊れる**（実測）：**負の経路のケースが、共用のクライアントで
    #   意図的にクライアント認証を失敗させる**ので、3 回では**本筋のケースが 401 になった**
    #   （`RT-196.3` / `RT-196.4` / `EX-3.5` ほか 5 件）。
    #   **断る長さは短く**（テストは解除まで待つ）。
    $env:AuthFailureMaxAttempts = '20'
    $env:AuthFailureLockoutSeconds = '5'

    # **数えた分の寿命**（#305 の段階 4）。
    #   **上限まで叩くのに掛かる時間より、長くすること** —
    #   **短いと、数が積まれる前に忘れるので、いつまでも断らない。**
    #   **断る長さ（5 秒）とは別**である。
    $env:AuthFailureWindowSeconds = '60'

    # **利用者のロックアウト**（#305 の段階 4 で `/token` の
    #   `grant_type=password` も、この数えに合流した）。
    #   **上限を高くしてある** — **負の経路のケースが、共用のテスト利用者で
    #   意図的にパスワードを間違える**（`TC-4.2`）ため。
    #   **断る長さは短く**（`RT-305.8` が解除まで待つ）。
    $env:MaxFailedAccessAttemptsBeforeLockout = '20'
    $env:DefaultAccountLockoutTimeSpanFromSeconds = '5'

    # **口ごとのレート制限**（#305 の段階 3）。
    #   **クライアントごとの上限は高くしてある**（`RT-305.5` は、この回数を超えるまで叩く）。
    #   **低くすると通しが壊れる** — **共用のクライアントで多数のケースが同じ口を叩く**ため。
    #   **窓は短く**（テストは次の窓まで待つ）。
    #   **送信元ごとの上限は切ってある（0）** — **通しの全ケースが 127.0.0.1 を共有する**ので、
    #   有効にすると無関係なケースが 429 を受ける。**こちらは `RT-305.6` を単独で回して測る**
    #   （`TESTING.md`）。
    $env:RateLimitPerClientPermits = '300'
    $env:RateLimitWindowSeconds = '20'

    # **送信元ごとの上限だけは、呼ぶ側が先に入れていたら尊重する。**
    #   **`RT-305.6` を単独で回して測るため**である（`TESTING.md`）。
    #
    #     $env:RateLimitPerIpPermits = '50'
    #     .\2_RunAllTests.ps1 -Launch -Filter RateLimitTests
    #
    #   **通し（何も入れていないとき）は 0 ＝ 制限しない。**
    if (-not $env:RateLimitPerIpPermits)
    {
        $env:RateLimitPerIpPermits = '0'
    }

    # **転送ヘッダの取り込みも、呼ぶ側が先に入れていたら尊重する。**
    #   **`RT-305.7`（断りが送信元ごとに分かれる）を単独で回して測るため**である。
    #   **通しの全ケースは 127.0.0.1 を共有する**ので、
    #   **送信元を変えるには `X-Forwarded-For` を取り込ませるしかない。**
    #
    #     $env:UseForwardedHeaders = 'on'
    #     $env:ForwardedHeadersKnownProxies = '127.0.0.1'
    #     .\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RT30507"
    #
    #   **値は `on` である**（`Config.UseForwardedHeaders` は `on` と比べる。
    #   **`true` では効かず、しかも黙って何も起きない** — 実測で踏んだ）。
    #   **`::1` も挙げる**（`localhost` は IPv6 に解決し得る。
    #   **前段として信用しないアドレスからの転送ヘッダは、黙って捨てられる**）。
    #   **通し（何も入れていないとき）は off** ＝ 接続元をそのまま使う。
    if (-not $env:UseForwardedHeaders)
    {
        $env:UseForwardedHeaders = 'off'
    }

    # **退役させる途中の署名証明書**（#292 の段階 3）。
    #   **/samlmetadata が 2 本広告する状態を作る**（`SA-2.2` が、それを測る）。
    #   **値は「いま署名に使っていない証明書」**でよい（広告するだけなので）。
    $env:PreviousSigningCerFilePaths = 'C:/root/files/resource/X509/SHA256RSA_Upstream.cer'
}

function Wait-Site
{
    param(
        [string] $Name,
        [string] $SiteUrl,
        [System.Diagnostics.Process] $Process,
        [string] $OutLog,
        [string] $ErrLog
    )

    $discovery = "$SiteUrl/.well-known/openid-configuration"
    $ready = $false
    $lastError = ''

    # 待ち時間は「回数 × タイムアウト」ではなく、実時間で測る。
    # 接続が拒否されるうちは即座に返るが、起動中は TimeoutSec まで待つため、
    # 回数で数えると条件によって上限が数倍変わる。
    $deadline = (Get-Date).AddSeconds(90)

    while ((Get-Date) -lt $deadline) {

        # **落ちていたら、待たずに止める。**
        # 起動に失敗しているのに待ち続けても、上限まで無駄に待つだけになる。
        if ($Process.HasExited) {
            throw ("$Name が起動できませんでした（終了コード {0}）。" -f $Process.ExitCode) `
                + "`n  標準出力 : $OutLog" `
                + "`n  標準エラー : $ErrLog"
        }

        try {
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $res = Invoke-WebRequest -Uri $discovery -TimeoutSec 5 -SkipCertificateCheck
                $code = [int]$res.StatusCode
            }
            else {
                $req = [System.Net.HttpWebRequest]::Create($discovery)
                $req.Timeout = 5000
                $res = $req.GetResponse()
                $code = [int]$res.StatusCode
                $res.Close()
            }

            if ($code -eq 200) { $ready = $true; break }

            $lastError = "HTTP $code"
        }
        catch {
            # 起動中は接続拒否・タイムアウトのどちらもあり得るので、ここでは止めない。
            # **ただし理由は残す。** 握り潰すと、時間切れの原因が分からなくなる。
            $lastError = $_.Exception.Message
        }

        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        throw "$Name が $SiteUrl で応答しません（90 秒待機）。" `
            + "`n  最後の理由 : $lastError" `
            + "`n  標準出力 : $OutLog" `
            + "`n  標準エラー : $ErrLog"
    }
}

# ------------------------------------------------------------------
# IIS Express の applicationhost.config を作る
# ------------------------------------------------------------------
# net48 版は ASP.NET なので Kestrel では動かない。
# **既定のテンプレートのサイトを 1 つ書き換えるだけにする。**
# 仮想ディレクトリを作らないので、アプリはサイトの直下（/）に置ける。
function New-IisExpressConfig
{
    param(
        [string] $Path,
        [string] $SitePath,
        [int]    $Port,
        [switch] $ClientCertificate
    )

    if (-not (Test-Path $iisTmpl)) {
        throw "IIS Express のテンプレートが見つかりません : $iisTmpl"
    }

    [xml]$doc = Get-Content $iisTmpl -Raw

    $site = $doc.configuration.'system.applicationHost'.sites.site |
        Where-Object { $_.name -eq 'WebSite1' } | Select-Object -First 1

    if ($null -eq $site) {
        throw "テンプレートに WebSite1 がありません : $iisTmpl"
    }

    $site.name = 'MPAS48'
    $site.application.virtualDirectory.physicalPath = $SitePath
    $site.bindings.binding.protocol = 'https'
    $site.bindings.binding.bindingInformation = "*:${Port}:localhost"

    # **mTLS のテストのとき（-NetFxMtls）だけ、クライアント証明書を要求させる**（#226）。
    #   SslNegotiateCert は「要求するが、無くても通す」。
    #   **掛けるのは /token と /userinfo だけ。** サイト全体に掛けると、net48 版の FAPI2 の自己テスト
    #   （サーバが自分自身を HTTPS で呼ぶ）が証明書を求められて止まり、RT-197.1 が時間切れになる（実測）。
    #   管理者権限は要らない（このファイルは test.ps1 が自前で作るもの）。
    if ($ClientCertificate) {
        # /token   : mTLS のクライアント認証
        # /userinfo: 証明書に紐づくトークン（cnf）の照合
        # ※ 変数名は $path にしない。**引数の $Path（保存先）を上書きする**（大文字小文字を区別しない）
        foreach ($locationPath in 'MPAS48/token', 'MPAS48/userinfo') {
            $location = $doc.CreateElement('location')
            $location.SetAttribute('path', $locationPath)
            $location.InnerXml = '<system.webServer><security><access sslFlags="Ssl, SslNegotiateCert" /></security></system.webServer>'
            [void]$doc.configuration.AppendChild($location)
        }
    }

    New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
    $doc.Save($Path)
}

$core  = $null
$netFx = $null

# **子プロセス（dotnet）の出力は UTF-8。読む側が UTF-8 でなければ化ける。**
#   例 : 「復元対象のプロジェクト...」が「蠕ｩ蜈・ｯｾ雎｡...」になり、テスト名の日本語も読めなくなる。
#
#   **版ではなく、コンソールのコード ページで決まる。**
#   PowerShell が native コマンドの出力を解釈するのに使うのは [Console]::OutputEncoding で、
#   **これはコンソール（chcp）に従う。7 でも日本語 Windows の既定は 932 である。**
#   （7 が UTF-8 にするのは $OutputEncoding ＝ **送る**側。**受ける**側は別物。）
#
#   **以前は 5.1 のときだけ直していた**（「7 は既定が UTF-8」という誤った前提）。
#   **7 の実コンソールで E2ETests.log が化けて分かった**（#245 の段階 3）。
#   開発機の 5.1 / 7 がどちらも 65001 だったため、それまで表面化しなかった。
#
#   **この実行の間だけ変え、最後に戻す**（コンソールの設定が残らないように）。
$prevConsoleEncoding = $null
try {
    $prevConsoleEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
}
catch {
    # コンソールが無い（完全にリダイレクトされた）場合など。読めるかは環境任せになる。
    $prevConsoleEncoding = $null
}

try {

    # **使うストアの DB コンテナを、テストの間だけ起動する**（#305 の後）。
    #   **自分が起動したものだけを、finally で止める。**
    if ($storeService) {
        $storeStarted = Start-StoreContainer -Service $storeService -Port $storePort -Name $info.Name

        #  **自分で起動したときだけ、ログを「その時刻から後」で見る。**
        $since = if ($storeStarted) { $script:StoreSince } else { $null }

        Wait-Store -Service $storeService -Port $storePort -Name $info.Name -Since $since
    }

    if ($Launch) {

        New-Item -ItemType Directory -Force $LogDir | Out-Null

        # **テスト専用のクライアントは、ここでは差し込まない**（#264）。
        #   **サーバ側の種データが、テスト利用者の登録（saml2OAuth2Data）として作る**
        #   （`CommonLibrary/Extensions/Sts/TestClients.cs`。`IsDebug` ＋ `TestUserPWD` のとき）。
        #
        #   **以前は環境変数で差し込んでいた**が、**net48 版は一覧ごと 1 本の環境変数**で渡すため、
        #   **件数に上限があった**（#262 で踏んだ。約 17 件で Windows の環境ブロック 32,767 文字を
        #   超え、**IIS Express が起動するのに全要求が 500 になる**）。
        #   **user store は 1 件ずつ別の行なので、上限が無い。**
        #
        #   **client_id は固定値**で、**E2E の `KnownClients.SeededClientIds` と揃えてある。**
        #   そのため、**テストへ渡す環境変数（`MPAS_<名前>`）も要らない。**

        # **有効期限のテスト（#188）は、寿命をごく短くして測る。**
        #   既定（認可コード 600 秒 / Request Object 300 秒 / refresh_token 14 日）を待つのは現実的でない。
        #   **他のテストは落ちるので、-Filter と併せて使う。**
        if ($ShortLifetimes) {
            Write-Warning '-ShortLifetimes : 寿命をごく短くして起動します。-Filter と併せて使ってください（#188）。'
            $env:OAuth2AuthorizationCodeExpireTimeSpanFromSeconds = '2'
            $env:RequestObjectExpireTimeSpanFromSeconds = '2'
            $env:OAuth2RefreshTokenExpireTimeSpanFromDays = '0'
        }

        # **DPoP の nonce のテスト（#311 の段階 4）は、要求する設定で起動して測る。**
        #   **既定は要求しない**（nonce を知らないクライアントが全部止まるため）。
        #   **他の DPoP のテストは落ちるので、-Filter と併せて使う。**
        #   **鍵も渡す** — **渡さないとプロセスごとのランダムになり、
        #   net10.0 版と net48 版で別の nonce になる**（測る分には困らないが、揃えておく）。
        if ($DPoPNonce) {
            Write-Warning '-DPoPNonce : nonce を要求して起動します。-Filter と併せて使ってください（#311）。'
            $env:EnableDPoPNonce = 'true'
            $env:DPoPNonceSecret = 'e2e-dpop-nonce-secret'
            $env:MPAS_DPOP_NONCE = 'true'
        }

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # **コールバックは、スクリプト ブロックではなくコンパイルしたデリゲートにする。**
            #   クライアント証明書のネゴシエーション（-NetFxMtls）が入ると、
            #   サーバ証明書の検証が**ランスペースの無いスレッド**で呼ばれ、
            #   スクリプト ブロックでは
            #     「このスレッドには、スクリプトを実行するために使用できる実行空間が存在しません」
            #   になってハンドシェイクごと落ちる（起動待ちが 90 秒で失敗する）。実測で切り分けた（#226）。
            if (-not ('MpasTestTls' -as [type])) {
                Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class MpasTestTls
{
    public static void TrustAll()
    {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            { return true; };
    }
}
"@
            }
            [MpasTestTls]::TrustAll()

            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12
        }

        # --------------------------------------------------------------
        # net10.0 版（Kestrel）
        # --------------------------------------------------------------
        Write-Host "net10.0 版を $Url で起動します..." -ForegroundColor Cyan

        # ビルドは済ませてから起動する（dotnet run のビルドを待たない）。
        dotnet build (Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln') `
            -c $Configuration -v:q -nologo | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw 'net10.0 版のビルドに失敗しました。'
        }

        # **環境変数は、子プロセスの起動時にコピーされる。**
        # 2 つのサイトへ別々の URL を渡せるのは、この性質による。
        # 起動の直前に書き換えること。後から変えても、動いている側には効かない。
        $env:ASPNETCORE_ENVIRONMENT = 'Development'
        $env:OAuth2AuthorizationServerEndpointsRootURI = $Url
        $env:OAuth2ClientEndpointsRootURI = $Url
        # **Obsolete のテスト（Implicit / ROPC）も必ず測る（#220）。**
        #   雛形の既定は無効にしたが、**テストでは有効にして起動する。**
        #   無効なままだと Skip になり、廃止したフローの回帰が効かなくなる。
        $env:EnableImplicitGrantType = 'true'
        $env:EnableResourceOwnerPasswordCredentialsGrantType = 'true'
        # **動的クライアント登録（RFC 7591）も測る（#307 の段階 1）。**
        #   雛形の既定は無効（口そのものを張らない）だが、**テストでは有効にして起動する。**
        #   無効なままだと registration_endpoint が広告されず、RT-307.* が Skip になる。
        $env:EnableDynamicClientRegistration = 'true'
        # **software_statement の発行者も渡す（#307 の段階 4）。**
        #   **net10.0 は「節」として読む**ので、appSettings__<キー>__<鍵>__<属性> で足す
        #   （UserClaimsMapping と同じ事情）。
        $ssPrefix = 'Env:\appSettings__SoftwareStatementIssuers__' `
            + $script:SoftwareStatementIssuerKey + '__'
        Set-Item -Path ($ssPrefix + 'display_name')  -Value 'E2E Test Vendor'
        Set-Item -Path ($ssPrefix + 'enabled')       -Value 'true'
        Set-Item -Path ($ssPrefix + 'issuer')        -Value $script:SoftwareStatementIssuer
        Set-Item -Path ($ssPrefix + 'cer_file_path') -Value $script:SoftwareStatementCer
        Set-Item -Path ($ssPrefix + 'alg')           -Value $script:SoftwareStatementAlg
        #   **発行者に許す範囲**（#307 の段階 6 の (A)）。
        Set-Item -Path ($ssPrefix + 'allowed_scope') `
            -Value $script:SoftwareStatementAllowedScope
        Set-Item -Path ($ssPrefix + 'allowed_grant_types') `
            -Value $script:SoftwareStatementAllowedGrantTypes

        # **client_credentials から動的登録を叩くクライアントを足す**（#307 の段階 5-b）。
        #   **節として足すので、雛形に在るクライアントは消えない**
        #   （**net48 は 1 本の JSON 文字列なので、この足し方ができない**）。
        $ccPrefix = 'Env:\appSettings__OAuth2ClientsInformation__' `
            + $script:DcrCcClientId + '__'
        Set-Item -Path ($ccPrefix + 'client_secret') -Value $script:DcrCcClientSecret
        Set-Item -Path ($ccPrefix + 'client_name')   -Value 'TestClientDcrCc'
        Set-Item -Path ($ccPrefix + 'scope')         -Value 'client_registration'
        Set-Item -Path ($ccPrefix + 'owner') `
            -Value ('e2e_dcr_owner' + $script:TestUserSuffixCore)

        $ccPrefix2 = 'Env:\appSettings__OAuth2ClientsInformation__' `
            + $script:DcrCcNoOwnerClientId + '__'
        Set-Item -Path ($ccPrefix2 + 'client_secret') -Value $script:DcrCcNoOwnerSecret
        Set-Item -Path ($ccPrefix2 + 'client_name')   -Value 'TestClientDcrCcNoOwner'
        Set-Item -Path ($ccPrefix2 + 'scope')         -Value 'client_registration'
        #   **owner は渡さない**（**それがこのクライアントの役**である）。

        # **テスト利用者をサイトごとに分ける**（#260）。
        #   2 つのサイトを同時に立てるので、DB ストアでは 1 つの DB を共有する。
        #   分けないと、同じ利用者の DeviceToken / UnstructuredData を書き換え合って
        #   間欠で落ちる。**mem では各サイトが自前のストアを持つので、もともと起きない。**
        $env:TestUserSuffix = $script:TestUserSuffixCore

        # ID フェデレーションの下流として振る舞う（#250 の段階 5）
        Set-IdFederationEnv -TargetKey 'core' -SiteUrl $Url

        # **profile / address のクレームの対応付け（#230）。**
        #   この実装は氏名・住所の項目を持たず、入れ物は UnstructuredData（中身は導入する側が決める）。
        #   テストは、画面から入れられる usd1 / usd2 を値の在り処にする。
        #   net10.0 は「節」として読むので、appSettings__<キー>__<クレーム名> で足せる。
        foreach ($m in $script:UserClaimsMapping.GetEnumerator()) {
            Set-Item -Path ("Env:\appSettings__UserClaimsMapping__" + $m.Key) -Value $m.Value
        }

        # UserStore の切り替え（#207）。mem のときは何も渡さない（構成ファイルのまま）。
        if ($UserStoreType -ne 'mem') {
            $env:UserStoreType = $UserStoreType
            Set-Item -Path ("Env:\" + $storeConnKey) -Value $storeConnStr
        }

        # プッシュ通知の送信箱（テスト用）。サイトは FCM に送らず、ここへファイルとして書く（#196）。
        # テストは、認証デバイスの代わりにここを読む。サイトごとに分け、前回の残りは消す。
        $coreOutbox = Join-Path $LogDir 'fcm\core'
        New-Item -ItemType Directory -Force $coreOutbox | Out-Null
        Remove-Item (Join-Path $coreOutbox '*') -Force -ErrorAction SilentlyContinue
        $env:FcmOutboxDirectory = $coreOutbox

        # サイトの出力をファイルへ残す。
        # 起動に失敗したとき、これが無いと「応答しません」しか分からない。
        $coreOut = Join-Path $LogDir 'MpasSite.out.log'
        $coreErr = Join-Path $LogDir 'MpasSite.err.log'

        # **dotnet run ではなく、ビルド済みの exe を直接起動する。**
        # dotnet run はアプリを子プロセスとして起動するため、
        # 親（dotnet）を止めてもアプリが残り、次回の起動がポートを奪われる。
        $coreExe = Get-ChildItem -Recurse -ErrorAction SilentlyContinue `
            -Path (Join-Path $coreDir "bin\$Configuration") `
            -Filter 'MultiPurposeAuthSite.exe' | Select-Object -First 1

        if ($null -eq $coreExe) {
            throw "net10.0 版の実行ファイルが見つかりません : $coreDir\bin\$Configuration"
        }

        # **mTLS のテストのために、クライアント証明書を受け付けさせる（#226）。**
        #   アプリのコードは変えず、テスト専用のフック（Tests\MtlsTestHook）を起動時に読ませる。
        #   Kestrel は既定でクライアント証明書を要求せず、要求させても自己署名の証明書はチェーンの検証で落ちるため。
        #   **このサイトにだけ渡す**（環境変数は起動時にコピーされるので、直後に消す）。
        $mtlsHook = $null
        dotnet build (Join-Path $PSScriptRoot 'MtlsTestHook\MtlsTestHook.csproj') `
            -c $Configuration -v:q -nologo | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $mtlsHook = Get-ChildItem -Recurse -ErrorAction SilentlyContinue `
                -Path (Join-Path $PSScriptRoot "MtlsTestHook\bin\$Configuration") `
                -Filter 'MtlsTestHook.dll' | Select-Object -First 1
        }
        if ($null -eq $mtlsHook) {
            Write-Warning 'MtlsTestHook を作れなかったため、mTLS は受け付けません（FA-6 は Skip）。'
        }
        else {
            $env:DOTNET_STARTUP_HOOKS = $mtlsHook.FullName
        }

        $core = Start-Process -FilePath $coreExe.FullName `
            -ArgumentList @('--urls', $Url) `
            -WorkingDirectory $coreDir -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $coreOut -RedirectStandardError $coreErr

        Remove-Item Env:\DOTNET_STARTUP_HOOKS -ErrorAction SilentlyContinue

        Wait-Site -Name 'net10.0 版' -SiteUrl $Url -Process $core `
            -OutLog $coreOut -ErrLog $coreErr

        Write-Host '起動しました。' -ForegroundColor Green
        $env:MPAS_CORE_BASEURL = $Url
        $env:MPAS_CORE_FCM_OUTBOX = $coreOutbox
        $env:MPAS_CORE_TESTUSER_SUFFIX = $script:TestUserSuffixCore
        if ($null -ne $mtlsHook) { $env:MPAS_CORE_MTLS = 'true' }   # FA-6 を回してよい（#226）

        # --------------------------------------------------------------
        # net48 版（IIS Express）
        # --------------------------------------------------------------
        if ($NoNetFx) {
            Write-Host 'net48 版は起動しません（-NoNetFx）。その分は Skip されます。' -ForegroundColor Yellow
        }
        elseif (-not (Test-Path $iisExe)) {
            Write-Host "IIS Express が見つかりません（$iisExe）。net48 版は Skip されます。" -ForegroundColor Yellow
        }
        elseif (-not (Test-Path (Join-Path $netFxDir 'bin\MultiPurposeAuthSite.dll'))) {
            Write-Host 'net48 版がビルドされていません（..\..\1_BuildAll.ps1）。Skip されます。' -ForegroundColor Yellow
        }
        else {
            Write-Host "net48 版を $NetFxUrl で起動します..." -ForegroundColor Cyan

            $iisCfg   = Join-Path $LogDir 'applicationhost.config'
            $netFxOut = Join-Path $LogDir 'IisExpress.out.log'
            $netFxErr = Join-Path $LogDir 'IisExpress.err.log'

            New-IisExpressConfig -Path $iisCfg -SitePath $netFxDir -Port ([uri]$NetFxUrl).Port `
                -ClientCertificate:$NetFxMtls

            $env:OAuth2AuthorizationServerEndpointsRootURI = $NetFxUrl
            $env:OAuth2ClientEndpointsRootURI = $NetFxUrl
            # **Obsolete のテスト（Implicit / ROPC）も必ず測る（#220）。**
            #   雛形の既定は無効にしたが、**テストでは有効にして起動する。**
            #   無効なままだと Skip になり、廃止したフローの回帰が効かなくなる。
            $env:EnableImplicitGrantType = 'true'
            $env:EnableResourceOwnerPasswordCredentialsGrantType = 'true'
            # **動的クライアント登録（RFC 7591）も測る（#307 の段階 1。上の net10.0 側と同じ理由）**
            $env:EnableDynamicClientRegistration = 'true'
            # **software_statement の発行者も渡す（#307 の段階 4。net48 は 1 本の JSON 文字列）**
            #   **1 行で組む** — **XML の属性値と同じ事情**で、改行を入れる形にしない。
            $env:SoftwareStatementIssuers = (
                '{"' + $script:SoftwareStatementIssuerKey + '":{' +
                '"display_name":"E2E Test Vendor","enabled":"true",' +
                '"issuer":"' + $script:SoftwareStatementIssuer + '",' +
                '"cer_file_path":"' + $script:SoftwareStatementCer + '",' +
                '"alg":"' + $script:SoftwareStatementAlg + '",' +
                '"allowed_scope":"' + $script:SoftwareStatementAllowedScope + '",' +
                '"allowed_grant_types":"' +
                    $script:SoftwareStatementAllowedGrantTypes + '"}}')

            # **テスト利用者をサイトごとに分ける**（#260。上の net10.0 側と同じ理由）
            $env:TestUserSuffix = $script:TestUserSuffixNetFx

            # ID フェデレーションの下流として振る舞う（#250 の段階 5）
            Set-IdFederationEnv -TargetKey 'netfx' -SiteUrl $NetFxUrl

            # クレームの対応付け（#230）。net48 は 1 個の値（JSON 文字列）として読む。
            $env:UserClaimsMapping = '{' + (
                ($script:UserClaimsMapping.GetEnumerator() | ForEach-Object {
                    '"{0}": "{1}"' -f $_.Key, $_.Value }) -join ', ') + '}'

            # UserStore の切り替え（#207）。npg はここに来ない（上で NoNetFx にしている）。
            if ($UserStoreType -ne 'mem') {
                $env:UserStoreType = $UserStoreType
                Set-Item -Path ("Env:\" + $storeConnKey) -Value $storeConnStr
            }

            $netFxOutbox = Join-Path $LogDir 'fcm\netfx'
            New-Item -ItemType Directory -Force $netFxOutbox | Out-Null
            Remove-Item (Join-Path $netFxOutbox '*') -Force -ErrorAction SilentlyContinue
            $env:FcmOutboxDirectory = $netFxOutbox

            $netFx = Start-Process -FilePath $iisExe `
                -ArgumentList @("/config:$iisCfg", '/site:MPAS48') `
                -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $netFxOut -RedirectStandardError $netFxErr

            Wait-Site -Name 'net48 版' -SiteUrl $NetFxUrl -Process $netFx `
                -OutLog $netFxOut -ErrLog $netFxErr

            Write-Host '起動しました。' -ForegroundColor Green
            $env:MPAS_NETFX_BASEURL = $NetFxUrl
            $env:MPAS_NETFX_FCM_OUTBOX = $netFxOutbox
            $env:MPAS_NETFX_TESTUSER_SUFFIX = $script:TestUserSuffixNetFx
            if ($NetFxMtls) { $env:MPAS_NETFX_MTLS = 'true' }   # FA-6 を net48 版でも回す（#226）
        }

        # **RT-307.18 〜 .21 を回してよい**（#307 の段階 4）。
        #   **期待する iss をテストへ渡す** — **サイトへ渡した値と、必ず同じ値を使う。**
        #   **渡していなければ、テスト側は Skip する**（MtlsTests.SkipIfNoMtls と同じ作法）。
        $env:MPAS_SOFTWARE_STATEMENT_ISS = $script:SoftwareStatementIssuer

        # **RT-307.25 / .26 を回してよい**（#307 の段階 6）。
        #   **サイトへ渡した値と、必ず同じ値をテストへ渡す。**
        #   **両方の対象に同じ発行者を渡している**ので、**しるしは対象ごとに分けない**
        #   （**構成ファイル発のクライアント（段階 5-b）とは事情が違う**）。
        $env:MPAS_SOFTWARE_STATEMENT_ALLOWED_SCOPE = $script:SoftwareStatementAllowedScope
        $env:MPAS_SOFTWARE_STATEMENT_ROLLOVER      = 'true'   # 2 本目の鍵も渡してある

        # **RT-308.* を回してよい**（#308 の段階 3）。
        #   **設定の発行者の「鍵」をテストへ渡す** —
        #   **「設定に在る鍵は、画面から足せない」ことを測る**のに要る。
        $env:MPAS_SOFTWARE_STATEMENT_KEY = $script:SoftwareStatementIssuerKey

        # **RT-307.22 〜 .24 を回してよい**（#307 の段階 5-b）。
        #   **サイトへ渡した値と、必ず同じ値をテストへ渡す。**
        #   **渡していなければ Skip する**（net48 はここに来ないので、そちらは Skip）。
        #   **対象ごとのしるしにする**（`MPAS_CORE_MTLS` と同じ作法）。
        #   **process 全体に置くと、net48 のケースも「渡された」と見なして落ちる**（実測）。
        $env:MPAS_CORE_DCR_CC_CLIENT_ID             = $script:DcrCcClientId
        $env:MPAS_CORE_DCR_CC_CLIENT_SECRET         = $script:DcrCcClientSecret
        $env:MPAS_CORE_DCR_CC_OWNER                 = ('e2e_dcr_owner' + $script:TestUserSuffixCore)
        $env:MPAS_CORE_DCR_CC_NOOWNER_CLIENT_ID     = $script:DcrCcNoOwnerClientId
        $env:MPAS_CORE_DCR_CC_NOOWNER_CLIENT_SECRET = $script:DcrCcNoOwnerSecret

        if ($ShortLifetimes) {
            Remove-Item Env:\OAuth2AuthorizationCodeExpireTimeSpanFromSeconds -ErrorAction SilentlyContinue
            Remove-Item Env:\RequestObjectExpireTimeSpanFromSeconds -ErrorAction SilentlyContinue
            Remove-Item Env:\OAuth2RefreshTokenExpireTimeSpanFromDays -ErrorAction SilentlyContinue
            $env:MPAS_SHORT_LIFETIMES = 'true'   # RT-188 を回してよい（#188）
        }

        # 役目は終わっている。テスト側へ持ち込まない。
        Remove-Item Env:\OAuth2AuthorizationServerEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\OAuth2ClientEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\FcmOutboxDirectory -ErrorAction SilentlyContinue

        # **接続文字列を、テスト プロセスへ引き継がない。**
        # テストはサイトを HTTP で叩くだけで、DB へは触らない。
        if ($UserStoreType -ne 'mem') {
            Remove-Item Env:\UserStoreType -ErrorAction SilentlyContinue
            Remove-Item -Path ("Env:\" + $storeConnKey) -ErrorAction SilentlyContinue
        }
    }

    $testArgs = @('test', $csproj, '-c', $Configuration, '--logger', 'console;verbosity=normal')

    # **有効期限のテスト（RT-188）は、既定では走らせない**（#188）。
    #   ごく短い寿命で起動したときにだけ意味があり、既定の寿命では測れない。
    #   xUnit は「ケースが 0 件の Theory」を失敗として数えるため、
    #   **ケースを作らないのではなく、ここで除外する。**
    $expr = $Filter

    if (-not $ShortLifetimes) {
        $exclude = 'FullyQualifiedName!~LifetimeTests'
        if ($expr) { $expr = "($expr)&$exclude" } else { $expr = $exclude }
    }

    # **DPoP の nonce のテスト（RT-311.13 / RT-311.14）も、既定では走らせない**
    #   （#311 の段階 4）。**nonce を要求する設定で起動したときにだけ意味がある。**
    #   **ケースを作らないのではなく、ここで除外する**（上の RT-188 と同じ事情）。
    #   **チャレンジのスキーム（RT-311.12）は DPoPChallengeTests に在り、いつでも走る。**
    if (-not $DPoPNonce) {
        $exclude = 'FullyQualifiedName!~DPoPNonceTests'
        if ($expr) { $expr = "($expr)&$exclude" } else { $expr = $exclude }
    }

    # **ブラウザで測るもの（UI）を外す**（#277 の段階 7）。
    #   **既定では走らせる。** **ブラウザが無ければ Skip する**ので、
    #   **netfx 版やコンテナと同じ流儀**で、測れないことが結果に出る。
    #   **外す口だけ用意しておく**（ブラウザを動かしたくない場合）。
    if ($NoWebUI) {
        $exclude = 'FullyQualifiedName!~Tests.WebUI'
        if ($expr) { $expr = "($expr)&$exclude" } else { $expr = $exclude }
    }

    if ($expr) {
        $testArgs += @('--filter', $expr)
    }

    if ($TrxPath) {
        # --logger trx は --results-directory の下に書く。
        # 呼び出し側が指定したパスにそのまま置きたいので、分解して渡す。
        $trxDir  = Split-Path -Parent $TrxPath
        $trxName = Split-Path -Leaf $TrxPath

        if ($trxDir) {
            New-Item -ItemType Directory -Force $trxDir | Out-Null
            $testArgs += @('--results-directory', $trxDir)
        }

        $testArgs += @('--logger', "trx;LogFileName=$trxName")
    }

    # **ここだけ $ErrorActionPreference を Continue にし、標準エラーを文字列にして流す。**
    # Windows PowerShell 5.1 は、出力をリダイレクトしているとき、ネイティブ コマンドの
    # 標準エラー出力を 1 行ずつ ErrorRecord（NativeCommandError）に包む。
    # xUnit は失敗したテストの [FAIL] 行を標準エラーに書くため、Stop のままだと
    # **最初の失敗でスクリプトが止まり、集計も報告書も作られない**（実際に止まった）。
    # 全件成功している間は標準エラーに何も出ないので、表面化しない。
    # 合否は $LASTEXITCODE と TRX で判定するので、ここで止める必要は無い。
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & dotnet @testArgs 2>&1 | ForEach-Object { "$_" }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $eap
    }
}
finally {
    foreach ($p in @($core, $netFx)) {
        if ($null -ne $p -and -not $p.HasExited) {
            Write-Host 'サイトを停止します...' -ForegroundColor Cyan
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }

    # **自分が起動した DB コンテナだけを止める**（#305 の後）。
    #   **既に起動していたものは、そのまま残す。**
    if ($storeStarted -and $storeService) {
        Stop-StoreContainer -Service $storeService -Name $storeService
    }

    if ($Launch) {
        Remove-Item Env:\OAuth2AuthorizationServerEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\OAuth2ClientEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_BASEURL -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_BASEURL -ErrorAction SilentlyContinue
        Remove-Item Env:\FcmOutboxDirectory -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_FCM_OUTBOX -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_FCM_OUTBOX -ErrorAction SilentlyContinue
        Remove-Item Env:\TestUserSuffix -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_TESTUSER_SUFFIX -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_TESTUSER_SUFFIX -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT4_2 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT4_3 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT2_2 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT2_3 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_MTLS -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_MTLS -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_SHORT_LIFETIMES -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_SOFTWARE_STATEMENT_ALLOWED_SCOPE -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_SOFTWARE_STATEMENT_ROLLOVER -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_SOFTWARE_STATEMENT_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_DCR_CC_CLIENT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_DCR_CC_CLIENT_SECRET -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_DCR_CC_OWNER -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_DCR_CC_NOOWNER_CLIENT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_DCR_CC_NOOWNER_CLIENT_SECRET -ErrorAction SilentlyContinue
        Remove-Item Env:\OAuth2AuthorizationCodeExpireTimeSpanFromSeconds -ErrorAction SilentlyContinue
        Remove-Item Env:\RequestObjectExpireTimeSpanFromSeconds -ErrorAction SilentlyContinue
        Remove-Item Env:\OAuth2RefreshTokenExpireTimeSpanFromDays -ErrorAction SilentlyContinue
        Remove-Item Env:\DOTNET_STARTUP_HOOKS -ErrorAction SilentlyContinue
    }

    # コンソールの文字コードを戻す（この実行の間だけ UTF-8 にしている）
    if ($null -ne $prevConsoleEncoding) {
        try { [Console]::OutputEncoding = $prevConsoleEncoding } catch { }
    }
}

exit $exitCode
