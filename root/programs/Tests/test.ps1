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
    [string] $Url = 'https://localhost:44300',
    [string] $NetFxUrl = 'https://localhost:44302',
    [switch] $NoNetFx,
    [switch] $NetFxMtls,
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
# UserStore の切り替え（#207）
# ------------------------------------------------------------------
# 設定ファイルは書き換えない。**環境変数で上書きする**（FxContainerization=ON）。
# キー名がそのまま環境変数名になるので、ConnectionString_* を直接渡せる。
#
# **接続文字列の既定値は持たない。** 引数か環境変数で受ける。
$storeKeys = @{
    'sql' = @{ Key = 'ConnectionString_SQL'; Env = 'MPAS_CONNSTR_SQL'; Name = 'SQL Server' }
    'ora' = @{ Key = 'ConnectionString_ODP'; Env = 'MPAS_CONNSTR_ODP'; Name = 'Oracle' }
    'npg' = @{ Key = 'ConnectionString_NPS'; Env = 'MPAS_CONNSTR_NPS'; Name = 'PostgreSQL' }
}

$storeConnKey = $null
$storeConnStr = $null

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

function Get-InjectedTestClient
{
    <#
    .SYNOPSIS
    テスト専用のクライアントを、環境変数で差し込むための値を作る（#224）。

    .DESCRIPTION
    **既存の登録（既定は TestClient4）を写し、名前と oauth2_oidc_mode、-Override の項目だけを変える。**
    公開鍵（jwk_*_publickey）ごと写すので、署名検証を通り、
    **登録種別の判定まで届く**。雛形にも実設定にも手を入れない。

    **写す値は、JSON の生のテキスト**（\\ などのエスケープを含むまま）。
    -Override の値も、JSON の文字列として書く。

    差し込み方は、アプリによって違う。
      net10.0 : クライアント一覧は「節」として読むので、
                appSettings__OAuth2ClientsInformation__<client_id>__<項目> で 1 件足せる
      net48   : 1 個の値（JSON 文字列）として読むので、
                OAuth2ClientsInformation を一覧ごと差し替える（FxContainerization=ON）

    **JSON は構文解析しない。** 5.1 の ConvertFrom-Json は // コメントを読めない。
    登録は入れ子の無い平らなオブジェクトなので、生のテキストから区画を取り出す。
    **net48 は XML として読まない。** 属性値の改行が空白に潰れ、// が以降を飲む（CONFIGURATION.md 9 節）。

    **2 件目以降は、-NetFxBody に前の NetFxValue を渡す。** net48 は一覧ごと差し替えるので、
    前に足した分の上へ、さらに足す。

    .OUTPUTS
    ClientId / CoreEnv（環境変数名 → 値）/ NetFxValue。取り出せなければ $null。
    #>
    param(
        [string] $Name,
        [string] $Mode,
        [string] $ClientId,
        [string] $NetFxBody = '',
        [string] $Source = 'TestClient4',
        [hashtable] $Override = @{}
    )

    $coreText  = [System.IO.File]::ReadAllText((Join-Path $coreDir 'appsettings.json'))

    # 写す元の区画（入れ子の無い { ... }）
    $m = [regex]::Match($coreText,
        '\{[^{}]*"client_name"\s*:\s*"' + [regex]::Escape($Source) + '"[^{}]*\}')
    if (-not $m.Success) { return $null }

    $fields = [ordered]@{}
    foreach ($f in [regex]::Matches($m.Value, '"([A-Za-z0-9_]+)"\s*:\s*"((?:[^"\\]|\\.)*)"')) {
        $fields[$f.Groups[1].Value] = $f.Groups[2].Value
    }
    $fields['client_name'] = $Name
    $fields['oauth2_oidc_mode'] = $Mode
    foreach ($k in $Override.Keys) { $fields[$k] = $Override[$k] }

    # net10.0 : 節へ 1 件足す
    #   環境変数は JSON ではないので、エスケープを戻した値を渡す（\\ → \ など）。
    $coreEnv = @{}
    foreach ($k in $fields.Keys) {
        $coreEnv["appSettings__OAuth2ClientsInformation__${ClientId}__$k"] =
            [regex]::Unescape($fields[$k])
    }

    # net48 : 一覧の末尾の } の手前に 1 件足す
    if ([string]::IsNullOrEmpty($NetFxBody)) {
        $netFxText = [System.IO.File]::ReadAllText((Join-Path $netFxDir 'app.config'))
        $n = [regex]::Match($netFxText,
            'key="OAuth2ClientsInformation"\s+value=''(.*?)''\s*/>',
            [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $n.Success) { return $null }
        $NetFxBody = $n.Groups[1].Value
    }

    $body  = $NetFxBody.TrimEnd()
    if (-not $body.EndsWith('}')) { return $null }

    $pairs = ($fields.Keys | ForEach-Object { '"{0}": "{1}"' -f $_, $fields[$_] }) -join ', '
    $netFxValue = $body.Substring(0, $body.Length - 1).TrimEnd() +
        ",`r`n  `"$ClientId`": { $pairs }`r`n}"

    return @{ ClientId = $ClientId; CoreEnv = $coreEnv; NetFxValue = $netFxValue }
}

$core  = $null
$netFx = $null

# **子プロセス（dotnet）の出力は UTF-8。5.1 は既定（ANSI）で読むため化ける。**
#   例 : 「復元対象のプロジェクト...」が「蠕ｩ蜈・ｯｾ雎｡...」になり、テスト名の日本語も読めなくなる。
#   7 は既定が UTF-8 なので影響しない。**この実行の間だけ変え、最後に戻す**（コンソールの設定が残らないように）。
$prevConsoleEncoding = $null
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try {
        $prevConsoleEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
    }
    catch {
        # コンソールが無い（完全にリダイレクトされた）場合など。読めるかは環境任せになる。
        $prevConsoleEncoding = $null
    }
}

try {
    if ($Launch) {

        New-Item -ItemType Directory -Force $LogDir | Out-Null

        # **テスト専用のクライアントを差し込む**（#224 / #226）。
        #   既存の登録を写し、登録種別などだけ変えたもの
        #   （公開鍵ごと写すので、署名検証で先に落ちない）。設定ファイルは書き換えない。
        #     TestClient4_2 : normal  … CIBA を fapi_ciba 以外の登録で使うと拒否されるか
        #     TestClient4_3 : fapi_1  … 既知でない登録値（書き間違い）なら拒否されるか（#224 の段階 2）
        #     TestClient2_2 : fapi2   … mTLS で通るか（#226）。Subject はテスト専用の値
        #     TestClient2_3 : fapi_1  … 同じ証明書でも、登録値が不正なら拒否されるか（#226 / #224 の E）
        #   ※ Subject は E2E の KnownClients.MtlsSubjectDn と同じ値にすること。
        $mtlsDn = @{ tls_client_auth_subject_dn = 'CN=mpas-e2e-mtls-client' }
        $injected = $null
        $injectedIds = [ordered]@{}   # テストへ渡す環境変数名 → client_id
        foreach ($c in @(
            @{ Name = 'TestClient4_2'; Mode = 'normal'; ClientId = 'e2e0tc42000000000000000000000000'; Source = 'TestClient4'; Override = @{} },
            @{ Name = 'TestClient4_3'; Mode = 'fapi_1'; ClientId = 'e2e0tc43000000000000000000000000'; Source = 'TestClient4'; Override = @{} },
            @{ Name = 'TestClient2_2'; Mode = 'fapi2';  ClientId = 'e2e0tc22000000000000000000000000'; Source = 'TestClient2'; Override = $mtlsDn },
            @{ Name = 'TestClient2_3'; Mode = 'fapi_1'; ClientId = 'e2e0tc23000000000000000000000000'; Source = 'TestClient2'; Override = $mtlsDn })) {

            $base = ''
            if ($null -ne $injected) { $base = $injected.NetFxValue }

            $one = Get-InjectedTestClient -Name $c.Name -Mode $c.Mode -ClientId $c.ClientId -NetFxBody $base `
                -Source $c.Source -Override $c.Override
            if ($null -eq $one) {
                $injected = $null
                $injectedIds.Clear()
                break
            }

            if ($null -eq $injected) {
                $injected = $one
            }
            else {
                foreach ($k in $one.CoreEnv.Keys) { $injected.CoreEnv[$k] = $one.CoreEnv[$k] }
                $injected.NetFxValue = $one.NetFxValue
            }
            $injectedIds['MPAS_' + $c.Name.ToUpperInvariant()] = $c.ClientId
        }

        if ($null -eq $injected) {
            Write-Warning 'TestClient4 / TestClient2 の登録を取り出せなかったため、テスト専用のクライアントは差し込みません（FA-5 / FA-6 は Skip）。'
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

        # テスト専用のクライアント（#224）: net10.0 は節へ 1 件足す
        if ($null -ne $injected) {
            foreach ($k in $injected.CoreEnv.Keys) {
                Set-Item -Path ("Env:\" + $k) -Value $injected.CoreEnv[$k]
            }
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

            # テスト専用のクライアント（#224）: net48 は一覧ごと差し替える
            if ($null -ne $injected) {
                $env:OAuth2ClientsInformation = $injected.NetFxValue
            }

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
            if ($NetFxMtls) { $env:MPAS_NETFX_MTLS = 'true' }   # FA-6 を net48 版でも回す（#226）
        }

        # テスト専用のクライアント（#224）: 差し込みの値はテスト側へ持ち込まない。
        #   テストには client_id だけを渡す（client_secret などは写す元と同じなので、構成ファイルから読める）。
        if ($null -ne $injected) {
            foreach ($k in $injected.CoreEnv.Keys) {
                Remove-Item -Path ("Env:\" + $k) -ErrorAction SilentlyContinue
            }
            Remove-Item Env:\OAuth2ClientsInformation -ErrorAction SilentlyContinue
            foreach ($k in $injectedIds.Keys) {
                Set-Item -Path ("Env:\" + $k) -Value $injectedIds[$k]
            }
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

    if ($Filter) {
        $testArgs += @('--filter', $Filter)
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

    if ($Launch) {
        Remove-Item Env:\OAuth2AuthorizationServerEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\OAuth2ClientEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_BASEURL -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_BASEURL -ErrorAction SilentlyContinue
        Remove-Item Env:\FcmOutboxDirectory -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_FCM_OUTBOX -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_FCM_OUTBOX -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT4_2 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT4_3 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT2_2 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_TESTCLIENT2_3 -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_MTLS -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_NETFX_MTLS -ErrorAction SilentlyContinue
        Remove-Item Env:\DOTNET_STARTUP_HOOKS -ErrorAction SilentlyContinue
    }

    # コンソールの文字コードを戻す（この実行の間だけ UTF-8 にしている）
    if ($null -ne $prevConsoleEncoding) {
        try { [Console]::OutputEncoding = $prevConsoleEncoding } catch { }
    }
}

exit $exitCode
