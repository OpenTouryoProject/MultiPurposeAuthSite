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
        [int]    $Port
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

    New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
    $doc.Save($Path)
}

$core  = $null
$netFx = $null

try {
    if ($Launch) {

        New-Item -ItemType Directory -Force $LogDir | Out-Null

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
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

        $core = Start-Process -FilePath $coreExe.FullName `
            -ArgumentList @('--urls', $Url) `
            -WorkingDirectory $coreDir -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $coreOut -RedirectStandardError $coreErr

        Wait-Site -Name 'net10.0 版' -SiteUrl $Url -Process $core `
            -OutLog $coreOut -ErrLog $coreErr

        Write-Host '起動しました。' -ForegroundColor Green
        $env:MPAS_CORE_BASEURL = $Url
        $env:MPAS_CORE_FCM_OUTBOX = $coreOutbox

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

            New-IisExpressConfig -Path $iisCfg -SitePath $netFxDir -Port ([uri]$NetFxUrl).Port

            $env:OAuth2AuthorizationServerEndpointsRootURI = $NetFxUrl
            $env:OAuth2ClientEndpointsRootURI = $NetFxUrl

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
    }
}

exit $exitCode
