<#
.SYNOPSIS
    E2E テストを実行する。必要なら net10.0 版のサイトを起動してから実行する。

.DESCRIPTION
    テストは「動いているサイト」を HTTP で叩く。したがって、実行前に
    テスト対象が起動している必要がある。

    -Launch を付けると、net10.0 版を Kestrel で起動し、テストの後に停止する。
    このとき、構成ファイルの OAuth2AuthorizationServerEndpointsRootURI /
    OAuth2ClientEndpointsRootURI を、起動する URL に環境変数で合わせる。

    ** なぜ URL を合わせる必要があるか **

    アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、サーバ自身が
    「構成ファイルに書かれた URL」へ HTTP で折り返す。
    叩き先と構成が食い違うと、その折り返しが接続不能になり HTTP 500 になる。

    また、認証まわりの Cookie は SameSite=None で発行されるため、
    ** http では保持されない。** max_age を使うフロー（FAPI2）は
    auth_time Cookie を見るので、https で動かす必要がある。

    net48 版は IIS Express での起動が前提なので、このスクリプトからは起動しない。
    起動していなければ、その分のテストは Skip される。

.PARAMETER Launch
    net10.0 版を起動してからテストする。

.PARAMETER Url
    -Launch のときに待ち受ける URL（既定 https://localhost:44300）。

.PARAMETER Filter
    dotnet test の --filter に渡す式。

.PARAMETER LogDir
    サイトの起動ログ（MpasSite.out.log / MpasSite.err.log）の出力先。
    既定は E2ETests\Result（.gitignore 済み）。

.PARAMETER TrxPath
    テスト結果を TRX（XML）でも書き出す先。
    上位の ..\..\2_RunAllTests.ps1 が集計に使う。

    コンソール出力の集計行（"テストの合計数: ..."）はロケールで変わるため、
    機械で読むときはこちらを使う。

.EXAMPLE
    .\test.ps1 -Launch
    .\test.ps1 -Filter "FullyQualifiedName~RequestObjectTests"
#>
[CmdletBinding()]
param(
    [switch] $Launch,
    [string] $Url = 'https://localhost:44300',
    [string] $Filter,
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',
    [string] $TrxPath,
    [string] $LogDir = (Join-Path $PSScriptRoot 'E2ETests\Result')
)

$ErrorActionPreference = 'Stop'

$programs = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $PSScriptRoot 'E2ETests\E2ETests.csproj'
$appDir = Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore'

$app = $null

try {
    if ($Launch) {
        Write-Host "net10.0 版を $Url で起動します..." -ForegroundColor Cyan

        # ビルドは済ませてから起動する（dotnet run のビルドを待たない）。
        dotnet build (Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln') `
            -c $Configuration -v:q -nologo | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw 'net10.0 版のビルドに失敗しました。'
        }

        $env:ASPNETCORE_ENVIRONMENT = 'Development'
        $env:appSettings__OAuth2AuthorizationServerEndpointsRootURI = $Url
        $env:appSettings__OAuth2ClientEndpointsRootURI = $Url

        # サイトの出力をファイルへ残す。
        # 起動に失敗したとき、これが無いと「応答しません」しか分からない。
        New-Item -ItemType Directory -Force $LogDir | Out-Null
        $appOut = Join-Path $LogDir 'MpasSite.out.log'
        $appErr = Join-Path $LogDir 'MpasSite.err.log'

        $app = Start-Process -FilePath 'dotnet' `
            -ArgumentList @('run', '--no-build', '-c', $Configuration, '--urls', $Url) `
            -WorkingDirectory $appDir -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $appOut -RedirectStandardError $appErr

        # 起動を待つ（Discovery 文書が返るまで）。
        #
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

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12
        }

        $discovery = "$Url/.well-known/openid-configuration"
        $ready = $false
        $lastError = ''

        # 待ち時間は「回数 × タイムアウト」ではなく、実時間で測る。
        # 接続が拒否されるうちは即座に返るが、起動中は TimeoutSec まで待つため、
        # 回数で数えると条件によって上限が数倍変わる。
        $deadline = (Get-Date).AddSeconds(90)

        while ((Get-Date) -lt $deadline) {

            # **落ちていたら、待たずに止める。**
            # 起動に失敗しているのに待ち続けても、上限まで無駄に待つだけになる。
            if ($app.HasExited) {
                throw ("サイトが起動できませんでした（終了コード {0}）。" -f $app.ExitCode) `
                    + "`n  標準出力 : $appOut" `
                    + "`n  標準エラー : $appErr"
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
            throw "サイトが $Url で応答しません（90 秒待機）。" `
                + "`n  最後の理由 : $lastError" `
                + "`n  標準出力 : $appOut" `
                + "`n  標準エラー : $appErr"
        }

        Write-Host '起動しました。' -ForegroundColor Green

        $env:MPAS_CORE_BASEURL = $Url
    }

    $args = @('test', $csproj, '-c', $Configuration, '--logger', 'console;verbosity=normal')

    if ($Filter) {
        $args += @('--filter', $Filter)
    }

    if ($TrxPath) {
        # --logger trx は --results-directory の下に書く。
        # 呼び出し側が指定したパスにそのまま置きたいので、分解して渡す。
        $trxDir  = Split-Path -Parent $TrxPath
        $trxName = Split-Path -Leaf $TrxPath

        if ($trxDir) {
            New-Item -ItemType Directory -Force $trxDir | Out-Null
            $args += @('--results-directory', $trxDir)
        }

        $args += @('--logger', "trx;LogFileName=$trxName")
    }

    & dotnet @args
    $exitCode = $LASTEXITCODE
}
finally {
    if ($null -ne $app -and -not $app.HasExited) {
        Write-Host 'サイトを停止します...' -ForegroundColor Cyan
        Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue
    }

    if ($Launch) {
        Remove-Item Env:\appSettings__OAuth2AuthorizationServerEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\appSettings__OAuth2ClientEndpointsRootURI -ErrorAction SilentlyContinue
        Remove-Item Env:\MPAS_CORE_BASEURL -ErrorAction SilentlyContinue
    }
}

exit $exitCode
