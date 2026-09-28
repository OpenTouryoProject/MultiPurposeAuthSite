<#
.SYNOPSIS
    認証デバイス（web / PWA）を起動する。接続先と起動の仕方を、コメントアウトで切り替える。

.DESCRIPTION
    CHEATSHEET.md の 5 節（起動する）・6 節（組み合わせ早見表）のコマンドを 1 つにまとめたもの。
    **「どのサイトに繋ぐか」と「どう起動するか」の 2 択だけ**なので、
    下の 2 つのブロックで、使う行のコメント（#）を外す（1 行だけ有効にする）。

    ＜接続先（--dart-define-from-file の mpas.*.json）＞
      mpas.core.json  : https://localhost:44300                        net10.0 版（test.ps1 -Launch / Kestrel）
      mpas.netfx.json : https://localhost:44302                        net48 版（CHEATSHEET 5 節の手順）
      mpas.vs.json    : https://localhost:44300/MultiPurposeAuthSite    **Visual Studio から起動した場合**（仮想ディレクトリ付き）

    ＜起動の仕方（デバイス アプリの配信の仕方だけを決める）＞
      chrome     : flutter run -d chrome        画面を作るとき（ホット リロードが効く）。
                                                **OS の通知のクリックは動かない**（一時プロファイルの Chrome）
      web-server : flutter run -d web-server    **既定。** 普段の Chrome で開く
                                                （フォアグラウンド / バックグラウンドの両方を確かめられる）
      pwa        : flutter build web ＋ http.server
                                                **PWA としてインストールして確かめる**とき（manifest が要るのでビルドした出力を配信する）

      **CIBA も 2FA も、どのモードでも確かめられる**（chrome の OS 通知のクリックだけが例外）。
      **何を試すかはサイト側で選ぶ**（CIBA なら /Home/Saml2OAuth2Starters の
      ClientType = fapi_ciba ＋ [Test FAPI CIBA Profile (FAPI2)]。CHEATSHEET 8 節・9 節）。
      **PWA でも CIBA は動く**（#205 で実測。CHEATSHEET 8 節「PWA としてインストールして確かめる」）。
      既定を web-server にしているのは、**毎回ビルドしなくて済む**ため。

    ＜変えないもの＞
      **--web-port 5610 は固定。** redirect_uri（http://localhost:5610/）はサイト側の登録値
      （AuthenticationDevice_Web）と完全一致で照合され、**サイトの URL とは無関係**である。

    ＜前提＞
      firebase_web.json（CHEATSHEET 2 節）と、サーバ側の送信鍵（同 4 節）。
      **プッシュを使わないなら、firebase_web.json は無くてもよい**（$UseFirebase を $false にする）。

.PARAMETER ShowOnly
    実行せず、組み立てたコマンドだけを表示する。

.EXAMPLE
    .\setup_spa_device.ps1
    .\setup_spa_device.ps1 -ShowOnly
#>
param(
    [switch] $ShowOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# 接続先（1 行だけ有効にする）
# ------------------------------------------------------------------
#$MpasFile = 'mpas.core.json'    # net10.0 版（https://localhost:44300）
#$MpasFile = 'mpas.netfx.json'   # net48 版（https://localhost:44302）
$MpasFile = 'mpas.vs.json'      # Visual Studio（https://localhost:44300/MultiPurposeAuthSite）

# ------------------------------------------------------------------
# 起動の仕方（1 行だけ有効にする）
# ------------------------------------------------------------------
#   **CIBA / 2FA は、どのモードでも確かめられる**（試す内容はサイト側で選ぶ）。
#$Mode = 'chrome'        # 画面を作るとき（OS 通知のクリックだけ動かない）
$Mode = 'web-server'    # 既定（毎回ビルドしなくて済む）
#$Mode = 'pwa'           # インストールした状態で確かめるとき（CIBA も動く。ビルドが要る）

# ------------------------------------------------------------------
# プッシュ通知を使うか（firebase_web.json を渡すか）
# ------------------------------------------------------------------
$UseFirebase = $true
#$UseFirebase = $false

# ------------------------------------------------------------------
# ここから下は、通常は触らない
# ------------------------------------------------------------------

$WebPort = 5610   # **固定**（redirect_uri の登録値と完全一致で照合される）

Set-Location $PSScriptRoot

# 渡す設定ファイル
$defines = @()

if ($UseFirebase)
{
    if (-not (Test-Path 'firebase_web.json'))
    {
        throw 'firebase_web.json がありません（CHEATSHEET.md 2 節）。プッシュを使わないなら $UseFirebase = $false にしてください。'
    }

    $defines += '--dart-define-from-file=firebase_web.json'
}

if (-not (Test-Path $MpasFile))
{
    throw "$MpasFile がありません（CHEATSHEET.md 3 節）。"
}

$defines += "--dart-define-from-file=$MpasFile"

# 組み立て
$commands = @()

switch ($Mode)
{
    'chrome'
    {
        $commands += "flutter run -d chrome --web-port $WebPort $($defines -join ' ')"
    }
    'web-server'
    {
        $commands += "flutter run -d web-server --web-port $WebPort $($defines -join ' ')"
    }
    'pwa'
    {
        # **ビルドした出力（build\web）を配信する。** manifest / service worker が要るため。
        $commands += "flutter build web $($defines -join ' ')"
        $commands += "python -m http.server $WebPort"   # build\web で実行する
    }
    default
    {
        throw "Mode が不正です : $Mode（chrome / web-server / pwa）"
    }
}

Write-Host ''
Write-Host "  接続先 : $MpasFile" -ForegroundColor Cyan
Write-Host "  起動   : $Mode（http://localhost:$WebPort/）" -ForegroundColor Cyan
Write-Host "  プッシュ : $(if ($UseFirebase) { 'firebase_web.json を渡す' } else { '渡さない（プッシュ無し）' })" -ForegroundColor Cyan
Write-Host ''

foreach ($c in $commands)
{
    Write-Host "  > $c" -ForegroundColor DarkGray
}

Write-Host ''

if ($ShowOnly)
{
    Write-Host '  -ShowOnly : 実行しません。' -ForegroundColor Yellow
    return
}

# 実行
if ($Mode -eq 'pwa')
{
    Invoke-Expression $commands[0]

    if ($LASTEXITCODE -ne 0)
    {
        throw "flutter build web が失敗しました（終了コード $LASTEXITCODE）。"
    }

    Set-Location (Join-Path $PSScriptRoot 'build\web')

    Write-Host "  http://localhost:$WebPort/ を普段の Chrome で開く（Ctrl+C で止める）" -ForegroundColor Yellow
    Write-Host ''

    Invoke-Expression $commands[1]
}
else
{
    Write-Host "  認可画面へ移ると、このターミナルとの接続は切れる。ログは Chrome の DevTools（F12）で見る。" -ForegroundColor Yellow
    Write-Host ''

    Invoke-Expression $commands[0]
}
