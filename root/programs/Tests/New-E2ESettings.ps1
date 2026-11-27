<#
.SYNOPSIS
    E2E 用の設定ファイル（net10.0 版の appsettings.json。Windows なら net48 版の app.config も）を、雛形から作る。

.DESCRIPTION
    **CI と、Linux（SDK のコンテナ）で回すときのためのもの**（#435）。手元の Windows では、Readme.ja.md の初回の準備どおり手で作ってよい。

    - 雛形（_appsettings.json・_app.config）の **E2E に要る 4 つの穴埋め**（管理者の UID・パスワード、テスト利用者のパスワード、SaltParameter）だけを替える
      （ほかの穴埋め（プロキシ・SMTP・Twilio・外部ログイン）は E2E で使わないので、雛形のまま）
    - **-ResourceDir を付けると**、雛形のパスの `C:/root/files/resource` をその場所に置き換え、
      このリポジトリの root/files/resource をそこへ写す（log4net の構成の中の書き出し先も、写しの方だけ置き換える）。
      **Linux では必ず付ける**（ドライブ文字が無い）。原本（root/files/resource）は書き換えない
    - **既にある設定ファイルは上書きしない**（手元の実ファイルは秘密を含む）。上書きするなら -Force

    値はテスト専用で、秘密ではない（呼ぶ側が決める）。**このスクリプトに値を書かない。**

.PARAMETER AdministratorUID
    管理者の UID（メール アドレスの形）。

.PARAMETER AdministratorPWD
    管理者のパスワード。

.PARAMETER TestUserPWD
    テスト利用者のパスワード。

.PARAMETER SaltParameter
    SaltParameter。

.PARAMETER ResourceDir
    リソースの置き場（例：/tmp/mpas/resource）。付けなければ、雛形のまま C:/root/files/resource を指し、写しもしない。

.PARAMETER NoNetFx
    net48 版の app.config を作らない（Linux では、付けなくても作らない）。

.PARAMETER Force
    既にある設定ファイルを上書きする。

.EXAMPLE
    # Linux（SDK のコンテナ・GitHub Actions の ubuntu-latest）
    ./New-E2ESettings.ps1 -AdministratorUID administrator@example.com -AdministratorPWD '***' -TestUserPWD '***' -SaltParameter '***' -ResourceDir /tmp/mpas/resource
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AdministratorUID,
    [Parameter(Mandatory = $true)] [string] $AdministratorPWD,
    [Parameter(Mandatory = $true)] [string] $TestUserPWD,
    [Parameter(Mandatory = $true)] [string] $SaltParameter,
    [string] $ResourceDir,
    [switch] $NoNetFx,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

#  **$PSScriptRoot を param() の既定値で使わない**（5.1 の -File 起動で空になる。test.ps1 と同じ）
$programs = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $programs)
$core     = Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore'
$fx       = Join-Path $programs 'MultiPurposeAuthSite\MultiPurposeAuthSite'
$onLinux  = [bool] $IsLinux

if ($onLinux) {
    if (-not $ResourceDir) { throw 'Linux では -ResourceDir が要ります（雛形のパスは C:/root/files/resource）。' }
    $NoNetFx = $true
}

$coreOut = Join-Path $core 'appsettings.json'
$fxOut   = Join-Path $fx 'app.config'

foreach ($p in @($coreOut) + $(if ($NoNetFx) { @() } else { @($fxOut) })) {
    if ((Test-Path $p) -and -not $Force) {
        throw "既にあります（手元の実ファイルは秘密を含むので、上書きしません。上書きするなら -Force）: $p"
    }
}

# ------------------------------------------------------------------
# リソースの写し（-ResourceDir）
# ------------------------------------------------------------------
$from = 'C:/root/files/resource'
$to   = $null

if ($ResourceDir) {
    New-Item -ItemType Directory -Force $ResourceDir | Out-Null
    $ResourceDir = (Resolve-Path $ResourceDir).Path
    $to = $ResourceDir.Replace('\', '/').TrimEnd('/')

    Copy-Item (Join-Path $repoRoot 'root\files\resource\*') $ResourceDir -Recurse -Force

    #  **log4net の構成は、中身（書き出し先）も Windows のパス**（C:\root\files\resource\...）。写しの方だけ置き換える
    foreach ($conf in Get-ChildItem (Join-Path $ResourceDir 'MultiPurposeAuthSite\Log') -Filter 'SampleLogConf*.xml') {
        $text = [IO.File]::ReadAllText($conf.FullName)
        $text = $text.Replace('C:\root\files\resource\', $to + '/').Replace('C:\root\files\resource', $to)
        if ($onLinux) {
            #  書き出し先の残りの `\`（MultiPurposeAuthSite\Log\ACCESS_Core など）も `/` にする
            $text = [regex]::Replace($text, '(name="File"\s+value=")([^"]*)(")', {
                param($m) $m.Groups[1].Value + $m.Groups[2].Value.Replace('\', '/') + $m.Groups[3].Value })
        }
        [IO.File]::WriteAllText($conf.FullName, $text, (New-Object System.Text.UTF8Encoding($true)))
    }

    Write-Host "リソースを写しました : $ResourceDir"
}

# ------------------------------------------------------------------
# 設定ファイル
# ------------------------------------------------------------------
$vals = [ordered]@{
    AdministratorUID = $AdministratorUID
    AdministratorPWD = $AdministratorPWD
    TestUserPWD      = $TestUserPWD
    SaltParameter    = $SaltParameter
}

function Set-Placeholder
{
    param([string] $Text, [string] $Pattern, [string] $File)

    foreach ($k in $vals.Keys) {
        $re = $Pattern.Replace('{0}', [regex]::Escape($k))
        if (-not [regex]::IsMatch($Text, $re)) { throw "$k の穴埋め（[...]）が見つかりません : $File" }
        $v = $vals[$k]
        $Text = [regex]::Replace($Text, $re, { param($m) $m.Groups[1].Value + $v + $m.Groups[2].Value })
    }
    return $Text
}

$json = [IO.File]::ReadAllText((Join-Path $core '_appsettings.json'))
$json = Set-Placeholder -Text $json -Pattern '("{0}"\s*:\s*")\[[^\]"]*\](")' -File '_appsettings.json'
if ($to) { $json = $json.Replace($from, $to) }
[IO.File]::WriteAllText($coreOut, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "作りました : $coreOut"

if (-not $NoNetFx) {
    $xml = [IO.File]::ReadAllText((Join-Path $fx '_app.config'))
    $xml = Set-Placeholder -Text $xml -Pattern '(key="{0}"\s+value=")\[[^\]"]*\](")' -File '_app.config'
    if ($to) { $xml = $xml.Replace($from.Replace('/', '\'), $to.Replace('/', '\')) }
    [IO.File]::WriteAllText($fxOut, $xml, (New-Object System.Text.UTF8Encoding($true)))
    Write-Host "作りました : $fxOut"
}
