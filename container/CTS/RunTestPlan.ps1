<#
.SYNOPSIS
    適合性テスト（Conformance Suite）のプランを、REST の API で回す（#350）。
.DESCRIPTION
    ＜前提＞
      2_DockerComposeUp.bat で、Conformance Suite と相手の OP を起動しておくこと。
      Conformance Suite は dev の構成（SPRING_PROFILES_ACTIVE=dev）なので、API は認証なしで呼べる。

    ＜何をするか＞
      1. config\<プラン>.json（雛形）の差し込み口（@TEST_USER@・@TEST_PASSWORD@）を、
         **手元の appsettings.json のテスト利用者で埋めて**、out\<プラン>.json に書く（out\ は Git の管理外）。
         **テスト利用者のパスワードは秘密なので、雛形には書かない。**
      2. プランを作り（POST api/plan）、モジュールを 1 つずつ起動し（POST api/runner）、終わるまで待つ（GET api/info/{id}）。
         **ブラウザの操作（サインイン・同意）は、Conformance Suite の server が雛形の "browser" で自動で行う。**
      3. 結果を表で出し、out\ に JSON と、Conformance Suite の報告書（exporthtml の zip）を書く。

    ＜Python の run-test-plan.py を使わない理由＞
      原本の scripts\run-test-plan.py と同じ API を呼ぶだけなので、Python と追加のパッケージ（httpx・pyparsing）を要らなくした。
      **プランの選び方・バリアントは、このスクリプトの表で固定する**（下の $plans）。

    ＜終了コード＞
      0 : すべてのモジュールが終わり、FAILED・INTERRUPTED・時間切れが無い
      1 : どれかが FAILED・INTERRUPTED・時間切れ
      2 : 前提の誤り（Conformance Suite に届かない、設定が読めない など）
.PARAMETER Plan
    回すプラン（oidcc-basic / oidcc-config）。
.PARAMETER ModuleTimeoutSec
    1 つのモジュールを待つ上限（秒）。ブラウザの自動操作が合わないと WAITING のまま止まるので、上限で打ち切る。
.EXAMPLE
    .\RunTestPlan.ps1 -Plan oidcc-basic
.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/10  玄人 幸道         新規（#350）
#>
[CmdletBinding()]
param(
    [ValidateSet('oidcc-basic', 'oidcc-config')]
    [string]$Plan = 'oidcc-basic',

    [int]$ModuleTimeoutSec = 180
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$base = 'https://localhost.emobix.co.uk:8443/'
$appsettings = Join-Path $here '..\..\root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\appsettings.json'
$outDir = Join-Path $here 'out'

# プランの名前とバリアント（Conformance Suite の api/plan/info で確かめた値）
$plans = @{
    'oidcc-basic'  = @{ Name = 'oidcc-basic-certification-test-plan';  Variant = '{"server_metadata":"discovery","client_registration":"static_client"}' }
    'oidcc-config' = @{ Name = 'oidcc-config-certification-test-plan'; Variant = $null }
}

#region HTTP（自己署名の証明書。5.1 と 7 で API を分ける。root\CODING.md 5 節）

if ($PSVersionTable.PSVersion.Major -lt 6)
{
    if (-not ('MpasCtsTls' -as [type]))
    {
        # **スクリプト ブロックではなく、コンパイルしたデリゲートを使う**（root\CODING.md 5 節）
        Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class MpasCtsTls
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
    [MpasCtsTls]::TrustAll()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

function Invoke-Cts([string]$Method, [string]$PathAndQuery, [string]$Body, [string]$OutFile)
{
    $url = $base + $PathAndQuery

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $args1 = @{ Method = $Method; Uri = $url; SkipCertificateCheck = $true; TimeoutSec = 60 }
        # **本文の無い POST にも Content-Type を付ける**（7 はフォームの型を付け、api/runner が 415 で断る）
        if ($Method -eq 'POST') { $args1.ContentType = 'application/json' }
        if ($Body) { $args1.Body = [Text.Encoding]::UTF8.GetBytes($Body) }
        if ($OutFile) { Invoke-WebRequest @args1 -OutFile $OutFile; return $null }
        $res = Invoke-WebRequest @args1
        return [string]$res.Content
    }

    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.Timeout = 60000
    if ($Body)
    {
        $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($Body)
        $req.ContentType = 'application/json'
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
    }
    elseif ($Method -eq 'POST')
    {
        $req.ContentLength = 0
    }

    $res = $req.GetResponse()
    try
    {
        $stream = $res.GetResponseStream()
        if ($OutFile)
        {
            $fs = [IO.File]::Create($OutFile)
            try { $stream.CopyTo($fs) } finally { $fs.Close() }
            return $null
        }
        $reader = New-Object IO.StreamReader($stream, (New-Object Text.UTF8Encoding $false))
        return $reader.ReadToEnd()
    }
    finally
    {
        $res.Close()
    }
}

#endregion

#region 前提

try
{
    [void](Invoke-Cts 'GET' 'api/currentuser' $null $null)
}
catch
{
    Write-Host ('Conformance Suite（{0}）に届きません。2_DockerComposeUp.bat で起動してください（起動には 1〜2 分かかる）。' -f $base) -ForegroundColor Red
    Write-Host ('  理由 : {0}' -f $_.Exception.Message)
    exit 2
}

if (-not (Test-Path -LiteralPath $appsettings))
{
    Write-Host ('手元の appsettings.json がありません : {0}' -f $appsettings) -ForegroundColor Red
    exit 2
}

# **appsettings.json はコメントを含みうる**ので、ConvertFrom-Json（5.1 はコメントを読めない）ではなく、値を正規表現で引く
$settingsText = [IO.File]::ReadAllText($appsettings)
function Get-SettingValue([string]$Name)
{
    $m = [regex]::Match($settingsText, '"' + [regex]::Escape($Name) + '"\s*:\s*"((?:[^"\\]|\\.)*)"')
    if ($m.Success) { return [regex]::Unescape($m.Groups[1].Value) }
    return $null
}

$password = Get-SettingValue 'TestUserPWD'
$suffix = Get-SettingValue 'TestUserSuffix'
if ([string]::IsNullOrEmpty($password))
{
    Write-Host '手元の appsettings.json に TestUserPWD がありません（テスト利用者を作れない）。' -ForegroundColor Red
    exit 2
}

# テスト利用者（**OP の種データが作る一般の利用者**。E2E の TestEnv.TestUserName と同じ名前）
$user = 'tanaka' + [string]$suffix

#endregion

#region 設定を作る

$template = Join-Path $here ('config\{0}.json' -f $Plan)
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$configPath = Join-Path $outDir ('{0}.json' -f $Plan)

function ConvertTo-JsonString([string]$Value)
{
    # JSON の文字列の中身として埋める（引用符・バックスラッシュ・制御文字を逃がす）
    return (ConvertTo-Json $Value).Trim('"')
}

$config = [IO.File]::ReadAllText($template)
$config = $config.Replace('@TEST_USER@', (ConvertTo-JsonString $user))
$config = $config.Replace('@TEST_PASSWORD@', (ConvertTo-JsonString $password))
[IO.File]::WriteAllText($configPath, $config, (New-Object Text.UTF8Encoding $false))

#endregion

#region プランを作り、モジュールを回す

$p = $plans[$Plan]
$query = 'api/plan?planName=' + [Uri]::EscapeDataString($p.Name)
if ($p.Variant) { $query += '&variant=' + [Uri]::EscapeDataString($p.Variant) }

$created = (Invoke-Cts 'POST' $query $config $null) | ConvertFrom-Json
$planId = $created.id

Write-Host ('プラン : {0}（{1}）' -f $p.Name, $planId) -ForegroundColor Cyan
Write-Host ('  {0}plan-detail.html?plan={1}' -f $base, $planId)

$results = New-Object Collections.ArrayList

foreach ($m in @($created.modules))
{
    $runQuery = 'api/runner?test=' + [Uri]::EscapeDataString($m.testModule) + '&plan=' + [Uri]::EscapeDataString($planId)
    if ($m.variant)
    {
        $runQuery += '&variant=' + [Uri]::EscapeDataString(($m.variant | ConvertTo-Json -Compress))
    }

    $run = (Invoke-Cts 'POST' $runQuery $null $null) | ConvertFrom-Json
    $testId = $run.id

    # **待ち時間は回数ではなく実時間で測る**（root\CODING.md 5 節）
    $deadline = (Get-Date).AddSeconds($ModuleTimeoutSec)
    $info = $null
    do
    {
        Start-Sleep -Seconds 2
        $info = (Invoke-Cts 'GET' ('api/info/' + $testId) $null $null) | ConvertFrom-Json
    }
    while (($info.status -ne 'FINISHED') -and ($info.status -ne 'INTERRUPTED') -and ((Get-Date) -lt $deadline))

    $status = [string]$info.status
    $result = [string]$info.result
    if (($status -ne 'FINISHED') -and ($status -ne 'INTERRUPTED'))
    {
        $result = 'TIMEOUT（' + $status + '）'
    }

    [void]$results.Add([pscustomobject]@{ Module = $m.testModule; Status = $status; Result = $result; Id = $testId })
    Write-Host ('  {0,-12} {1}' -f $result, $m.testModule)
}

#endregion

#region 結果

$resultPath = Join-Path $outDir ('{0}-result.json' -f $Plan)
[IO.File]::WriteAllText($resultPath, (@{ plan = $p.Name; planId = $planId; modules = $results } | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))

$zip = Join-Path $outDir ('{0}-report.zip' -f $Plan)
try
{
    # **URL は api/plan/exporthtml/{id}**（release-v5.3.4 で確かめた。api/plan/{id}/exporthtml は 404）
    [void](Invoke-Cts 'GET' ('api/plan/exporthtml/' + $planId) $null $zip)
}
catch
{
    Write-Host ('報告書（exporthtml）を書き出せませんでした : {0}' -f $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host ''
Write-Host '================ 結果 ================'
$results | Group-Object Result | Sort-Object Name | ForEach-Object { Write-Host ('  {0,-20} {1}' -f $_.Name, $_.Count) }
Write-Host ('  結果の JSON : {0}' -f $resultPath)
Write-Host ('  報告書      : {0}' -f $zip)

$bad = @($results | Where-Object { ($_.Result -eq 'FAILED') -or ($_.Status -eq 'INTERRUPTED') -or ($_.Result -like 'TIMEOUT*') })
if ($bad.Count -gt 0) { exit 1 }
exit 0

#endregion
