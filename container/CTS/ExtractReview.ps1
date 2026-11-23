<#
.SYNOPSIS
    適合性テスト（Conformance Suite）の報告書から、REVIEW の判定と、その判定の材料（OP の応答）を取り出す（#417）。
.DESCRIPTION
    ＜何のためか＞
      REVIEW は、Conformance Suite が「画面の写しを上げて、人が合否を付ける」とする判定である。
      **自動の実行では写しを上げない**ので、代わりに、報告書のログに残った**自動操作のブラウザが受けた OP の応答**
      （WebRunner の「Scripted browser HTTP response」）と、**クライアント（Conformance Suite）へ返った応答**から、合否を付ける。
      合否の付け方と、今の基準は container\CTS\README.md の「REVIEW の見方」。

    ＜何をするか＞
      1. out\<プラン>-report.zip（RunTestPlan.ps1 が書く報告書）の、モジュールごとのログ（test-log-*.json）を読む。
      2. REVIEW の判定ごとに、その判定のある区間（ブラウザを OP へ送るたびに区切る）から、次を取り出す。
         - 判定の名前（src）・求められていること（msg）・原典（requirements）
         - ブラウザが受けた OP の応答（URL のパス・状態コード・タイトル・本文の文字・リンクと画像）
         - ブラウザが操作した画面（Login・Consent など）
         - クライアントへ返った応答（error・error_description、または code などのパラメタの名前）
         - モジュールの結果と、SUCCESS・INFO 以外の判定
      3. 判定の材料を 1 行にまとめた「材料の形」（Evidence）を作る。**次の実行で、基準と比べるため**（-Baseline）。
      4. out\review\<プラン>.json に詳細を書き、画面に表を出す。

    ＜秘密を出さない＞
      **ログには、テスト利用者のパスワード（WebRunner の commands）とクライアントの秘密鍵（config）が入っている。**
      これらの項目は読まない。out\ は Git の管理外。**取り出したものを Issue やコメントに貼らない**（合否と理由、要る文言だけを書く）。

    ＜終了コード＞
      0 : 取り出せた（-Baseline なら、すべて基準と同じ形）
      1 : -Baseline と比べて、形が変わった・基準に無い REVIEW がある（合否を付け直す）
      2 : 前提の誤り（報告書が無い など）
.PARAMETER Plan
    読むプラン。省略すると、out\ にある報告書（名前が oidcc- か fapi で始まるもの）をすべて読む。
.PARAMETER Baseline
    基準のファイル（既定は ReviewBaseline.csv）。在れば、材料の形を比べ、合否を引き継ぐ。-NoBaseline で比べない。
.PARAMETER NoBaseline
    基準と比べない。
.PARAMETER TextLength
    out\review\*.json に残す、画面の本文の文字数の上限。
.EXAMPLE
    .\ExtractReview.ps1
.EXAMPLE
    .\ExtractReview.ps1 -Plan oidcc-basic, fapi2-sp-mtls
.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/23  玄人 幸道         新規（#417）
#>
[CmdletBinding()]
param(
    [string[]]$Plan,
    [string]$Baseline = '',
    [switch]$NoBaseline,
    [int]$TextLength = 2000
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Windows PowerShell 5.1 は、param の既定値の中で $PSScriptRoot が空になるので、ここで決める
if (-not $Baseline) { $Baseline = Join-Path $PSScriptRoot 'ReviewBaseline.csv' }
$outDir = Join-Path $PSScriptRoot 'out'
$reviewDir = Join-Path $outDir 'review'

# 読まない項目（秘密を含む）。WebRunner の commands はテスト利用者のパスワード、config はクライアントの秘密鍵を含む
$secretFields = @('commands', 'config')

function Get-UrlPath([string]$url)
{
    # クエリとフラグメントを落とした「ホスト＋パス」（材料の形を、実行ごとに変わる値から切り離す）
    if ([string]::IsNullOrEmpty($url)) { return '' }
    try
    {
        $u = [Uri]$url
        return ('{0}{1}' -f $u.Authority, $u.AbsolutePath)
    }
    catch { return ($url -replace '[?#].*$', '') }
}

function ConvertTo-PageSummary([string]$html, [int]$max)
{
    # HTML から、タイトル・本文の文字・リンク・画像を取り出す
    $title = ''
    $m = [regex]::Match($html, '<title[^>]*>(.*?)</title>', 'IgnoreCase, Singleline')
    if ($m.Success) { $title = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value).Trim() }

    $links = @([regex]::Matches($html, '<a\b[^>]*\bhref\s*=\s*"([^"]*)"', 'IgnoreCase') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) } | Select-Object -Unique)
    $images = @([regex]::Matches($html, '<img\b[^>]*\bsrc\s*=\s*"([^"]*)"', 'IgnoreCase') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) } | Select-Object -Unique)

    $t = [regex]::Replace($html, '<(script|style|head)\b.*?</\1>', ' ', 'IgnoreCase, Singleline')
    $t = [regex]::Replace($t, '<[^>]+>', ' ')
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    $t = ([regex]::Replace($t, '\s+', ' ')).Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max) + '…' }

    return [pscustomobject]@{ Title = $title; Text = $t; Links = $links; Images = $images }
}

function Get-ClientResponse($entry)
{
    # クライアントへ返った応答。error があれば error と error_description、無ければパラメタの名前だけ（code などの値は出さない）
    $params = $null
    foreach ($name in 'url_query', 'url_fragment', 'post_body', 'incoming_query_string_params', 'incoming_body_form_params')
    {
        $p = $entry.PSObject.Properties[$name]
        if ($p -and $p.Value -and @($p.Value.PSObject.Properties).Count -gt 0) { $params = $p.Value; break }
    }
    if (-not $params) { return $null }
    $names = @($params.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names -contains 'response' -and -not ($names -contains 'error'))
    {
        # JARM：response の JWT の中身を見る（署名だけの JWT なら payload を読める。暗号化した JWT は読めない）
        $parts = ([string]$params.response).Split('.')
        if ($parts.Count -eq 3)
        {
            try
            {
                $b = $parts[1].Replace('-', '+').Replace('_', '/')
                switch ($b.Length % 4) { 2 { $b += '==' } 3 { $b += '=' } }
                $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) | ConvertFrom-Json
                $params = $claims
                $names = @('jarm') + @($claims.PSObject.Properties | ForEach-Object { $_.Name } | Where-Object { $_ -notin 'iss', 'aud', 'exp', 'iat' })
            }
            catch { $names = @('jarm(unreadable)') }
        }
        elseif ($parts.Count -eq 5) { $names = @('jarm(encrypted)') }
    }
    if ($names -contains 'error')
    {
        return [pscustomobject]@{ Kind = 'error'; Error = [string]$params.error; ErrorDescription = [string]$params.error_description; Names = $names }
    }
    return [pscustomobject]@{ Kind = 'params'; Error = ''; ErrorDescription = ''; Names = $names }
}

function Read-ModuleLog($json, [string]$planName, [int]$max)
{
    $results = @($json.results)
    $testName = [string]$json.testInfo.testName
    $testId = [string]$json.testInfo.testId

    # バリアント（モジュールごと。Hybrid の response_type など）
    $variant = ''
    $v = $results | Where-Object { $_.PSObject.Properties['variant'] -and $_.variant } | Select-Object -First 1
    if ($v) { $variant = (@($v.variant.PSObject.Properties | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join ',') }

    $finished = $results | Where-Object { $_.PSObject.Properties['testmodule_result'] } | Select-Object -Last 1
    $moduleResult = if ($finished) { [string]$finished.testmodule_result } else { '' }
    $notable = @($results | Where-Object { $_.result -in 'FAILURE', 'WARNING' } | ForEach-Object { '{0}:{1}' -f $_.result, $_.src })

    # ブラウザを OP へ送るたび（http=redirect）に区間を分ける。
    # **REVIEW は、送る直前に書かれることがある**（ログアウトの口）ので、前の区間の最後のブラウザの項目より後の REVIEW は、次の区間へ移す
    $segments = New-Object System.Collections.ArrayList
    $current = New-Object System.Collections.ArrayList
    foreach ($e in $results)
    {
        if ($e.PSObject.Properties['http'] -and $e.http -eq 'redirect' -and $current.Count -gt 0)
        {
            $lastBrowser = -1
            for ($k = 0; $k -lt $current.Count; $k++) { if ($current[$k].src -eq 'WebRunner') { $lastBrowser = $k } }
            $carry = @()
            for ($k = $current.Count - 1; $k -gt $lastBrowser; $k--)
            {
                if ($current[$k].result -eq 'REVIEW') { $carry = @($current[$k]) + $carry; $current.RemoveAt($k) }
            }
            [void]$segments.Add($current)
            $current = New-Object System.Collections.ArrayList
            foreach ($c in $carry) { [void]$current.Add($c) }
        }
        [void]$current.Add($e)
    }
    if ($current.Count -gt 0) { [void]$segments.Add($current) }

    $out = @()
    foreach ($seg in $segments)
    {
        $reviews = @($seg | Where-Object { $_.result -eq 'REVIEW' })
        if ($reviews.Count -eq 0) { continue }

        $items = @($seg)
        $redirect = $items | Where-Object { $_.PSObject.Properties['http'] -and $_.http -eq 'redirect' } | Select-Object -First 1
        $redirectTo = if ($redirect) { Get-UrlPath ([string]$redirect.redirect_to) } else { '' }

        # ブラウザが受けた応答。URL は、その後の WebRunner の項目の url（リダイレクトを追った後の画面）
        $pages = @()
        $tasks = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $items.Count; $i++)
        {
            $e = $items[$i]
            if ($e.src -ne 'WebRunner') { continue }
            if ($e.msg -eq 'Scripted browser HTTP response')
            {
                $url = ''
                for ($k = $i + 1; $k -lt $items.Count; $k++)
                {
                    if ($items[$k].src -eq 'WebRunner' -and $items[$k].PSObject.Properties['url'] -and $items[$k].url) { $url = [string]$items[$k].url; break }
                }
                if (-not $url)
                {
                    $req = $items[0..$i] | Where-Object { $_.src -eq 'WebRunner' -and $_.PSObject.Properties['request_uri'] } | Select-Object -Last 1
                    if ($req) { $url = [string]$req.request_uri }
                }
                $s = ConvertTo-PageSummary ([string]$e.response_content) $max
                $pages += [pscustomobject]@{
                    Url = Get-UrlPath $url; Status = $e.response_status_code; ContentType = [string]$e.response_content_type
                    Title = $s.Title; Text = $s.Text; Links = $s.Links; Images = $s.Images
                }
            }
            elseif ($e.PSObject.Properties['task'] -and $e.task -and $e.browser -in 'wait', 'text', 'click')
            {
                # 操作した画面（Verify Complete は Conformance Suite の側の待ち合わせなので数えない。
                # 画面の URL は、操作を始めたときのもの。complete の url は操作の後の画面なので使わない）
                if ($e.task -ne 'Verify Complete')
                {
                    $label = '{0}@{1}' -f $e.task, (Get-UrlPath ([string]$e.url))
                    if (-not $tasks.Contains($label)) { [void]$tasks.Add($label) }
                }
            }
        }

        $client = $null
        foreach ($e in $items)
        {
            if (($e.PSObject.Properties['http'] -and $e.http -in 'redirect-in', 'incoming'))
            {
                $c = Get-ClientResponse $e
                if ($c) { $client = $c }
            }
        }

        foreach ($r in $reviews)
        {
            # 材料の形：操作した画面・最後の OP の画面・クライアントへの応答（実行ごとに変わる値は入れない）
            $opPages = @($pages | Where-Object { $_.Url -and $_.Url -notlike 'localhost.emobix.co.uk*' })
            $last = $opPages | Select-Object -Last 1
            $parts = @()
            if ($tasks.Count -gt 0) { $parts += ('tasks=' + ($tasks -join '>')) }
            if ($last) { $parts += ('op-page={0} {1} [{2}]' -f $last.Status, $last.Url, $last.Title) }
            if ($client)
            {
                if ($client.Kind -eq 'error') { $parts += ('client=error:' + $client.Error) }
                else { $parts += ('client=' + (($client.Names | Sort-Object) -join '+')) }
            }
            if ($parts.Count -eq 0) { $parts += 'none' }

            $out += [pscustomobject]@{
                Plan = $planName; Module = $testName; TestId = $testId; Variant = $variant
                Src = [string]$r.src; Msg = [string]$r.msg; Requirements = [string]$r.requirements
                ModuleResult = $moduleResult; Notable = $notable
                RedirectTo = $redirectTo; Tasks = @($tasks); Pages = $pages; Client = $client
                Evidence = ($parts -join ' | ')
            }
        }
    }
    return $out
}

# 読む報告書
if ($Plan)
{
    $zips = foreach ($p in $Plan)
    {
        $f = Join-Path $outDir ('{0}-report.zip' -f $p)
        if (-not (Test-Path $f)) { Write-Host ('報告書がありません : {0}（RunTestPlan.ps1 -Plan {1} を先に回す）' -f $f, $p) -ForegroundColor Red; exit 2 }
        Get-Item $f
    }
}
else
{
    $zips = @(Get-ChildItem $outDir -Filter '*-report.zip' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(oidcc|fapi)' })
    if ($zips.Count -eq 0) { Write-Host ('報告書がありません : {0}\*-report.zip' -f $outDir) -ForegroundColor Red; exit 2 }
}

New-Item -ItemType Directory -Force $reviewDir | Out-Null

$all = @()
foreach ($zf in $zips)
{
    $planName = $zf.Name -replace '-report\.zip$', ''
    $rows = @()
    $z = [IO.Compression.ZipFile]::OpenRead($zf.FullName)
    try
    {
        foreach ($entry in $z.Entries | Where-Object { $_.FullName -like 'test-log-*.json' })
        {
            $reader = New-Object IO.StreamReader($entry.Open(), [Text.Encoding]::UTF8)
            try { $text = $reader.ReadToEnd() } finally { $reader.Close() }
            $json = $text | ConvertFrom-Json
            # 秘密を含む項目を、読む前に落とす
            foreach ($e in @($json.results)) { foreach ($s in $secretFields) { if ($e.PSObject.Properties[$s]) { $e.PSObject.Properties.Remove($s) } } }
            $rows += @(Read-ModuleLog $json $planName $TextLength)
        }
    }
    finally { $z.Dispose() }

    $file = Join-Path $reviewDir ('{0}.json' -f $planName)
    $body = ConvertTo-Json -InputObject @($rows) -Depth 8
    [IO.File]::WriteAllText($file, $body, (New-Object Text.UTF8Encoding($false)))
    $all += $rows
}

# 基準と比べる（Plan・Module・Variant・Src で引き、材料の形が同じなら合否を引き継ぐ）
$exit = 0
$base = @{}
$useBaseline = (-not $NoBaseline) -and (Test-Path $Baseline)
if ($useBaseline)
{
    foreach ($b in Import-Csv $Baseline -Encoding UTF8)
    {
        $base[('{0}|{1}|{2}|{3}' -f $b.Plan, $b.Module, $b.Variant, $b.Src)] = $b
    }
}

$table = foreach ($r in $all)
{
    $verdict = ''
    $state = ''
    if ($useBaseline)
    {
        $b = $base[('{0}|{1}|{2}|{3}' -f $r.Plan, $r.Module, $r.Variant, $r.Src)]
        if (-not $b) { $state = '基準に無い'; $exit = 1 }
        elseif ($b.Evidence -ne $r.Evidence) { $state = '形が変わった'; $verdict = $b.Verdict; $exit = 1 }
        else { $state = '同じ'; $verdict = $b.Verdict }
    }
    [pscustomobject]@{ Plan = $r.Plan; Module = $r.Module; Variant = $r.Variant; Src = $r.Src; Result = $r.ModuleResult; Evidence = $r.Evidence; Verdict = $verdict; State = $state }
}

$table | Sort-Object Plan, Module, Variant, Src | Format-Table -AutoSize -Wrap | Out-String -Width 400 | Write-Host
Write-Host ('REVIEW の判定 : {0}（モジュール {1}・名前 {2} 種類・判定 {3} 種類）' -f @($all).Count,
    @($all | ForEach-Object { '{0}|{1}' -f $_.Plan, $_.TestId } | Sort-Object -Unique).Count,
    @($all | ForEach-Object { $_.Module } | Sort-Object -Unique).Count,
    @($all | ForEach-Object { $_.Src } | Sort-Object -Unique).Count)
if ($useBaseline)
{
    $changed = @($table | Where-Object { $_.State -ne '同じ' })
    Write-Host ('基準 {0} と比べて : 同じ {1}・変わった・無い {2}' -f $Baseline, (@($table).Count - $changed.Count), $changed.Count) -ForegroundColor $(if ($changed.Count -gt 0) { 'Yellow' } else { 'Green' })
}
else
{
    Write-Host '基準とは比べていない（-NoBaseline か、基準のファイルが無い）'
}
Write-Host ('詳細 : {0}\<プラン>.json（Git の管理外。Issue やコメントに貼らない）' -f $reviewDir)
exit $exit
