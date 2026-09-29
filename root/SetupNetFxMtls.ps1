<#
.SYNOPSIS
    net48 版で mTLS（FA-6）を測るための証明書を、用意・信頼・確認・後片付けする。

.DESCRIPTION
    ＜なぜ要るか＞
      mTLS のテストは、既定では net10.0 版だけを測る（#226）。
      net10.0 版はテスト専用のフック（Tests/MtlsTestHook）で発行元を問わず受け付けるが、
      **net48 版（IIS Express）は、IIS がアプリより前で証明書の鎖を検証し、
      信頼できなければ HTTP 403.16 で断る。**
      IIS に「自己署名を通す」設定は無いので、**テスト用 CA を信頼されたルートに入れる**しかない。

      その準備は管理者権限を要し、後片付けまで人の判断が要るため、通しには含めていない。
      **手で打っていた 5 つのコマンドを、ここに置いた。**

    ＜シークレットは含まない＞
      私有鍵はスクリプトに現れない（証明書ストアの中で生成される）。
      -Action Trust が読む .cer は**公開部分だけ**である。
      パスワードも接続文字列も扱わないので、このファイルは資格情報にならない。

    ＜なぜ Prepare と Trust を分けるか＞
      **証明書は「テストを実行する利用者」の CurrentUser\My に無ければならない。**
      TestCertificate.ForTarget は、netfx のとき CurrentUser\My を Subject で引く。
      管理者の PowerShell が別アカウントなら、証明書は別の利用者のストアに入り、
      テストからは見えない（「証明書がありません」で止まる）。

      そこで **Prepare は通常の PowerShell、Trust だけ管理者**に分けた。
      同じアカウントで昇格するなら、まとめて実行しても同じ結果になる。

    ＜Subject は E2E の定数と一対一＞
      CN=mpas-e2e-mtls-client  … Flows.cs    の KnownClients.MtlsSubjectDn
      CN=mpas-e2e-mtls-other   … MtlsTests.cs の OtherSubjectDn

      **綴りが違うとテストが証明書を見つけられない。**
      そのため Prepare / Check は、その 2 つのソースを読んで**値が一致することを確かめる。**

.PARAMETER Action
    Prepare … CA とクライアント証明書 2 枚を作り、CA の公開部分を .cer に書き出す（管理者は不要）
    Trust   … その .cer を LocalMachine\Root に入れる（**管理者が必要**）
    Check   … いま何が在るかを表示する（どちらでもよい）
    Cleanup … 作ったものを消す（LocalMachine\Root の分は**管理者が必要**）

.PARAMETER CerPath
    CA の公開部分（.cer）の場所。既定は %TEMP%\mpas-e2e-ca.cer。
    **Prepare と Trust を別アカウントで実行するなら、両方に同じパスを明示すること**
    （%TEMP% はアカウントごとに違う）。

.PARAMETER Days
    証明書の有効期間（日）。既定 7。

.EXAMPLE
    # 1) 通常の PowerShell
    .\SetupNetFxMtls.ps1 -Action Prepare

.EXAMPLE
    # 2) 管理者の PowerShell
    .\SetupNetFxMtls.ps1 -Action Trust

.EXAMPLE
    # 3) 通常の PowerShell（-UpdateTestCases は付けない。原本に netfx の mTLS が混ざる）
    .\2_RunAllTests.ps1 -Launch -NetFxMtls

.EXAMPLE
    # 4) 後片付け（管理者。信頼されたルートにテスト用 CA を残さない）
    .\SetupNetFxMtls.ps1 -Action Cleanup

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/09/29  玄人 幸道         新規（#245 の段階 3。TESTING.md の手順をファイルにした）
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Trust', 'Check', 'Cleanup')]
    [string] $Action,

    [string] $CerPath,

    [int] $Days = 7
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
if (-not $CerPath)
{
    $CerPath = Join-Path $env:TEMP 'mpas-e2e-ca.cer'
}

$CaSubject = 'CN=MPAS E2E Test CA'
$ClientSubjects = @('CN=mpas-e2e-mtls-client', 'CN=mpas-e2e-mtls-other')
$AllSubjects = @($CaSubject) + $ClientSubjects

function Test-Elevated
{
    <#
    .SYNOPSIS
    管理者として実行しているか。
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-SubjectsMatchSource
{
    <#
    .SYNOPSIS
    E2E 側の定数と、このスクリプトの Subject が一致することを確かめる。

    .DESCRIPTION
    **綴りが違うと、テストが証明書を見つけられない**（症状は「証明書がありません」）。
    ソースが読めないときは警告だけにする。
    #>
    $root = Split-Path -Parent $PSCommandPath
    $targets = @(
        @{ Path = 'programs\Tests\E2ETests\Infrastructure\Flows.cs'; Name = 'MtlsSubjectDn' },
        @{ Path = 'programs\Tests\E2ETests\Tests\Fapi\MtlsTests.cs'; Name = 'OtherSubjectDn' }
    )

    foreach ($t in $targets)
    {
        $full = Join-Path $root $t.Path

        if (-not (Test-Path $full))
        {
            Write-Warning ("ソースが見つからないので Subject の突き合わせを省きます : " + $t.Path)
            continue
        }

        # 既定のエンコードは 5.1 が ANSI、7 が UTF-8 なので明示する（CODING.md 5 節）
        $text = Get-Content -Path $full -Raw -Encoding UTF8
        $m = [regex]::Match($text, ($t.Name + '\s*=\s*"(?<dn>[^"]+)"'))

        if (-not $m.Success)
        {
            Write-Warning ("定数 " + $t.Name + " が読めないので突き合わせを省きます : " + $t.Path)
            continue
        }

        if ($ClientSubjects -notcontains $m.Groups['dn'].Value)
        {
            throw ("E2E の " + $t.Name + " は '" + $m.Groups['dn'].Value + "' ですが、" +
                "このスクリプトは " + ($ClientSubjects -join ' / ') + " を作ります。" +
                "**どちらかを直してください**（一致しないとテストが証明書を見つけられません）。")
        }
    }

    Write-Output "  Subject は E2E の定数と一致しています。"
}

function Show-State
{
    <#
    .SYNOPSIS
    いま在る証明書を表示する。
    #>
    Write-Output ("  実行している利用者 : " + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-Output ("  管理者か           : " + (Test-Elevated))
    Write-Output ("  .cer の場所        : " + $CerPath + "  (在る : " + (Test-Path $CerPath) + ")")
    Write-Output ""

    foreach ($location in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\Root')
    {
        Write-Output ("  " + $location)

        $found = @(Get-ChildItem $location -ErrorAction SilentlyContinue |
            Where-Object { $AllSubjects -contains $_.Subject })

        if ($found.Count -eq 0)
        {
            Write-Output "      (無し)"
        }
        else
        {
            foreach ($c in $found | Sort-Object Subject)
            {
                # Format-Table は 5.1 が全角の幅を誤るので使わない（CODING.md 5 節）
                Write-Output ("      " + $c.Subject +
                    "  秘密鍵 : " + $c.HasPrivateKey +
                    "  期限 : " + $c.NotAfter.ToString('yyyy-MM-dd') +
                    "  有効 : " + ($c.NotBefore -le (Get-Date) -and (Get-Date) -le $c.NotAfter))
            }
        }
    }
}

switch ($Action)
{
    'Prepare'
    {
        Write-Output "=== Prepare : 証明書を作る（管理者は不要）==="

        if (Test-Elevated)
        {
            Write-Warning ("管理者として実行しています。**証明書は管理者の CurrentUser\My に入ります。**" +
                "テストを別のアカウントで実行するなら、そのアカウントで実行し直してください。")
        }

        Assert-SubjectsMatchSource

        $ca = New-SelfSignedCertificate -Subject $CaSubject `
            -KeyUsage CertSign, CRLSign, DigitalSignature `
            -TextExtension @('2.5.29.19={critical}{text}ca=true') `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays($Days)

        Write-Output ("  CA を作りました : " + $ca.Subject + " (Thumbprint " + $ca.Thumbprint + ")")

        foreach ($subject in $ClientSubjects)
        {
            # 1.3.6.1.5.5.7.3.2 = クライアント認証の EKU
            $client = New-SelfSignedCertificate -Subject $subject -Signer $ca `
                -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
                -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays($Days)

            Write-Output ("  クライアント証明書を作りました : " + $client.Subject)
        }

        New-Item -ItemType Directory -Force (Split-Path -Parent $CerPath) | Out-Null
        Export-Certificate -Cert $ca -FilePath $CerPath | Out-Null

        Write-Output ("  CA の公開部分を書き出しました : " + $CerPath)
        Write-Output ""
        Write-Output "  次は、**管理者の PowerShell** で :"
        Write-Output ("      .\SetupNetFxMtls.ps1 -Action Trust -CerPath '" + $CerPath + "'")
    }

    'Trust'
    {
        Write-Output "=== Trust : CA を信頼されたルートに入れる（管理者が必要）==="

        if (-not (Test-Elevated))
        {
            throw ("管理者として実行してください。LocalMachine\Root へは書き込めません。" +
                "（PowerShell を「管理者として実行」で開き直してください）")
        }

        if (-not (Test-Path $CerPath))
        {
            throw ($CerPath + " がありません。先に -Action Prepare を実行してください。" +
                "**別のアカウントで Prepare したなら、-CerPath でそのパスを渡してください**" +
                "（%TEMP% はアカウントごとに違います）。")
        }

        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

        Write-Output ("  信頼されたルートに入れました : " + $CerPath)
        Write-Output ""
        Write-Output "  次は、**通常の PowerShell**（証明書を作った利用者）で :"
        Write-Output "      .\2_RunAllTests.ps1 -Launch -NetFxMtls"
        Write-Output "  **-UpdateTestCases は付けないこと**（原本に netfx の mTLS ケースが混ざります）。"
        Write-Output "  測り終わったら、**必ず** -Action Cleanup を実行してください。"
    }

    'Check'
    {
        Write-Output "=== Check : いま在るもの ==="

        Show-State

        Write-Output ""
        Assert-SubjectsMatchSource
    }

    'Cleanup'
    {
        Write-Output "=== Cleanup : 作ったものを消す ==="

        # CurrentUser\My は管理者でなくても消せる
        $mine = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $AllSubjects -contains $_.Subject })

        foreach ($c in $mine)
        {
            Remove-Item -Path $c.PSPath -Force
            Write-Output ("  CurrentUser\My から消しました : " + $c.Subject)
        }

        if ($mine.Count -eq 0)
        {
            Write-Output "  CurrentUser\My : 消すものはありませんでした。"
        }

        $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
            Where-Object { $AllSubjects -contains $_.Subject })

        if ($roots.Count -eq 0)
        {
            Write-Output "  LocalMachine\Root : 消すものはありませんでした。"
        }
        elseif (-not (Test-Elevated))
        {
            Write-Warning ("LocalMachine\Root に " + $roots.Count + " 件残っています。" +
                "**管理者の PowerShell で -Action Cleanup を実行してください。**" +
                "信頼されたルートにテスト用 CA を残さないこと。")
        }
        else
        {
            foreach ($c in $roots)
            {
                Remove-Item -Path $c.PSPath -Force
                Write-Output ("  LocalMachine\Root から消しました : " + $c.Subject)
            }
        }

        if (Test-Path $CerPath)
        {
            Remove-Item $CerPath -Force
            Write-Output ("  .cer を消しました : " + $CerPath)
        }

        Write-Output ""
        Write-Output "  残っていないことの確認 :"
        Show-State
    }
}
