<#
.SYNOPSIS
    publish の成果物が、MPAS のソースより古くないかを確かめる（#340）。

.DESCRIPTION
    ＜なぜ要るか＞
      **E2E と Stub は、用意（1_Publish*.ps1）と起動（2_DockerComposeUp.bat）を分けている**（#340）。
      **MPAS を直した後に用意を忘れると、古いアプリのまま起動する**（#294 で --build を足したのと同じ種類の事故）。
      起動の前にこれを呼び、**古ければ警告する。起動は止めない**（設定だけ変えて起動し直すときの邪魔をしない）。

    ＜何と比べるか＞
      - 成果物 : <PublishDir>\MultiPurposeAuthSite.dll（Dockerfile の ENTRYPOINT） の更新時刻
      - ソース : root\programs の CommonLibrary・MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore と、
                 OpenTouryo のアセンブリ（OpenTouryoAssemblies\Build_netcore100）の、いちばん新しい更新時刻
                 （bin・obj は見ない。手元の appsettings.json も見ない — 起動時にマウントするので、イメージには入らない）

    **戻り値（終了コード）は常に 0**（警告だけ）。

.PARAMETER PublishDir
    publish の成果物の置き場（app\publish）。

.EXAMPLE
    .\CheckPublishFreshness.ps1 -PublishDir ..\E2E\app\publish

.NOTES
    作成者          ：玄人 幸道
    更新履歴        ：
     日時        更新者            内容
     ----------  ----------------  -------------------------------------------------
     2026/11/07  玄人 幸道         新規（#340）
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PublishDir
)

$ErrorActionPreference = 'Stop'

# パスの既定値は param() に書かない（5.1 の -File で $PSScriptRoot が空になる。CODING.md 5 節）
$here = Split-Path -Parent $PSCommandPath
$programs = Join-Path $here '..\..\root\programs'

$dll = Join-Path $PublishDir 'MultiPurposeAuthSite.dll'

if (-not (Test-Path $dll))
{
    Write-Output ""
    Write-Output "  [警告] publish の成果物がありません : $dll"
    Write-Output "         先に 1_Publish*.ps1 を実行してください（#340）。"
    Write-Output ""
    exit 0
}

$published = (Get-Item $dll).LastWriteTime

$sourceDirs = @(
    (Join-Path $programs 'CommonLibrary'),
    (Join-Path $programs 'MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore'),
    (Join-Path $programs 'OpenTouryoAssemblies\Build_netcore100')
)

$newest = $null

foreach ($dir in $sourceDirs)
{
    if (-not (Test-Path $dir))
    {
        continue
    }

    $file = Get-ChildItem $dir -Recurse -File |
        Where-Object {
            $_.FullName -notmatch '\\(bin|obj)\\' -and
            $_.Name -ne 'appsettings.json'
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($file -and ((-not $newest) -or $newest.LastWriteTime -lt $file.LastWriteTime))
    {
        $newest = $file
    }
}

if ($newest -and $published -lt $newest.LastWriteTime)
{
    Write-Output ""
    Write-Output "  [警告] publish の成果物が、MPAS のソースより古い（#340）。"
    Write-Output ("         成果物 : {0:yyyy-MM-dd HH:mm:ss}  {1}" -f $published, $dll)
    Write-Output ("         ソース : {0:yyyy-MM-dd HH:mm:ss}  {1}" -f $newest.LastWriteTime, $newest.FullName)
    Write-Output "         **このまま起動すると、古いアプリで動く。** MPAS を直したなら、先に 1_Publish*.ps1 を実行してください。"
    Write-Output ""
}

exit 0
