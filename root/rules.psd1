# 期待値の変更の検出器の、MultiPurposeAuthSite の規則（QUALITY.md 3 節。#335）。
#   本体（CheckExpectationChange.ps1）と共通の規則（rules.common.psd1）は、OpenTouryoCodingAgentAssets の写しであり、ここでは直さない。
#   このファイルは MultiPurposeAuthSite が持つ。置き換えの前の検出器（#315・#324）の、MultiPurposeAuthSite に固有の部分を移したもの
#   （OpenTouryoCodingAgentAssets の docs/expectation-guard/rules.MultiPurposeAuthSite.psd1 の下書きから）。
#   置き換えの前後で、導入の後の全コミットの判定が同じであることを確かめた（#335）。
@{
    Reference    = 'QUALITY.md 3 節'
    IntroducedBy = 'root/CheckExpectationChange.ps1'
    DiffScope    = @('root/programs/Tests/')

    Guard = @(
        '^root/CheckExpectationChange\.ps1$'
        '^root/programs/Tests/E2ETests/Infrastructure/TestReport\.cs$'
    )

    LineRules = @(
        @{
            Name  = 'テストの削除'
            Paths = @('^root/programs/Tests/.+\.cs$')
            Count = 'Removed'
            Match = @( @{ Pattern = '[\[,]\s*(Fact|Theory|SkippableFact|SkippableTheory|InlineData|MemberData|ClassData|Test|TestCase|TestCaseSource)\s*[\],(]' } )
        }
        @{
            Name  = 'Skip の追加'
            Paths = @('^root/programs/Tests/.+\.cs$')
            Count = 'Added'
            Match = @(
                @{ Pattern = '\bSkip\s*\.\s*(If|IfNot)\s*\(|[\[,(]\s*Skip\s*=|\bSkipException\s*\(|[\[,]\s*(Ignore|Explicit)\s*[\],(]' }
                # Skip を包んだヘルパー（Flows.SkipIfGrantTypeNotSupportedAsync・MtlsTests.SkipIfNoMtls・UsersAdmin.SkipIfLockedDownAsync など）の呼び出し。
                #   定義の行（Task・Task<…>・void・bool の後）は数えない。OpenTouryoCodingAgentAssets#6 の初回の計測で、突き合わせ役が 4 件に見つけた
                @{ Pattern = '(?<!(\bTask|\bvoid|\bbool|>)\s+)\bSkipIf\w*\s*\(' }
            )
        }
        @{
            # 単体テストの検証は Assert と [Basis]。**E2E の Assert は前提の確認なので、数えない**（#324）
            Name  = '検証の削除'
            Paths = @('^root/programs/Tests/.+\.cs$')
            Count = 'Removed'
            Match = @(
                @{ Pattern = '\.\s*(Verify|VerifyEqual)\s*\(' }
                @{ Pattern = '\bAssert\s*\.|\[\s*Basis\s*\('; Paths = @('^root/programs/Tests/UnitTests/') }
            )
        }
    )

    KeyedArgumentRules = @(
        @{
            Paths       = @('^root/programs/Tests/.+\.cs$')
            Call        = 'Report'
            KeyIndex    = 0
            ValueIndex  = 3
            MinArgs     = 4
            RemovedName = '根拠の削除'
            ChangedName = '根拠の変更'
        }
    )

    GeneratedRules = @(
        @{
            Name           = 'TESTCASES.md'
            Generated      = 'root/programs/Tests/TESTCASES.md'
            Sources        = @('^root/programs/Tests/E2ETests/Tests/.+\.cs$')
            Items          = @(
                @{ Pattern = '(?<![\w])Report\s*\('; Take = 'All'; Label = 'Report' }
                @{ Pattern = '\.\s*(?<label>Step|Note|Target|Verify|VerifyEqual|Observe)\s*\('; Take = 'First' }
                @{ Pattern = 'public\s+(?:async\s+)?(?:Task|void)\s+(?<name>\w+)\s*\('; Take = 'Name'; Label = 'test' }
            )
            ExemptTrailer  = 'TestCases-Unchanged'
            Hint           = @('root で .\2_RunAllTests.ps1 -Launch -UpdateTestCases を回してください。')
            CommandPattern = 'TESTCASES\.md'
        }
    )

    # 承認の理由の書き方に足す（共通の規則の ApprovalReasonPatterns に足される。OpenTouryoCodingAgentAssets#6）
    #   テストの ID（RT-352.1 など）は Issue 番号を含む
    ApprovalReasonPatterns = @('\bRT-\d+')

    # 書き忘れの組（共通の規則の TrailerRequirements に足される。警告だけ。OpenTouryoCodingAgentAssets#6）
    #   リスク「高」の名前空間（QUALITY.md 1 節の品質マップ）を fixed で変えたら、fixed の前に別モデルのレビュー（quality-reviewer。4 節）
    TrailerRequirements = @(
        @{
            Name    = 'Reviewed-with'
            Message = '(?i)\bfixed\s+#\d+'
            Paths   = @(
                '^root/programs/CommonLibrary/TokenProviders/'
                '^root/programs/CommonLibrary/Extensions/Sts/'
                '^root/programs/CommonLibrary/SamlProviders/'
                '^root/programs/CommonLibrary/Extensions/FIDO/'
                '^root/programs/MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/'
                '^root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/'
            )
            Value   = '^(quality-reviewer|human)\b'
            Hint    = 'リスク「高」の名前空間（TokenProviders・Extensions.Sts・SamlProviders・Extensions.FIDO・Controllers）なので、fixed の前に quality-reviewer で別モデルのレビューを回し、Reviewed-with: quality-reviewer (<モデル ID>) を書く（QUALITY.md 4 節）'
        }
    )
}
