//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ProductionCheck
//* クラス日本語名  ：開発向けの設定が残っていないかを、起動時に確かめる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/17  玄人 幸道         新規（#219 の B）
//**********************************************************************************

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>
    /// 開発向けの設定が残っていないかを、起動時に確かめる（#219 の B）
    /// </summary>
    /// <remarks>
    /// **切替の一覧は CONFIGURATION.md 11 節が一次情報。** ここは、その読み落としを拾う。
    ///
    /// **起動は止めない。** 設定を直せない状況で復旧できなくなるため、警告に留める。
    ///
    /// **`UserStoreType` が `mem` のときは、何も言わない。**
    /// `mem` は開発・テスト専用（再起動で消える）であり、そこで警告しても雑音にしかならない。
    /// </remarks>
    public class ProductionCheck
    {
        /// <summary>雛形（_appsettings.json / _app.config）の、未設定を表す値</summary>
        private const string NotFilledIn = "[Please fill in this input item.]";

        /// <summary>
        /// 開発向けの設定が残っていないかを確かめ、OPERATION ログに警告を出す。
        /// </summary>
        /// <returns>警告の一覧（無ければ空）</returns>
        /// <remarks>
        /// **戻り値は、テストと呼び出し元の判断のために返す。** ログ出力はこのメソッドが行う。
        /// **例外は外に出さない。** 起動処理から呼ぶため。
        /// </remarks>
        public static List<string> WarnIfRisky()
        {
            List<string> warnings = new List<string>();

            try
            {
                // **管理者の資格情報は、ストアの種類によらず確かめる。**
                //   雛形の値のまま動いていたら、それ自体が問題であるため。
                if (Config.AdministratorUID == ProductionCheck.NotFilledIn
                    || Config.AdministratorPWD == ProductionCheck.NotFilledIn)
                {
                    warnings.Add("AdministratorUID / AdministratorPWD が雛形の値のままです。");
                }

                if (Config.UserStoreType != EnumUserStoreType.Memory)
                {
                    // ここから下は「本番らしい構成」でだけ確かめる。

                    if (Config.IsDebug)
                    {
                        warnings.Add("IsDebug が true です。テスト利用者の生成や、"
                            + "メール / SMS の送信の代替が有効になります。");
                    }

                    if (!string.IsNullOrWhiteSpace(Config.TestUserPWD))
                    {
                        warnings.Add("TestUserPWD が設定されています。"
                            + "IsDebug が true なら、テスト利用者が作られます。");
                    }

                    if (!Config.IsLockedDownRedirectEndpoint)
                    {
                        warnings.Add("IsLockedDownRedirectEndpoint が false です。"
                            + "自己テスト画面（/Home/Saml2OAuth2Starters）が開いています。");
                    }

                    if (!string.IsNullOrWhiteSpace(Config.FcmOutboxDirectory))
                    {
                        warnings.Add("FcmOutboxDirectory が設定されています。"
                            + "プッシュ通知は FCM に送られず、ファイルに書かれます。");
                    }

                    if (Config.EnabeDebugTraceLog)
                    {
                        warnings.Add("EnabeDebugTraceLog が true です。");
                    }
                }

                foreach (string warning in warnings)
                {
                    Logging.MyOperationTrace(
                        "[設定の確認] " + warning + "（CONFIGURATION.md 11 節）");
                }
            }
            catch (Exception ex)
            {
                // **確かめること自体で起動を止めない。**
                Logging.MyDebugLogForEx(ex);
            }

            return warnings;
        }
    }
}
