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
//*  2026/09/18  玄人 幸道         RequirePkce / RequirePkceS256 の確認を追加（#220）
//*  2026/09/25  玄人 幸道         CibaProvider.DebugModeWithOutAD の確認を追加
//*  2026/09/25  玄人 幸道         改名した設定キーの警告を、一覧（Config.RenamedKeys）から出す（#236）
//*  2026/10/04  玄人 幸道         CorsAllowedOrigins の * を警告（#265）
//*  2026/10/22  玄人 幸道         RequirePkceS256 を Open棟梁 の CmnServerParams から読むようにした（#294）
//*  2026/10/24  玄人 幸道         設定の確認の文言を resx にした（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;

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
                    warnings.Add(Resources.Diagnostics.CheckAdministratorNotFilledIn);
                }

                if (Config.UserStoreType != EnumUserStoreType.Memory)
                {
                    // ここから下は「本番らしい構成」でだけ確かめる。

                    if (Config.IsDebug)
                    {
                        warnings.Add(Resources.Diagnostics.CheckIsDebug);
                    }

                    if (!string.IsNullOrWhiteSpace(Config.TestUserPWD))
                    {
                        warnings.Add(Resources.Diagnostics.CheckTestUserPwd);
                    }

                    if (!Config.IsLockedDownTestEndpoints)
                    {
                        warnings.Add(Resources.Diagnostics.CheckTestEndpointsOpen);
                    }

                    // **CORS の追加分に `*` が書かれていないか**（#265）。
                    //   **`*` は落とす**実装だが、**書いた側は「開いたつもり」になる。**
                    //   オリジンは `https://host[:port]` の形で書くこと。
                    if (!string.IsNullOrWhiteSpace(Config.CorsAllowedOrigins)
                        && Config.CorsAllowedOrigins.Contains("*"))
                    {
                        warnings.Add(Resources.Diagnostics.CheckCorsWildcard);
                    }

                    if (!string.IsNullOrWhiteSpace(Config.FcmOutboxDirectory))
                    {
                        warnings.Add(Resources.Diagnostics.CheckFcmOutbox);
                    }

                    // **ここだけは設定ではなく、コードに埋め込んだ値を見る。**
                    //   DebugModeWithOutAD は const なので、有効にするにはソースを書き換えて
                    //   ビルドし直すことになる。設定で事故ることは無いが、
                    //   **書き換えたまま出荷した場合に気付く手段が無かった。**
                    //   有効だと、CIBA が認証デバイスの承認を経ずに成立する（自動で許可される）。
                    //   **到達できないコードの警告は抑える。** const が false の間は、
                    //   この中に入らないことがコンパイル時に判るため（両アプリの /ciba_authz と同じ扱い）。
#pragma warning disable 162

                    if (Extensions.Sts.CibaProvider.DebugModeWithOutAD)
                    {
                        warnings.Add(Resources.Diagnostics.CheckCibaDebugMode);
                    }

#pragma warning restore 162

                    // **改名したキーは、一覧から確かめる**（Config.RenamedKeys）。
                    //   旧いキー名でも動くが、**放置すると、いつ読まれなくなるか分からない。**
                    foreach (KeyValuePair<string, string> old in Config.OldKeysStillUsed())
                    {
                        warnings.Add(string.Format(Resources.Diagnostics.CheckRenamedKey, old.Key, old.Value));
                    }

                    if (Config.EnableDebugTraceLog)
                    {
                        warnings.Add(Resources.Diagnostics.CheckDebugTraceLog);
                    }

                    // **これは「開発向けの設定が残っている」ではない（#220）。**
                    //   false は従来の OAuth 2.0 のままというだけで、それ自体は誤りではない。
                    //   ただし**本番では意図して選ぶべき**なので、選ばれていないことを知らせる。
                    //   有効にすると繋がらなくなるクライアントがあるため、**既定は false のまま。**
                    List<string> loosePkce = new List<string>();

                    if (!Config.RequirePkce)
                    {
                        loosePkce.Add("RequirePkce");
                    }

                    if (!CmnServerParams.RequirePkceS256)
                    {
                        loosePkce.Add("RequirePkceS256");
                    }

                    if (loosePkce.Count != 0)
                    {
                        warnings.Add(string.Format(Resources.Diagnostics.CheckLoosePkce, string.Join(" / ", loosePkce)));
                    }
                }

                foreach (string warning in warnings)
                {
                    Logging.MyOperationTrace(string.Format(Resources.Diagnostics.CheckFormat, warning));
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
