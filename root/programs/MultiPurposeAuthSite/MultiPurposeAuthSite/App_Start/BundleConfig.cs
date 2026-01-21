//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：BundleConfig
//* クラス日本語名  ：バンドル＆ミニフィケーションに関する指定
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Web.Optimization;
using MultiPurposeAuthSite.Co;

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// バンドル＆ミニフィケーションに関する指定
    /// </summary>
    public class BundleConfig
    {
        /// <summary>
        /// 特集：ASP.NET 4.5新機能概説（1）：
        /// Visual Studio 2012の新機能とASP.NET 4.5のコア機能 (3-4) - ＠IT
        /// http://www.atmarkit.co.jp/ait/articles/1303/08/news072_3.html
        /// ASP.NET 4.5では、リクエスト時のファイル読み込み時間を
        /// 削減するためにバンドル＆ミニフィケーションの仕組みが導入された。
        /// Bundling の詳細については、http://go.microsoft.com/fwlink/?LinkId=254725 を参照してください
        /// </summary>
        public static void RegisterBundles(BundleCollection bundles)
        {
            // see : https://www.asp.net/ajax/cdn

            string jqueryVersion = "3.7.1";

            BundleTable.EnableOptimizations = !Config.IsDebug;
            BundleTable.Bundles.UseCdn = true; // same as: bundles.UseCdn = true;

            // ( new ScriptBundle("~/XXXX") のパスは実在するpathと被るとRender時にバグる。
            // なので、bundlesと実在しないpathを指定している（CSSも同じbundlesを使用する）。

            bundles.Add(new ScriptBundle("~/bundles/app").Include(
                        "~/Scripts/app/Site.js"));

            bundles.Add(new ScriptBundle("~/bundles/touryo").Include(
                        "~/Scripts/touryo/common.js",
                        "~/Scripts/touryo/else.js"));

            bundles.Add(new ScriptBundle("~/bundles/multiauthsite").Include(
                        "~/Scripts/touryo/oauthimplicit.js",
                        "~/Scripts/touryo/arrayBufferUtil.js",
                        "~/Scripts/touryo/msWebauthn.js",
                        "~/Scripts/touryo/ffWebauthn.js"));

            //jquery、jqueryvalを新規作成テンプレ準拠に
            bundles.Add(new ScriptBundle("~/bundles/jquery").Include(
                        "~/Scripts/jquery-{version}.js"));

            bundles.Add(new ScriptBundle("~/bundles/jqueryval").Include(
                        "~/Scripts/jquery.validate*"));

            // jqueryvaluno、jqueryunoajax (削除)

            //modernizr、bootstrapを新規作成テンプレ準拠に
            // 開発と学習には、Modernizr の開発バージョンを使用します。次に、実稼働の準備が
            // 運用の準備が完了したら、https://modernizr.com のビルド ツールを使用し、必要なテストのみを選択します。
            bundles.Add(new ScriptBundle("~/bundles/modernizr").Include(
                        "~/Scripts/modernizr-*"));

            bundles.Add(new Bundle("~/bundles/bootstrap").Include(
                      "~/Scripts/bootstrap.js"));

            // respond (削除)

            bundles.Add(new StyleBundle("~/bundles/css").Include(
                        "~/Content/bootstrap.css",
                        "~/Content/font-awesome.min.css",
                        "~/Content/touryo/Style.css",
                        "~/Content/app/Site.css"));
        }
    }
}