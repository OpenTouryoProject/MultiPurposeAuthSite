//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：RouteConfig
//* クラス日本語名  ：ルート定義に関する指定
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Web.Mvc;
using System.Web.Routing;

using MultiPurposeAuthSite.Co;

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// ルート定義に関する指定
    /// </summary>
    public class RouteConfig
    {
        /// <summary>
        /// ［ASP.NET MVC］ルート定義を追加するには？［3.5、4、C#、VB］ － ＠IT
        /// http://www.atmarkit.co.jp/fdotnet/dotnettips/1031aspmvcrouting1/aspmvcrouting1.html
        ///  RegisterRoutesメソッドはアプリケーション起動
        ///  （Startイベント・ハンドラ）のタイミングで呼び出されるメソッドで、
        ///  デフォルトのルート（名前はDefault）を追加している。
        /// </summary>
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            // ルートを追加するには、ルートの集合を表すRouteCollectionオブジェクトから
            // MapRouteメソッドを呼び出すだけだ。MapRouteメソッドの構文は、次のとおりである。

            // MapRouteメソッドの構文 
            // MapRoute(String name, String url [,Object defaults])  
            // ・ name：ルート名。
            // ・ url：URIパターン。
            // ・ defaults：初期値。 

            routes.MapRoute(
                name: "OAuth2Authorize",
                url: Config.OAuth2AuthorizeEndpoint.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "Account", action = "OAuth2Authorize" }
            );

            // Defaultルートを定義
            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );
        }
    }
}