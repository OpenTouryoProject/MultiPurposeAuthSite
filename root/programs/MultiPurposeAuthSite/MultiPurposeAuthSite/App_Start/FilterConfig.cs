//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：FilterConfig
//* クラス日本語名  ：グローバルフィルタに関する指定
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

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// グローバルフィルタに関する指定
    /// </summary>
    public class FilterConfig
    {
        /// <summary>
        /// ASP.NET MVC 3 の新機能、グローバルフィルタは地味だけどイケてる - しばやん雑記
        /// http://shiba-yan.hatenablog.jp/entry/20110104/1294073715
        /// 　ASP.NET MVC 3 ではグローバルフィルタという機能が追加されました。
        /// 　Razor や DI に比べてかなり地味ですが、今までコントローラクラスに毎回付ける必要があった
        /// 　アクションフィルタを Global.asax で一括指定できるようになりました。
        /// </summary>
        /// <param name="filters"></param>
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            // デフォルトで HandleError アクションフィルタを全てのコントローラへ適用するようになっている。
            filters.Add(new HandleErrorAttribute());
            // https://forums.asp.net/t/2125704.aspx?Authorize+attribute+not+working
            filters.Add(new AuthorizeAttribute());

            //// OutputCache アクションフィルタ
            //// 全てのページを 60 秒間キャッシュする
            //filters.Add(new OutputCacheAttribute { Duration = 60 });
        }
    }
}