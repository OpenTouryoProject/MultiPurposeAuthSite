//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：Program
//* クラス日本語名  ：Program
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//**********************************************************************************

using System.Net.Http;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite
{
    /// <summary>Program</summary>
    public class Program
    {
        /// <summary>
        /// Main（エントリポイント）</summary>
        /// <param name="args">コマンドライン引数</param>
        public static void Main(string[] args)
        {
            // OpenID用
            OAuth2AndOIDCClient.HttpClient = new HttpClient();

            // BuildWebHostが返すIWebHostをRunする。
            // 呼び出し元スレッドは終了までブロックされる。
            Program.BuildWebHost(args).Run();
        }

        /// <summary>BuildWebHost</summary>
        /// <param name="args">コマンドライン引数</param>
        /// <returns>IWebHost</returns>
        public static IWebHost BuildWebHost(string[] args)
        {
            // WebHost経由で、IWebHost, IWebHostBuilderにアクセスする。

            return WebHost.CreateDefaultBuilder(args) //  IWebHostBuilderを取得する。
                .UseStartup<Startup>() // IWebHostBuilder.UseStartup<TStartup> メソッドにStartupクラスを指定。
                .Build(); // IWebHostBuilder.Build メソッドでIWebHostクラスインスタンスを返す。
        }
    }
}
