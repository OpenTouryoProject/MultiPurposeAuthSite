//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：Startup
//* クラス日本語名  ：Startup
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Notifications;

using System;
using System.IO;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Caching.Memory;

using Microsoft.AspNetCore.Mvc.Cors.Internal;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Util;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// Startup
    /// ミドルウェア /サービス / フレームワークを
    /// Startupクラスのメソッドで注入することにより、活用できるようになる。
    /// </summary>
    public class Startup
    {
    	#region mem & prop & constructor

        /// <summary>HostingEnvironment </summary>
        public IHostingEnvironment HostingEnvironment { get; }

        /// <summary>Configuration</summary>
        public IConfiguration Configuration { get; }
        
        /// <summary>constructor</summary>
        /// <param name="env">IConfiguration</param>
        /// <param name="config">IConfiguration</param>
        public Startup(IHostingEnvironment env, IConfiguration config)
        {
            // 自前
            //IConfigurationBuilder builder = new ConfigurationBuilder()
            //    .SetBasePath(env.ContentRootPath)
            //    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
            //    .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
            //    .AddEnvironmentVariables();
            //config = builder.Build();

            // メンバに設定
            this.HostingEnvironment = env;
            this.Configuration = config;

            // ライブラリにも設定
            GetConfigParameter.InitConfiguration(config);
            // Dockerで埋め込まれたリソースを使用する場合、
            // 以下のコメントアウトを解除し、appsettings.jsonのappSettings sectionに、
            // "Azure": "既定の名前空間" を指定し、設定ファイルを埋め込まれたリソースに変更する。
            //Touryo.Infrastructure.Business.Dao.MyBaseDao.UseEmbeddedResource = true;
        }

        #endregion
        
        #region Configure & ConfigureServices
        
        /// <summary>
        /// Configure
        /// ・必須
        /// ・ConfigureServices メソッドの後に、WebHostに呼び出される。
        /// ・アプリケーションの要求処理パイプラインを構成する。
        /// </summary>
        /// <param name="app">IApplicationBuilder</param>
        /// <param name="loggerFactory">ILoggerFactory</param>
        /// <remarks>
        /// this.HostingEnvironmentやthis.Configurationを見て、パイプライン構成を切り替える。
        /// </remarks>
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            // Development、Staging、Productionの
            // 環境変数（ASPNETCORE_ENVIRONMENT）値を使用可能。
            //bool flg = this.HostingEnvironment.IsDevelopment();
            //flg = this.HostingEnvironment.IsStaging();
            //flg = this.HostingEnvironment.IsProduction();

            #region Development or それ以外のモード

            if (this.HostingEnvironment.IsDevelopment())
            {
                // Developmentモードの場合

                // 開発用エラー画面
                //app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();

                // https://forums.asp.net/t/2114176.aspx?app+UseDeveloperExceptionPage+not+working
                // UseDeveloperExceptionPageとUseIdentity、併用できない？
                // UseStatusCodePagesWithRedirects＋自作開発用エラー画面？
                //app.UseStatusCodePagesWithRedirects(
                //    GetConfigParameter.GetConfigValue(FxLiteral.ERROR_SCREEN_PATH));

                // 簡易ログ出力
                loggerFactory.AddConsole(Configuration.GetSection("Logging"));
                loggerFactory.AddDebug();

                // ブラウザー リンク
                // 開発環境と 1-n ブラウザの間の通信チャネルを作成
                // https://blogs.msdn.microsoft.com/chack/2013/12/16/visual-studio-2013-1/
                app.UseBrowserLink();
            }
            else
            {
                // Developmentモードでない場合

                // カスタム例外処理ページ
                // app.UseExceptionHandler("/Home/Error");
                // MyMVCCoreFilterAttribute.OnExceptionで処理。
            }

            #endregion

            #region パイプラインに追加

            // Cookieを使用する。
            app.UseCookiePolicy(new CookiePolicyOptions()
            {
                HttpOnly = HttpOnlyPolicy.Always,
                // https://github.com/aspnet/Security/issues/1822
                MinimumSameSitePolicy = SameSiteMode.None, //SameSiteMode.Strict,
                //Secure= CookieSecurePolicy.Always
            });

            // Sessionを使用する。
            app.UseSession(new SessionOptions()
            {
                IdleTimeout = TimeSpan.FromMinutes(30), // ここで調整
                IOTimeout = TimeSpan.FromSeconds(30),
                Cookie = new CookieBuilder()
                {
                    Expiration = TimeSpan.FromDays(1), // 効かない
                    HttpOnly = true,
                    Name = GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName"),
                    Path = "/",
                    SameSite = SameSiteMode.Strict,
                    SecurePolicy = CookieSecurePolicy.SameAsRequest
                }
            });

            // HttpContextのマイグレーション用
            app.UseHttpContextAccessor();

            // /wwwroot（既定の）の
            // 静的ファイルをパイプラインに追加
            app.UseStaticFiles();

            // エラー画面
            app.UseExceptionHandler("/Home/Error");

            // Identity
            app.UseAuthentication();

            // MVCをパイプラインに追加（routesも設定）
            app.UseMvc(routes =>
            {
                #region Account
                routes.MapRoute(
                   name: "OAuth2Authorize",
                   template: Config.OAuth2AuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "OAuth2Authorize" });
                #endregion

                #region OAuth2Endpoint
                routes.MapRoute(
                    name: "OAuth2Token",
                    template: Config.OAuth2TokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "OAuth2Token" });

                routes.MapRoute(
                    name: "GetUserClaims",
                    template: Config.OAuth2UserInfoEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "GetUserClaims" });

                routes.MapRoute(
                    name: "RevokeToken",
                    template: Config.OAuth2RevokeTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RevokeToken" });

                routes.MapRoute(
                    name: "IntrospectToken",
                    template: Config.OAuth2IntrospectTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "IntrospectToken" });
                #endregion

                #region OAuth2ResourceServer
                routes.MapRoute(
                    name: "TestHybridFlow",
                    template: Config.TestHybridFlowWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2ResourceServer", action = "TestHybridFlow" });

                routes.MapRoute(
                    name: "TestChageToUser",
                    template: Config.TestChageToUserWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2ResourceServer", action = "TestChageToUser" });
                #endregion


                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            // UseCorsでAllowAllOriginsを指定。
            app.UseCors("AllowAllOrigins");

            #endregion
        }

        /// <summary>
        /// ConfigureServices
        /// 必要に応じて、ミドルウェア /サービス / フレームワークを注入する。
        /// ・実行は任意
        /// ・Configure メソッドの前に、WebHostにより呼び出される。
        /// ・規約によって構成オプションを設定する。
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        /// <remarks>
        /// IServiceCollectionコンテナにサービスを追加すると、
        /// Configure メソッドと、アプリケーション内でサービスを利用できるようになる。
        /// サービスは、DI or IApplicationBuilder.ApplicationServices から解決される。
        /// </remarks>
        public void ConfigureServices(IServiceCollection services)
        {
            // 構成情報から、AppConfiguration SectionをAppConfiguration Classへバインドするようなケース。
            //services.Configure<AppConfiguration>(Configuration.GetSection("AppConfiguration"));

            #region Development or それ以外のモード

            if (this.HostingEnvironment.IsDevelopment())
            {
                // Developmentモードの場合

                // Sessionのモード
                services.AddDistributedMemoryCache(); // 開発用
            }
            else
            {
                // Developmentモードでない場合

                // Sessionのモード
                //services.AddDistributedSqlServerCache();
                //services.AddDistributedRedisCache();
            }

            #endregion

            // Sessionを使用する。
            services.AddSession();

            // HttpContextのマイグレーション用
            services.AddHttpContextAccessor();

            #region Add Frameworks

            // 一般的な Webアプリでは、
            // EF, Identity, MVC などのミドルウェア サービスを登録する。
            // ミドルウェアの実行順序は、IStartupFilter の登録順に設定される。

            // EF
            //services.AddDbContext<ApplicationDbContext>(options =>
            //    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            // Identity

            // must be added before AddIdentity()
            services.AddScoped<IPasswordHasher<ApplicationUser>, CustomPasswordHasher<ApplicationUser>>();

            services.AddIdentity<ApplicationUser, ApplicationRole>()
                //.AddEntityFrameworkStores<ApplicationDbContext>()
                .AddUserStore<UserStoreCore>()
                .AddRoleStore<RoleStoreCore>()
                .AddDefaultTokenProviders();
            
            // Add application services.
            services.AddTransient<IUserStore<ApplicationUser>, UserStoreCore>();
            services.AddTransient<IRoleStore<ApplicationRole>, RoleStoreCore>();
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<ISmsSender, SmsSender>();

            // AddMvc
            services.AddMvc();

            // AddCors
            services.AddCors(
                o => o.AddPolicy("AllowAllOrigins", 
                builder =>
                {
                    builder
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
                }));


            #region ASP.NET Core Identity認証

            #region IdentityOptions

            Action<IdentityOptions> IdentityOptionsConf = new Action<IdentityOptions>(idOptions =>
                {
                    // ユーザー
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#user
                    //idOptions.SignIn.AllowedUserNameCharacters = false;
                    idOptions.User.RequireUniqueEmail = Config.RequireUniqueEmail;

                    // サインイン
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#sign-in
                    idOptions.SignIn.RequireConfirmedEmail = false;
                    idOptions.SignIn.RequireConfirmedPhoneNumber = false;

                    // パスワード検証（8文字以上の大文字・小文字、数値、記号
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#password
                    idOptions.Password.RequiredLength = Config.RequiredLength;
                    idOptions.Password.RequireNonAlphanumeric = Config.RequireNonLetterOrDigit;
                    idOptions.Password.RequireDigit = Config.RequireDigit;
                    idOptions.Password.RequireLowercase = Config.RequireLowercase;
                    idOptions.Password.RequireUppercase = Config.RequireUppercase;

                    // ユーザ ロックアウト
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#lockout
                    idOptions.Lockout.DefaultLockoutTimeSpan = Config.DefaultAccountLockoutTimeSpanFromSeconds;
                    idOptions.Lockout.MaxFailedAccessAttempts = Config.MaxFailedAccessAttemptsBeforeLockout;
                    idOptions.Lockout.AllowedForNewUsers = Config.UserLockoutEnabledByDefault;

                    // 二要素認証

                    // トークン
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#tokens
                    //idOptions.Tokens...

                });

            services.Configure<IdentityOptions>(IdentityOptionsConf);
            
            #endregion

            #region AuthOptions

            AuthenticationBuilder authenticationBuilder = services.AddAuthentication();

            #region AuthCookie

            authenticationBuilder.AddCookie(options =>
                {
                    // https://community.auth0.com/t/asp-net-core-2-intermittent-correlation-failed-errors/11918/18
                    options.ExpireTimeSpan = new TimeSpan(0, 2, 0);

                    options.LoginPath = "/MultiPurposeAuthSite/Account/Login";
                    options.LogoutPath = "/MultiPurposeAuthSite/Account/LogOff";
                    //options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                    //options.Cookie.Name = "YourAppCookieName";
                    //options.Cookie.HttpOnly = true;
                    //options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    // ReturnUrlParameter requires 
                    //using Microsoft.AspNetCore.Authentication.Cookies;
                    //options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
                    //options.SlidingExpiration = true;
                });

            #endregion

            #region 外部ログイン
            if (Config.MicrosoftAccountAuthentication)
            {
                authenticationBuilder.AddMicrosoftAccount(options =>
                {
                    options.ClientId = Config.MicrosoftAccountAuthenticationClientId;
                    options.ClientSecret = Config.MicrosoftAccountAuthenticationClientSecret;
                });
            }
            if (Config.GoogleAuthentication)
            {
                authenticationBuilder.AddGoogle(options =>
                {
                    options.ClientId = Config.GoogleAuthenticationClientId;
                    options.ClientSecret = Config.GoogleAuthenticationClientSecret;
                });
            }
            if (Config.FacebookAuthentication)
            {
                authenticationBuilder.AddFacebook(options =>
                {
                    options.AppId = Config.FacebookAuthenticationClientId;
                    options.AppSecret = Config.FacebookAuthenticationClientSecret;
                });
            }
            if (Config.TwitterAuthentication)
            {
                authenticationBuilder.AddTwitter(options =>
                {
                    options.ConsumerKey = Config.TwitterAuthenticationClientId;
                    options.ConsumerSecret = Config.TwitterAuthenticationClientSecret;
                });
            }
            #endregion

            #region OAuth2 / OIDC

            // スクラッチ実装

            #endregion

            #endregion

            #endregion

            #region Forms認証
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            //{
            //    options.LoginPath = new PathString("/Home/Login");
            //    //options.LogoutPath = new PathString("/Home/Logout");
            //    options.AccessDeniedPath = new PathString(GetConfigParameter.GetConfigValue("FxErrorScreenPath"));
            //    options.ReturnUrlParameter = "ReturnUrl";
            //    options.ExpireTimeSpan = TimeSpan.FromHours(1);
            //    options.SlidingExpiration = true;
            //    options.Cookie.HttpOnly = true;
            //    //options.DataProtectionProvider = DataProtectionProvider.Create(new DirectoryInfo(@"C:\artifacts"));
            //});
            #endregion

            #endregion
        }

        #endregion
    }
}
