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
//*  2020/02/28  西野 大介         プッシュ通知、CIBA対応実施
//*  2020/07/29  西野 大介         SecurityStamp対応
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認（/2fa_result）のルートを追加（#213）
//*  2026/09/17  玄人 幸道         開発向けの設定が残っていないかを起動時に確かめる（#219）
//*  2026/09/17  玄人 幸道         テスト用の口（/TestHybridFlow）を閉じられるようにする（#219）
//*  2026/09/19  玄人 幸道         認証クッキーの設定を、実際に使うスキームへ移す（#223）
//*  2026/09/25  玄人 幸道         設定キーの改名（AuthRequestPushUri）に追随（#236）
//*  2026/09/27  玄人 幸道         AuthRequestPushUri は Open棟梁 側で読むようにした（#236 の宿題）
//*  2026/09/27  玄人 幸道         /end_session（RP-Initiated Logout）のルートを追加（#232）
//*  2026/09/30  玄人 幸道         Google の email_verified をクレームに写す（#140 の段階 1）
//*  2026/09/30  玄人 幸道         AuthCookieName で認証 Cookie の名前を変えられるようにした（#250 の段階 4）
//*  2026/09/30  玄人 幸道         Facebook / Twitter の外部ログインの登録を削除（#249）
//*  2026/09/30  玄人 幸道         DataProtection の鍵の置き場を設定できるようにした（#251）
//*  2026/09/30  玄人 幸道         認証 Cookie の名前を設定できるようにした（#250 の段階 4）
//*  2026/10/01  玄人 幸道         TempData の Cookie にも接頭辞を付ける（#255）
//*  2026/10/01  玄人 幸道         メアドの一意を常に必須にした（#151 の段階 3）
//*  2026/10/04  玄人 幸道         CORSをエンドポイント単位にした（#265）
//*  2026/10/04  玄人 幸道         CORSの許可オリジンを要求ごとに判定（#266）
//*  2026/10/06  玄人 幸道         セッションの置き場を設定で選べるようにした（#256）
//*  2026/10/07  玄人 幸道         Open棟梁 MVC_Coreに倣い、配備で切り替える形に整理（#279）。
//*                                転送ヘッダの取り込み、HTTPSリダイレクト、Cookieの
//*                                Secure属性を設定で切り替え、CookiePolicyをDIに一本化。
//*  2026/10/08  玄人 幸道         AntiForgery の Cookie にも接頭辞を掛ける（#282）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Notifications;

using System;
using System.IO;
using System.Net;   // IPAddress（#279）

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Antiforgery;   // AntiforgeryOptions（#282）
using Microsoft.AspNetCore.HttpOverrides;   // 転送ヘッダ（#279）
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Caching.Memory;

//using Microsoft.AspNetCore.Mvc.Cors.Internal;
using Microsoft.AspNetCore.Mvc; // CookieTempDataProviderOptions（#255）

using Touryo.Infrastructure.Framework.Authentication;
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

        /// <summary>Configuration</summary>
        public IConfiguration Configuration { get; }
        
        /// <summary>constructor</summary>
        /// <param name="configuration">IConfiguration</param>
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            // ライブラリにも設定
            GetConfigParameter.InitConfiguration(configuration);
            // Dockerで埋め込まれたリソースを使用する場合、
            // 以下のコメントアウトを解除し、appsettings.jsonのappSettings sectionに、
            // "Azure": "既定の名前空間" を指定し、設定ファイルを埋め込まれたリソースに変更する。
            //Touryo.Infrastructure.Business.Dao.MyBaseDao.UseEmbeddedResource = true;
        }

        #endregion
        
        #region Configure & ConfigureServices
        
        /// <summary>
        /// This method gets called by the runtime.
        /// Use this method to configure the HTTP request pipeline.
        /// </summary>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {            
            // **開発向けの設定が残っていないかを確かめる**（#219。CONFIGURATION.md 11 節）。
            //   起動は止めない。警告を OPERATION ログに出すだけ。
            ProductionCheck.WarnIfRisky();

            #region 転送ヘッダの取り込み（#279。上流 #549）

            //  **リバース プロキシで TLS を終端すると、アプリから見た接続は HTTP になる。**
            //    利用者のブラウザは HTTPS で繋いでいるのに `Request.IsHttps` は false のままで、
            //    **Cookie に Secure 属性が付かず、組み立てる絶対 URL も http になる**
            //    （SAML の ACS URL や、OIDC の `redirect_uri` の照合に効く）。
            //
            //  **必ずパイプラインの先頭に置く。**
            //    後ろに置くと、それより前のミドルウェア（`UseHttpsRedirection` など）が
            //    **取り込み前のスキームを見てしまう。**
            //
            //  **既定は off**（`Config.UseForwardedHeaders`）。
            if (Config.UseForwardedHeaders)
            {
                ForwardedHeadersOptions forwardedHeadersOptions = new ForwardedHeadersOptions()
                {
                    ForwardedHeaders =
                        ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
                };

                // **既定ではループバックからの転送しか信用しない。**
                //   コンテナや Kubernetes では前段が別アドレスになるため、
                //   **指定しないとヘッダが黙って捨てられ、何も起きない。**
                forwardedHeadersOptions.KnownIPNetworks.Clear();
                forwardedHeadersOptions.KnownProxies.Clear();

                string knownProxies = Config.ForwardedHeadersKnownProxies;

                if (!string.IsNullOrEmpty(knownProxies))
                {
                    foreach (string ip in knownProxies.Split(','))
                    {
                        string trimmed = ip.Trim();

                        if (!string.IsNullOrEmpty(trimmed))
                        {
                            forwardedHeadersOptions.KnownProxies.Add(IPAddress.Parse(trimmed));
                        }
                    }
                }
                else
                {
                    // **前段を特定できない場合（コンテナ等）は、範囲の制限を外したまま使う。**
                    //   **アプリが前段を経由せず直接叩ける状態では使わないこと。**
                    //   クライアントが `X-Forwarded-Proto` を詐称でき、
                    //   **HTTP で来ているのに HTTPS だと判断させられる。**
                }

                app.UseForwardedHeaders(forwardedHeadersOptions);
            }

            #endregion

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");

                // The default HSTS value is 30 days.
                // You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            //  **HTTPS へのリダイレクト**（#279。上流 #541）。
            //    **以前はコメントアウトで置いてあった**ので、
            //    **本番で有効にするにはソースを書き換えることになっていた。**
            //
            //    **既定は off**（`Config.UseHttpsRedirection`）。
            //    **on にするだけでは足りない。リダイレクト先のポートも要る。**
            //    決められないと、ミドルウェアは警告を出すだけで素通りする（見落としやすい）。
            //
            //      warn: ...HttpsRedirectionMiddleware[3]
            //            Failed to determine the https port for redirect.
            //
            //    ポートは次のいずれかで決まる。
            //      ・https の URL を Kestrel にバインドする（`--urls` に https://… を含める）
            //      ・環境変数 `ASPNETCORE_HTTPS_PORT=443`（**単数**）
            //      ・環境変数 `HTTPS_PORT=443`
            //
            //    **`ASPNETCORE_HTTPS_PORTS`（複数）では決まらない。** 紛らわしいので注意。
            if (Config.UseHttpsRedirection)
            {
                app.UseHttpsRedirection();
            }

            // HttpContextのマイグレーション用
            app._UseHttpContextAccessor();

            // /wwwroot（既定の）の
            // 静的ファイルをパイプラインに追加
            app.UseStaticFiles();

            // Cookieを使用する。
            //  **引数を渡さない**（#279。上流 #541）。
            //    **引数を渡すと、`ConfigureServices` の
            //    `services.Configure<CookiePolicyOptions>` が使われなくなる。**
            //    以前は両方に書いてあり、**DI 側は効いていなかった。**
            //    **設定は `ConfigureServices` 側に一本化してある。**
            app.UseCookiePolicy();

            // Sessionを使用する。
            app.UseSession(new SessionOptions()
            {
                IdleTimeout = TimeSpan.FromMinutes(30), // ここで調整
                IOTimeout = TimeSpan.FromSeconds(30),
                Cookie = new CookieBuilder()
                {
                    // **Expiration は書かない**（#279。上流 #541）。
                    //   **セッション Cookie は有効期限を持たない**（ブラウザを閉じると消える）
                    //   ため、指定しても無視される。
                    //   **持続時間を変えたいなら、上の `IdleTimeout` を使う。**
                    HttpOnly = true,
                    // **接頭辞を掛ける**（#255。同じホストに 2 つ立てたときに分けるため）
                    Name = Config.PrefixCookieName(
                        GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName")),
                    Path = "/",
                    SameSite = SameSiteMode.Strict,
                    SecurePolicy = CookieSecurePolicy.SameAsRequest
                }
            });

            // Routing
            app.UseRouting();

            // Identity
            app.UseAuthentication();
            app.UseAuthorization();
            
            // **CORS**（#265）。**既定のポリシーは置かない。**
            //   **口ごとに属性で選ぶ**（`[EnableCors("...")]` / `[DisableCors]`）。
            //   以前はここにインラインで全開のポリシーを書いていたため、
            //   **`/token` `/revoke` `/introspect` まで任意オリジンから叩けた。**
            //
            //   **位置は変えていない**（認証・認可の後ろ）。
            //   プリフライト（`OPTIONS`）が 204 で返ることは実測済みで、
            //   **動いているものを動かさない。**
            app.UseCors();
            
            app.UseEndpoints(endpoints =>
            {
                #region AuthZ(N)Server

                #region Initial Request
                endpoints.MapControllerRoute(
                   name: "Saml2Request",
                   pattern: Config.Saml2RequestEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "Saml2Request" });

                endpoints.MapControllerRoute(
                   name: "OAuth2Authorize",
                   pattern: Config.OAuth2AuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "OAuth2Authorize" });

                // **RP からのログアウト**（RP-Initiated Logout 1.0。#232）
                endpoints.MapControllerRoute(
                   name: "EndSession",
                   pattern: Config.OAuth2EndSessionEndpoint.Substring(1), // 先頭の[/]を削除,
                   defaults: new { controller = "Account", action = "EndSession" });
                #endregion

                #region WebAPI Endpoint

                endpoints.MapControllerRoute(
                    name: "OAuth2Token",
                    pattern: Config.OAuth2TokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "OAuth2Token" });

                endpoints.MapControllerRoute(
                    name: "GetUserClaims",
                    pattern: Config.OAuth2UserInfoEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "GetUserClaims" });

                endpoints.MapControllerRoute(
                    name: "RevokeToken",
                    pattern: Config.OAuth2RevokeTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RevokeToken" });

                endpoints.MapControllerRoute(
                    name: "IntrospectToken",
                    pattern: Config.OAuth2IntrospectTokenEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "IntrospectToken" });

                endpoints.MapControllerRoute(
                    name: "JwksUri",
                    pattern: OAuth2AndOIDCParams.JwkSetUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "JwksUri" });

                endpoints.MapControllerRoute(
                    name: "PushedAuthorizationRequest",
                    pattern: OAuth2AndOIDCParams.AuthRequestPushUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "PushedAuthorizationRequest" });

                endpoints.MapControllerRoute(
                    name: "RequestObjectUri",
                    pattern: OAuth2AndOIDCParams.RequestObjectRegUri.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "RequestObjectUri" });

                #endregion

                #region Back Channel

                #region Device AuthZ

                endpoints.MapControllerRoute(
                    name: "DeviceAuthZAuthorize",
                    pattern: Config.DeviceAuthZAuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "DeviceAuthZAuthorize" });

                endpoints.MapControllerRoute(
                    name: "DeviceAuthZVerify",
                    pattern: Config.DeviceAuthZVerifyEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "Account", action = "DeviceAuthZVerify" });

                #endregion

                #region CIBA FAPI2

                endpoints.MapControllerRoute(
                    name: "CibaAuthorize",
                    pattern: Config.CibaAuthorizeEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "CibaAuthorize" });

                endpoints.MapControllerRoute(
                    name: "CibaPushResult",
                    pattern: Config.CibaPushResultEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "CibaPushResult" });

                #endregion

                #endregion

                #region Push Notification

                endpoints.MapControllerRoute(
                    name: "SetDeviceToken",
                    pattern: Config.SetDeviceTokenWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "SetDeviceToken" });

                endpoints.MapControllerRoute(
                    name: "TwoFactorPushResult",
                    pattern: Config.TwoFactorPushResultEndpoint.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2Endpoint", action = "TwoFactorPushResult" });

                #endregion

                #endregion

                #region ResourceServer
                // **テスト用の口は、閉じられるようにする**（#219）。
                if (!Config.IsLockedDownTestEndpoints)
                {
                    endpoints.MapControllerRoute(
                        name: "TestHybridFlow",
                        pattern: Config.TestHybridFlowWebAPI.Substring(1), // 先頭の[/]を削除,
                        defaults: new { controller = "OAuth2ResourceServer", action = "TestHybridFlow" });
                }

                endpoints.MapControllerRoute(
                    name: "ChageToUser",
                    pattern: Config.ChageToUserWebAPI.Substring(1), // 先頭の[/]を削除,
                    defaults: new { controller = "OAuth2ResourceServer", action = "ChageToUser" });
                #endregion

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        /// <summary>
        /// This method gets called by the runtime.
        /// Use this method to add services to the container.
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        public void ConfigureServices(IServiceCollection services)
        {
            // 構成情報から、AppConfiguration SectionをAppConfiguration Classへバインドするようなケース。
            //services.Configure<AppConfiguration>(Configuration.GetSection("AppConfiguration"));

            // HttpContextのマイグレーション用
            services._AddHttpContextAccessor();

            #region DataProtection の鍵の永続化（#251。C-13）

            // **鍵の置き場を指定しないと、%LOCALAPPDATA% 配下に置かれる**（コンテナでは揮発）。
            //   そうすると —
            //     ・**再起動で認証 Cookie と AntiForgery トークンが全て無効**になる
            //     ・**複数インスタンスでインスタンス間の Cookie が通らない**
            //     ・**メール確認 / パスワード リセットのリンクが切れる**
            //       （DataProtectorTokenProvider が使う）
            //
            //   **net48 の <machineKey> と同じ役割**だが、**鍵そのものは設定に書かない。**
            //   **鍵は自動生成・自動ローテーションされ、その「置き場」を共有する。**
            //
            //   **access_token / id_token には影響しない**（JWS。自前の署名鍵）。
            //   **PPID にも影響しない**（SaltParameter から導出）。
            //   **認可コード / refresh_token にも影響しない**（サーバ側のストアに保存）。
            //   つまり「発行済みのトークンが無効になる」話ではなく、
            //   **「画面のセッションが切れる」**話である。
            //
            // **未設定なら、従来どおり何もしない**（下位互換）。
            if (!string.IsNullOrEmpty(Config.DataProtectionKeyPath))
            {
                services.AddDataProtection()
                    .PersistKeysToFileSystem(
                        new DirectoryInfo(Config.DataProtectionKeyPath))
                    // **アプリケーション名も固定する**（#279。上流 #541）。
                    //   **既定ではコンテンツ ルートのパスから決まる**ため、
                    //   **鍵を共有していても、配置先のパスが違うと復号できない**
                    //   （Windows の `C:\…` とコンテナの `/app` など）。
                    //   **症状は「ログインし直しになる」だけなので、気付きにくい。**
                    .SetApplicationName(Const.DataProtectionApplicationName);

                // **鍵リングは平文の XML である。** マウント先の保護は運用側の責任。
                //   証明書で包む（ProtectKeysWithCertificate）かどうかは、ここでは決めない。
            }

            #endregion

            #region Cookie ポリシー（#279。上流 #541）

            //  **`Configure` 側の `app.UseCookiePolicy()` が、ここの設定を使う。**
            //    **以前は `Configure` 側で引数を渡しており、ここは効いていなかった。**
            //    **値は、効いていた側（`Configure` 側の引数）をそのまま移している。**
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.HttpOnly = HttpOnlyPolicy.Always;

                // https://github.com/aspnet/Security/issues/1822
                //   **`Strict` にしない。** ID 連携の外部ログインや
                //   `response_mode=form_post` の戻りで、Cookie が送られなくなる。
                //
                //   **明示を外すと、`samesite` 属性ごと出なくなる**（#279 で実測）。
                //   **「`Lax` に格上げされる」ではない。**
                //   属性が無ければ**ブラウザ側の既定（Chrome は `Lax`）**が適用されるので、
                //   **結果として `None` ではなくなる。**
                //   **`RT-279.1` が、この属性を見て固定している。**
                options.MinimumSameSitePolicy = SameSiteMode.None;

                // **Cookie の Secure 属性**（既定は空＝各 Cookie の設定に従う）。
                //   TLS で公開するなら `always` にする。
                //   **平文 HTTP の環境で `always` にすると、Cookie が送られず
                //   サインインできなくなる**ので、既定では変えない。
                if (Config.CookieSecurePolicyAlways)
                {
                    options.Secure = CookieSecurePolicy.Always;
                }

                // **同意の確認は、明示的に書かない**（＝ 既定の false のまま）。
                //   **以前は `options.CheckConsentNeeded = context => true;` と書いてあったが、
                //   `Configure` 側で引数を渡していたため効いていなかった。**
                //   **有効にすると、同意前は必須でない Cookie（セッションを含む）が
                //   送られなくなる**ので、挙動が変わる。
                //   **同意を取る画面を用意したうえで有効にすること**（この Issue では変えない）。
            });

            #endregion

            #region セッションの置き場（#256）

            //  **プロセス内だと、インスタンスを増やすと壊れる。**
            //    要求が別のインスタンスへ回ると、セッションに置いた値が読めない
            //    （ID フェデレーションの `state` / `nonce` / `code_verifier`、
            //     自己テスト画面の値、管理画面の `access_token`、FIDO2 の challenge）。
            //
            //  **`UserStoreType` と同じ流儀で選ぶ**（`SessionStoreType`）。
            //    **書かなければ `mem`**（＝ 従来どおり）。
            //
            //  **net48 版は `Web.config` の `sessionState` で選ぶ**ので、ここは net10.0 版だけの話。
            //
            //  **Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い。**
            //    **3 方言は揃わない**ので、それらのストアで複数インスタンスにするなら `redis`。
            if (Config.SessionStoreType != EnumSessionStoreType.Memory
                && string.IsNullOrEmpty(Config.SessionStoreConnectionString))
            {
                // **ここで落とす。** 接続文字列が無いと、
                //   `IDistributedCache` は**最初にセッションを触った時に**落ちる。
                //   起動は通ってしまうので、**画面が 500 を返すだけで理由が分からない。**
                throw new InvalidOperationException(
                    "SessionStoreType が " + Config.SessionStoreType
                    + " なので、SessionStoreConnectionString が必要です。");
            }

            switch (Config.SessionStoreType)
            {
                case EnumSessionStoreType.SqlServer:

                    // **テーブルが要る**（`Create_SessionCache.sql`）。
                    //   スキーマ名・テーブル名は `Const` に置いてある（DDL と食い違わせない）。
                    services.AddDistributedSqlServerCache(options =>
                    {
                        options.ConnectionString = Config.SessionStoreConnectionString;
                        options.SchemaName = Const.SessionCacheSchemaName;
                        options.TableName = Const.SessionCacheTableName;
                    });

                    break;

                case EnumSessionStoreType.Redis:

                    // **方言に依らない。** `UserStoreType` が `ora` / `npg` でも使える。
                    services.AddStackExchangeRedisCache(options =>
                    {
                        options.Configuration = Config.SessionStoreConnectionString;
                    });

                    break;

                default:

                    // **プロセス内**（既定）。**単一インスタンスなら、これで足りる。**
                    services.AddDistributedMemoryCache();

                    break;
            }

            #endregion

            // Sessionを使用する。
            services.AddSession();

            // Core 3.0のテンプレートではUseMvcの
            // 代わりにこれらを使用するようになった。
            services
                .AddControllersWithViews()// MVC & WebAPI
                .AddNewtonsoftJson();// JSON シリアライザの変更

            #region Add Frameworks

            // 一般的な Webアプリでは、
            // EF, Identity, MVC などのミドルウェア サービスを登録する。
            // ミドルウェアの実行順序は、IStartupFilter の登録順に設定される。

            // EF
            //services.AddDbContext<ApplicationDbContext>(options =>
            //    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            // AddMvc
            services.AddMvc();

            // **TempData の Cookie の名前にも接頭辞を付ける**（#255）。
            //   **空なら既定のまま**（`.AspNetCore.Mvc.CookieTempDataProvider`）。
            //
            //   **同じホストに 2 つ立てると、この Cookie も上書きし合う**
            //   （Cookie のスコープにポートは入らないため）。
            //   **中身は配備ごとの鍵で守られており相手は読めない**が、**消えるので
            //   画面のメッセージ（[TempData] ErrorMessage など）が出なくなる。**
            //
            //   **net10.0 版だけの話。** net48 版の TempData はセッションに載る。
            //   **PostConfigure で掛ける。** 既定の名前が入った後に読みたいため
            //   （Configure だと、既定が入る前に走る余地がある）。
            if (!string.IsNullOrEmpty(Config.CookieNamePrefix))
            {
                services.PostConfigure<CookieTempDataProviderOptions>(options =>
                {
                    options.Cookie.Name = Config.PrefixCookieName(options.Cookie.Name);
                });

                // **AntiForgery の Cookie にも掛ける**（#282）。
                //   **既定の名前は DataProtection の識別子から導かれる**ので、
                //   **#279 で SetApplicationName を入れた後は、
                //   `DataProtectionKeyPath` を設定した配備同士が同じ名前になる**
                //   （実測 : 置き場の有無だけで名前が変わった。#282）。
                //
                //   **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
                //   **同じホストに 2 つ建てると互いに上書きする。**
                //   **検証は落とす側に倒れる**（復号できなければ拒む）ので、
                //   **CSRF の穴にはならないが、正しい POST が 400 になる。**
                services.PostConfigure<AntiforgeryOptions>(options =>
                {
                    options.Cookie.Name = Config.PrefixCookieName(options.Cookie.Name);
                });

                // **Identity が使う Cookie すべてに掛ける**（#255）。
                //   **AuthCookieName で名前を決めた後**に付けたいので、PostConfigure で行う。
                //   AuthCookieName が空でも、**枠組みの既定名に接頭辞が付く。**
                //
                //   **サインインの Cookie（Application）だけでは足りない。**
                //   **外部ログイン（External）は ID フェデレーションと外部 IdP の途中で使い**、
                //   **2 要素認証（TwoFactor*）も同じように途中の状態を持つ。**
                //   **これらが混ざると、連携や 2FA の途中で別のサイトの状態を掴む。**
                string[] identitySchemes = new string[]
                {
                    IdentityConstants.ApplicationScheme,
                    IdentityConstants.ExternalScheme,
                    IdentityConstants.TwoFactorUserIdScheme,
                    IdentityConstants.TwoFactorRememberMeScheme
                };

                foreach (string scheme in identitySchemes)
                {
                    services.PostConfigure<CookieAuthenticationOptions>(
                        scheme, options =>
                        {
                            options.Cookie.Name = Config.PrefixCookieName(options.Cookie.Name);
                        });
                }
            }

            // AddCors（#265）
            //
            //   **口の性質で分ける。** 既定のポリシーは置かない（属性で選ぶ）。
            //
            //   | ポリシー | 付ける口 |
            //   |---|---|
            //   | MpasPublicDocs  | `.well-known/openid-configuration` / `jwkcerts` / `samlmetadata` |
            //   | MpasBrowserApi  | `/token` `/userinfo` `/SetDeviceToken` `/ciba_result` `/2fa_result` |
            //   | （付けない）    | `/revoke` `/introspect` `/device_authz` `/ciba_authz` `/par` `/ros` |
            //
            //   **`AllowCredentials` は、どちらにも付けない。**
            //   **Cookie で通る口をこの範囲に入れない**ためである
            //   （入れると、他オリジンの JS から利用者の資格情報で呼べる）。
            services.AddCors(o =>
            {
                // **公開情報。** 誰でも読んでよい（RP の検出に使う）。
                o.AddPolicy(Const.CorsPolicyPublicDocs, builder =>
                {
                    builder
                    .AllowAnyOrigin()
                    .WithMethods("GET")
                    .AllowAnyHeader();
                });

                // **ブラウザから叩く口。** **許すオリジンだけ。**
                //   **1 件も無ければ、どのオリジンも通さない**（安全側の既定）。
                //
                //   **要求ごとに判定する**（#266）。**起動時に配列を固定しない。**
                //   **画面から登録したクライアントのオリジンは、起動の後に増える**
                //   （種データも含めて、サイトが動き出してから作られる）。
                //   `GetCorsAllowedOrigins` は**毎回作る**（#271）。
                //   **呼ばれるのは `Origin` 付きの要求のときだけ**で、読むのは
                //   URI 関連の 6 列だけ（#270）。キャッシュは取りこぼしを生んでいた。
                o.AddPolicy(Const.CorsPolicyBrowserApi, builder =>
                {
                    builder
                    .SetIsOriginAllowed(origin =>
                        CmnEndpoints.GetCorsAllowedOrigins().Contains(origin))
                    .AllowAnyMethod()
                    .AllowAnyHeader();
                });

                // **自己テスト用の口（ValuesController）だけが使う。**
                //   `Config.IsLockedDownTestEndpoints` が true の配備では、その口自体が閉じる。
                o.AddPolicy("AllowAllOrigins", builder =>
                {
                    builder
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
                });
            });

            #region ASP.NET Core Identity

            // must be added before AddIdentity()
            services.AddScoped<IPasswordHasher<ApplicationUser>, CustomPasswordHasher<ApplicationUser>>();
            services.AddScoped<ISecurityStampValidator, SecurityStampValidator<ApplicationUser>>();

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

            #region 認証

            #region IdentityOptions

            Action<IdentityOptions> IdentityOptionsConf = new Action<IdentityOptions>(idOptions =>
                {
                    // ユーザー
                    // https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-2.2#user
                    //idOptions.SignIn.AllowedUserNameCharacters = false;
                    // **メアドは常に一意**（#151 の段階 3）。
                    //   **利用者名とメアドの両方でサインインできる**ので、
                    //   **メアドが一意でないと FindByEmailAsync が成り立たない。**
                    //   以前は RequireUniqueEmail の設定で切り替えていた（その設定は落とした）。
                    idOptions.User.RequireUniqueEmail = true;

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

            // **スキーム "Cookies" の登録は、外せない（#223）。**
            //   Open棟梁のフレームワーク（MyMVCCoreFilterAttribute）がこのスキームを参照するため、
            //   登録が無いと、次の例外で落ちる。
            //     No authentication handler is registered for the scheme 'Cookies'.
            //
            //   **ただし、このサイトがサインインに使うのは Identity.Application。**
            //   ここに LoginPath や ExpireTimeSpan を書いても**効かない**ので、書かない。
            //   実際の設定は、下の ConfigureApplicationCookie で行う。
            authenticationBuilder.AddCookie();

            // **ASP.NET Core Identity のクッキー（Identity.Application）を設定する（#223）。**
            //
            //   以前は authenticationBuilder.AddCookie(options => ...) に書いていたが、
            //   **それはスキーム "Cookies" の設定で、サインインには使われていなかった。**
            //   AddIdentity が既定のスキームを Identity.Application にするため、
            //   **書いた設定が 1 つも効いていなかった**（LoginPath も ExpireTimeSpan も）。
            //
            //   ConfigureApplicationCookie は Identity.Application を設定するので、
            //   ここに書いたことが実際に効く。**AddIdentity より後に呼ぶこと。**
            services.ConfigureApplicationCookie(options =>
                {
                    // **接頭辞を直書きしない。** PathBase は実行時に前置される
                    //   （IIS Express の仮想アプリでは /MultiPurposeAuthSite が付く）。
                    options.LoginPath = "/Account/Login";
                    options.LogoutPath = "/Account/LogOff";
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    // **net48 と同じ設定キーで揃える**（App_Start/StartupAuth.cs）。
                    //   以前の net10.0 は、この 2 つを読んでいなかった。
                    options.ExpireTimeSpan = Config.AuthCookieExpiresFromHours;
                    options.SlidingExpiration = Config.AuthCookieSlidingExpiration;

                    //options.AccessDeniedPath = "/Identity/Account/AccessDenied";

                    // **Cookie の名前を設定で変えられるようにする**（#250 の段階 4）。
                    //   **空なら既定のまま**（`.AspNetCore.Identity.Application`）。
                    //   **同じホストに 2 つ立てるときだけ指定する**
                    //   （Cookie のスコープにポートは入らないため、
                    //     上流と下流を同じホストで動かすと、同名の Cookie が奪い合いになる）。
                    if (!string.IsNullOrEmpty(Config.AuthCookieName))
                    {
                        options.Cookie.Name = Config.AuthCookieName;
                    }

                    options.Cookie.HttpOnly = true;

                    // ※ SecurityStamp の検証（OnValidatePrincipal）は書かない。
                    //    Identity が既定で設定しており、間隔は
                    //    SecurityStampValidatorOptions.ValidationInterval で指定している（下の方）。
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

                    // **email_verified をクレームに写す**（#140 の段階 1）。
                    //   Google は userinfo で email_verified を返すが、
                    //   **既定の ClaimActions には含まれない**ので、明示的に写す。
                    //   これが無いと、**Google はメアドを検証しているのに**
                    //   「言っていない」扱いになり、既存アカウントへのリンクが拒否される
                    //   （判定は Extensions.Sts.AccountLink）。
                    //
                    //   **他の 3 つ（Microsoft / Facebook / Twitter）には足さない。**
                    //     Microsoft : Graph の /me に相当するクレームが無い
                    //     Facebook  : verified はアカウントの検証で、メアドの検証ではない
                    //     Twitter   : メアド自体が返らないのが普通
                    options.ClaimActions.MapJsonKey(
                        OAuth2AndOIDCConst.email_verified, OAuth2AndOIDCConst.email_verified);
                });
            }
            // **Facebook / Twitter は取り下げた**（#249）。
            //   **動かないからではなく、維持コストが便益に見合わないため。**
            //   ・この 2 つだけ、メアドを取るための専用コードを抱えていた（net48 側）
            //   ・両アプリに二重にあり、外部 API の変更に追随する必要があった
            //   ・#140 の段階 1（C-23）以降、**検証済みのメアドを示せないので、
            //     既存アカウントへの自動リンクができない側に固定される**
            //
            //   **削除せずコメントアウトにしてある。**
            //   判断が変われば戻せるように、パッケージ参照と設定キーも残してある。
            //if (Config.FacebookAuthentication)
            //{
            //    authenticationBuilder.AddFacebook(options =>
            //    {
            //        options.AppId = Config.FacebookAuthenticationClientId;
            //        options.AppSecret = Config.FacebookAuthenticationClientSecret;
            //    });
            //}
            //if (Config.TwitterAuthentication)
            //{
            //    authenticationBuilder.AddTwitter(options =>
            //    {
            //        options.ConsumerKey = Config.TwitterAuthenticationClientId;
            //        options.ConsumerSecret = Config.TwitterAuthenticationClientSecret;
            //        options.RetrieveUserDetails = true;
            //    });
            //}
            #endregion

            #region OAuth2 / OIDC

            // スクラッチ実装

            #endregion

            #endregion

            services.Configure<SecurityStampValidatorOptions>(options =>
            {
                options.ValidationInterval = Config.SecurityStampValidateIntervalFromSeconds;
            });

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
