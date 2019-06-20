//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：WebApiConfig
//* クラス日本語名  ：ルート定義に関する指定（WebApi用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite
{
    /// <summary>
    /// ルート定義に関する指定（WebApi用）
    /// </summary>
    public static class WebApiConfig
    {
        /// <summary>
        /// Routing in ASP.NET Web API  The Official Microsoft ASP.NET Site
        /// http://www.asp.net/web-api/overview/web-api-routing-and-actions/routing-in-aspnet-web-api
        ///  Web API RoutingはMVC Routingに非常に似ています。
        ///  主な違いは Web API URI パスではなく HTTP メソッドを使用してアクションを選択することです。
        ///  さらに、Web APIの中でMVC Routingを使用しても良い。
        /// </summary>
        public static void Register(HttpConfiguration config)
        {
            // ↓使用しない。
            //// Web API configuration and services
            //// 「Bearer Token」認証のみを使用するように、Web API を設定。
            //config.SuppressDefaultHostAuthentication();
            //config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // JSON を既定にして、CamelCaseを使用 (JSON.NET)
            config.Formatters.Remove(config.Formatters.XmlFormatter);
            config.Formatters.Add(config.Formatters.JsonFormatter);
            config.Formatters.JsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

            // CORS (Cross-Origin Resource Sharing)の有効化
            // 別ドメイン上で動作する Web アプリからアクセス可能に設定。
            config.EnableCors();

            // Web API routes を設定する。

            // Attribute Routing
            config.MapHttpAttributeRoutes();

            // MapHttpRoute
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            #region OAuth2Endpoint
            config.Routes.MapHttpRoute(
                name: "OAuth2Token",
                routeTemplate: Config.OAuth2TokenEndpoint.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "OAuth2Token" }
            );

            config.Routes.MapHttpRoute(
                name: "GetUserClaims",
                routeTemplate: Config.OAuth2UserInfoEndpoint.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "GetUserClaims" }
            );

            config.Routes.MapHttpRoute(
                name: "RevokeToken",
                routeTemplate: Config.OAuth2RevokeTokenEndpoint.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "RevokeToken" }
            );

            config.Routes.MapHttpRoute(
                name: "IntrospectToken",
                routeTemplate: Config.OAuth2IntrospectTokenEndpoint.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "IntrospectToken" }
            );

            config.Routes.MapHttpRoute(
                name: "JwksUri",
                routeTemplate: OAuth2AndOIDCParams.JwkSetUri.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "JwksUri" }
            );

            config.Routes.MapHttpRoute(
                name: "RequestObjectUri",
                routeTemplate: OAuth2AndOIDCParams.RequestObjectRegUri.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2Endpoint", action = "RequestObjectUri" }
            );
            #endregion

            #region OAuth2ResourceServer

            config.Routes.MapHttpRoute(
                name: "TestHybridFlow",
                routeTemplate: Config.TestHybridFlowWebAPI.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2ResourceServer", action = "TestHybridFlow" }
            );

            config.Routes.MapHttpRoute(
                name: "TestChageToUser",
                routeTemplate: Config.TestChageToUserWebAPI.Substring(1), // 先頭の[/]を削除
                defaults: new { controller = "OAuth2ResourceServer", action = "TestChageToUser" }
            );

            #endregion

            //// トレース機能を有効化します。
            //TraceConfig.Register(config);
        }
    }
}
