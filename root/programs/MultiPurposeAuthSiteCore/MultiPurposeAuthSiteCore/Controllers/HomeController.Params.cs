//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストのパラメタ（初期化と保存）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         コメントの誤りを直した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using Microsoft.AspNetCore.Http;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストのパラメタ（初期化と保存））</summary>
    public partial class HomeController
    {
        #region Params

        /// <summary>Issuer</summary>
        private string Issuer = "";

        /// <summary>RedirectUri</summary>
        private string RedirectUri = "";

        /// <summary>ClarifyRedirectUri</summary>
        private bool ClarifyRedirectUri = false;

        #region Saml2

        /// <summary>SAML2 の要求の宛先</summary>
        private string Saml2RequestEndpoint = "";

        /// <summary>NameIDFormat（SAML2。画面で選ぶ。#277 の段階 4）</summary>
        private string NameIdFormat = "";

        /// <summary>AuthnRequest の ID（#276）</summary>
        /// <remarks>**応答の `InResponseTo` と照合する**ために持つ。</remarks>
        private string SamlRequestId = "";

        #endregion

        #region OAuth2
        /// <summary>認可エンドポイント</summary>
        private string OAuth2AuthorizeEndpoint = "";

        /// <summary>ClientName</summary>
        private string ClientName = "";

        /// <summary>ClientId</summary>
        private string ClientId = "";

        /// <summary>state（SAML2 では RelayState）</summary>
        private string State = "";

        /// <summary>nonce</summary>
        private string Nonce = "";

        /// <summary>ResponseMode</summary>
        private string ResponseMode = ""; 

        /// <summary>code_verifier</summary>
        private string CodeVerifier = "";

        /// <summary>code_challenge</summary>
        private string CodeChallenge = "";

        /// <summary>prompt（画面で選ぶ。#246 の項目 3）</summary>
        private string Prompt = "";

        /// <summary>max_age（画面で選ぶ。#246 の項目 3）</summary>
        private string MaxAge = "";
        #endregion

        #endregion

        #region InitParams

        #region InitSaml2Params

        /// <summary>テスト用にパラメタを初期化</summary>
        private void InitSaml2Params()
        {
            this.Saml2RequestEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            // Issuer (RootURI + ClientId) 
            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            this.Issuer = "http://" + ClientId;

            if (this.ClarifyRedirectUri)
            {
                this.RedirectUri = Helper.GetInstance().GetAssertionConsumerServiceURL(this.ClientId);
            }

            // RelayStateに入れる（本来の用途と異なるが）。
            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
        }

        /// <summary>テスト用にパラメタを保存</summary>
        private void SaveSaml2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時
            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            // client_id → Issuer
            HttpContext.Session.SetString(Const.TestClientId, this.ClientId);
            responseCookies.Set(Const.TestClientId, this.ClientId, this._cookieOptions);

            // redirect_uri → AssertionConsumerService
            HttpContext.Session.SetString(Const.TestRedirectUri, this.RedirectUri);
            responseCookies.Set(Const.TestRedirectUri, this.RedirectUri, this._cookieOptions);

            // state → RelayState
            HttpContext.Session.SetString(Const.TestState, this.State);
            responseCookies.Set(Const.TestState, this.State, this._cookieOptions);

            // **AuthnRequest の ID**（#276。応答の InResponseTo と照合する）
            HttpContext.Session.SetString(Const.TestSamlRequestId, this.SamlRequestId);
            responseCookies.Set(Const.TestSamlRequestId, this.SamlRequestId, this._cookieOptions);
        }

        #endregion

        #region InitOAuth2Params

        /// <summary>テスト用にパラメタを初期化</summary>
        private void InitOAuth2Params()
        {
            this.OAuth2AuthorizeEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI
            + Config.OAuth2AuthorizeEndpoint;

            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            // ココでは、まだ、response_typeが明確にならないので取得できない。
            //this.RedirectUri = Helper.GetInstance().GetClientsRedirectUri(this.ClientName, response_type);

            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。

            this.CodeVerifier = "";
            this.CodeChallenge = "";
        }

        /// <summary>テスト用にパラメタを保存</summary>
        private void SaveOAuth2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            IResponseCookies responseCookies = MyHttpContext.Current.Response.Cookies;

            // client_id
            HttpContext.Session.SetString(Const.TestClientId, this.ClientId);
            responseCookies.Set(Const.TestClientId, this.ClientId, this._cookieOptions);

            // state
            HttpContext.Session.SetString(Const.TestState, this.State);
            responseCookies.Set(Const.TestState, this.State, this._cookieOptions);

            // redirect_uri
            // OIDCでもTokenリクエストにredirect_uriを指定する（OIDC Core 3.1.3.1）（#186）。
            HttpContext.Session.SetString(Const.TestRedirectUri, this.RedirectUri);
            responseCookies.Set(Const.TestRedirectUri, this.RedirectUri, this._cookieOptions);

            // nonce
            HttpContext.Session.SetString(Const.TestNonce, this.Nonce);
            responseCookies.Set(Const.TestNonce, this.Nonce, this._cookieOptions);

            // code_verifier
            HttpContext.Session.SetString(Const.TestCodeVerifier, this.CodeVerifier);
            responseCookies.Set(Const.TestCodeVerifier, this.CodeVerifier, this._cookieOptions);
        }

        #endregion

        #endregion
    }
}