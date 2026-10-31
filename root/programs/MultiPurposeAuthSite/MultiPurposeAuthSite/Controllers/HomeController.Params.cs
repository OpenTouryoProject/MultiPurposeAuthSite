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
using MultiPurposeAuthSite.Util.Sts;

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

            // client_id → Issuer
            Session[Const.TestClientId] = this.ClientId;
            Response.Cookies[Const.TestClientId].Value = this.ClientId;

            // redirect_uri → AssertionConsumerService
            Session[Const.TestRedirectUri] = this.RedirectUri;
            Response.Cookies[Const.TestRedirectUri].Value = this.RedirectUri;

            // state → RelayState
            Session[Const.TestState] = this.State;
            Response.Cookies[Const.TestState].Value = this.State;

            // **AuthnRequest の ID**（#276。応答の InResponseTo と照合する）
            Session[Const.TestSamlRequestId] = this.SamlRequestId;
            Response.Cookies[Const.TestSamlRequestId].Value = this.SamlRequestId;
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

            // client_id
            Session[Const.TestClientId] = this.ClientId;
            Response.Cookies[Const.TestClientId].Value = this.ClientId;

            // state
            Session[Const.TestState] = this.State;
            Response.Cookies[Const.TestState].Value = this.State;

            // redirect_uri
            // OIDCでもTokenリクエストにredirect_uriを指定する（OIDC Core 3.1.3.1）（#186）。
            Session[Const.TestRedirectUri] = this.RedirectUri;
            Response.Cookies[Const.TestRedirectUri].Value = this.RedirectUri;

            // nonce
            Session[Const.TestNonce] = this.Nonce;
            Response.Cookies[Const.TestNonce].Value = this.Nonce;

            // code_verifier
            Session[Const.TestCodeVerifier] = this.CodeVerifier;
            Response.Cookies[Const.TestCodeVerifier].Value = this.CodeVerifier;
        }

        #endregion

        #endregion
    }
}