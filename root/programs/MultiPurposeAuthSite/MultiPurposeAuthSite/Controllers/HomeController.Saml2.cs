//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストの SAML2
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Web.Mvc;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストの SAML2）</summary>
    public partial class HomeController
    {
        #region Assemble

        #region AssembleSaml2

        /// <summary>画面で選んだ NameIDFormat を、列挙型へ直す（#277 の段階 4）</summary>
        /// <returns>SAML2Enum.NameIDFormat</returns>
        /// <remarks>
        /// **選ばなければ `Unspecified`**（IdP 側の既定と同じ。`CmnEndpoints`）。
        /// **知らない値も `Unspecified`** に倒す（画面からは選べないが、念のため）。
        ///
        /// **`Transient` は返さない。** `GetSubForSAML2` に分岐が無く、
        /// **NameID が空のまま返る**ため（画面の候補にも入れていない）。
        /// </remarks>
        private SAML2Enum.NameIDFormat ToNameIDFormat()
        {
            switch (this.NameIdFormat)
            {
                case Const.NameIdFormatEmailAddress:
                    return SAML2Enum.NameIDFormat.EmailAddress;

                case Const.NameIdFormatPersistent:
                    return SAML2Enum.NameIDFormat.Persistent;

                default:
                    return SAML2Enum.NameIDFormat.Unspecified;
            }
        }
        #endregion

        #endregion

        #region Action Method

        #region SAML2

        /// <summary>Test Saml2 Redirect & Redirect Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectRedirectBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpRedirect,
                this.ToNameIDFormat(),
                this.Issuer, this.RedirectUri, this.State, out id);

            // **応答の InResponseTo と照合する**（#276）。
            this.SamlRequestId = id;

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Redirect & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpPost,
                this.ToNameIDFormat(),
                this.Issuer, this.RedirectUri, this.State, out id);

            // **応答の InResponseTo と照合する**（#276）。
            this.SamlRequestId = id;

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Post & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2PostPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string samlRequest = SAML2Client.CreatePostRequest(
                SAML2Enum.ProtocolBinding.HttpPost,
                this.ToNameIDFormat(),
                this.Issuer, this.RedirectUri, this.State, out id);

            // **応答の InResponseTo と照合する**（#276）。
            this.SamlRequestId = id;

            this.SaveSaml2Params();

            // Post
            ViewData["RelayState"] = this.State;
            ViewData["SAMLRequest"] = samlRequest;
            ViewData["Action"] = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            return View("PostBinding");
        }

        /// <summary>Test Saml2 Post & Redirect Binding</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **4 つ目の組み合わせ**（#246 の項目 2）。
        /// 要求を POST で送り、**応答は Redirect（GET）で受ける**。
        /// `ProtocolBinding` が応答の受け取り方を決めるので、`HttpRedirect` を渡す。
        /// </remarks>
        private ActionResult Saml2PostRedirectBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string samlRequest = SAML2Client.CreatePostRequest(
                SAML2Enum.ProtocolBinding.HttpRedirect,
                this.ToNameIDFormat(),
                this.Issuer, this.RedirectUri, this.State, out id);

            // **応答の InResponseTo と照合する**（#276）。
            this.SamlRequestId = id;

            this.SaveSaml2Params();

            // Post
            ViewData["RelayState"] = this.State;
            ViewData["SAMLRequest"] = samlRequest;
            ViewData["Action"] = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            return View("PostBinding");
        }

        #endregion

        #endregion
    }
}