//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の SAML2 の口
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//**********************************************************************************

/*
SAML2 の IdP としての口
（AuthnRequest の受け付けと検証、SAMLResponse の作成）
を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using Saml = MultiPurposeAuthSite.SamlProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Xml;
using System.Security.Claims;

using System.Web.Mvc;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の SAML2 の口**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region Saml2 Request

        /// <summary>Saml2Request</summary>
        /// <param name="samlRequest">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult</returns>
        public ActionResult Saml2Request(string samlRequest, string relayState, string sigAlg)
        {
            bool verified = false;

            string queryString = "";

            XmlDocument samlRequest2 = null;
            XmlNamespaceManager samlNsMgr = null;

            string iss = "";
            string id = "";

            // Cookie認証チケットからClaimsIdentityを取得しておく。
            AuthenticateResult ticket = this.AuthenticationManager
                .AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie).Result;
            ClaimsIdentity identity = (ticket != null) ? ticket.Identity : null;

            SAML2Enum.StatusCode statusCode = SAML2Enum.StatusCode.Success;

            try
            {

                if (Request.HttpMethod.ToLower() == "get")
                {
                    // DecodeRedirect
                    string rawUrl = Request.RawUrl;
                    queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);

                    // VerifySamlRequest（展開と読み込みも行う）
                    verified = Saml.CmnEndpoints.VerifySamlRequest(
                        queryString, "", out iss, out id, out samlRequest2);
                }
                else if (Request.HttpMethod.ToLower() == "post")
                {
                    // VerifySamlRequest（展開と読み込みも行う）
                    verified = Saml.CmnEndpoints.VerifySamlRequest(
                        "", samlRequest, out iss, out id, out samlRequest2);
                }

                // XmlNamespaceManager（応答の組み立てで、要求の ACS URL などを読む）
                if (samlRequest2 != null)
                {
                    samlNsMgr = SAML2Bindings.CreateNamespaceManager(samlRequest2);
                }

                // レスポンス生成
                if (verified)
                {
                    // Assertion > AttributeStatement > Attribute > AttributeValueに
                    // クレームを足すなら、ココで、identity.Claimsに値を詰めたりする。

                    return this.CreateSaml2Response(
                        identity, statusCode, iss, relayState, id, samlRequest2, samlNsMgr);
                }
                else
                {
                    // Error Response
                    Logging.MyOperationTrace(string.Format(
                        Resources.Diagnostics.LogSaml2RequestNotVerified, LogSanitizer.Sanitize(iss)));
                    statusCode = SAML2Enum.StatusCode.Requester;
                }
            }
            catch (Exception ex)
            {
                // Error Response
                Logging.MyOperationTrace(string.Format(Resources.Diagnostics.LogSaml2RequestFailed,
                    LogSanitizer.Sanitize(iss), LogSanitizer.Sanitize(ex.Message, Const.LogDetailMaxLength)));
                statusCode = SAML2Enum.StatusCode.Responder;
            }

            // Error Response
            try
            {
                return this.CreateSaml2Response(
                    identity, statusCode, iss, relayState, id, samlRequest2, samlNsMgr);
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    Resources.Diagnostics.LogSaml2ErrorResponseFailed, LogSanitizer.Sanitize(ex.Message, Const.LogDetailMaxLength)));

                // **iss などが取れていないと返せない。**
                //   **以前は null を返していた**が、
                //   **MVC のアクションから null を返すと 500 になる**（#276）。
                return View("Error");
            }
        }

        /// <summary>SAML2 の応答を返す（#276）</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="statusCode">SAML2Enum.StatusCode</param>
        /// <param name="iss">Request の Issuer</param>
        /// <param name="relayState">RelayState</param>
        /// <param name="inResponseTo">Request の ID</param>
        /// <param name="samlRequest">XmlDocument（読めていなければ null）</param>
        /// <param name="samlNsMgr">XmlNamespaceManager（同上）</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **応答を組み立てて返すところを 1 本にまとめた**（#276）。
        ///
        /// **`CreateSamlResponse` は 3 通りを返す。**
        ///
        /// | 戻り値 | 意味 | 返し方 |
        /// |---|---|---|
        /// | `HttpRedirect` | Redirect Binding で返す | クエリ文字列付きのリダイレクト |
        /// | `HttpPost` | POST Binding で返す | 自動送信フォーム |
        /// | **`null`** | **応答を返す先が決まらない** | **エラー画面** |
        ///
        /// **以前は `== HttpRedirect` の 2 分岐**だったので、
        /// **`null` が POST 側に落ち、`action` も `SAMLResponse` も空の
        /// 自動送信フォームが返っていた。**
        /// </remarks>
        private ActionResult CreateSaml2Response(
            ClaimsIdentity identity, SAML2Enum.StatusCode statusCode,
            string iss, string relayState, string inResponseTo,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr)
        {
            string rtnUrl = "";
            string samlResponse = "";
            string queryString = "";

            SAML2Enum.ProtocolBinding? protocolBinding = Saml.CmnEndpoints.CreateSamlResponse(
                identity, SAML2Enum.AuthnContextClassRef.PasswordProtectedTransport, statusCode,
                iss, relayState, inResponseTo,
                out rtnUrl, out samlResponse, out queryString, samlRequest, samlNsMgr);

            if (protocolBinding == SAML2Enum.ProtocolBinding.HttpRedirect)
            {
                // Redirect
                return Redirect(rtnUrl + "?" + queryString);
            }
            else if (protocolBinding == SAML2Enum.ProtocolBinding.HttpPost)
            {
                // Post
                ViewData["RelayState"] = relayState;
                ViewData["SAMLResponse"] = samlResponse;
                ViewData["Action"] = rtnUrl;

                return View("PostBinding");
            }

            // **応答を返す先が決まらない**（ACS URL が事前登録されていない）。
            //   **要求に書かれた URL へは返さない**（SAML Core 3.2.1）。
            return View("Error");
        }

        #endregion

        #region Saml2 Response

        /// <summary>AssertionConsumerService</summary>
        /// <param name="samlResponse">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult（Saml2Response 画面）</returns>
        /// <remarks>
        /// **検証の本体は Open棟梁 の `SAML2Client.VerifyResponseWithReason`**
        /// （#246 で両アプリから寄せ、#286 の段階 1 で鍵と期待 Issuer を引数にし、#294 で移した）。
        ///
        /// **アサーションを画面に出す**（#246 の項目 3）。
        /// 以前は `?ret=認証完了（nameId=…）` / `?ret=認証失敗` という URL に移るだけで、
        /// **どこで落ちたのかが分からず、読み取った属性も XML も捨てていた。**
        /// </remarks>
        [AllowAnonymous]
        public ActionResult AssertionConsumerService(string samlResponse, string relayState, string sigAlg)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                // テスト用のエンドポイントを閉じている。
                return View("Error");
            }

            bool isGet = (Request.HttpMethod.ToLower() == "get");
            string queryString = "";

            if (isGet)
            {
                // **Redirect Binding は、クエリ文字列そのものが署名の対象**である。
                string rawUrl = Request.RawUrl;
                queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);
            }

            // LoadRequestParameters（state と RelayState を照合するため）
            string clientId_InSessionOrCookie = "";
            string state_InSessionOrCookie = "";
            string redirect_uri_InSessionOrCookie = "";
            string nonce_InSessionOrCookie = "";
            string code_verifier_InSessionOrCookie = "";
            this.LoadRequestParameters(
                out clientId_InSessionOrCookie,
                out state_InSessionOrCookie,
                out redirect_uri_InSessionOrCookie,
                out nonce_InSessionOrCookie,
                out code_verifier_InSessionOrCookie);

            // **自分の ACS URL**（#276。Audience / Recipient と照合する）。
            //   **IdP は登録値「test_self_saml」をこの形に展開して入れる**
            //   （`SamlProviders/CmnEndpoints`）。
            string acsUrl = Config.OAuth2ClientEndpointsRootURI + Config.Saml2ResponseEndpoint;

            string requestId = this.LoadTestSamlRequestId();

            SAML2VerifyResult result = Sts.SelfTestClient.VerifySaml2Response(
                samlResponse, queryString, relayState,
                state_InSessionOrCookie, isGet, acsUrl, requestId);

            ViewBag.Verdict = SamlProviders.CmnSaml2Response.VerdictOf(result);
            ViewBag.Reason = SamlProviders.CmnSaml2Response.ReasonOf(result, CmnServerParams.IssuerId, acsUrl, requestId);
            ViewBag.Binding = SamlProviders.CmnSaml2Response.BindingOf(result);
            ViewBag.SigAlg = result.SigAlg;
            ViewBag.RelayState = result.RelayState;
            ViewBag.RelayStateMatched = result.RelayStateMatched;
            ViewBag.AudienceMatched = result.AudienceMatched;
            ViewBag.RecipientMatched = result.RecipientMatched;
            ViewBag.InResponseToMatched = result.InResponseToMatched;
            ViewBag.NotExpired = result.NotExpired;
            ViewBag.SignatureVerified = result.SignatureVerified;
            ViewBag.IssuerMatched = result.IssuerMatched;
            ViewBag.NameId = result.NameId;
            ViewBag.Issuer = result.Issuer;
            ViewBag.Audience = result.Audience;
            ViewBag.InResponseTo = result.InResponseTo;
            ViewBag.Recipient = result.Recipient;
            ViewBag.NotOnOrAfter = SamlProviders.CmnSaml2Response.NotOnOrAfterOf(result);
            ViewBag.StatusCode = result.StatusCode?.ToString() ?? "";
            ViewBag.NameIdFormat = result.NameIdFormat?.ToString() ?? "";
            ViewBag.AuthnContextClassRef = result.AuthnContextClassRef?.ToString() ?? "";
            ViewBag.ResponseXml = SamlProviders.CmnSaml2Response.FormatXml(result.Response);

            //  **アサーションの属性**（#286 の段階 4）。**目視のため**（判定には使わない）。
            ViewBag.Attributes = result.Attributes;
            ViewBag.AttrEmail = SAML2Attributes.GetEmail(result.Attributes);
            ViewBag.AttrUserName = SAML2Attributes.GetUserName(result.Attributes);
            ViewBag.AttrEmailVerified = SAML2Attributes.GetEmailVerified(result.Attributes);

            return View("Saml2Response");
        }

        /// <summary>送った AuthnRequest の ID を取り出す（#276）</summary>
        /// <returns>ID（無ければ空）</returns>
        /// <remarks>
        /// **`LoadRequestParameters` と同じ流儀**（Session → Cookie、読んだら消す）。
        /// **あちらは 5 つの out を持っており、OAuth2 側からも呼ばれる**ので、
        /// **SAML 専用のこれを別に立てている**（引数を増やさないため）。
        /// </remarks>
        private string LoadTestSamlRequestId()
        {
            string id = (string)Session[Const.TestSamlRequestId];

            if (!string.IsNullOrEmpty(id))
            {
                Session.Remove(Const.TestSamlRequestId);
            }
            else
            {
                id = Request.Cookies[Const.TestSamlRequestId]?.Value;

                if (!string.IsNullOrEmpty(id))
                {
                    Response.Cookies[Const.TestSamlRequestId].Value = "";
                }
            }

            return id ?? "";
        }

        #endregion
    }
}
