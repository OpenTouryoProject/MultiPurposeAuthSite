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
//*  2026/10/28  玄人 幸道         自己テストの ACS（AssertionConsumerService）を SelfTest.cs へ移した（#294）
//*  2026/10/29  玄人 幸道         Redirect Binding の署名の対象を、受け取ったままのクエリにした（#294）
//**********************************************************************************

/*
 * SAML2 の IdP としての口
 * （AuthnRequest の受け付けと検証、SAMLResponse の作成）
 * を担うAccountControllerの一部
 * （自己テストの SP 側の受け口（AssertionConsumerService）は、SelfTest.cs に在る）
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using Saml = MultiPurposeAuthSite.SamlProviders;

using System;
using System.Xml;
using System.Threading.Tasks;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の SAML2 の口**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        /// <summary>Saml2Request</summary>
        /// <param name="samlRequest">string</param>
        /// <param name="relayState">string</param>
        /// <param name="sigAlg">string</param>
        /// <returns>ActionResult</returns>
        public async Task<ActionResult> Saml2Request(string samlRequest, string relayState, string sigAlg)
        {
            bool verified = false;

            string queryString = "";

            XmlDocument samlRequest2 = null;
            XmlNamespaceManager samlNsMgr = null;

            string iss = "";
            string id = "";

            // Cookie認証チケットからClaimsPrincipalを取得しておく。
            AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
            ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

            // ClaimsIdentityを生成
            ClaimsIdentity identity = new ClaimsIdentity(principal.Claims,
                 OAuth2AndOIDCConst.Bearer, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

            SAML2Enum.StatusCode statusCode = SAML2Enum.StatusCode.Success;

            try
            {
                if (Request.Method.ToLower() == "get")
                {
                    // DecodeRedirect
                    //   **署名の対象は、受け取ったままのクエリ**（#294。SAML Bindings 3.4.4.1）。
                    //   以前は `GetEncodedUrl()`（組み直した URL）から取っていたので、
                    //   SP の符号化（`%2f` / `%2F` など）と違うと、署名の検証に失敗し得た（net48 版は RawUrl）。
                    queryString = (Request.QueryString.Value ?? "").TrimStart('?');

                    // VerifySamlRequest（展開と読み込みも行う）
                    verified = Saml.CmnEndpoints.VerifySamlRequest(
                        queryString, "", out iss, out id, out samlRequest2);
                }
                else if (Request.Method.ToLower() == "post")
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
        /// **`null` を POST 側に落とすと、`action` も `SAMLResponse` も空の
        /// 自動送信フォームが返る**ので、3 通りに分ける。
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
    }
}
