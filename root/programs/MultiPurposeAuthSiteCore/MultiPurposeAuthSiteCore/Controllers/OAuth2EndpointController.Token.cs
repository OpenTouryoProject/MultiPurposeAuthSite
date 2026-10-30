//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：OAuth2EndpointController
//* クラス日本語名  ：OAuth2EndpointController の トークン（/token）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         未知の grant_type を unsupported_grant_type、無いときを invalid_request で返す・grant_type を大文字小文字まで比べる・device_code で client_assertion も渡す（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;

using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cors;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（トークン（/token））</summary>
    public partial class OAuth2EndpointController
    {
        #region /token

        /// <summary>
        /// Tokenエンドポイント
        /// POST: /token
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>成功は 200、エラーは 400 / 401（RFC 6749 5.1 / 5.2）（#196）</returns>
        [HttpPost]
        [EnableCors(Const.CorsPolicyBrowserApi)]   // SPA（public クライアント ＋ PKCE）が叩く（#265）
        public IActionResult OAuth2Token(IFormCollection formData)
        {
            // **トークンを含む応答は、キャッシュに残してはならない**（RFC 6749 5.1 / 5.2 の MUST）（#218）。
            //   成功・エラーのどちらの経路でも返すので、入口で付ける。
            this.SetNoStore();

            Dictionary<string, string> ret = null;
            // grant_typeが未知・未指定、フォームデータ無しの経路でも使うので初期化する（#185）。
            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData != null)
            {
                #region credentials

                // client_id, client_secret

                // client_secret_basic
                if (!Token.CmnEndpoints.GetBasicCredentials(
                MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string client_id, out string client_secret))
                {
                    // client_secret_post
                    client_id = formData[OAuth2AndOIDCConst.client_id];
                    client_secret = formData[OAuth2AndOIDCConst.client_secret];
                }

                // **JWT アサーションは 2 種類ある。混ぜないこと（#238）。**
                //
                //   client_assertion（RFC 7523 §2.2）: **クライアント認証**。client_secret の代わり。
                //   assertion        （RFC 7523 §2.1）: **グラントそのもの**。誰の認可かを表す。
                //
                //   両方を同時に送れる（グラントは assertion、認証は client_assertion）。
                //   **この実装は従来どちらも assertion で受けていた**ので、
                //   client_assertion を優先しつつ、無ければ assertion も読む（後方互換）。

                // クライアント認証のアサーション
                string clientAssertion = OAuth2AndOIDCSpec.GetClientAssertion(
                    formData[OAuth2AndOIDCConst.client_assertion],
                    formData[OAuth2AndOIDCConst.client_assertion_type],
                    formData[OAuth2AndOIDCConst.assertion]);

                // グラントのアサーション（grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer）
                string assertion = formData[OAuth2AndOIDCConst.assertion];

                // クライアント証明書

                // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;
                //if (x509 != null)
                //{
                //    //string thumbprint = x509.Thumbprint;
                //    //string subject = x509.Subject;
                //    //string subjectName = x509.SubjectName.Name;                     // Subjectと同じ
                //    //string algFriendlyName = x509.SignatureAlgorithm.FriendlyName;　// sha256RSA, etc.
                //}

                #endregion


                #region DPoP（#311 の段階 1）

                //  **DPoP の証明**（RFC 9449 §4）。
                //    **ヘッダで来る**（本文のパラメタではない）。
                //    **無ければ従来どおり bearer** で発行する（既定の挙動を変えない）。
                //    **検証は `CmnEndpoints` 側**（グラントの入口で、code を使う前に見る）。
                string dPoPProof = MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_DPoP];

                #endregion

                #region grant_type

                string grant_type = formData[OAuth2AndOIDCConst.grant_type];
                if (!string.IsNullOrEmpty(grant_type))
                {
                    string scope = "";
                    //  **大文字小文字まで比べる**（#294。grant_type の値は大文字小文字を区別する。以前は ToLower していた）。
                    switch (grant_type)
                    {
                        case OAuth2AndOIDCConst.AuthorizationCodeGrantType:
                            string code = formData[OAuth2AndOIDCConst.code];
                            string redirect_uri = formData[OAuth2AndOIDCConst.redirect_uri];
                            string code_verifier = formData[OAuth2AndOIDCConst.code_verifier];

                            if (Token.CmnEndpoints.GrantAuthorizationCodeCredentials(
                                grant_type, client_id, client_secret, clientAssertion, x509,
                                dPoPProof, code, code_verifier, redirect_uri, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.RefreshTokenGrantType:
                            string refresh_token = formData[OAuth2AndOIDCConst.RefreshToken];
                            if (Token.CmnEndpoints.GrantRefreshTokenCredentials(
                                grant_type, client_id, client_secret, clientAssertion,
                                x509, dPoPProof, refresh_token, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType:
                            string username = formData[Const.ParamUsername];
                            string password = formData[Const.ParamPassword];
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantResourceOwnerCredentials(
                                grant_type, client_id, client_secret, clientAssertion, x509,
                                dPoPProof, username, password, scope, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.ClientCredentialsGrantType:
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantClientCredentials(
                                grant_type, client_id, client_secret, clientAssertion,
                                x509, dPoPProof, scope, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType:
                            // トークン要求の scope を渡す（RFC 7521 4.1 / RFC 7523 2.1）（#218）
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantJwtBearerTokenCredentials(
                            grant_type, assertion, x509, dPoPProof, scope, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.DeviceAuthZGrantType:
                            string device_code = formData[OAuth2AndOIDCConst.device_code];
                            //  **private_key_jwt も受ける**（#294）。
                            if (Token.CmnEndpoints.GrantDeviceAuthZ(grant_type,
                                client_id, client_secret, clientAssertion, x509, dPoPProof, device_code,
                                out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.CibaGrantType:
                            string auth_req_id = formData[OAuth2AndOIDCConst.auth_req_id];
                            if (Token.CmnEndpoints.GrantCiba(grant_type,
                                client_id, client_secret, clientAssertion, x509,
                                dPoPProof, auth_req_id, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        default:
                            //  **unsupported_grant_type**（RFC 6749 §5.2。#294。以前は invalid_grant だった）。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid grant_type.");
                            break;
                    }
                }
                else
                {
                    //  **invalid_request**（RFC 6749 §5.2 : 必須のパラメタが無い。#294。以前は invalid_grant だった）。
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "grant_type is null or empty.");
                }

                #endregion
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return this.OAuth2Error(err, Const.EndpointToken); // 失敗（RFC 6749 5.2 : 400 / 401）（#196）
        }

        #endregion

        #region DPoP の照合（#311 の段階 2）

        /// <summary>DPoP に縛られたトークンなら、証明を照合する（#311 の段階 2）</summary>
        /// <param name="identity">検証済みの ClaimsIdentity</param>
        /// <param name="accessToken">提示された access_token</param>
        /// <param name="isDPoP">**`DPoP` スキームで来たか**</param>
        /// <param name="dpopError">out : error（**`use_dpop_nonce` のときだけ**。#311 の段階 4）</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **縛っていないトークン（`cnf.jkt` 無し）は、これまでどおり通る**
        /// （**DPoP を知らないクライアントに影響しない**）。
        ///
        /// **`Bearer` スキームで来た要求には、証明を渡さない** ＝
        /// **縛られたトークンなら断る**（RFC 9449 §7.1）。
        /// **縛りを「使う側の出し方」で外せてはいけない。**
        ///
        /// **`htu` は、要求のパスから設定の URL を引く**（`CmnDPoP.EndpointUriOf`。
        /// **`Host` ヘッダは見ない**）。**`htm` は、実際のメソッド**である。
        /// </remarks>
        private bool VerifyDPoP(
            ClaimsIdentity identity, string accessToken, bool isDPoP, out string dpopError)
        {
            return Token.CmnAccessToken.VerifyDPoPBinding(
                identity, accessToken,
                //  **core のヘッダは `StringValues`（構造体）**なので、**文字列にしてから渡す**
                //    （`null` との三項演算子が、そのままでは通らない）。
                isDPoP ? MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_DPoP].ToString() : null,
                MyHttpContext.Current.Request.Method,
                Token.CmnDPoP.EndpointUriOf(MyHttpContext.Current.Request.Path),
                out dpopError);
        }

        #endregion
    }
}