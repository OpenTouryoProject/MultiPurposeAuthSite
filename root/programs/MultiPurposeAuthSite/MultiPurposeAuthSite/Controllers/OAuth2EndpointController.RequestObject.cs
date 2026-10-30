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
//* クラス日本語名  ：OAuth2EndpointController の 要求オブジェクト（/par・/ros）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         /ros の summary を POST に直し、失敗を JSON のエラーで返す（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;

using System.IO;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;

using System.Web;
using System.Web.Http;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.Presentation;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（要求オブジェクト（/par・/ros））</summary>
    public partial class OAuth2EndpointController
    {
        #region /par (PAR : RFC 9126)

        /// <summary>
        /// 認可要求を先に預かり、request_uri を払い出す WebAPI（PAR。RFC 9126）（#229）
        /// POST: /par
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>成功は 201、エラーは 400 / 401</returns>
        /// <remarks>
        /// **独自の /ros とは別の口。** /ros は署名付き JWT を生の本文で受け、クライアント認証をしない
        /// （後方互換のため残している）。こちらは RFC のとおり、フォーム形式＋クライアント認証で受ける。
        /// </remarks>
        [HttpPost]
        public IHttpActionResult PushedAuthorizationRequest(FormDataCollection formData)
        {
            // **資格情報を受け取るので、キャッシュに残さない**（#218 と同じ理由）。
            this.SetNoStore();

            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData == null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");

                return this.OAuth2Error(err, Const.EndpointPar);
            }

            // client_secret_basic
            if (!Token.CmnEndpoints.GetBasicCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string client_id, out string client_secret))
            {
                // client_secret_post
                client_id = formData[OAuth2AndOIDCConst.client_id];
                client_secret = formData[OAuth2AndOIDCConst.client_secret];
            }

            // private_key_jwt / mTLS
            string assertion = OAuth2AndOIDCSpec.GetClientAssertion(
                formData[OAuth2AndOIDCConst.client_assertion],
                formData[OAuth2AndOIDCConst.client_assertion_type],
                formData[OAuth2AndOIDCConst.assertion]);
            X509Certificate2 x509 = Request.GetClientCertificate();

            NameValueCollection parameters = formData.ReadAsNameValueCollection();

            if (Token.CmnEndpoints.PushedAuthorizationRequest(
                client_id, client_secret, assertion, x509, parameters,
                out Dictionary<string, string> ret, out err))
            {
                // RFC 9126 §2.2 : 成功は 201
                return this.Content(HttpStatusCode.Created,
                    ret, new System.Net.Http.Formatting.JsonMediaTypeFormatter());
            }

            return this.OAuth2Error(err, Const.EndpointPar);
        }

        #endregion

        #region /ros (RequestObject)

        /// <summary>
        /// RequestObjectを登録するWebAPI
        /// POST: /ros
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        public HttpResponseMessage RequestObjectUri()
        {
            // RequestObjectを取り出す。
            string body = new StreamReader(HttpContext.Current.Request.InputStream).ReadToEnd();

            // **処理は CommonLibrary（#235）。** 両アプリに同じものを書いていた。
            //   ここは、本文を渡して応答を包むだけ。
            if (Token.CmnEndpoints.RegisterRequestObject(body, out Dictionary<string, object> ret))
            {
                // 成功
                return new HttpResponseMessage()
                {
                    Content = new JsonContent(JsonConvert.SerializeObject(
                        ret, Newtonsoft.Json.Formatting.None)),
                    StatusCode = HttpStatusCode.Created
                };
            }

            // 失敗
            //   **JSON のエラーで返す**（#294。以前は本文の無い 400 だった）。
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new JsonContent(JsonConvert.SerializeObject(new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.error, Const.InvalidRequestObject },
                    { OAuth2AndOIDCConst.error_description, "The request object is not accepted." }
                }))
            };
        }

        #endregion
    }
}