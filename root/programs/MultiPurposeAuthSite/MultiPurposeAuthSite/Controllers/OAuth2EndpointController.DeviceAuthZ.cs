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
//* クラス日本語名  ：OAuth2EndpointController の デバイス認可（/device_authz）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         client_assertion（private_key_jwt）も受ける・expires_in / interval を数値で返す（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（デバイス認可（/device_authz））</summary>
    public partial class OAuth2EndpointController
    {
        #region /device

        /// <summary>
        /// Device AuthZの認可リクエストを受信
        /// POST: /device_authz
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>成功は 200、エラーは 400 / 401（RFC 8628 3.1 / RFC 6749 5.2）（#196）</returns>
        [HttpPost]
        public async Task<IHttpActionResult> DeviceAuthZAuthorize(FormDataCollection formData)
        {
            // **資格情報・属性を返すので、キャッシュに残さない**（#218）。
            //   RFC は MUST としていないが、困る性質は /token と同じ。
            this.SetNoStore();

            string err = "";
            string errDescription = "";

            if (formData != null)
            {
                // client_id, client_secret

                // client_secret_basic
                if (!Token.CmnEndpoints.GetBasicCredentials(
                    HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                    out string client_id, out string client_secret))
                {
                    // client_secret_post
                    client_id = formData[OAuth2AndOIDCConst.client_id];
                    client_secret = formData[OAuth2AndOIDCConst.client_secret];
                }

                // クライアント認証（RFC 8628 3.1）（#193）
                // パブリック クライアントは、client_idの確認のみ。
                X509Certificate2 x509 = Request.GetClientCertificate();
                //  **private_key_jwt も受ける**（#294。/token・/par と同じ取り出し方）。
                //    **client_id は、認証できたクライアント**（アサーションのときは `iss`）を使う。
                string clientAssertion = OAuth2AndOIDCSpec.GetClientAssertion(
                    formData[OAuth2AndOIDCConst.client_assertion],
                    formData[OAuth2AndOIDCConst.client_assertion_type],
                    formData[OAuth2AndOIDCConst.assertion]);

                if (!Token.CmnEndpoints.DeviceAuthZClientAuthentication(
                    client_id, client_secret, clientAssertion, ref x509, out client_id))
                {
                    // RFC 6749 5.2 : invalid_client は 401（#196）
                    return this.OAuth2Error(new Dictionary<string, string>()
                    {
                        {OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client},
                        {OAuth2AndOIDCConst.error_description, "Invalid credential."}
                    }, Const.EndpointDeviceAuthZ);
                }

                // **登録種別で、このグラントを許すか**（normal と device だけ）。
                //   利用者が user_code を承認した後で失敗させないよう、開始の時点で弾く。
                //   トークン発行（CmnEndpoints.GrantDeviceAuthZ）でも同じ判定をしている。
                if (!Token.CmnEndpoints.IsDeviceAuthZAllowed(client_id))
                {
                    return this.OAuth2Error(new Dictionary<string, string>()
                    {
                        {OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client},
                        {OAuth2AndOIDCConst.error_description,
                            "This client is not allowed to use the device authorization grant."}
                    }, Const.EndpointDeviceAuthZ);
                }

                // scopeパラメタ
                string scope = formData[OAuth2AndOIDCConst.scope];

                // codeの生成は先送り
                Dictionary<string, string> tempDic = new Dictionary<string, string>()
                {
                    {OAuth2AndOIDCConst.client_id, client_id},
                    {OAuth2AndOIDCConst.scope, scope}
                };

                //string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(...);
                string tempData = JsonConvert.SerializeObject(tempDic);

                // authReqExp
                int requested_expiry = Config.DeviceAuthZExpireTimeSpanFromSeconds;
                long authReqExp = DateTimeOffset.Now.AddSeconds(
                    Config.DeviceAuthZExpireTimeSpanFromSeconds).ToUnixTimeSeconds();

                // 検証用エンドポイントの絶対URI
                string verificationUri =
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZVerifyEndpoint;

                // DeviceAuthZ情報をストア
                string deviceCode;
                string userCode;
                Sts.DeviceAuthZProvider.Create(authReqExp, tempData, out deviceCode, out userCode);

                // ココまでの結果をレスポンス（RFC 8628 3.2 : 200）
                //   **expires_in / interval は JSON の数値**（RFC 8628 §3.2。#294。以前は文字列だった）。
                return this.Ok(new Dictionary<string, object>()
                {
                    {OAuth2AndOIDCConst.device_code, deviceCode},
                    {OAuth2AndOIDCConst.user_code, userCode},
                    // RFC 8628 3.2 : ユーザが辿れるURIを返す（#193）。
                    {OAuth2AndOIDCConst.verification_uri, verificationUri},
                    {OAuth2AndOIDCConst.verification_uri_complete, verificationUri + "?user_code=" + userCode},
                    {OAuth2AndOIDCConst.expires_in, requested_expiry},
                    {OAuth2AndOIDCConst.PollingInterval, Config.DeviceAuthZPollingIntervalSeconds}
                });
            }
            else
            {
                // フォームデータ無し（#193）
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "Form data is null.";
            }

            // エラー（RFC 6749 5.2 : 400）（#196）
            return this.OAuth2Error(new Dictionary<string, string>()
            {
                {OAuth2AndOIDCConst.error, err},
                {OAuth2AndOIDCConst.error_description, errDescription}
            }, Const.EndpointDeviceAuthZ);
        }

        // DeviceAuthZResponse画面 → HomeControllerに。
        // DeviceAuthZVerify画面 → AccountControllerに。

        #endregion
    }
}