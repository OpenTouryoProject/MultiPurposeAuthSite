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
//* クラス名        ：Fido2ServerController
//* クラス日本語名  ：Fido2ServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/05  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.FIDO;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Objects;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Framework.Presentation;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>Fido2ServerのApiController（ライブラリ）</summary>
    [EnableCors(
        // リソースへのアクセスを許可されている発生元
        origins: "*",
        // リソースによってサポートされているヘッダー
        headers: "*",
        // リソースによってサポートされているメソッド
        methods: "*",
        // 
        SupportsCredentials = true)]
    public class Fido2ServerController : ApiController
    {
        /// <summary>origin</summary>
        private string _origin = new Func<string>(() =>
        {
            string temp = Config.OAuth2AuthorizationServerEndpointsRootURI;
            Uri uri = new Uri(temp);
            temp = temp.Substring(0, temp.IndexOf(uri.Authority) + uri.Authority.Length);
            return temp;
        })();

        /// <summary>FormatException</summary>
        /// <param name="e">Exception</param>
        /// <returns>string</returns>
        private string FormatException(Exception e)
        {
            return string.Format(
                "{0}{1}",
                e.Message,
                e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }

        //[HttpGet]
        //[Route("Fido2/CredentialCreationOptions")]
        //public Dictionary<string, string> Index()
        //{
        //    return new Dictionary<string, string>()
        //    {
        //        { "txt", "notepad.exe"},
        //        { "bmp", "paint.exe"},
        //        { "dib", "paint.exe"},
        //        { "rtf", "wordpad.exe"}
        //    };
        //}

        #region 登録フロー

        /// <summary>
        /// CredentialCreationOptions
        /// </summary>
        /// <param name="requestJSON">JObject</param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        [Route("Fido2/CredentialCreationOptions")]
        public HttpResponseMessage CredentialCreationOptions(JObject requestJSON)
        {
            string username = (string)requestJSON["username"];
            string displayName = (string)requestJSON["displayName"];
            bool residentKey = bool.Parse((string)requestJSON["authenticatorSelection"]["residentKey"]);
            string authenticatorAttachment = (string)requestJSON["authenticatorSelection"]["authenticatorAttachment"];
            string userVerification = (string)requestJSON["authenticatorSelection"]["userVerification"];
            string attestation = (string)requestJSON["attestation"];

            CredentialCreateOptions options = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper(this._origin);

                options = webAuthnHelper.CredentialCreationOptions(
                    username, attestation, authenticatorAttachment, residentKey, userVerification);

                // Sessionに保存
                HttpContext.Current.Session["fido2.CredentialCreateOptions"] = options.ToJson();
            }
            catch (Exception e)
            {
                options = new CredentialCreateOptions
                {
                    Status = "error",
                    ErrorMessage = FormatException(e)
                };
            }

            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                        options,
                        new JsonSerializerSettings
                        {
                            Formatting = Formatting.None,
                            ContractResolver = new CamelCasePropertyNamesContractResolver()
                        })
            };
        }

        /// <summary>
        /// AuthenticatorAttestation
        /// </summary>
        /// <param name="attestationResponse">AuthenticatorAttestationRawResponse</param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        [Route("Fido2/AuthenticatorAttestation")]
        public async Task<HttpResponseMessage> AuthenticatorAttestation(
            AuthenticatorAttestationRawResponse attestationResponse)
        {
            CredentialMakeResult result = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper(this._origin);

                // Sessionから復元
                CredentialCreateOptions options = CredentialCreateOptions.FromJson(
                    (string)HttpContext.Current.Session["fido2.CredentialCreateOptions"]);

                result = await webAuthnHelper.AuthenticatorAttestation(attestationResponse, options);
            }
            catch (Exception e)
            {
                result = new CredentialMakeResult
                {
                    Status = "error",
                    ErrorMessage = FormatException(e)
                };
            }

            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                    result,
                    new JsonSerializerSettings
                    {
                        Formatting = Formatting.None,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        #endregion

        #region 認証フロー

        /// <summary>
        /// CredentialGetOptions
        /// </summary>
        /// <param name="requestJSON">JObject</param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        [Route("Fido2/CredentialGetOptions")]
        public HttpResponseMessage CredentialGetOptions(JObject requestJSON)
        {
            AssertionOptions options = null;

            string username = (string)requestJSON["username"];
            string userVerification = (string)requestJSON["userVerification"];
            // ※ userVerification を使ってない。

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper(this._origin);
                options = webAuthnHelper.CredentialGetOptions(username);

                // Sessionに保存
                HttpContext.Current.Session["fido2.AssertionOptions"] = options.ToJson();
            }
            catch (Exception e)
            {
                options = new AssertionOptions
                {
                    Status = "error",
                    ErrorMessage = FormatException(e)
                };
            }

            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                    options,
                    new JsonSerializerSettings
                    {
                        Formatting = Formatting.None,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        /// <summary>
        /// AuthenticatorAttestation
        /// </summary>
        /// <param name="attestationResponse">AuthenticatorAttestationRawResponse</param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        [Route("Fido2/AuthenticatorAssertion")]
        public async Task<HttpResponseMessage> AuthenticatorAssertion(
            AuthenticatorAssertionRawResponse clientResponse)
        {
            AssertionVerificationResult result = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper(this._origin);

                // Sessionから復元
                AssertionOptions options = AssertionOptions.FromJson(
                    (string)HttpContext.Current.Session["fido2.AssertionOptions"]);

                result = await webAuthnHelper.AuthenticatorAssertion(clientResponse, options);
            }
            catch (Exception e)
            {
                result = new AssertionVerificationResult
                {
                    Status = "error",
                    ErrorMessage = FormatException(e)
                };
            }

            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                    result,
                    new JsonSerializerSettings
                    {
                        Formatting = Formatting.None,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        #endregion
    }
}