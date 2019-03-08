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
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;

using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Extensions.FIDO;

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http;
using System.Net.Http.Formatting;

using Microsoft.Owin.Security;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Objects;
using Fido2NetLib.Development;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.Presentation;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>Fido2ServerのApiController（ライブラリ）</summary>
    [Authorize]
    public class Fido2ServerController : ApiController
    {
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

        #region 登録フロー

        /// <summary>
        /// CredentialCreationOptions
        /// </summary>
        /// <param name="username"string></param>
        /// <param name="attType">string</param>
        /// <param name="authType">string</param>
        /// <param name="requireResidentKey">string</param>
        /// <param name="userVerification">string</param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        public HttpResponseMessage CredentialCreationOptions(
            string username, string attType, string authType, bool requireResidentKey, string userVerification)
        {
            CredentialCreateOptions options = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper();
                options = webAuthnHelper.CredentialCreationOptions(
                    username, attType, authType, requireResidentKey, userVerification);
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
        public async Task<HttpResponseMessage> AuthenticatorAttestation(
            AuthenticatorAttestationRawResponse attestationResponse)
        {
            CredentialMakeResult result = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper();
                result = await webAuthnHelper.AuthenticatorAttestation(attestationResponse);
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
        /// <param name="username"string></param>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        public HttpResponseMessage CredentialGetOptions(string username)
        {
            AssertionOptions options = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper();
                options = webAuthnHelper.CredentialGetOptions(username);
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
        public async Task<HttpResponseMessage> AuthenticatorAssertion(
            AuthenticatorAssertionRawResponse clientResponse)
        {
            AssertionVerificationResult result = null;

            try
            {
                WebAuthnHelper webAuthnHelper = new WebAuthnHelper();
                result = await webAuthnHelper.AuthenticatorAssertion(clientResponse);
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