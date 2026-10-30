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
//* クラス日本語名  ：OAuth2EndpointController の メタデータ（/jwkcerts・discovery・/samlmetadata）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;

using System.Xml;
using System.Text;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cors;

using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（メタデータ（/jwkcerts・discovery・/samlmetadata））</summary>
    public partial class OAuth2EndpointController
    {
        #region /jwks.json

        /// <summary>
        /// JWK Set documentを返すWebAPI
        /// GET: /jwkcerts
        /// </summary>
        /// <returns>IActionResult</returns>
        /// <remarks>
        /// **覚えて返す**（#303。E-7）。**要求ごとにファイルを開いて読んでいた。**
        /// **内容は鍵を入れ替えるまで変わらない**ので、
        /// **ファイルの更新を見て、変わっていなければ覚えている分を返す**
        /// （Open棟梁 の `JwkSetDocument`）。
        ///
        /// **`Cache-Control` と `ETag` も付ける。**
        /// **`JwkSetCacheMaxAgeSeconds` が 0（既定）なら `no-store`** ＝ 従来どおり。
        /// **`If-None-Match` が一致すれば `304`**（本文を送らない）。
        /// </remarks>
        [HttpGet]
        [EnableCors(Const.CorsPolicyPublicDocs)]   // jwkcerts（公開情報。#265）
        public IActionResult JwksUri()
        {
            string body = JwkSetDocument.Get(out string etag);
            int maxAge = Config.JwkSetCacheMaxAgeSeconds;

            IHeaderDictionary headers = MyHttpContext.Current.Response.Headers;

            headers["ETag"] = etag;
            headers[Const.HeaderCacheControl] = (0 < maxAge)
                ? "public, max-age=" + maxAge.ToString() : Const.CacheControlNoStore;

            //  **同じものを持っている相手には、本文を送らない**（`304`）。
            //    **`If-None-Match` は、複数の ETag をカンマ区切りで送れる**（RFC 9110 §13.1.2）。
            string ifNoneMatch = MyHttpContext.Current.Request.Headers["If-None-Match"];

            if (!string.IsNullOrEmpty(ifNoneMatch))
            {
                foreach (string candidate in ifNoneMatch.Split(','))
                {
                    if (candidate.Trim() == etag)
                    {
                        return this.StatusCode(304);
                    }
                }
            }

            return this.Content(body, "application/json");
        }

        #endregion

        #region /.well-known/openid-configuration

        /// <summary>
        /// OpenID Provider Configurationを返すWebAPI
        /// GET: /.well-known/openid-configuration
        /// </summary>
        /// <returns>ContentResult</returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")] // ココは固定
        [EnableCors(Const.CorsPolicyPublicDocs)]   // .well-known/openid-configuration（公開情報。#265）
        public ContentResult OpenIDConfig()
        {
            // JsonSerializerSettingsを指定して、可読性の高いJSONを返す。
            return this.Content(
                JsonConvert.SerializeObject(
                    Token.CmnEndpoints.OpenIDConfig(),
                    new JsonSerializerSettings
                    {
                        Formatting = Newtonsoft.Json.Formatting.Indented,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
                    , "application/json");
        }

        #endregion

        #region /samlmetadata

        /// <summary>
        /// SamlMetadataを返すWebAPI
        /// GET: /samlmetadata
        /// </summary>
        /// <returns>ContentResult</returns>
        [HttpGet]
        [Route("samlmetadata")]  // ココは固定
        [EnableCors(Const.CorsPolicyPublicDocs)]   // samlmetadata（公開情報。#265）
        public ContentResult SamlMetadata()
        {
            //  **組み立ては `CmnSamlMetadata` に 1 か所だけ置いてある**（#292 の段階 3）。
            //    **両アプリに同文で在った**ので寄せた。
            //    **退役前の署名証明書も並べて広告する**（`PreviousSigningCerFilePaths`）。
            XmlDocument samlMetadata = SamlProviders.CmnSamlMetadata.CreateForThisDeployment();

            return this.Content(
                samlMetadata.XmlToString(
                    new XmlWriterSettings()
                    {
                        Encoding = Encoding.UTF8,
                        Indent = true
                    })
                    , "application/xml");
        }

        #endregion
    }
}