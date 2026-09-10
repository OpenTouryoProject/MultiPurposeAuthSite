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
//* クラス名        ：CmnResponseObject
//* クラス日本語名  ：CmnResponseObject(JARM)
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/06/26  西野 大介         新規
//*  2026/09/11  玄人 幸道         exp を NumericDate（JSON の数値）で出すよう修正（#201）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;


namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnResponseObject(JARM)</summary>
    public class CmnResponseObject
    {
        /// <summary>Create (CmnAccessTokenを踏襲)</summary>
        /// <param name="responseDictionary">Dictionary(string, string)</param>
        /// <param name="clientId">string</param>
        /// <param name="expiresUtc">DateTimeOffset</param>
        /// <returns>response(JARM)</returns>
        public static string Create(
            Dictionary<string, string> responseDictionary,
            string clientId, DateTimeOffset? expiresUtc)
        {
            // 応答パラメタ（code / state など）は文字列のまま、
            // exp だけは RFC 7519 の NumericDate（JSON の数値）で入れる（#201）。
            // 引数は Dictionary<string, string> のまま、ここで object の辞書に写す。
            // こうすれば、両アプリの呼び出し側（30 箇所余り）を変えずに済む。
            Dictionary<string, object> payload = new Dictionary<string, object>();

            foreach (KeyValuePair<string, string> item in responseDictionary)
            {
                payload[item.Key] = item.Value;
            }

            if (string.IsNullOrEmpty(clientId))
            {
                // error
            }
            else
            {
                payload[OAuth2AndOIDCConst.iss] = Config.IssuerId;
                payload[OAuth2AndOIDCConst.aud] = clientId;

                // 文字列にしない（#184 と同じ）。
                // 検証側（Open棟梁 の ResponseObject.Verify）は (string) で読むが、
                // JSON の数値も文字列として読めるので、変更は要らない。
                payload[OAuth2AndOIDCConst.exp] = expiresUtc.Value.ToUnixTimeSeconds();
            }

            // 秘密鍵
            string pfxFilePath = Config.RsaPfxFilePath;
            string pfxPassword = Config.RsaPfxPassword;

            // JWS(RS256)
            JWS_RS256_X509 jwsRS256 = new JWS_RS256_X509(pfxFilePath, pfxPassword);

            // 鍵変換
            RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);

            // JWSHeaderのセット
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    rpkc.X509PfxToJwk(Config.RsaPfxFilePath, Config.RsaPfxPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            // Create
            return jwsRS256.Create(
                JsonConvert.SerializeObject(payload));
        }

        // VerifyはClient側のみなので、
        // .Framework.Authentication側に実装。
    }
}
