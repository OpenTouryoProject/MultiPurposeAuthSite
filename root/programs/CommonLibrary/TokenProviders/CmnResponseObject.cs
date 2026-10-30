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
//*  2026/10/15  玄人 幸道         ヘッダにjkuを入れないようにした（#302）
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
        /// <remarks>
        /// **組み立ては Open棟梁 の `ResponseObject.Create`**（iss / aud / exp を足して署名する。#294）。
        /// **exp は RFC 7519 の NumericDate（JSON の数値）**で入る（#201）。
        ///
        /// **`clientId` が空の経路は、ここに残す**（**iss / aud / exp を入れずに署名する**）。
        /// **`ResponseObject.Create` は aud を必須にしている**（空なら `ArgumentNullException`）ので、
        /// **呼ぶ前に分ける**（Open棟梁 #634 の補足 3-3）。
        /// </remarks>
        public static string Create(
            Dictionary<string, string> responseDictionary,
            string clientId, DateTimeOffset? expiresUtc)
        {
            JWS jws = CmnResponseObject.CreateJws();

            if (string.IsNullOrEmpty(clientId))
            {
                return jws.Create(JsonConvert.SerializeObject(responseDictionary));
            }

            return ResponseObject.Create(
                responseDictionary, jws, CmnServerParams.IssuerId, clientId, expiresUtc.Value);
        }

        /// <summary>署名に使う JWS（RS256。kid は、その鍵の JWK の kid）</summary>
        /// <returns>JWS</returns>
        /// <remarks>**`jku` は入れない**（#302）。**鍵は `kid` で引く。**</remarks>
        private static JWS CreateJws()
        {
            // 秘密鍵
            string pfxFilePath = CmnServerParams.RsaPfxFilePath;
            string pfxPassword = CmnServerParams.RsaPfxPassword;

            // JWS(RS256)
            JWS_RS256_X509 jwsRS256 = new JWS_RS256_X509(pfxFilePath, pfxPassword);

            // 鍵変換
            RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);

            // JWSHeaderのセット
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    rpkc.X509PfxToJwk(pfxFilePath, pfxPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];

            return jwsRS256;
        }

        // VerifyはClient側のみなので、
        // .Framework.Authentication側に実装。
    }
}
