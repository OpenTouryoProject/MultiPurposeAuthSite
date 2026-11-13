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
//*  2026/10/31  玄人 幸道         clientId を必須にし、iss・aud・exp の無い応答を作らないようにした（JARM 2.1。#317）
//*  2026/10/31  玄人 幸道         TokenProviders から Extensions/Sts へ移した（配置の見直し。#294）
//*  2026/11/13  玄人 幸道         JARM の署名を、登録の authorization_signed_response_alg（既定は RS256）と SigningKeys の鍵で行う（#370）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;
using MultiPurposeAuthSite.TokenProviders;


namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>CmnResponseObject(JARM)</summary>
    public class CmnResponseObject
    {
        /// <summary>Create (CmnAccessTokenを踏襲)</summary>
        /// <param name="responseDictionary">Dictionary(string, string)</param>
        /// <param name="clientId">string</param>
        /// <param name="expiresUtc">DateTimeOffset（exp）</param>
        /// <returns>response(JARM)</returns>
        /// <remarks>
        /// **組み立ては Open棟梁 の `ResponseObject.Create`**（iss / aud / exp を足して署名する。#294）。
        /// **exp は RFC 7519 の NumericDate（JSON の数値）**で入る（#201）。
        ///
        /// **JARM 2.1 : JWT は、成功でもエラーでも常に `iss` / `aud` / `exp` を持つ**（#317）。
        /// **`clientId` は必須**（空なら `ArgumentNullException`）。
        /// 以前は空のとき **iss / aud / exp を入れずに署名していた**が、
        /// **JARM 2.4 どおりに検証する RP（OpenTouryo#644 の後の Open棟梁 など）は、それを断る。**
        /// **呼び出し側の漏れを、実行時に気付けるようにする**（黙って欠けた JWT を返さない）。
        ///
        /// **呼び出しは `AccountController.CreateAuthorizationResponse` の 1 か所**（両版。#294）で、
        /// **照合済みの `redirect_uri` へ返すときだけ**通る（`client_id` は確かめ済み）。
        /// </remarks>
        public static string Create(
            Dictionary<string, string> responseDictionary,
            string clientId, DateTimeOffset expiresUtc)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentNullException(nameof(clientId),
                    "JARM requires aud (client_id). JARM 2.1");
            }

            return ResponseObject.Create(
                responseDictionary, CmnResponseObject.CreateJws(clientId),
                CmnServerParams.IssuerId, clientId, expiresUtc);
        }

        /// <summary>署名に使う JWS（alg は登録の authorization_signed_response_alg。kid は、その鍵の JWK の kid）</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **alg は登録の `authorization_signed_response_alg`**（JARM §3。#370）。
        /// **登録が無ければ RS256**（JARM §3。FAPI の登録も。`Helper.GetAuthorizationSignedResponseAlg`）。
        /// **以前は RS256 に固定だった**（FAPI 2.0 Message Signing は RS256 を認めない）。
        /// **鍵は `SigningKeys` の表が持つ**（id_token と同じ鍵。`jwks_uri` に載る）。
        /// **`jku` は入れない**（#302）。**鍵は `kid` で引く。**
        /// **扱わない alg の登録（構成ファイルの誤り）は、成功の応答なら入口（`CmnEndpoints.CheckClientMode`）で断ってある。**
        /// **ただし、要求の検証で断るエラー応答は、その確かめより前に JARM で返る**ので、ここに来うる。
        /// **そのときは `RS256`（JARM §3 の既定）で署名し、記録に残す**（例外にすると 500 になる。別モデルのレビューの指摘）。
        /// </remarks>
        private static JWS CreateJws(string clientId)
        {
            string alg = Helper.GetInstance().GetAuthorizationSignedResponseAlg(clientId);
            SigningKeys.Entry key = SigningKeys.Of(alg);

            if (key == null)
            {
                Logging.MyOperationTrace(string.Format(
                    "The registered authorization_signed_response_alg is not supported. RS256 is used. ({0})",
                    alg)); // 構成ファイルの登録値（外から来る値ではない）

                key = SigningKeys.Of(JwtConst.RS256);
            }

            JWS jws = key.CreateJwsFromPfx();
            string kid = (string)key.JwkFromPfx()[JwtConst.kid];

            if (key.IsRsa)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
            }

            return jws;
        }

        // VerifyはClient側のみなので、
        // .Framework.Authentication側に実装。
    }
}
