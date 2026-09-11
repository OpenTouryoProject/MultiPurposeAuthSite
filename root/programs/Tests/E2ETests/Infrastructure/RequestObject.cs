//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：RequestObjectBuilder
//* クラス日本語名  ：Request Object（JAR）の組み立て
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         署名鍵の読み込みを JwtBearerAssertion と共用（internal 化）
//*  2026/09/11  玄人 幸道         署名と BASE64URL を JwsSigner / Base64Url へ移す（JwtBearerAssertion と共用）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// Request Object（RFC 9101 / JAR）を組み立てて、PARエンドポイントに登録する。
    ///
    /// 実装側の Touryo.Infrastructure.Framework.Authentication.RequestObject は使わない。
    /// 同じコードで作って同じコードで検証すると、
    /// 「サーバが何を受け取っているか」を確かめたことにならないため、
    /// 署名は JwsSigner（System.Security.Cryptography だけで RS256 の JWS を作る）で行う。
    /// </summary>
    public static class RequestObjectBuilder
    {
        /// <summary>PARエンドポイントのパス</summary>
        public const string RegistrationPath = "/ros";

        /// <summary>request_uri の接頭辞</summary>
        public const string RequestUriPrefix = "urn:oauth:request:";

        /// <summary>
        /// Request Object（署名付きJWT）を作る。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id（iss にも入れる）</param>
        /// <param name="parameters">認可リクエストのパラメタ</param>
        /// <returns>JWS</returns>
        public static string Create(
            IdPClient client, string clientId, IDictionary<string, object> parameters)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>();

            // RFC 9101 4: iss は client_id、aud は認可サーバ。
            payload["iss"] = clientId;
            payload["aud"] = client.Target.BaseUrl;
            payload["client_id"] = clientId;

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            payload["iat"] = now;
            payload["nbf"] = now;
            payload["exp"] = now + 600;
            payload["jti"] = Guid.NewGuid().ToString("N");

            foreach (KeyValuePair<string, object> p in parameters)
            {
                if (p.Value != null)
                {
                    payload[p.Key] = p.Value;
                }
            }

            return JwsSigner.SignRS256(client, payload);
        }

        /// <summary>
        /// Request Object を PARエンドポイントへ登録し、request_uri を得る。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="requestObject">JWS</param>
        /// <returns>request_uri（失敗したら null）</returns>
        public static async Task<string> RegisterAsync(IdPClient client, string requestObject)
        {
            JsonResponse res = await client.PostTextAsync(RegistrationPath, requestObject);

            if (!res.IsJson)
            {
                return null;
            }

            return res.String("request_uri");
        }

        /// <summary>
        /// Request Object を作って登録し、認可リクエストのURLを返す。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="parameters">認可リクエストのパラメタ</param>
        /// <returns>認可リクエストのURL（失敗したら null）</returns>
        public static async Task<string> BuildAuthorizeUrlAsync(
            IdPClient client, string clientId, IDictionary<string, object> parameters)
        {
            string requestUri = await RegisterAsync(
                client, Create(client, clientId, parameters));

            if (string.IsNullOrEmpty(requestUri))
            {
                return null;
            }

            // request_uri は URL エンコードしない。
            // サーバは StringExtractor.GetParameterFromQueryString で
            // 生のクエリ文字列から取り出しており、デコードしないため、
            // エンコードすると urn:oauth:request: の接頭辞を外せず、見つからない。
            // アプリ同梱の自己テスト（HomeController）も、そのまま連結している。
            return client.Target.Url("/authorize?request_uri=" + requestUri);
        }
    }
}
