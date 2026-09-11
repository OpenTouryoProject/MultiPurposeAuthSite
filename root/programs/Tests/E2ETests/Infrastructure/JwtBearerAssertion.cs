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
//* クラス名        ：JwtBearerAssertion
//* クラス日本語名  ：JWT Bearer グラント（RFC 7523）の assertion を作る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//*  2026/09/11  玄人 幸道         署名を JwsSigner へ移す（RequestObjectBuilder の内部を使わない）
//**********************************************************************************

using System;
using System.Collections.Generic;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// JWT Bearer グラント（RFC 7523）の assertion を作る。
    ///
    /// 実装側の JwtAssertion は使わない（RequestObjectBuilder と同じ理由）。
    /// 署名も、RequestObjectBuilder と同じく JwsSigner で行う。
    /// </summary>
    public static class JwtBearerAssertion
    {
        /// <summary>grant_type</summary>
        public const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

        /// <summary>
        /// assertion を作る。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id（iss と sub に入れる）</param>
        /// <param name="overrides">上書きするクレーム（値が null なら、そのクレームを入れない）</param>
        /// <returns>JWS</returns>
        public static string Create(
            IdPClient client, string clientId, IDictionary<string, object> overrides = null)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                // RFC 7523 §3 : iss / sub / aud / exp は必須。
                // クライアント自身の資格として使うので、sub も client_id にする。
                { "iss", clientId },
                { "sub", clientId },

                // aud はトークン エンドポイント（§3 (3)）。
                { "aud", client.Target.Url("/token") },
                { "iat", now },
                { "exp", now + 300 },
                { "jti", Guid.NewGuid().ToString("N") },

                // この実装は scope を assertion の中から読む（トークン要求の scope は見ない）。
                { "scope", "profile email" }
            };

            if (overrides != null)
            {
                foreach (KeyValuePair<string, object> p in overrides)
                {
                    if (p.Value == null)
                    {
                        payload.Remove(p.Key);
                    }
                    else
                    {
                        payload[p.Key] = p.Value;
                    }
                }
            }

            return JwsSigner.SignRS256(client, payload);
        }
    }
}
