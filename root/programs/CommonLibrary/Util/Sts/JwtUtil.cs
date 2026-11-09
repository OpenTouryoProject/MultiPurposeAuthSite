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
//* クラス名        ：JwtUtil
//* クラス日本語名  ：登録された公開鍵（JWK）と、JWT のクレームの読み出し（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/01  玄人 幸道         新規（TokenProviders/CmnEndpoints.RequestObject.cs から移した。#321）
//*  2026/11/06  玄人 幸道         日付の形の文字列を日付に変えずに読む TryReadPayloadAsIs・TryParseObjectAsIs を足した（#337）
//**********************************************************************************

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>登録された公開鍵（JWK）と、JWT のクレームの読み出し</summary>
    /// <remarks>
    /// **STS のあちこちが使う部品**（クライアント認証・トークン エンドポイント・CIBA・Request Object・動的登録）。
    /// **以前は `CmnEndpoints`（`CmnEndpoints.RequestObject.cs`）に在った**（#321 で、拡張仕様の分を
    /// `Extensions/Sts` へ切り出したときに、両方から使うここへ出した）。
    /// </remarks>
    public static class JwtUtil
    {
        #region staticメソッド

        #region JWT の読み取り（#241）

        /// <summary>公開鍵（JWK）を、登録する形（Base64URL）にする（#307 の段階 3）</summary>
        /// <param name="jwk">JWK（1 本。JWK Set ではない）</param>
        /// <returns>登録する値（Base64URL の JWK）</returns>
        /// <remarks>
        /// **`DecodeRegisteredJwk` の逆である。** **形の知識を 1 か所に置くため、ここに並べた。**
        /// **列が持つのは「JWK 1 本を Base64URL にしたもの」**で、**JWK Set ではない**
        /// （`jwk_rsa_publickey` / `jwk_ecdsa_publickey` の 2 列に分かれている）。
        /// **余白を入れない**（`Formatting.None`）。
        /// </remarks>
        public static string EncodeRegisteredJwk(JObject jwk)
        {
            if (jwk == null)
            {
                return "";
            }

            return CustomEncode.ToBase64UrlString(
                CustomEncode.StringToByte(
                    jwk.ToString(Formatting.None), CustomEncode.us_ascii));
        }

        /// <summary>登録された公開鍵（Base64URL の JWK）を復号する（無ければ空）</summary>
        /// <param name="base64UrlJwk">登録された値</param>
        /// <returns>JWK の JSON（無ければ空）</returns>
        /// <remarks>
        /// **未登録のクライアントでは空が返る**（#241）。
        /// 以前は空かどうかを確かめる前に復号しており、
        /// `FromBase64UrlString(null)` が NullReferenceException になって **HTTP 500** だった。
        /// </remarks>
        public static string DecodeRegisteredJwk(string base64UrlJwk)
        {
            if (string.IsNullOrEmpty(base64UrlJwk))
            {
                return "";
            }

            try
            {
                return CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(base64UrlJwk), CustomEncode.us_ascii);
            }
            catch
            {
                // 登録の値が壊れている（運用の誤り）。**要求の側の誤りと区別せず、認証失敗にする。**
                return "";
            }
        }

        /// <summary>JWT の payload から、文字列のクレームを取り出す（無い・文字列でなければ空）</summary>
        /// <param name="payload">payload（null 可）</param>
        /// <param name="name">クレーム名</param>
        /// <returns>値（無ければ空）</returns>
        /// <remarks>
        /// **`(string)payload[name]` は、値がオブジェクトや配列だと例外になる**（#294）。
        /// **外から来た JWT の `iss` などを読むときは、こちらを使う**（#241 と同じ方針）。
        /// </remarks>
        public static string StringClaimOf(JObject payload, string name)
        {
            JToken value = (payload == null) ? null : payload[name];

            return (value != null && value.Type == JTokenType.String) ? (string)value : "";
        }

        /// <summary>JWT の payload を、日付の形の文字列を日付に変えずに読む（読めなければ null。#337）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>payload（JWT でない・オブジェクトでなければ null）</returns>
        /// <remarks>
        /// **Open棟梁 の `JwtReader.TryReadPayload` は、既定の読み方**（`DateParseHandling.DateTime`）**で読む。**
        /// 日付の形の文字列（`binding_message` などが、たまたまそうなったとき）は Date になり、
        /// **`CmnJwtToken.TryGetStringClaim` で読めない**（OpenTouryo#662）。
        /// **クレームを文字列で取り出す呼び出し側は、こちらで読む。**
        /// **外から来た値なので、例外にしない**（#241 と同じ方針）。
        /// </remarks>
        public static JObject TryReadPayloadAsIs(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return null;
            }

            string[] segments = jwt.Split('.');

            if (segments.Length != 3 || string.IsNullOrEmpty(segments[1]))
            {
                return null;
            }

            try
            {
                return JwtUtil.TryParseObjectAsIs(CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(segments[1]), CustomEncode.UTF_8));
            }
            catch
            {
                // BASE64URL でない（外から来た値なので、例外にしない）。
                return null;
            }
        }

        /// <summary>JSON のオブジェクトを、日付の形の文字列を日付に変えずに読む（読めなければ null。#337）</summary>
        /// <param name="json">JSON（null 可）</param>
        /// <returns>JObject（JSON でない・オブジェクトでなければ null）</returns>
        /// <remarks>`TryReadPayloadAsIs` と同じ理由（`UserClaims` の #261 と同じ読み方）。</remarks>
        public static JObject TryParseObjectAsIs(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                return null;
            }

            try
            {
                return JsonConvert.DeserializeObject(json, new JsonSerializerSettings()
                {
                    DateParseHandling = DateParseHandling.None
                }) as JObject;
            }
            catch
            {
                // JSON でない
                return null;
            }
        }

        #endregion

        #endregion
    }
}
