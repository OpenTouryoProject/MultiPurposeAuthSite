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
//* クラス名        ：Jwks
//* クラス日本語名  ：JWK Set による署名検証（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストの追加に伴う）
//**********************************************************************************

using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// JWK Set を使って JWT の署名を検証する。
    ///
    /// **実装側の JWS クラスは使わない。**
    /// 同じコードで署名して同じコードで検証しても、
    /// 「RP が公開鍵だけで検証できるか」を確かめたことにならない。
    /// ここでは System.Security.Cryptography だけで組む。
    /// </summary>
    public static class Jwks
    {
        /// <summary>署名検証の結果</summary>
        public sealed class Result
        {
            /// <summary>検証できたか</summary>
            public bool Verified { get; set; }

            /// <summary>読み手向けの説明（できなかった理由を含む）</summary>
            public string Detail { get; set; }

            /// <summary>使った鍵の kid</summary>
            public string Kid { get; set; }

            /// <summary>JWT ヘッダの alg</summary>
            public string Alg { get; set; }
        }

        /// <summary>
        /// JWT を JWK Set で検証する。
        /// </summary>
        /// <param name="jwt">JWT</param>
        /// <param name="jwkSet">JWK Set（keys 配列を持つ JSON）</param>
        /// <returns>Result</returns>
        public static Result Verify(string jwt, JsonElement jwkSet)
        {
            Result result = new Result();

            string[] parts = jwt.Split('.');

            if (parts.Length != 3)
            {
                result.Detail = "JWS の形式（3 パート）ではない";
                return result;
            }

            JsonElement header = Jwt.Header(jwt);
            result.Alg = Jwt.String(header, "alg");
            result.Kid = Jwt.String(header, "kid");

            if (result.Alg != "RS256")
            {
                // このテストは RS256 だけを見る。ES256 は別の鍵種になる。
                result.Detail = "alg が RS256 ではない（" + (result.Alg ?? "なし") + "）";
                return result;
            }

            JsonElement key;
            if (!TryFindRsaKey(jwkSet, result.Kid, out key))
            {
                result.Detail = "JWK Set に kid=" + (result.Kid ?? "なし") + " の RSA 公開鍵が無い";
                return result;
            }

            string n = Jwt.String(key, "n");
            string e = Jwt.String(key, "e");

            if (string.IsNullOrEmpty(n) || string.IsNullOrEmpty(e))
            {
                result.Detail = "JWK に n / e が無い";
                return result;
            }

            using (RSA rsa = RSA.Create())
            {
                RSAParameters p = new RSAParameters()
                {
                    Modulus  = FromBase64Url(n),
                    Exponent = FromBase64Url(e)
                };

                rsa.ImportParameters(p);

                byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
                byte[] signature    = FromBase64Url(parts[2]);

                result.Verified = rsa.VerifyData(
                    signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            result.Detail = result.Verified
                ? "JWK Set の公開鍵（kid=" + result.Kid + "）で検証できた"
                : "署名が公開鍵と一致しない";

            return result;
        }

        /// <summary>
        /// alg を none に書き換え、署名を落とした JWT を作る。
        ///
        /// RP ではなく**認可サーバが**、これを受け付けないことを確かめるために使う。
        /// </summary>
        /// <param name="jwt">元の JWT</param>
        /// <returns>alg=none の JWT</returns>
        public static string ToAlgNone(string jwt)
        {
            string[] parts = jwt.Split('.');

            string payload = parts.Length >= 2 ? parts[1] : "";
            string header  = ToBase64Url(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));

            // 署名は空にする（RFC 7519 の Unsecured JWS）。
            return header + "." + payload + ".";
        }

        /// <summary>
        /// ペイロードを 1 文字書き換えた JWT を作る（署名はそのまま）。
        /// </summary>
        /// <param name="jwt">元の JWT</param>
        /// <returns>改竄した JWT</returns>
        public static string Tamper(string jwt)
        {
            string[] parts = jwt.Split('.');

            if (parts.Length != 3)
            {
                return jwt;
            }

            JsonElement payload = Jwt.Payload(jwt);
            string sub = Jwt.String(payload, "sub") ?? "";

            // sub を別の値にする。署名は付け替えないので、検証すれば必ず落ちる。
            string json = Encoding.UTF8.GetString(FromBase64Url(parts[1]));
            string modified = json.Replace("\"" + sub + "\"", "\"tampered@example.com\"");

            return parts[0] + "." + ToBase64Url(Encoding.UTF8.GetBytes(modified)) + "." + parts[2];
        }

        #region Private

        /// <summary>JWK Set から RSA 公開鍵を探す</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <param name="kid">kid（null なら最初の RSA 鍵）</param>
        /// <param name="key">見つかった鍵</param>
        /// <returns>見つかれば true</returns>
        private static bool TryFindRsaKey(JsonElement jwkSet, string kid, out JsonElement key)
        {
            key = default(JsonElement);

            JsonElement keys;
            if (!jwkSet.TryGetProperty("keys", out keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (JsonElement k in keys.EnumerateArray())
            {
                if (Jwt.String(k, "kty") != "RSA")
                {
                    continue;
                }

                if (string.IsNullOrEmpty(kid) || Jwt.String(k, "kid") == kid)
                {
                    key = k;
                    return true;
                }
            }

            return false;
        }

        /// <summary>BASE64URL をデコードする</summary>
        /// <param name="value">BASE64URL文字列</param>
        /// <returns>バイト列</returns>
        private static byte[] FromBase64Url(string value)
        {
            string temp = value.Replace('-', '+').Replace('_', '/');

            switch (temp.Length % 4)
            {
                case 2:
                    temp += "==";
                    break;
                case 3:
                    temp += "=";
                    break;
            }

            return Convert.FromBase64String(temp);
        }

        /// <summary>BASE64URL にする</summary>
        /// <param name="value">バイト列</param>
        /// <returns>BASE64URL文字列</returns>
        private static string ToBase64Url(byte[] value)
        {
            return Convert.ToBase64String(value)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        #endregion
    }
}
