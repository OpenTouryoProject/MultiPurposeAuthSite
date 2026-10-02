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
//*  2026/09/11  玄人 幸道         BASE64URL の変換を Base64Url へ集約
//*  2026/10/02  玄人 幸道         alg だけを書き換える口を追加（C-8）（#129 の段階 1）
//*  2026/10/02  玄人 幸道         RS384 / RS512 も検証できるようにした（#129 の段階 2）
//*  2026/10/02  玄人 幸道         EC（ES256 / ES384 / ES512）も検証できるようにした（#129 の段階 3）
//*  2026/10/03  玄人 幸道         PS256 / PS384 / PS512（RSASSA-PSS）も検証できるようにした（#129 の段階 4）
//**********************************************************************************

using System.Collections.Generic;
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
    ///
    /// **RSA（`RS*` / `PS*`）と EC（`ES*`）の両方**を扱う（#129 の段階 2〜4）。
    /// **`PS*` は RSASSA-PSS** で、**鍵は `RS*` と同じ 1 本**である。
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

            // **alg から、鍵の種類とダイジェストが決まる**（JWA）。
            //
            //   | alg | kty | crv | ダイジェスト | パディング |
            //   |---|---|---|---|---|
            //   | RS256 / RS384 / RS512 | RSA | （無し。**1 本の鍵で 6 つ**） | SHA-256 / 384 / 512 | PKCS #1 v1.5 |
            //   | PS256 / PS384 / PS512 | RSA | 同上 | SHA-256 / 384 / 512 | **RSASSA-PSS** |
            //   | ES256 | EC | P-256 | SHA-256 | － |
            //   | ES384 | EC | P-384 | SHA-384 | － |
            //   | ES512 | EC | P-521 | SHA-512 | － |
            string kty = null;
            string crv = null;
            HashAlgorithmName hash;

            if (!Jwks.TryResolveAlg(result.Alg, out kty, out crv, out hash))
            {
                result.Detail = "この認可サーバが発行しない alg（" + (result.Alg ?? "なし") + "）";
                return result;
            }

            JsonElement key;
            if (!Jwks.TryFindKey(jwkSet, result.Kid, kty, crv, out key))
            {
                result.Detail = "JWK Set に kid=" + (result.Kid ?? "なし")
                    + " の " + kty + (crv == null ? "" : "（" + crv + "）") + " 公開鍵が無い";
                return result;
            }

            byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            byte[] signature    = Base64Url.Decode(parts[2]);

            if (kty == "RSA")
            {
                string n = Jwt.String(key, "n");
                string e = Jwt.String(key, "e");

                if (string.IsNullOrEmpty(n) || string.IsNullOrEmpty(e))
                {
                    result.Detail = "JWK に n / e が無い";
                    return result;
                }

                // **RS* は PKCS #1 v1.5、PS* は RSASSA-PSS**（#129 の段階 4）。
                //   **鍵は同じ 1 本**で、パディングとダイジェストだけが違う。
                RSASignaturePadding padding = result.Alg.StartsWith("PS")
                    ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

                using (RSA rsa = RSA.Create())
                {
                    RSAParameters p = new RSAParameters()
                    {
                        Modulus  = Base64Url.Decode(n),
                        Exponent = Base64Url.Decode(e)
                    };

                    rsa.ImportParameters(p);

                    result.Verified = rsa.VerifyData(
                        signingInput, signature, hash, padding);
                }
            }
            else
            {
                string x = Jwt.String(key, "x");
                string y = Jwt.String(key, "y");

                if (string.IsNullOrEmpty(x) || string.IsNullOrEmpty(y))
                {
                    result.Detail = "JWK に x / y が無い";
                    return result;
                }

                // **JWS の ECDSA 署名は r || s の生の連結**（RFC 7518 3.4）。
                //   .NET の既定は DER なので、IeeeP1363FixedFieldConcatenation を指定する。
                using (ECDsa ecdsa = ECDsa.Create())
                {
                    ECParameters p = new ECParameters()
                    {
                        Curve = Jwks.CurveOf(crv),
                        Q = new ECPoint()
                        {
                            X = Base64Url.Decode(x),
                            Y = Base64Url.Decode(y)
                        }
                    };

                    ecdsa.ImportParameters(p);

                    result.Verified = ecdsa.VerifyData(
                        signingInput, signature, hash,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                }
            }

            result.Detail = result.Verified
                ? "JWK Set の公開鍵（kid=" + result.Kid + " / alg=" + result.Alg + "）で検証できた"
                : "署名が公開鍵と一致しない";

            return result;
        }

        /// <summary>
        /// ヘッダの alg だけを書き換えた JWT を作る（署名と kid は、そのまま）。
        ///
        /// **認可サーバが「受ける alg」を決めているか**を確かめるために使う（C-8。#129 の段階 1）。
        /// **`ToAlgNone` はヘッダを丸ごと作り替える**ので、`kid` が消えて alg の判定まで届かない。
        /// こちらは **`kid` を残す**ので、鍵が引けたうえで alg だけが違う形になる。
        /// </summary>
        /// <param name="jwt">元の JWT</param>
        /// <param name="alg">書き換える alg（例 : HS256 / RS384 / PS256）</param>
        /// <returns>alg を書き換えた JWT</returns>
        public static string WithAlg(string jwt, string alg)
        {
            string[] parts = jwt.Split('.');

            if (parts.Length != 3)
            {
                return jwt;
            }

            // ヘッダを読んで、alg だけ差し替える（他の項目は保つ）。
            Dictionary<string, object> header = new Dictionary<string, object>();

            using (JsonDocument doc = JsonDocument.Parse(
                Encoding.UTF8.GetString(Base64Url.Decode(parts[0]))))
            {
                foreach (JsonProperty p in doc.RootElement.EnumerateObject())
                {
                    header[p.Name] = p.Value.ToString();
                }
            }

            header["alg"] = alg;

            string rewritten = Base64Url.Encode(
                Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));

            // **署名はそのまま。** 受け付けてしまえば、それだけで問題になる。
            return rewritten + "." + parts[1] + "." + parts[2];
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
            string header  = Base64Url.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));

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
            string json = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));
            string modified = json.Replace("\"" + sub + "\"", "\"tampered@example.com\"");

            return parts[0] + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(modified)) + "." + parts[2];
        }

        #region Private

        /// <summary>JWK Set から RSA 公開鍵を探す</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <param name="kid">kid（null なら最初の RSA 鍵）</param>
        /// <param name="key">見つかった鍵</param>
        /// <returns>見つかれば true</returns>
        private static bool TryFindKey(
            JsonElement jwkSet, string kid, string kty, string crv, out JsonElement key)
        {
            key = default(JsonElement);

            JsonElement keys;
            if (!jwkSet.TryGetProperty("keys", out keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (JsonElement k in keys.EnumerateArray())
            {
                if (Jwt.String(k, "kty") != kty)
                {
                    continue;
                }

                // **EC は曲線まで合っていること**（#129 の段階 3）。
                //   kty だけで選ぶと、P-256 の鍵で ES512 を検証しようとして落ちる。
                if (crv != null && Jwt.String(k, "crv") != crv)
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

        /// <summary>alg から、要る鍵の種類とダイジェストを決める（#129 の段階 3）</summary>
        /// <param name="alg">JWT ヘッダの alg</param>
        /// <param name="kty">kty（RSA / EC）</param>
        /// <param name="crv">crv（EC のみ。RSA は null）</param>
        /// <param name="hash">ダイジェスト</param>
        /// <returns>この認可サーバが発行する alg なら true</returns>
        public static bool TryResolveAlg(
            string alg, out string kty, out string crv, out HashAlgorithmName hash)
        {
            kty = null;
            crv = null;
            hash = HashAlgorithmName.SHA256;

            if (string.IsNullOrEmpty(alg) || alg.Length != 5)
            {
                return false;
            }

            string family = alg.Substring(0, 2);
            string size   = alg.Substring(2);

            if (family == "RS" || family == "PS")
            {
                // **RS* と PS* は同じ RSA の鍵**（違いはパディング。#129 の段階 4）。
                kty = "RSA";
            }
            else if (family == "ES")
            {
                kty = "EC";

                if (size == "256") { crv = "P-256"; }
                else if (size == "384") { crv = "P-384"; }
                else if (size == "512") { crv = "P-521"; } // **521。512 ではない**（JWA）
                else { return false; }
            }
            else
            {
                return false;
            }

            if (size == "256") { hash = HashAlgorithmName.SHA256; }
            else if (size == "384") { hash = HashAlgorithmName.SHA384; }
            else if (size == "512") { hash = HashAlgorithmName.SHA512; }
            else { return false; }

            return true;
        }

        /// <summary>その alg を検証できる公開鍵が、JWK Set に在るか（#129 の段階 3）</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <param name="alg">alg</param>
        /// <returns>在れば true</returns>
        /// <remarks>
        /// **広告（Discovery）と公開鍵（jwkcerts）が揃っていること**を測るために使う（`RT-129.6`）。
        /// **kid は見ない**（どの鍵かではなく、「その alg 用の鍵が在るか」を見る）。
        /// </remarks>
        public static bool HasKeyFor(JsonElement jwkSet, string alg)
        {
            string kty;
            string crv;
            HashAlgorithmName hash;

            if (!Jwks.TryResolveAlg(alg, out kty, out crv, out hash))
            {
                return false;
            }

            JsonElement key;
            return Jwks.TryFindKey(jwkSet, null, kty, crv, out key);
        }

        /// <summary>crv から ECCurve を引く</summary>
        /// <param name="crv">P-256 / P-384 / P-521</param>
        /// <returns>ECCurve</returns>
        private static ECCurve CurveOf(string crv)
        {
            if (crv == "P-384") { return ECCurve.NamedCurves.nistP384; }
            if (crv == "P-521") { return ECCurve.NamedCurves.nistP521; }

            return ECCurve.NamedCurves.nistP256;
        }

        #endregion
    }
}
