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
//* クラス名        ：JwsSigner
//* クラス日本語名  ：RS256 / ES256 の JWS の署名（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/11  玄人 幸道         新規（RequestObjectBuilder と JwtBearerAssertion に重複していた署名を集約）
//*  2026/09/11  玄人 幸道         ES256 の署名（CIBA の認証リクエスト用）を追加（#196）
//*  2026/10/19  玄人 幸道         公開鍵の JWK を作る口を追加（#307 の段階 3）
//*  2026/10/21  玄人 幸道         DPoP の証明を作る口を追加（#311 の段階 1）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// クライアントの秘密鍵で、RS256 / ES256 の JWS を作る。
    ///
    /// RS256 : Request Object（RequestObjectBuilder）と、JWT Bearer の assertion（JwtBearerAssertion）で使う。
    ///         署名鍵は、テスト用クライアントの jwk_rsa_publickey と対になる SpRp_RsaPfxFilePath（構成ファイル）。
    /// ES256 : CIBA の認証リクエスト（RequestObjectBuilder.CreateCiba）で使う。
    ///         署名鍵は、CIBA のクライアントの jwk_ecdsa_publickey と対になる SpRp_EcdsaPfxFilePath（構成ファイル）。
    ///
    /// 実装側の JWS クラスは使わず、System.Security.Cryptography だけで組む
    /// （同じコードで作って同じコードで検証すると、「サーバが何を受け取っているか」を確かめたことにならないため）。
    /// </summary>
    public static class JwsSigner
    {
        /// <summary>ペイロードに RS256 で署名し、JWS（コンパクト形式）を返す</summary>
        /// <param name="client">IdPClient（署名鍵の場所を構成ファイルから読む）</param>
        /// <param name="payload">ペイロード（クレーム）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **鍵を選べる**（#307 の段階 6）。**既定は `SpRp_RsaPfxFilePath`** で、
        /// **発行者の鍵の入れ替えを測るときだけ、別の鍵を指す**
        /// （**構成ファイルに在る鍵しか指せない** — **テスト側で鍵を持たない**）。
        /// </remarks>
        public static string SignRS256(
            IdPClient client, IDictionary<string, object> payload,
            string pathKey = "SpRp_RsaPfxFilePath", string passwordKey = "SpRp_RsaPfxPassword")
        {
            string signingInput = SigningInput("RS256", payload);

            using (X509Certificate2 cert = LoadCertificate(client, pathKey, passwordKey))
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                if (rsa == null)
                {
                    throw new InvalidOperationException(
                        "RSAの秘密鍵を取り出せませんでした: " + client.Config.Get(pathKey));
                }

                byte[] signature = rsa.SignData(
                    Encoding.UTF8.GetBytes(signingInput),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return signingInput + "." + Base64Url.Encode(signature);
            }
        }

        /// <summary>ペイロードに ES256 で署名し、JWS（コンパクト形式）を返す</summary>
        /// <param name="client">IdPClient（署名鍵の場所を構成ファイルから読む）</param>
        /// <param name="payload">ペイロード（クレーム）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// JWS の ES256 の署名は、R と S をつないだ 64 バイト（RFC 7518 3.4）。
        /// .NET の ECDsa.SignData は、既定でこの形（IEEE P1363）で返す。
        /// </remarks>
        public static string SignES256(IdPClient client, IDictionary<string, object> payload)
        {
            string signingInput = SigningInput("ES256", payload);

            using (X509Certificate2 cert = LoadCertificate(client, "SpRp_EcdsaPfxFilePath", "SpRp_EcdsaPfxPassword"))
            using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
            {
                if (ecdsa == null)
                {
                    throw new InvalidOperationException(
                        "ECDSAの秘密鍵を取り出せませんでした: " + client.Config.Get("SpRp_EcdsaPfxFilePath"));
                }

                byte[] signature = ecdsa.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);

                return signingInput + "." + Base64Url.Encode(signature);
            }
        }

        /// <summary>署名鍵（RSA）の**公開鍵**を JWK にする（#307 の段階 3）</summary>
        /// <param name="client">IdPClient（鍵の場所を構成ファイルから読む）</param>
        /// <returns>JWK（JSON の文字列。1 本）</returns>
        /// <remarks>
        /// **動的登録の `jwks` に載せるために使う。**
        /// **秘密鍵は出さない**（`n` と `e` だけ）。
        /// **`kid` は RFC 7638 の指紋**（鍵から作るので、サーバの登録値と同じ値になる）。
        /// </remarks>
        public static string PublicRsaJwk(IdPClient client)
        {
            using (X509Certificate2 cert = LoadCertificate(
                client, "SpRp_RsaPfxFilePath", "SpRp_RsaPfxPassword"))
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                if (rsa == null)
                {
                    throw new InvalidOperationException(
                        "RSAの公開鍵を取り出せませんでした: " + client.Config.Get("SpRp_RsaPfxFilePath"));
                }

                RSAParameters p = rsa.ExportParameters(false);

                string n = Base64Url.Encode(p.Modulus);
                string e = Base64Url.Encode(p.Exponent);

                //  **RFC 7638 : 必須の項目だけを、辞書順の JSON にして SHA-256 する。**
                string kid = JwsSigner.Thumbprint(
                    "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}");

                return "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\","
                    + "\"n\":\"" + n + "\",\"e\":\"" + e + "\",\"kid\":\"" + kid + "\"}";
            }
        }

        /// <summary>署名鍵（ECDSA）の**公開鍵**を JWK にする（#307 の段階 3）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>JWK（JSON の文字列。1 本）</returns>
        /// <remarks>**曲線は P-256**（この鍵は ES256 用）。</remarks>
        public static string PublicEcJwk(IdPClient client)
        {
            using (X509Certificate2 cert = LoadCertificate(
                client, "SpRp_EcdsaPfxFilePath", "SpRp_EcdsaPfxPassword"))
            using (ECDsa ecdsa = cert.GetECDsaPublicKey())
            {
                if (ecdsa == null)
                {
                    throw new InvalidOperationException(
                        "ECDSAの公開鍵を取り出せませんでした: "
                        + client.Config.Get("SpRp_EcdsaPfxFilePath"));
                }

                ECParameters p = ecdsa.ExportParameters(false);

                string x = Base64Url.Encode(p.Q.X);
                string y = Base64Url.Encode(p.Q.Y);

                string kid = JwsSigner.Thumbprint(
                    "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x
                    + "\",\"y\":\"" + y + "\"}");

                return "{\"kty\":\"EC\",\"alg\":\"ES256\",\"use\":\"sig\","
                    + "\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y
                    + "\",\"kid\":\"" + kid + "\"}";
            }
        }

        #region DPoP（#311 の段階 1）

        /// <summary>DPoP の証明（proof）を作る（RFC 9449 §4）</summary>
        /// <param name="client">IdPClient（署名鍵の場所を構成ファイルから読む）</param>
        /// <param name="payload">ペイロード（`jti` / `htm` / `htu` / `iat` など）</param>
        /// <param name="es256">true なら ES256（既定）、false なら RS256</param>
        /// <returns>証明（JWS。コンパクト形式）</returns>
        /// <remarks>
        /// **ヘッダに公開鍵（`jwk`）を入れる**のが、普通の JWS との違いである
        /// （**検証する側は、要求の中の鍵で検証する**）。
        /// **`typ` は `dpop+jwt`。**
        ///
        /// **ペイロードは呼び出し側が作る** — **わざと壊した証明も作れるように**している
        /// （`RT-311.4`）。
        ///
        /// **鍵はテスト用クライアントのもの**（`SpRp_EcdsaPfxFilePath` / `SpRp_RsaPfxFilePath`）。
        /// **DPoP の鍵は、登録も要らない** — **その場で作って、指紋で縛られる**だけである。
        /// </remarks>
        public static string SignDPoP(
            IdPClient client, IDictionary<string, object> payload, bool es256 = true)
        {
            Dictionary<string, object> header = new Dictionary<string, object>()
            {
                { "alg", es256 ? "ES256" : "RS256" },
                { "typ", "dpop+jwt" },
                { "jwk", JwsSigner.DPoPJwk(client, es256) }
            };

            string signingInput =
                Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header))
                + "." + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));

            return signingInput + "." + Base64Url.Encode(
                JwsSigner.SignatureOf(client, signingInput, es256));
        }

        /// <summary>DPoP の証明のヘッダに入れる公開鍵（必須の項目だけ）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="es256">true なら EC（P-256）、false なら RSA</param>
        /// <returns>JWK（辞書）</returns>
        /// <remarks>
        /// **必須の項目だけを入れる**（RFC 7638 が指紋に使う項目）。
        /// **`kid` も `use` も入れない** — **入れても指紋は変わらない**が、
        /// **「指紋の材料はこれだけ」**ということを、作る側でも明示しておく。
        /// </remarks>
        public static Dictionary<string, object> DPoPJwk(IdPClient client, bool es256 = true)
        {
            if (es256)
            {
                using (X509Certificate2 cert = LoadCertificate(
                    client, "SpRp_EcdsaPfxFilePath", "SpRp_EcdsaPfxPassword"))
                using (ECDsa ecdsa = cert.GetECDsaPublicKey())
                {
                    ECParameters p = ecdsa.ExportParameters(false);

                    return new Dictionary<string, object>()
                    {
                        { "crv", "P-256" },
                        { "kty", "EC" },
                        { "x", Base64Url.Encode(p.Q.X) },
                        { "y", Base64Url.Encode(p.Q.Y) }
                    };
                }
            }

            using (X509Certificate2 cert = LoadCertificate(
                client, "SpRp_RsaPfxFilePath", "SpRp_RsaPfxPassword"))
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                RSAParameters p = rsa.ExportParameters(false);

                return new Dictionary<string, object>()
                {
                    { "e", Base64Url.Encode(p.Exponent) },
                    { "kty", "RSA" },
                    { "n", Base64Url.Encode(p.Modulus) }
                };
            }
        }

        /// <summary>DPoP の鍵の指紋（`cnf.jkt` の期待値。RFC 7638）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="es256">true なら EC（P-256）、false なら RSA</param>
        /// <returns>BASE64URL(SHA-256(正規化した JSON))</returns>
        /// <remarks>
        /// **サーバと同じ計算を、テスト側でも独立に行う**
        /// （**実装のコードは使わない** — 使うと「同じコードで作って同じコードで確かめた」ことになる）。
        /// </remarks>
        public static string DPoPJkt(IdPClient client, bool es256 = true)
        {
            Dictionary<string, object> jwk = JwsSigner.DPoPJwk(client, es256);

            string canonical = es256
                ? "{\"crv\":\"" + jwk["crv"] + "\",\"kty\":\"" + jwk["kty"]
                    + "\",\"x\":\"" + jwk["x"] + "\",\"y\":\"" + jwk["y"] + "\"}"
                : "{\"e\":\"" + jwk["e"] + "\",\"kty\":\"" + jwk["kty"]
                    + "\",\"n\":\"" + jwk["n"] + "\"}";

            return JwsSigner.Thumbprint(canonical);
        }

        /// <summary>署名する（ES256 / RS256）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="signingInput">ヘッダ.ペイロード</param>
        /// <param name="es256">true なら ES256、false なら RS256</param>
        /// <returns>署名</returns>
        private static byte[] SignatureOf(IdPClient client, string signingInput, bool es256)
        {
            if (es256)
            {
                using (X509Certificate2 cert = LoadCertificate(
                    client, "SpRp_EcdsaPfxFilePath", "SpRp_EcdsaPfxPassword"))
                using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
                {
                    if (ecdsa == null)
                    {
                        throw new InvalidOperationException(
                            "ECDSAの秘密鍵を取り出せませんでした: "
                            + client.Config.Get("SpRp_EcdsaPfxFilePath"));
                    }

                    return ecdsa.SignData(
                        Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);
                }
            }

            using (X509Certificate2 cert = LoadCertificate(
                client, "SpRp_RsaPfxFilePath", "SpRp_RsaPfxPassword"))
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                if (rsa == null)
                {
                    throw new InvalidOperationException(
                        "RSAの秘密鍵を取り出せませんでした: "
                        + client.Config.Get("SpRp_RsaPfxFilePath"));
                }

                return rsa.SignData(
                    Encoding.UTF8.GetBytes(signingInput),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        #endregion

        /// <summary>JWK の指紋（RFC 7638）</summary>
        /// <param name="canonical">必須の項目だけを辞書順に並べた JSON</param>
        /// <returns>BASE64URL(SHA-256(JSON))</returns>
        public static string Thumbprint(string canonical)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return Base64Url.Encode(sha256.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
            }
        }

        /// <summary>署名する入力（ヘッダ.ペイロード）を作る</summary>
        /// <param name="alg">alg（RS256 / ES256）</param>
        /// <param name="payload">ペイロード</param>
        /// <returns>BASE64URL(ヘッダ) + "." + BASE64URL(ペイロード)</returns>
        private static string SigningInput(string alg, IDictionary<string, object> payload)
        {
            Dictionary<string, object> header = new Dictionary<string, object>()
            {
                { "alg", alg },
                { "typ", "JWT" }
            };

            return Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header))
                + "." + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
        }

        /// <summary>署名鍵の証明書（クライアントの秘密鍵を含む pfx）を読む</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="pathKey">pfx のパスの構成キー</param>
        /// <param name="passwordKey">pfx のパスワードの構成キー</param>
        /// <returns>X509Certificate2</returns>
        private static X509Certificate2 LoadCertificate(IdPClient client, string pathKey, string passwordKey)
        {
            string path = client.Config.Get(pathKey);
            string password = client.Config.Get(passwordKey);

            if (string.IsNullOrEmpty(path))
            {
                throw new InvalidOperationException(
                    pathKey + " が構成ファイルにありません: " + client.Config.Path);
            }

            return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.Exportable);
        }
    }
}
