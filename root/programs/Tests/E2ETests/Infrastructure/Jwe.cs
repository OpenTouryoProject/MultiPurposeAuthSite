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
//* クラス名        ：Jwe
//* クラス日本語名  ：JWE の復号（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/10  玄人 幸道         新規（FAPI2 の id_token の中を見るため。#352）
//**********************************************************************************

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// JWE（Compact Serialization）を、クライアントの秘密鍵で復号する（#352）。
    ///
    /// **実装側の JWE クラスは使わない**（`Jwks` と同じ理由）。
    /// 同じコードで暗号化して同じコードで復号しても、「RP が復号できるか」を確かめたことにならない。
    /// ここでは System.Security.Cryptography だけで組む。
    ///
    /// **扱うのは、この認可サーバが出す組み合わせだけ**（Discovery の
    /// `id_token_encryption_alg_values_supported` = `RSA-OAEP`、`..._enc_values_supported` = `A256GCM`）。
    /// </summary>
    public static class Jwe
    {
        /// <summary>復号の結果</summary>
        public sealed class Result
        {
            /// <summary>復号できたか</summary>
            public bool Decrypted { get; set; }

            /// <summary>読み手向けの説明（できなかった理由を含む）</summary>
            public string Detail { get; set; }

            /// <summary>JWE ヘッダの alg</summary>
            public string Alg { get; set; }

            /// <summary>JWE ヘッダの enc</summary>
            public string Enc { get; set; }

            /// <summary>平文（Nested JWT なら、中の JWS）</summary>
            public string Plaintext { get; set; }
        }

        /// <summary>
        /// テスト用クライアントの秘密鍵（`SpRp_RsaPfxFilePath`。`jwk_rsa_publickey` と対）で復号する。
        /// </summary>
        /// <param name="client">IdPClient（構成ファイルを読む）</param>
        /// <param name="jwe">JWE</param>
        /// <returns>Result</returns>
        public static Result DecryptWithClientKey(IdPClient client, string jwe)
        {
            Result result = new Result();

            string[] parts = (jwe ?? "").Split('.');

            if (parts.Length != 5)
            {
                result.Detail = "JWE の形式（5 パート）ではない（" + parts.Length + " パート）";
                return result;
            }

            JsonElement header = Jwt.Header(jwe);
            result.Alg = Jwt.String(header, "alg");
            result.Enc = Jwt.String(header, "enc");

            // **RSA-OAEP は SHA-1 の OAEP**（RFC 7518 §4.3。SHA-256 は RSA-OAEP-256）。
            if (result.Alg != "RSA-OAEP" || result.Enc != "A256GCM")
            {
                result.Detail = "扱わない組み合わせ（alg=" + (result.Alg ?? "なし")
                    + " / enc=" + (result.Enc ?? "なし") + "）";
                return result;
            }

            try
            {
                byte[] cek;

                using (X509Certificate2 cert = JwsSigner.LoadCertificate(
                    client, "SpRp_RsaPfxFilePath", "SpRp_RsaPfxPassword"))
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    cek = rsa.Decrypt(Base64Url.Decode(parts[1]), RSAEncryptionPadding.OaepSHA1);
                }

                byte[] iv         = Base64Url.Decode(parts[2]);
                byte[] cipherText = Base64Url.Decode(parts[3]);
                byte[] tag        = Base64Url.Decode(parts[4]);
                byte[] plainText  = new byte[cipherText.Length];

                // **追加の認証データは、保護されたヘッダの base64url の ASCII**（RFC 7516 §5.2 の 15）。
                byte[] aad = Encoding.ASCII.GetBytes(parts[0]);

                using (AesGcm aes = new AesGcm(cek, tag.Length))
                {
                    aes.Decrypt(iv, cipherText, tag, plainText, aad);
                }

                result.Plaintext = Encoding.UTF8.GetString(plainText);
                result.Decrypted = true;
                result.Detail = "クライアントの秘密鍵で復号できた（alg=" + result.Alg + " / enc=" + result.Enc + "）";
            }
            catch (CryptographicException ex)
            {
                result.Detail = "復号できない（" + ex.Message + "）";
            }

            return result;
        }
    }
}
