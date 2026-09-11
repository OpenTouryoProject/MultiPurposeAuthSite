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
//* クラス日本語名  ：RS256 の JWS の署名（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/11  玄人 幸道         新規（RequestObjectBuilder と JwtBearerAssertion に重複していた署名を集約）
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
    /// クライアントの秘密鍵で、RS256 の JWS を作る。
    ///
    /// Request Object（RequestObjectBuilder）と、JWT Bearer の assertion（JwtBearerAssertion）で使う。
    /// 実装側の JWS クラスは使わず、System.Security.Cryptography だけで組む
    /// （同じコードで作って同じコードで検証すると、「サーバが何を受け取っているか」を確かめたことにならないため）。
    ///
    /// 署名鍵は、テスト用クライアントが登録している jwk_rsa_publickey と対になる
    /// SpRp_RsaPfxFilePath（構成ファイル）を使う。
    /// </summary>
    public static class JwsSigner
    {
        /// <summary>ペイロードに RS256 で署名し、JWS（コンパクト形式）を返す</summary>
        /// <param name="client">IdPClient（署名鍵の場所を構成ファイルから読む）</param>
        /// <param name="payload">ペイロード（クレーム）</param>
        /// <returns>JWS</returns>
        public static string SignRS256(IdPClient client, IDictionary<string, object> payload)
        {
            Dictionary<string, object> header = new Dictionary<string, object>()
            {
                { "alg", "RS256" },
                { "typ", "JWT" }
            };

            string signingInput =
                Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header))
                + "." + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));

            using (RSA rsa = LoadSigningKey(client))
            {
                byte[] signature = rsa.SignData(
                    Encoding.UTF8.GetBytes(signingInput),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return signingInput + "." + Base64Url.Encode(signature);
            }
        }

        /// <summary>署名鍵（クライアントの秘密鍵）を読む</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>RSA</returns>
        private static RSA LoadSigningKey(IdPClient client)
        {
            string path = client.Config.Get("SpRp_RsaPfxFilePath");
            string password = client.Config.Get("SpRp_RsaPfxPassword");

            if (string.IsNullOrEmpty(path))
            {
                throw new InvalidOperationException(
                    "SpRp_RsaPfxFilePath が構成ファイルにありません: " + client.Config.Path);
            }

            X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(
                path, password, X509KeyStorageFlags.Exportable);

            RSA rsa = cert.GetRSAPrivateKey();

            if (rsa == null)
            {
                throw new InvalidOperationException(
                    "RSAの秘密鍵を取り出せませんでした: " + path);
            }

            return rsa;
        }
    }
}
