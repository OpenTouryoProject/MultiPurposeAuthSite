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
//* クラス名        ：SigningKeysTests
//* クラス日本語名  ：署名の鍵（証明書）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using MultiPurposeAuthSite.TokenProviders;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Security.Jwt;


using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// SigningKeys.Entry の *.cer の経路（E2E の通しでは通らない）。
    /// **使い捨ての証明書を作って確かめる。**
    /// </summary>
    public class SigningKeysTests : IDisposable
    {
        private const string Password = "unit-test-only";

        private readonly string _dir = Path.Combine(Path.GetTempPath(), "mpas-ut-" + Guid.NewGuid().ToString("N"));

        /// <summary>RSA と ES256 の証明書を作り、設定に入れる</summary>
        public SigningKeysTests()
        {
            Directory.CreateDirectory(this._dir);

            Dictionary<string, string> config = new Dictionary<string, string>
            {
                { "RsaPfxPassword", Password },
                { "EcdsaPfxPassword", Password },
                //  **`JwkSet.json` の無い配備**（検証は証明書に落ちる）。
                { "JwkSetFilePath", Path.Combine(this._dir, "no-such-JwkSet.json") }
            };

            using (RSA rsa = RSA.Create(2048))
            {
                this.Write(config, "Rsa", new CertificateRequest("CN=ut-rsa", rsa,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }

            using (ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                this.Write(config, "Ecdsa", new CertificateRequest("CN=ut-ec", ec, HashAlgorithmName.SHA256));
            }

            TestConfig.Set(config);
        }

        /// <summary>後片付け</summary>
        public void Dispose()
        {
            Directory.Delete(this._dir, true);
        }

        /// <summary>*.cer と *.pfx で、同じ kid の JWK になる</summary>
        [Theory]
        [InlineData("RS256")]
        [InlineData("PS256")]
        [InlineData("ES256")]
        [Basis("設計：SigningKeys.Entry.HashAlgorithmName のコメント（食い違うと、載っていない kid で署名する）")]
        public void cerとpfxで同じkidのJWKになる(string alg)
        {
            SigningKeys.Entry entry = SigningKeys.Of(alg);

            JObject fromCer = entry.JwkFromCer();
            JObject fromPfx = entry.JwkFromPfx();

            Assert.False(string.IsNullOrEmpty((string)fromCer["kid"]));
            Assert.Equal((string)fromPfx["kid"], (string)fromCer["kid"]);
        }

        /// <summary>*.pfx で署名したものを、*.cer で検証できる</summary>
        [Theory]
        [InlineData("RS256")]
        [InlineData("PS256")]
        [InlineData("ES256")]
        [Basis("RFC 7515 §5.2（JWS の検証）")]
        public void pfxで署名したものをcerで検証できる(string alg)
        {
            SigningKeys.Entry entry = SigningKeys.Of(alg);

            string jwt = entry.CreateJwsFromPfx().Create("{\"sub\":\"ut\"}");

            Assert.True(entry.CreateJwsFromCer().Verify(jwt));
        }

        /// <summary>改ざんしたものは、*.cer の検証で落ちる</summary>
        [Theory]
        [InlineData("RS256")]
        [InlineData("ES256")]
        [Basis("RFC 7515 §5.2（JWS の検証）")]
        public void 改ざんしたものはcerの検証で落ちる(string alg)
        {
            SigningKeys.Entry entry = SigningKeys.Of(alg);

            string[] parts = entry.CreateJwsFromPfx().Create("{\"sub\":\"ut\"}").Split('.');
            string other = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"sub\":\"other\"}"))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            Assert.False(entry.CreateJwsFromCer().Verify(parts[0] + "." + other + "." + parts[2]));
        }

        /// <summary>扱わない alg は引けない</summary>
        [Theory]
        [InlineData("none")]
        [InlineData("HS256")]
        [InlineData("")]
        [InlineData(null)]
        [Basis("RFC 8725 §3.1（使う alg を確かめる）")]
        public void 扱わないalgは引けない(string alg)
        {
            Assert.Null(SigningKeys.Of(alg));
        }

        /// <summary>kid が空でも、JWK Set に無くても、自分の証明書で検証する</summary>
        [Theory]
        [InlineData("RS256", "")]
        [InlineData("RS256", "unknown-kid")]
        [InlineData("ES256", "")]
        [InlineData("ES256", "unknown-kid")]
        [Basis("設計：CmnAccessToken.SelectJws のコメント（kid が空・JWK Set に無ければ、alg に対応する自分の証明書）")]
        public void kidを引けなければ自分の証明書で検証する(string alg, string kid)
        {
            SigningKeys.Entry entry = SigningKeys.Of(alg);

            Assert.True(CmnAccessToken.VerifySignature(SigningKeysTests.Sign(entry.CreateJwsFromPfx(), kid)));
        }

        /// <summary>別の鍵の署名は、kid を引けなくても通らない</summary>
        [Theory]
        [InlineData("RS256", "")]
        [InlineData("RS256", "unknown-kid")]
        [InlineData("ES256", "")]
        [InlineData("ES256", "unknown-kid")]
        [Basis("RFC 7515 §5.2（JWS の検証）")]
        public void 別の鍵の署名は通らない(string alg, string kid)
        {
            string pfx = Path.Combine(this._dir, "other.pfx");

            if (alg == "RS256")
            {
                using (RSA rsa = RSA.Create(2048))
                {
                    this.WriteOther(pfx, new CertificateRequest("CN=other", rsa,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                }
            }
            else
            {
                using (ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                {
                    this.WriteOther(pfx, new CertificateRequest("CN=other", ec, HashAlgorithmName.SHA256));
                }
            }

            Assert.False(CmnAccessToken.VerifySignature(
                SigningKeysTests.Sign(JwsFactory.CreateFromPfx(alg, pfx, Password), kid)));
        }

        /// <summary>自分が発行しない alg は、ヘッダを書き換えても通らない</summary>
        [Theory]
        [InlineData("none")]
        [InlineData("HS256")]
        [Basis("RFC 8725 §3.1（使う alg を確かめる）")]
        public void 自分が発行しないalgは通らない(string alg)
        {
            string[] parts = SigningKeysTests.Sign(SigningKeys.Of("RS256").CreateJwsFromPfx(), "").Split('.');
            string header = SigningKeysTests.Base64Url("{\"alg\":\"" + alg + "\",\"kid\":\"\",\"typ\":\"JWT\"}");

            Assert.False(CmnAccessToken.VerifySignature(header + "." + parts[1] + "." + parts[2]));
        }

        /// <summary>kid を入れて署名する</summary>
        /// <param name="jws">JWS</param>
        /// <param name="kid">kid</param>
        /// <returns>JWT</returns>
        private static string Sign(JWS jws, string kid)
        {
            if (jws is JWS_RSA)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
            }

            return jws.Create("{\"sub\":\"ut\"}");
        }

        /// <summary>base64url</summary>
        /// <param name="value">文字列</param>
        /// <returns>base64url</returns>
        private static string Base64Url(string value)
        {
            return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>別の鍵を *.pfx に書く</summary>
        /// <param name="path">パス</param>
        /// <param name="request">CertificateRequest</param>
        private void WriteOther(string path, CertificateRequest request)
        {
            using (X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
            {
                File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, Password));
            }
        }

        /// <summary>証明書をファイルに書いて、設定に入れる</summary>
        private void Write(Dictionary<string, string> config, string name, CertificateRequest request)
        {
            using (X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
            {
                string pfx = Path.Combine(this._dir, name + ".pfx");
                string cer = Path.Combine(this._dir, name + ".cer");

                File.WriteAllBytes(pfx, cert.Export(X509ContentType.Pfx, Password));
                File.WriteAllBytes(cer, cert.Export(X509ContentType.Cert));

                config[name + "PfxFilePath"] = pfx;
                config["SpRp_" + name + "CerFilePath"] = cer;
            }
        }
    }
}
