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
//* クラス名        ：SigningKeys
//* クラス日本語名  ：この認可サーバが署名に使う鍵（alg → 鍵）の表
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（#129 の段階 3 / D-9）
//*  2026/10/03  玄人 幸道         ECのJWK検証を上流のJWS_ES*_Paramに戻した（OpenTouryo#595）
//*  2026/10/03  玄人 幸道         PS256 / PS384 / PS512 を追加（#129 の段階 4）
//**********************************************************************************

using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// この認可サーバが署名に使う鍵の表（#129 の段階 3 / D-9）。
    /// </summary>
    /// <remarks>
    /// **alg から鍵への対応は、ここだけが持つ。**
    ///
    /// | 使う側 | 何を引くか |
    /// |---|---|
    /// | 発行（`CmnAccessToken.SelectJwsForSigning`） | `CreateJwsFromPfx` ＋ `JwkFromPfx`（`kid` 用） |
    /// | 検証・証明書（`CmnAccessToken.SelectJwsFromCertificate`） | `CreateJwsFromCer` |
    /// | 検証・JWK（`CmnAccessToken.SelectJws`） | `CreateJwsFromJwk` |
    /// | JWK Set の生成（`CommandLineTools/CreateJwkSetJson`） | `JwkFromCer`（`SupportedAlgs` を回す） |
    ///
    /// **散っていると、JWK Set に載っていない鍵で署名していても気付けない**（D-9）。
    /// **`CreateJwkSetJson` はこのファイルをソース参照している**（`Compile Include` の `Link`）ので、
    /// **アプリが署名に使う鍵が、そのまま `jwkcerts` に載る。**
    ///
    /// **このファイルは `MultiPurposeAuthSite.Co.Config` を参照しない。**
    /// 参照すると、ソース参照している `CreateJwkSetJson` が CommonLibrary ごと必要になる。
    /// 設定は `GetConfigParameter` で直に引く（`Config` / `CmnClientParams` と同じ流儀）。
    ///
    /// **RSA の 6 つは、同じ 1 本の鍵**である。
    ///
    /// | | 違い |
    /// |---|---|
    /// | `RS256` / `RS384` / `RS512` | **ダイジェストだけ**（パディングは PKCS #1 v1.5） |
    /// | `PS256` / `PS384` / `PS512` | **パディングが RSASSA-PSS**（#129 の段階 4） |
    ///
    /// **`ES256` / `ES384` / `ES512` は曲線が alg に紐づく**ので、**鍵が 3 本に分かれる**
    /// （JWA : `ES256`→P-256、`ES384`→P-384、`ES512`→P-521）。
    /// </remarks>
    public class SigningKeys
    {
        #region Entry

        /// <summary>alg 1 つ分の鍵</summary>
        public class Entry
        {
            #region mem & prop & constructor

            /// <summary>設定キー名（署名に使う *.pfx のパス）</summary>
            private readonly string _pfxFilePathKey;

            /// <summary>設定キー名（*.pfx のパスワード）</summary>
            private readonly string _pfxPasswordKey;

            /// <summary>設定キー名（検証に使う *.cer のパス）</summary>
            private readonly string _cerFilePathKey;

            /// <summary>EC の曲線とダイジェスト（RSA のときは未使用）</summary>
            private readonly JWS_ECDSA.ES _es;

            /// <summary>alg（RS256 / RS384 / RS512 / ES256 / ES384 / ES512）</summary>
            public string Alg { get; private set; }

            /// <summary>kty（RSA / EC）</summary>
            public string Kty { get; private set; }

            /// <summary>crv（EC のみ。RSA は null）</summary>
            public string Crv { get; private set; }

            /// <summary>RSA の鍵か</summary>
            public bool IsRsa
            {
                get { return this.Kty == JwtConst.RSA; }
            }

            /// <summary>Constructor（RSA）</summary>
            /// <param name="alg">alg</param>
            /// <param name="pfxFilePathKey">設定キー名（*.pfx のパス）</param>
            /// <param name="pfxPasswordKey">設定キー名（*.pfx のパスワード）</param>
            /// <param name="cerFilePathKey">設定キー名（*.cer のパス）</param>
            internal Entry(string alg,
                string pfxFilePathKey, string pfxPasswordKey, string cerFilePathKey)
            {
                this.Alg = alg;
                this.Kty = JwtConst.RSA;
                this.Crv = null;
                this._pfxFilePathKey = pfxFilePathKey;
                this._pfxPasswordKey = pfxPasswordKey;
                this._cerFilePathKey = cerFilePathKey;
            }

            /// <summary>Constructor（EC）</summary>
            /// <param name="alg">alg</param>
            /// <param name="es">JWS_ECDSA.ES</param>
            /// <param name="crv">crv（P-256 / P-384 / P-521）</param>
            /// <param name="pfxFilePathKey">設定キー名（*.pfx のパス）</param>
            /// <param name="pfxPasswordKey">設定キー名（*.pfx のパスワード）</param>
            /// <param name="cerFilePathKey">設定キー名（*.cer のパス）</param>
            internal Entry(string alg, JWS_ECDSA.ES es, string crv,
                string pfxFilePathKey, string pfxPasswordKey, string cerFilePathKey)
            {
                this.Alg = alg;
                this.Kty = JwtConst.EC;
                this.Crv = crv;
                this._es = es;
                this._pfxFilePathKey = pfxFilePathKey;
                this._pfxPasswordKey = pfxPasswordKey;
                this._cerFilePathKey = cerFilePathKey;
            }

            #endregion

            #region 設定値

            /// <summary>署名に使う *.pfx のパス</summary>
            public string PfxFilePath
            {
                get { return GetConfigParameter.GetConfigValue(this._pfxFilePathKey); }
            }

            /// <summary>*.pfx のパスワード</summary>
            public string PfxPassword
            {
                get { return GetConfigParameter.GetConfigValue(this._pfxPasswordKey); }
            }

            /// <summary>検証に使う *.cer のパス</summary>
            public string CerFilePath
            {
                get { return GetConfigParameter.GetConfigValue(this._cerFilePathKey); }
            }

            #endregion

            #region JWS

            /// <summary>署名する JWS を作る（*.pfx。秘密鍵が要る）</summary>
            /// <returns>JWS</returns>
            public JWS CreateJwsFromPfx()
            {
                string path = this.PfxFilePath;
                string password = this.PfxPassword;

                if (this.Alg == JwtConst.RS256) { return new JWS_RS256_X509(path, password); }
                if (this.Alg == JwtConst.RS384) { return new JWS_RS384_X509(path, password); }
                if (this.Alg == JwtConst.RS512) { return new JWS_RS512_X509(path, password); }
                if (this.Alg == JwtConst.PS256) { return new JWS_PS256_X509(path, password); }
                if (this.Alg == JwtConst.PS384) { return new JWS_PS384_X509(path, password); }
                if (this.Alg == JwtConst.PS512) { return new JWS_PS512_X509(path, password); }
                if (this.Alg == JwtConst.ES256) { return new JWS_ES256_X509(path, password); }
                if (this.Alg == JwtConst.ES384) { return new JWS_ES384_X509(path, password); }
                if (this.Alg == JwtConst.ES512) { return new JWS_ES512_X509(path, password); }

                return null;
            }

            /// <summary>検証する JWS を作る（*.cer。公開鍵だけで足りる）</summary>
            /// <returns>JWS</returns>
            public JWS CreateJwsFromCer()
            {
                string path = this.CerFilePath;

                if (this.Alg == JwtConst.RS256) { return new JWS_RS256_X509(path, ""); }
                if (this.Alg == JwtConst.RS384) { return new JWS_RS384_X509(path, ""); }
                if (this.Alg == JwtConst.RS512) { return new JWS_RS512_X509(path, ""); }
                if (this.Alg == JwtConst.PS256) { return new JWS_PS256_X509(path, ""); }
                if (this.Alg == JwtConst.PS384) { return new JWS_PS384_X509(path, ""); }
                if (this.Alg == JwtConst.PS512) { return new JWS_PS512_X509(path, ""); }
                if (this.Alg == JwtConst.ES256) { return new JWS_ES256_X509(path, ""); }
                if (this.Alg == JwtConst.ES384) { return new JWS_ES384_X509(path, ""); }
                if (this.Alg == JwtConst.ES512) { return new JWS_ES512_X509(path, ""); }

                return null;
            }

            /// <summary>検証する JWS を作る（JWK Set から引いた公開鍵）</summary>
            /// <param name="jwkObject">JWK</param>
            /// <returns>JWS</returns>
            /// <remarks>
            /// **`kid` で JWK を引いて検証する経路**である（＝ 鍵の入れ替えで要る経路。D-9）。
            ///
            /// > **`JWS_ES384_Param` / `JWS_ES512_Param` は、一度 Windows で検証できなかった**
            /// > （`DigitalSignECDsaCng` がダイジェストを受け取らず、`ECDsaCng` の既定 SHA-256 になっていた）。
            /// > **上流で直ったので**（OpenTouryoProject/OpenTouryo#595）、**ここは上流の class を使う。**
            /// > 回避のために置いていた派生 class は外した。
            /// </remarks>
            public JWS CreateJwsFromJwk(JObject jwkObject)
            {
                if (this.IsRsa)
                {
                    // **RSA の 6 つは同じ鍵**なので、鍵の変換は RS._256 で足りる。
                    RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
                    RSAParameters param = rpkc.JwkToProvider(jwkObject).ExportParameters(false);

                    if (this.Alg == JwtConst.RS384) { return new JWS_RS384_Param(param); }
                    if (this.Alg == JwtConst.RS512) { return new JWS_RS512_Param(param); }
                    if (this.Alg == JwtConst.PS256) { return new JWS_PS256_Param(param); }
                    if (this.Alg == JwtConst.PS384) { return new JWS_PS384_Param(param); }
                    if (this.Alg == JwtConst.PS512) { return new JWS_PS512_Param(param); }

                    return new JWS_RS256_Param(param);
                }
                else
                {
                    // **EC は曲線が alg に紐づく**ので、alg に対応する変換器で引く。
                    EccPublicKeyConverter epkc = new EccPublicKeyConverter(this._es);
                    ECParameters param = epkc.JwkToParam(jwkObject);

                    if (this.Alg == JwtConst.ES384) { return new JWS_ES384_Param(param, false); }
                    if (this.Alg == JwtConst.ES512) { return new JWS_ES512_Param(param, false); }

                    return new JWS_ES256_Param(param, false);
                }
            }

            #endregion

            #region JWK

            /// <summary>*.pfx から JWK（公開鍵）を作る（`kid` を引くため）</summary>
            /// <returns>JWK</returns>
            public JObject JwkFromPfx()
            {
                if (this.IsRsa)
                {
                    // **RSA の kid は RS._256 で作る**（下の remarks）。
                    RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
                    return JsonConvert.DeserializeObject<JObject>(
                        rpkc.X509PfxToJwk(this.PfxFilePath, this.PfxPassword));
                }

                EccPublicKeyConverter epkc = new EccPublicKeyConverter(this._es);
                return JsonConvert.DeserializeObject<JObject>(
                    epkc.X509PfxToJwk(this.PfxFilePath, this.PfxPassword, this.HashAlgorithmName));
            }

            /// <summary>*.cer から JWK（公開鍵）を作る（JWK Set に載せるため）</summary>
            /// <returns>JWK</returns>
            public JObject JwkFromCer()
            {
                if (this.IsRsa)
                {
                    // **RSA の kid は RS._256 で作る**（下の remarks）。
                    RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
                    return JsonConvert.DeserializeObject<JObject>(
                        rpkc.X509CerToJwk(this.CerFilePath));
                }

                EccPublicKeyConverter epkc = new EccPublicKeyConverter(this._es);
                return JsonConvert.DeserializeObject<JObject>(
                    epkc.X509CerToJwk(this.CerFilePath));
            }

            /// <summary>この alg のダイジェスト</summary>
            /// <remarks>
            /// **`kid` は、このダイジェストで作られる**（Open棟梁 の `*KeyConverter`。RFC 7638）。
            ///
            /// | | `kid` の材料 | |
            /// |---|---|---|
            /// | RSA | kty / n / e | **`RS._256` 固定で作る。** そうしないとダイジェストごとに `kid` が変わり、**1 本の鍵が 6 つに見える**（`RS*` ＋ `PS*`） |
            /// | EC | crv / kty / x / y | **alg のダイジェストで作る。** 鍵そのものが曲線ごとに違うので、`kid` も違ってよい |
            ///
            /// **署名（`JwkFromPfx`）と JWK Set の生成（`JwkFromCer`）が同じ作り方をすること。**
            /// 食い違うと、**載っていない `kid` で署名する**ことになる。
            /// </remarks>
            public HashAlgorithmName HashAlgorithmName
            {
                get
                {
                    if (this.Alg.EndsWith("384")) { return System.Security.Cryptography.HashAlgorithmName.SHA384; }
                    if (this.Alg.EndsWith("512")) { return System.Security.Cryptography.HashAlgorithmName.SHA512; }

                    return System.Security.Cryptography.HashAlgorithmName.SHA256;
                }
            }

            #endregion
        }

        #endregion

        #region 表

        /// <summary>この認可サーバが署名に使う alg（広告・発行・検証が、この並びを見る）</summary>
        /// <remarks>
        /// **増やすときは、この表に 1 行足すだけでよい。**
        /// ただし **E2E の `RT-129.2`（受けない alg の一覧）も直すこと**
        /// （黙って広がらないようにするため）。
        /// </remarks>
        private static readonly Entry[] _entries = new Entry[]
        {
            // RSA（**1 本の鍵で 3 つの alg**。ダイジェストだけが違い、kid も同じ）
            new Entry(JwtConst.RS256,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.RS384,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.RS512,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),

            // RSA / RSASSA-PSS（**鍵は RS* と同じ 1 本**。パディングだけが違う。#129 の段階 4）
            new Entry(JwtConst.PS256,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.PS384,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.PS512,
                "RsaPfxFilePath", "RsaPfxPassword", "SpRp_RsaCerFilePath"),

            // EC（**曲線が alg に紐づく**ので、鍵が 3 本に分かれる）
            new Entry(JwtConst.ES256, JWS_ECDSA.ES._256, JwtConst.P256,
                "EcdsaPfxFilePath", "EcdsaPfxPassword", "SpRp_EcdsaCerFilePath"),
            new Entry(JwtConst.ES384, JWS_ECDSA.ES._384, JwtConst.P384,
                "Ecdsa384PfxFilePath", "Ecdsa384PfxPassword", "SpRp_Ecdsa384CerFilePath"),
            new Entry(JwtConst.ES512, JWS_ECDSA.ES._512, JwtConst.P521,
                "Ecdsa512PfxFilePath", "Ecdsa512PfxPassword", "SpRp_Ecdsa512CerFilePath")
        };

        /// <summary>この認可サーバが署名に使う alg の一覧</summary>
        public static string[] SupportedAlgs
        {
            get
            {
                string[] algs = new string[SigningKeys._entries.Length];

                for (int i = 0; i < SigningKeys._entries.Length; i++)
                {
                    algs[i] = SigningKeys._entries[i].Alg;
                }

                return algs;
            }
        }

        /// <summary>alg に対応する鍵を引く</summary>
        /// <param name="alg">alg</param>
        /// <returns>Entry（扱わない alg なら null）</returns>
        public static Entry Of(string alg)
        {
            if (string.IsNullOrEmpty(alg))
            {
                return null;
            }

            foreach (Entry entry in SigningKeys._entries)
            {
                if (entry.Alg == alg)
                {
                    return entry;
                }
            }

            return null;
        }

        /// <summary>この認可サーバが署名に使う alg かどうか</summary>
        /// <param name="alg">alg</param>
        /// <returns>使うなら true</returns>
        public static bool IsSupported(string alg)
        {
            return SigningKeys.Of(alg) != null;
        }

        #endregion
    }
}
