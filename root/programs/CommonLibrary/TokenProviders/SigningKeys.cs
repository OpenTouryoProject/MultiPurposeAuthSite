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
//*  2026/10/13  玄人 幸道         設定キーを自前のものに分け、旧キーも読む（#290）
//*  2026/10/20  玄人 幸道         任意のパスの .cer から検証鍵を作る口を追加（#307 の段階 4）
//*  2026/10/21  玄人 幸道         RSA の公開鍵のパラメタから検証する JWS を作る口を追加（#308 の段階 1）
//*  2026/11/06  玄人 幸道         自分の証明書を、サーバ側のキー（RsaCerFilePath ほか）で読む。空なら SpRp_*CerFilePath（#339）
//**********************************************************************************

using System.Collections.Generic;
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
    /// | JWK Set の生成（`CommandLineTools/CreateJwkSetJson`） | `JwkFromCer`（`JwsFactory.SupportedAlgs` を回す） |
    ///
    /// **alg → JWS の class の対応と、扱う alg の一覧は Open棟梁 の `JwsFactory` が持つ**（#294）。
    /// **ここに残るのは「どの設定キーの鍵を使うか」**（配備の決め）である。
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
            /// <remarks>
            /// **サーバ側のキー（`RsaCerFilePath` など。`*PfxFilePath` と対になる）を読む**（#339）。
            /// **空なら `_legacyCerFilePathKey`（`SpRp_*CerFilePath`）を読む。**
            ///
            /// **相手（上流）の証明書は、別のキーで持つ**
            /// （`IdFederationOidcCerFilePath` / `IdFederationSaml2CerFilePath`。#286 / #289）。
            /// </remarks>
            private readonly string _cerFilePathKey;

            /// <summary>設定キー名（*.cer のパス。以前のキー）</summary>
            /// <remarks>
            /// **以前は `SpRp_*CerFilePath` を、この配備の証明書として読んでいた**（#290）。
            /// **あれは Open棟梁 のクライアント役のキー**（`CmnClientParams`。相手の証明書）で、
            /// 自分の値として使い回すと、認可サーバ兼クライアントの配備で相手の値を置けなくなる
            /// （Open棟梁 の Framework/ANALYSIS.md 8.1。#339）。
            /// **配備済みの設定ファイルには、サーバ側のキーが無い**ので、空ならこちらを読む（**設定を直さなくても動く**）。
            /// </remarks>
            private readonly string _legacyCerFilePathKey;

            /// <summary>EC の曲線とダイジェスト（RSA のときは未使用）</summary>
            private readonly JWS_ECDSA.ES _es;

            /// <summary>alg（RS256 / RS384 / RS512 / ES256 / ES384 / ES512）</summary>
            public string Alg { get; private set; }

            /// <summary>RSA の鍵か</summary>
            public bool IsRsa
            {
                get { return JwsFactory.GetKty(this.Alg) == JwtConst.RSA; }
            }

            /// <summary>Constructor（RSA）</summary>
            /// <param name="alg">alg</param>
            /// <param name="pfxFilePathKey">設定キー名（*.pfx のパス）</param>
            /// <param name="pfxPasswordKey">設定キー名（*.pfx のパスワード）</param>
            /// <param name="cerFilePathKey">設定キー名（*.cer のパス）</param>
            /// <param name="legacyCerFilePathKey">設定キー名（*.cer のパス。以前のキー）</param>
            internal Entry(string alg,
                string pfxFilePathKey, string pfxPasswordKey,
                string cerFilePathKey, string legacyCerFilePathKey)
            {
                this.Alg = alg;
                this._pfxFilePathKey = pfxFilePathKey;
                this._pfxPasswordKey = pfxPasswordKey;
                this._cerFilePathKey = cerFilePathKey;
                this._legacyCerFilePathKey = legacyCerFilePathKey;
            }

            /// <summary>Constructor（EC）</summary>
            /// <param name="alg">alg</param>
            /// <param name="es">JWS_ECDSA.ES</param>
            /// <param name="pfxFilePathKey">設定キー名（*.pfx のパス）</param>
            /// <param name="pfxPasswordKey">設定キー名（*.pfx のパスワード）</param>
            /// <param name="cerFilePathKey">設定キー名（*.cer のパス）</param>
            /// <param name="legacyCerFilePathKey">設定キー名（*.cer のパス。以前のキー）</param>
            internal Entry(string alg, JWS_ECDSA.ES es,
                string pfxFilePathKey, string pfxPasswordKey,
                string cerFilePathKey, string legacyCerFilePathKey)
            {
                this.Alg = alg;
                this._es = es;
                this._pfxFilePathKey = pfxFilePathKey;
                this._pfxPasswordKey = pfxPasswordKey;
                this._cerFilePathKey = cerFilePathKey;
                this._legacyCerFilePathKey = legacyCerFilePathKey;
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
            /// <remarks>**サーバ側のキーが空なら、以前のキー（`SpRp_*CerFilePath`）を読む**（#339）。</remarks>
            public string CerFilePath
            {
                get
                {
                    string value = GetConfigParameter.GetConfigValue(this._cerFilePathKey);

                    return string.IsNullOrEmpty(value)
                        ? GetConfigParameter.GetConfigValue(this._legacyCerFilePathKey) : value;
                }
            }

            /// <summary>設定キー名（*.cer のパス）</summary>
            public string CerFilePathKey
            {
                get { return this._cerFilePathKey; }
            }

            /// <summary>設定キー名（*.cer のパス。以前のキー）</summary>
            public string LegacyCerFilePathKey
            {
                get { return this._legacyCerFilePathKey; }
            }

            /// <summary>以前のキー（`SpRp_*CerFilePath`）だけで、証明書を読んでいるか</summary>
            /// <remarks>起動時の警告に使う（`ProductionCheck`。#339）。</remarks>
            public bool UsesLegacyCerFilePathKey
            {
                get
                {
                    return string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(this._cerFilePathKey))
                        && !string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(this._legacyCerFilePathKey));
                }
            }

            #endregion

            #region JWS

            /// <summary>署名する JWS を作る（*.pfx。秘密鍵が要る）</summary>
            /// <returns>JWS</returns>
            public JWS CreateJwsFromPfx()
            {
                return JwsFactory.CreateFromPfx(this.Alg, this.PfxFilePath, this.PfxPassword);
            }

            /// <summary>検証する JWS を作る（*.cer。公開鍵だけで足りる）</summary>
            /// <returns>JWS</returns>
            public JWS CreateJwsFromCer()
            {
                return JwsFactory.CreateFromCertificate(this.Alg, this.CerFilePath);
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

        /// <summary>この認可サーバが署名に使う鍵（alg ごとの設定キー）</summary>
        /// <remarks>
        /// **広告・発行・検証が見る alg の一覧は `JwsFactory.SupportedAlgs`**（#294）。
        /// **この表は、その全部に鍵を持つこと**（**`Of` が null を返す alg を広告しない**）。
        /// **増やすときは E2E の `RT-129.2`（受けない alg の一覧）も直すこと**
        /// （黙って広がらないようにするため）。
        /// </remarks>
        private static readonly Entry[] _entries = new Entry[]
        {
            // RSA（**1 本の鍵で 3 つの alg**。ダイジェストだけが違い、kid も同じ）
            new Entry(JwtConst.RS256,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.RS384,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.RS512,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),

            // RSA / RSASSA-PSS（**鍵は RS* と同じ 1 本**。パディングだけが違う。#129 の段階 4）
            new Entry(JwtConst.PS256,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.PS384,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),
            new Entry(JwtConst.PS512,
                "RsaPfxFilePath", "RsaPfxPassword", "RsaCerFilePath", "SpRp_RsaCerFilePath"),

            // EC（**曲線が alg に紐づく**ので、鍵が 3 本に分かれる）
            new Entry(JwtConst.ES256, JWS_ECDSA.ES._256,
                "EcdsaPfxFilePath", "EcdsaPfxPassword", "EcdsaCerFilePath", "SpRp_EcdsaCerFilePath"),
            new Entry(JwtConst.ES384, JWS_ECDSA.ES._384,
                "Ecdsa384PfxFilePath", "Ecdsa384PfxPassword", "Ecdsa384CerFilePath", "SpRp_Ecdsa384CerFilePath"),
            new Entry(JwtConst.ES512, JWS_ECDSA.ES._512,
                "Ecdsa512PfxFilePath", "Ecdsa512PfxPassword", "Ecdsa512CerFilePath", "SpRp_Ecdsa512CerFilePath")
        };

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

        /// <summary>この認可サーバの RSA の証明書（*.cer）のパス</summary>
        /// <remarks>
        /// **SAML2 のメタデータに載せる証明書**と、**自己テスト（SP 役）が応答を検証する証明書**（#339）。
        /// **RSA の 6 つの alg は同じ 1 本の鍵**なので、`RS256` の行を読む。
        /// </remarks>
        public static string RsaCerFilePath
        {
            get { return SigningKeys.Of(JwtConst.RS256).CerFilePath; }
        }

        /// <summary>以前のキー（`SpRp_*CerFilePath`）だけで読んでいる証明書（起動時の警告に使う。#339）</summary>
        /// <returns>「以前のキー → サーバ側のキー」の一覧（重複なし。無ければ空）</returns>
        public static List<KeyValuePair<string, string>> LegacyCerFilePathKeysStillUsed()
        {
            List<KeyValuePair<string, string>> used = new List<KeyValuePair<string, string>>();

            foreach (Entry entry in SigningKeys._entries)
            {
                KeyValuePair<string, string> pair =
                    new KeyValuePair<string, string>(entry.LegacyCerFilePathKey, entry.CerFilePathKey);

                if (entry.UsesLegacyCerFilePathKey && !used.Contains(pair))
                {
                    used.Add(pair);
                }
            }

            return used;
        }

        #endregion
    }
}
