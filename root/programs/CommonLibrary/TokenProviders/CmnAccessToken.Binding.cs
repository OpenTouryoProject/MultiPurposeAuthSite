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
//* クラス名        ：CmnAccessToken
//* クラス日本語名  ：CmnAccessToken の 鍵への紐づけ（cnf。DPoP・mTLS）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（CmnAccessToken.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken（鍵への紐づけ（cnf。DPoP・mTLS））</summary>
    public partial class CmnAccessToken
    {
        #region Binding

        #region cnf

        /// <summary>cnf（鍵への紐づけ）を書く（RFC 8705 §3.1 / RFC 9449 §6）</summary>
        /// <param name="payload">access_token の payload</param>
        /// <param name="x509">クライアント証明書（mTLS。無ければ null）</param>
        /// <param name="jkt">DPoP の鍵の指紋（無ければ空）</param>
        /// <remarks>
        /// **どちらも「このトークンは、この鍵の持ち主のものだ」という印**である。
        ///
        /// | 入れるもの | いつ | 根拠 |
        /// |---|---|---|
        /// | `x5t#S256` | **クライアント証明書が提示されたとき**（mTLS） | RFC 8705 §3.1 |
        /// | `jkt` | **DPoP の証明が通ったとき** | RFC 9449 §6 |
        ///
        /// **両方在れば、両方書く。** **どちらを要求するかは、照合する側が決める**
        /// （**mTLS の照合は `VerifyCertificateBinding`**。**DPoP の照合は段階 2**）。
        ///
        /// **どちらも無ければ `cnf` を書かない** ＝ **従来どおり bearer** である。
        ///
        /// **RFC 8705 §3.1 の `x5t#S256` は、証明書（DER）の SHA-256 を BASE64URL したもの。**
        /// 以前は SHA-1 のサムプリント（16 進）を入れ、キーの #S256 / #S512 も
        /// **証明書の署名アルゴリズム**で選んでいた。どちらも仕様と違い、
        /// RFC のとおりに照合するリソース サーバとは紐づけが一致しない。
        /// </remarks>
        private static void WriteCnf(JObject payload, X509Certificate2 x509, string jkt)
        {
            JObject cnf = new JObject();

            if (x509 != null)
            {
                cnf.Add(OAuth2AndOIDCConst.x5t + CmnAccessToken.S256,
                    CmnAccessToken.ComputeCertificateThumbprint(x509));
            }

            if (!string.IsNullOrEmpty(jkt))
            {
                cnf.Add(OAuth2AndOIDCConst.jkt, jkt);
            }

            if (cnf.Count == 0)
            {
                //  **書くものが無ければ、残っている `cnf` を落とす**（#311 の段階 4）。
                //    **`refresh_token` に預けた payload は `cnf.jkt` を持つ**ようになったので、
                //    **そのまま通すと「証明なしの要求で、縛られたトークンが出る」**ことになる。
                //    **いまは縛られた `refresh_token` を証明なしでは使わせない**ので通らないが、
                //    **印の出どころを 1 つに保つ**（**書くのはこの関数だけ**）。
                payload.Remove(OAuth2AndOIDCConst.cnf);

                return;
            }

            payload[OAuth2AndOIDCConst.cnf] = cnf;
        }

        #endregion

        #region DPoP（RFC 9449）

        /// <summary>トークンに書かれた `cnf.jkt`（無ければ空）（#311 の段階 2）</summary>
        /// <param name="identity">VerifyAccessToken が返した ClaimsIdentity</param>
        /// <returns>jkt（縛られていなければ空）</returns>
        public static string JktOf(ClaimsIdentity identity)
        {
            if (identity == null)
            {
                return "";
            }

            Claim jkt = identity.Claims.FirstOrDefault(x => x.Type == Const.UrnCnfJktClaim);

            return (jkt == null) ? "" : (jkt.Value ?? "");
        }

        /// <summary>
        /// トークンの `cnf.jkt`（鍵への紐づけ）と、提示された DPoP の証明を照合する（RFC 9449 §7.1）
        /// </summary>
        /// <param name="identity">VerifyAccessToken が返した ClaimsIdentity</param>
        /// <param name="accessToken">提示された access_token</param>
        /// <param name="proof">`DPoP` ヘッダの値（**`DPoP` スキームでなければ空を渡すこと**）</param>
        /// <param name="htm">この要求の HTTP メソッド（**大文字**）</param>
        /// <param name="htu">この口の宛先</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **鍵に縛ったトークンは、その鍵で署名した証明と一緒でしか使えない。**
        /// **縛っていないトークン（`cnf.jkt` 無し）は、これまでどおり bearer として扱う**
        /// （**mTLS の `VerifyCertificateBinding` と同じ形**）。
        ///
        /// **縛っているのに証明が無い要求は拒否する。**
        /// **`Bearer` スキームで出してきた要求も拒否する**（呼び出し側が空を渡す） —
        /// **縛りを「使う側の出し方」で外せてはいけない。**
        /// </remarks>
        public static bool VerifyDPoPBinding(
            ClaimsIdentity identity, string accessToken,
            string proof, string htm, string htu, out string error)
        {
            error = null;

            string boundJkt = CmnAccessToken.JktOf(identity);

            if (string.IsNullOrEmpty(boundJkt))
            {
                // 縛っていないトークン
                return true;
            }

            if (CmnDPoP.VerifyForResource(
                proof, htm, htu, accessToken, boundJkt, out string dpopError, out string _))
            {
                return true;
            }

            //  **`use_dpop_nonce` だけは、呼び出し側に伝える**（RFC 9449 §9。#311 の段階 4）。
            //    **クライアントは「nonce を貰い直して出し直す」ことになる** —
            //    **`invalid_token` と区別できなければ、出し直す理由が分からない。**
            error = dpopError;

            return false;
        }

        /// <summary>預ける payload に、DPoP の鍵の指紋を書く / 落とす（#311 の段階 4）</summary>
        /// <param name="payload">access_token の payload（JSON の文字列）</param>
        /// <param name="jkt">DPoP の鍵の指紋（**空なら落とす**）</param>
        /// <returns>書き換えた payload（読めなければ、受け取ったものをそのまま返す）</returns>
        /// <remarks>
        /// **`refresh_token` を鍵に縛るため**である（RFC 9449 §5）。
        /// **預ける payload に印を残しておかないと、次に使われたときに
        /// 「縛られていたのか」が分からない。**
        ///
        /// **`cnf` を丸ごと置き換えない** — **`jkt` だけを足す / 落とす。**
        /// **mTLS の印（`x5t#S256`）と同じ場所**であり、**巻き込んで消さない。**
        /// </remarks>
        public static string BindJkt(string payload, string jkt)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return payload;
            }

            try
            {
                JObject jobj = (JObject)JsonConvert.DeserializeObject(payload);

                if (jobj == null)
                {
                    return payload;
                }

                JObject cnf = jobj[OAuth2AndOIDCConst.cnf] as JObject;

                if (string.IsNullOrEmpty(jkt))
                {
                    if (cnf == null)
                    {
                        return payload;
                    }

                    cnf.Remove(OAuth2AndOIDCConst.jkt);

                    if (cnf.Count == 0)
                    {
                        jobj.Remove(OAuth2AndOIDCConst.cnf);
                    }
                }
                else
                {
                    if (cnf == null)
                    {
                        cnf = new JObject();
                        jobj[OAuth2AndOIDCConst.cnf] = cnf;
                    }

                    cnf[OAuth2AndOIDCConst.jkt] = jkt;
                }

                return JsonConvert.SerializeObject(jobj);
            }
            catch (Exception)
            {
                // **読めない payload は、そのまま返す**（この関数で要求を止めない）。
                return payload;
            }
        }

        /// <summary>預かった payload に書かれた DPoP の鍵の指紋（#311 の段階 4）</summary>
        /// <param name="payload">access_token の payload（JSON の文字列）</param>
        /// <returns>`cnf.jkt`（無ければ空）</returns>
        /// <remarks>
        /// **`refresh_token` が縛られているか**を見るために読む。
        /// **空なら縛られていない** ＝ **これまでどおり、証明なしでも使える。**
        /// </remarks>
        public static string JktOfPayload(string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return "";
            }

            try
            {
                JObject jobj = (JObject)JsonConvert.DeserializeObject(payload);
                JObject cnf = (jobj == null) ? null : jobj[OAuth2AndOIDCConst.cnf] as JObject;

                return (cnf == null) ? "" : ((string)cnf[OAuth2AndOIDCConst.jkt] ?? "");
            }
            catch (Exception)
            {
                // **読めなければ、縛られていないものとして扱う**（従来の挙動に倒す）。
                return "";
            }
        }

        #endregion

        #region mTLS（RFC 8705）

        /// <summary>証明書（DER）の SHA-256 を BASE64URL した値（RFC 8705 3.1 の x5t#S256）</summary>
        /// <param name="x509">クライアント証明書</param>
        /// <returns>BASE64URL の文字列</returns>
        private static string ComputeCertificateThumbprint(X509Certificate2 x509)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(sha256.ComputeHash(x509.RawData));
            }
        }

        /// <summary>
        /// トークンの cnf（証明書への紐づけ）と、提示されたクライアント証明書を照合する（RFC 8705 3）
        /// </summary>
        /// <param name="identity">VerifyAccessToken が返した ClaimsIdentity</param>
        /// <param name="x509">TLS で提示されたクライアント証明書（無ければ null）</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **証明書に紐づけたトークン（sender-constrained）は、その証明書を提示した要求でしか使えない。**
        /// RFC 8705 3 は、保護されたリソースに照合を求めている。
        /// 紐づいていないトークン（cnf 無し）は、これまでどおり bearer として扱う。
        ///
        /// **紐づいているのに証明書が無い要求は拒否する。** 以前は照合しておらず、
        /// 漏えいしたトークンを証明書なしで使えた。
        /// </remarks>
        public static bool VerifyCertificateBinding(ClaimsIdentity identity, X509Certificate2 x509)
        {
            if (identity == null)
            {
                return false;
            }

            Claim cnf = identity.Claims.FirstOrDefault(
                x => x.Type.StartsWith(OAuth2AndOIDCConst.UrnCnfX5tClaim));

            if (cnf == null)
            {
                // 紐づいていないトークン
                return true;
            }

            if (x509 == null)
            {
                // 紐づいているのに、証明書が提示されていない
                return false;
            }

            string expected = "";

            if (cnf.Type == OAuth2AndOIDCConst.UrnCnfX5tClaim + CmnAccessToken.S256)
            {
                expected = CmnAccessToken.ComputeCertificateThumbprint(x509);
            }
            else
            {
                // 未知の方式（#S512 など）は、照合できないので通さない
                return false;
            }

            return string.Equals(cnf.Value, expected, StringComparison.Ordinal);
        }

        #endregion

        #endregion
    }
}
