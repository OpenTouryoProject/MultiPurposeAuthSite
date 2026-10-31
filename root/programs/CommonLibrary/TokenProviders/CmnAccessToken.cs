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
//* クラス日本語名  ：CmnAccessToken
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/25  西野 大介         新規
//*  2019/06/20  西野 大介         IssuedTokenProvider対応
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/03/17  西野 大介         CIBA対応実施 (ES256)
//*  2020/12/21  西野 大介         ClientMode追加対応実施
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/09/07  玄人 幸道         nonceをstateから捏造しないよう修正（#191）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/23  玄人 幸道         cnf を RFC 8705 の形式で書き、提示された証明書と照合する口を追加
//*  2026/09/25  玄人 幸道         profile / address のクレームを、設定の対応付けから返す（#230）
//*  2026/09/27  玄人 幸道         署名検証の鍵選択を切り出し、署名だけを検証する口を追加（#232）
//*  2026/10/02  玄人 幸道         受ける alg を自分が発行する 2 つに固定（C-8）（#129 の段階 1）
//*  2026/10/15  玄人 幸道         ヘッダにjkuを入れないようにした（#302）
//*  2026/10/18  玄人 幸道         クライアントの登録が在るかの確認を効かせた（#307 の段階 2）
//*  2026/10/21  玄人 幸道         sid クレームを載せ替えるようにした（#310 の段階 1）
//*  2026/10/21  玄人 幸道         cnf に jkt（DPoP）も書けるようにした（#311 の段階 1）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//*  2026/10/30  玄人 幸道         預ける refresh_token の payload に、利用者の SecurityStamp のハッシュを書く口を追加（#294）
//*  2026/10/31  玄人 幸道         partial に分割した（Create / Verify / Binding / SecurityStamp。#294）
//*  2026/10/31  玄人 幸道         S256 / S512 を readonly に（#294）
//**********************************************************************************

using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken</summary>
    public partial class CmnAccessToken
    {
        /// <summary>S256</summary>
        private static readonly string S256 = "#S256";
        /// <summary>S512</summary>
        private static readonly string S512 = "#S512";

        #region SelectJws

        #region SelectJwsForSigning

        /// <summary>署名に使う JWS を選ぶ（kid / typ まで入れて返す）</summary>
        /// <param name="alg">alg（SupportedAlgs のいずれか）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **鍵は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// **`RS256` / `RS384` / `RS512` は同じ RSA の鍵**で、**ダイジェストだけが違う。**
        /// **`ES256` / `ES384` / `ES512` は曲線が alg に紐づく**ので、**鍵が 3 本に分かれる。**
        ///
        /// **`kid` は鍵から作る**（RFC 7638）。
        /// RSA は kty / n / e から作るので **`RS256` / `RS384` / `RS512` で同じ値**になり、
        /// EC は crv / kty / x / y から作るので **曲線ごとに違う値**になる。
        /// ＝ **RP は `jwkcerts` に載っている鍵で、そのまま検証できる**
        /// （どのダイジェストかは、ヘッダの alg が伝える）。
        ///
        /// **既知でない alg では null を返す。** 入口（`CmnEndpoints.CheckClientMode`）で
        /// 弾いてあるので、ここへは来ない。
        /// </remarks>
        private static JWS SelectJwsForSigning(string alg)
        {
            SigningKeys.Entry key = SigningKeys.Of(alg);

            if (key == null)
            {
                return null;
            }

            JWS jws = key.CreateJwsFromPfx();

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            JObject jwk = key.JwkFromPfx();
            string kid = (string)jwk[JwtConst.kid];

            //  **`jku` は入れない**（#302。RFC 9068 / D-10）。
            //    **ヘッダに「鍵の在り処」を書くと、検証する側はその URL を取りに行く。**
            //    **出どころを発行者が自由に指し示せる**ことになり、
            //    **検証側の SSRF を誘発しうる。**
            //    **鍵は `kid` ＋ discovery の `jwks_uri` で引く**のが標準の経路である
            //    （この製品の検証は `CmnAccessToken.SelectJws` が `kid` で `JwkSet.json` を引く。
            //    Open棟梁 も `jku` を「非推奨」「廃止」と注記して読んでいない）。
            //  **`typ` は `at+jwt`**（#302 の段階 2。RFC 9068 §2.1）。
            //    **トークンの取り違え（token confusion）を防ぐ型**である
            //    （**id_token / Request Object / JARM は `JWT` のまま** — あちらは別の型）。
            //    **Open棟梁 [#611](https://github.com/OpenTouryoProject/OpenTouryo/issues/611) で
            //    署名の前に `typ` を設定できるようになった。** それまでは `readonly` だった。
            if (key.IsRsa)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
                ((JWS_RSA)jws).JWSHeader.typ = JwtConst.AT_JWT;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
                ((JWS_ECDSA)jws).JWSHeader.typ = JwtConst.AT_JWT;
            }

            return jws;
        }

        #endregion

        #region SelectJws（検証）

        /// <summary>JWT の署名を検証する鍵（JWS）を選ぶ（#232 で切り出し）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>JWS（決まらなければ null ＝ 検証失敗）</returns>
        /// <remarks>
        /// **ここで検証するのは「この認可サーバが発行したトークン」だけ**である
        /// （access_token / id_token / id_token_hint）。相手の OP が発行したものは通らない。
        ///
        /// **受ける alg を、自分が発行するものに固定する**（C-8。#129 の段階 1）。
        ///
        /// | ヘッダの alg | |
        /// |---|---|
        /// | `JwsFactory.SupportedAlgs` のいずれか | **受ける**（この認可サーバが発行しうる） |
        /// | それ以外（`none` / `HS256` / `HS384` など） | **即、検証失敗**（null を返す） |
        ///
        /// **以前は、知らない alg を RS256 として扱っていた。**
        /// 署名は自分の公開鍵で確かめるので偽造はできなかったが、
        /// **サーバが期待する alg を決めていなかった**（アルゴリズム混同の温床）。
        /// **alg の選択肢を増やす前に、受ける範囲を決めておく**（#129 の段階 2 以降）。
        ///
        /// **鍵は、alg に対応するものを選ぶ。**
        ///
        /// | ヘッダ | 使う鍵 |
        /// |---|---|
        /// | `kid` が空 | **自分の証明書**（alg に対応する方。RSA / ECDSA） |
        /// | `kid` が在る | **JWK Set の、その kid**。**JWK の alg がヘッダと一致すること** |
        /// | `kid` が JWK Set に無い | **自分の証明書**（alg に対応する方）に落とす |
        ///
        /// **kid を引けないときに証明書へ落とすのは、従来どおり**である
        /// （`JwkSet.json` を置いていない配備でも、自分の鍵で検証できる）。
        /// **以前は、そこで必ず RSA を選んでいた**ので、
        /// **ES256 で発行したトークンが検証できなかった。**
        /// </remarks>
        private static JWS SelectJws(string jwt)
        {
            JWS jws = null;

            // 証明書を使用するか、Jwkを使用するか判定
            // ヘッダの解析は、JWTでない文字列を渡されても例外にしない（#185）。
            Dictionary<string, string> header = null;
            try
            {
                string[] segments = jwt.Split('.');
                if (segments.Length == 3)
                {
                    header = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                        CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(segments[0]), CustomEncode.UTF_8));
                }
            }
            catch
            {
                // Base64Url、JSONとして壊れている ＝ 検証失敗として扱う。
                header = null;
            }

            if (header != null
                && header.ContainsKey(JwtConst.kid)
                && header.ContainsKey(JwtConst.alg))
            {
                string alg = header[JwtConst.alg];

                // **自分が発行する alg だけを受ける**（C-8。#129 の段階 1）。
                //   **一覧は 1 か所で持つ**（#129 の段階 2 で RS384 / RS512 を足した）。
                //   **それ以外の alg のトークンは、自分が発行したものではない。**
                if (!JwsFactory.IsSupported(alg))
                {
                    return null;
                }

                if (string.IsNullOrEmpty(header[JwtConst.kid]))
                {
                    // 証明書を使用（alg に対応する鍵）
                    jws = CmnAccessToken.SelectJwsFromCertificate(alg);
                }
                else
                {
                    JObject jwkObject = null;

                    if (ResourceLoader.Exists(OAuth2AndOIDCParams.JwkSetFilePath, false))
                    {
                        JwkSet jwkSetObject = JwkSet.LoadJwkSet(OAuth2AndOIDCParams.JwkSetFilePath);
                        jwkObject = JwkSet.GetJwkObject(jwkSetObject, header[JwtConst.kid]);
                    }

                    if (jwkObject == null)
                    {
                        // kid を引けなかった（JwkSet.json が無い、または載っていない kid）。
                        //   **証明書に落とす**（従来どおり）。**ただし alg に対応する鍵を選ぶ。**
                        jws = CmnAccessToken.SelectJwsFromCertificate(alg);
                    }
                    else if (!JwsFactory.IsSameKeyType(jwkObject, alg))
                    {
                        // **JWK の鍵の種類と、ヘッダの alg が食い違っている。**
                        //   どちらを信じるかという話にしないため、受けない。
                        return null;
                    }
                    else
                    {
                        // Jwkを使用（alg → class の対応は Open棟梁 の JwsFactory が持つ）
                        jws = JwsFactory.CreateFromJwk(alg, jwkObject);
                    }
                }
            }

            return jws;
        }

        /// <summary>自分の証明書から、alg に対応する JWS を作る（C-8。#129 の段階 1）</summary>
        /// <param name="alg">ヘッダの alg（SupportedAlgs のいずれか）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **呼ぶ前に alg を確かめてあること**（`SelectJws` が `SupportedAlgs` に限っている）。
        /// **公開鍵（.cer）で検証する。** 署名に使う秘密鍵（.pfx）は、ここでは要らない。
        /// **鍵は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// </remarks>
        private static JWS SelectJwsFromCertificate(string alg)
        {
            SigningKeys.Entry key = SigningKeys.Of(alg);

            return (key == null) ? null : key.CreateJwsFromCer();
        }

        #endregion

        #endregion
    }
}
