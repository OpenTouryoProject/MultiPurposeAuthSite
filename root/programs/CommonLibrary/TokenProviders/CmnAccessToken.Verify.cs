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
//* クラス日本語名  ：CmnAccessToken の 検証
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（CmnAccessToken.cs から partial に分割。#294）
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Security.Claims;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken（検証）</summary>
    public partial class CmnAccessToken
    {
        #region Verify

        /// <summary>JWT の署名だけを検証する（#232）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>この認可サーバの鍵で署名されていれば true</returns>
        /// <remarks>
        /// **id_token_hint の検証に使う**（RP-Initiated Logout 1.0 §2）。
        /// そちらは **exp が切れていても受ける**（SHOULD）ため、
        /// 期限・失効まで見る VerifyAccessToken は使えない。
        /// **iss や aud の確認は、呼び出し側が行う。**
        /// </remarks>
        public static bool VerifySignature(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return false;
            }

            JWS jws = CmnAccessToken.SelectJws(jwt);

            //  **こちらは `id_token` なので `JWT` を期待する**（#302 の段階 2）。
            //    **`id_token_hint` に access_token を渡されても、ここで落ちる。**
            return jws != null && jws.Verify(jwt, JwtConst.JWT);
        }

        /// <summary>Verify</summary>
        /// <param name="jwt">string</param>
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>検証結果</returns>
        public static bool VerifyAccessToken(string jwt, out ClaimsIdentity identity)
        {
            JObject claims = null;
            return CmnAccessToken.VerifyAccessToken(jwt, out claims, out identity);
        }

        /// <summary>Verify</summary>
        /// <param name="jwt">string</param>
        /// <param name="claims">out JObject</param>
        /// <param name="identity">out ClaimsIdentity</param>
        /// <returns>検証結果</returns>
        public static bool VerifyAccessToken(string jwt, out JObject claims, out ClaimsIdentity identity)
        {
            claims = null; // = new JObject();
            // JObjectのnull対策は内包するCollectionの型自体が変わるので上手く行かない。
            // ≒ OAuth2EndpointController.GetUserClaimsでのnullチェックは必要。

            identity = new ClaimsIdentity();

            if (!string.IsNullOrEmpty(jwt))
            {
                // 検証（鍵の選択は SelectJws に切り出した。#232）
                JWS jws = CmnAccessToken.SelectJws(jwt);

                //  **`typ` は `at+jwt` を期待する**（#302 の段階 2。RFC 9068 §4）。
                //    **リソース サーバは、access_token 以外の JWT を受け取ったら拒否する。**
                //    **id_token や Request Object が流れ込んでも、ここで落ちる。**
                //    **Open棟梁 の既定（引数なしの `Verify`）は照合しない**ので、
                //    **期待値は呼ぶ側が決める**（Open棟梁 #611 の決め事）。
                // jwsが決まらなかった場合（kid無し、ヘッダ破損など）は検証失敗（#185）。
                if (jws != null && jws.Verify(jwt, JwtConst.AT_JWT))
                {
                    // 検証できた。

                    // デシリアライズ、
                    string[] temp = jwt.Split('.');
                    string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                    Dictionary<string, object> tokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                    DateTime? datetime = RevocationProvider.Get((string)tokenClaimSet[OAuth2AndOIDCConst.jti]);

                    if (datetime == null)
                    {
                        // iss, expの検証
                        //  **クライアントの登録が、まだ在ること**（#307 の段階 2）。
                        //    **撤去されたクライアントのトークンを、期限まで通してはならない**
                        //    （RFC 7592 §2.3 : 削除したら、そのクライアントのトークンを無効にすべき）。
                        //
                        //  **以前は `GetClientSecret(aud) != null` だったが、効いていなかった** —
                        //    **`GetClientSecret` は、未登録でも `""` を返す**ので、**常に真**だった。
                        //    **`IsNullOrEmpty` にもしない** — **秘密を持たない public クライアントが止まる。**
                        if ((string)tokenClaimSet[OAuth2AndOIDCConst.iss] == CmnServerParams.IssuerId
                            && Helper.GetInstance().HasClient((string)tokenClaimSet[OAuth2AndOIDCConst.aud])
                            // CmnJwtToken.VerifyExpはstring引数のみ。expは数値になったのでToStringで渡す
                            // （文字列で発行された過去のTokenも、そのまま通る）。
                            && CmnJwtToken.VerifyExp(tokenClaimSet[OAuth2AndOIDCConst.exp].ToString()))
                        {
                            // claims
                            if(tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.claims))
                                claims = (JObject)tokenClaimSet[OAuth2AndOIDCConst.claims];

                            // subの検証
                            // ApplicationUser を取得する。
                            string subjectTypes = "";
                            ApplicationUser user = PPIDExtension.GetUserFromSub(
                                (string)tokenClaimSet[OAuth2AndOIDCConst.aud],
                                (string)tokenClaimSet[OAuth2AndOIDCConst.sub],
                                out subjectTypes);
                            //CmnUserStore.FindByName((string)tokenClaimSet[OAuth2AndOIDCConst.sub]); // 同期版でOK。

                            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                            {
                                // PPIDの場合
                                CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                return true;
                            }
                            else
                            {
                                if (user != null)
                                {
                                    // User Accountの場合
                                    CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                    return true;
                                }
                                else
                                {
                                    // Client Accountの場合

                                    // ClaimとStoreのAudience(aud)に対応するSubject(sub)が一致するかを確認し、一致する場合のみ、認証する。
                                    // ※ でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                                    if ((string)tokenClaimSet[OAuth2AndOIDCConst.sub]
                                        == Helper.GetInstance().GetClientName((string)tokenClaimSet[OAuth2AndOIDCConst.aud]))
                                    {
                                        CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                        return true;
                                    }
                                }
                            }
                        }
                        else
                        {
                            // クレーム検証の失敗
                        }
                    }
                    else
                    {
                        // 取り消し済み
                    }
                }
                else
                {
                    // JWT署名検証の失敗
                }
            }
            else
            {
                // 引数に問題
            }

            return false;
        }

        #endregion
    }
}
