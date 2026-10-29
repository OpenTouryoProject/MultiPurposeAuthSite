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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の 取り消し・照会エンドポイント
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util;

using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
# endif

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（取り消し・照会エンドポイント）</summary>
    public partial class CmnEndpoints
    {
        #region Revocation / Introspection Endpoint

        #region Public

        #region RevokeToken / IntrospectToken

        /// <summary>トークンを失効させる（RFC 7009）。クライアント認証は済んでいること。</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="token">失効させるトークン</param>
        /// <param name="token_type_hint">token_type_hint（任意）</param>
        /// <returns>成功なら空の辞書。他クライアントのトークンなら error を持つ辞書</returns>
        /// <remarks>
        /// 両アプリの /revoke から呼ぶ（#200 で Controller から移した）。
        /// ・無効なトークン（存在しない・失効済み・期限切れ）も成功として扱う（RFC 7009 2.2）（#200）
        /// ・他のクライアントのトークンは、要求を拒否してエラーを返す（RFC 7009 2.1）（#194）
        /// </remarks>
        public static Dictionary<string, string> RevokeToken(
            string client_id, string token, string token_type_hint)
        {
            Dictionary<string, string> err = new Dictionary<string, string>();

            foreach (string type in CmnEndpoints.TokenSearchOrder(token_type_hint))
            {
                if (type == OAuth2AndOIDCConst.AccessToken)
                {
                    // 検証（署名・期限・失効済みか）に通らなければ、access_token としては見つからない。
                    if (!CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                    {
                        continue;
                    }

                    // Tokenが呼び出し元に発行されたものかを確認（RFC 7009 2.1）（#194）
                    if (!CmnEndpoints.CheckTokenOwner(client_id, identity))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The token was not issued to this client.");
                        return err;
                    }

                    // access_token取消（jtiで記録する）
                    Claim jti = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnJwtIdClaim).FirstOrDefault<Claim>();

                    if (jti != null)
                    {
                        RevocationProvider.Create(jti.Value);
                    }

                    return err; // 成功（空）
                }
                else
                {
                    string tokenPayload = RefreshTokenProvider.Refer(token);

                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        continue;
                    }

                    // Tokenが呼び出し元に発行されたものかを確認（RFC 7009 2.1）（#194）
                    if (!CmnEndpoints.CheckRefreshTokenOwner(client_id, tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The token was not issued to this client.");
                        return err;
                    }

                    // refresh_token取消
                    RefreshTokenProvider.Delete(token);
                    return err; // 成功（空）
                }
            }

            // どの種類でも見つからない ＝ 無効なトークン。
            // 使えなくするという目的は達しているので、エラーにしない（RFC 7009 2.2）（#200）。
            return err;
        }

        /// <summary>トークンのメタデータを返す（RFC 7662）。クライアント認証は済んでいること。</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="token">問い合わせるトークン</param>
        /// <param name="token_type_hint">token_type_hint（任意）</param>
        /// <returns>active と、有効ならメタデータ</returns>
        /// <remarks>
        /// 両アプリの /introspect から呼ぶ（#200 で Controller から移した）。
        /// ・無効なトークン（存在しない・失効済み・期限切れ）は active=false（RFC 7662 2.2）（#200）
        /// ・他のクライアントのトークンも active=false だけを返す（RFC 7662 2.2 / 4）（#194）
        /// </remarks>
        public static Dictionary<string, object> IntrospectToken(
            string client_id, string token, string token_type_hint)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();

            foreach (string type in CmnEndpoints.TokenSearchOrder(token_type_hint))
            {
                string accessToken = token;

                if (type == OAuth2AndOIDCConst.RefreshToken)
                {
                    string tokenPayload = RefreshTokenProvider.Refer(token);

                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        continue;
                    }

                    // AccessToken化して、検証とメタデータの取り出しを共通化する。
                    // 有効期限を「現在時刻」にすると、作ってから検証するまでの間に秒をまたいだとき
                    // 失効扱いになる（VerifyExp は秒単位の exp >= now）。検証の間は持つ期限にする（#200）。
                    accessToken = CmnAccessToken.ProtectFromPayload(
                        "", tokenPayload, DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        null, OAuth2AndOIDCEnum.ClientMode.normal, out string aud, out string sub);
                }

                if (string.IsNullOrEmpty(accessToken)
                    || !CmnAccessToken.VerifyAccessToken(accessToken, out ClaimsIdentity identity))
                {
                    continue;
                }

                // Tokenが呼び出し元に発行されたものでなければ、
                // メタデータを返さない（RFC 7662 2.2 / 4）（#194）。
                if (!CmnEndpoints.CheckTokenOwner(client_id, identity))
                {
                    ret.Add(OAuth2AndOIDCConst.active, false);
                    return ret;
                }

                // メタデータの返却
                ret.Add(OAuth2AndOIDCConst.active, true);

                // **token_type は「トークンの型」**（RFC 6749 5.1 の bearer など）であって、
                //   見つかった種別（access_token / refresh_token）ではない（#218）。
                //   トークン応答（CreateAccessTokenResponse）と同じ値を返す。
                //   **リフレッシュ トークンには 5.1 の型が無いので、付けない**
                //   （RFC 7662 2.2 では OPTIONAL）。
                if (type == OAuth2AndOIDCConst.AccessToken)
                {
                    ret.Add(OAuth2AndOIDCConst.token_type, OAuth2AndOIDCConst.Bearer.ToLower());
                }

                string scopes = "";
                foreach (Claim claim in identity.Claims)
                {
                    if (!claim.Type.StartsWith(OAuth2AndOIDCConst.UrnClaimBase))
                    {
                        continue;
                    }

                    if (claim.Type == OAuth2AndOIDCConst.UrnScopesClaim)
                    {
                        scopes += claim.Value + " ";
                    }
                    else if (claim.Type.StartsWith(OAuth2AndOIDCConst.UrnCnfX5tClaim))
                    {
                        string temp = OAuth2AndOIDCConst.x5t
                            + claim.Type.Substring(OAuth2AndOIDCConst.UrnCnfX5tClaim.Length);
                        ret.Add(OAuth2AndOIDCConst.cnf, new Dictionary<string, string>()
                        {
                            { temp, claim.Value }
                        });
                    }
                    else
                    {
                        string name = claim.Type.Substring(OAuth2AndOIDCConst.UrnClaimBase.Length);

                        // refresh_token の exp / nbf / iat / jti は、上で作った一時的な access_token の値で、
                        // refresh_token 自身のものではない。誤解を招くので返さない（#200）。
                        if (type == OAuth2AndOIDCConst.RefreshToken
                            && (name == OAuth2AndOIDCConst.exp || name == OAuth2AndOIDCConst.nbf
                                || name == OAuth2AndOIDCConst.iat || name == OAuth2AndOIDCConst.jti))
                        {
                            continue;
                        }

                        ret.Add(name, claim.Value);
                    }
                }

                ret.Add(OAuth2AndOIDCConst.UrnScopesClaim.Substring(
                    OAuth2AndOIDCConst.UrnClaimBase.Length), scopes.Trim());

                return ret; // 成功
            }

            // どの種類でも見つからない ＝ 使えないトークン。
            // エラーではなく、問い合わせへの正常な答えとして active=false を返す（RFC 7662 2.2）（#200）。
            ret.Add(OAuth2AndOIDCConst.active, false);
            return ret;
        }

        #endregion

        #endregion

        #region Private

        #region Token所有者の確認

        /// <summary>Tokenが、認証したクライアントに発行されたものかを確認する</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="identity">ClaimsIdentity（VerifyAccessTokenの結果）</param>
        /// <returns>bool</returns>
        /// <remarks>RFC 7009 2.1 / RFC 7662 2.1（#194）</remarks>
        private static bool CheckTokenOwner(string client_id, ClaimsIdentity identity)
        {
            if (string.IsNullOrEmpty(client_id) || identity == null) return false;

            Claim aud = identity.Claims.Where(
                x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

            return (aud != null && aud.Value == client_id);
        }

        /// <summary>RefreshTokenが、認証したクライアントに発行されたものかを確認する</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="tokenPayload">RefreshTokenProvider.Referの結果</param>
        /// <returns>bool</returns>
        /// <remarks>RFC 7009 2.1（#194）</remarks>
        private static bool CheckRefreshTokenOwner(string client_id, string tokenPayload)
        {
            if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(tokenPayload)) return false;

            JObject payload = (JObject)JsonConvert.DeserializeObject(tokenPayload);

            return (payload != null
                && (string)payload[OAuth2AndOIDCConst.aud] == client_id);
        }

        #endregion

        #region TokenSearchOrder

        /// <summary>
        /// token_type_hint から、トークンを探す順番を決める。
        /// </summary>
        /// <param name="token_type_hint">token_type_hint（省略・未知の値は既定の順番）</param>
        /// <returns>探す順番（access_token / refresh_token）</returns>
        /// <remarks>
        /// ヒントは探す順番の手掛かりにすぎない。
        /// ヒントの種類で見つからなければ、他の種類も探す（RFC 7009 2.1 / RFC 7662 2.1）（#200）。
        /// </remarks>
        private static string[] TokenSearchOrder(string token_type_hint)
        {
            if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
            {
                return new string[] { OAuth2AndOIDCConst.RefreshToken, OAuth2AndOIDCConst.AccessToken };
            }

            return new string[] { OAuth2AndOIDCConst.AccessToken, OAuth2AndOIDCConst.RefreshToken };
        }

        #endregion

        #endregion

        #endregion
    }
}