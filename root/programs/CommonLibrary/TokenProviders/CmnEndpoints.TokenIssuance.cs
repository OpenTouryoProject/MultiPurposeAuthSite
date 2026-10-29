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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の トークンの発行の共通部品（ロックアウト・CheckClientMode・DPoP・応答）
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
    /// <summary>CmnEndpoints（トークンの発行の共通部品（ロックアウト・CheckClientMode・DPoP・応答））</summary>
    public partial class CmnEndpoints
    {
        #region Common

        #region Private

        #region 利用者のロックアウト

        /// <summary>この配備で、利用者のロックアウトを使うか</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>使うなら true</returns>
        /// <remarks>
        /// **画面のサインインと同じ条件で判定する**（#305 の段階 4）。
        /// **`UserLockoutEnabledByDefault` が false の配備では、何もしない**
        /// （`SignInManager.PasswordSignInAsync` に渡している値と同じ）。
        /// </remarks>
        private static bool UserLockoutEnabled(ApplicationUser user)
        {
            return Config.UserLockoutEnabledByDefault
                && 0 < Config.MaxFailedAccessAttemptsBeforeLockout
                && CmnUserStore.GetLockoutEnabled(user);
        }

        /// <summary>いま、この利用者を断っているか</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>断っていれば true</returns>
        private static bool IsUserLockedOut(ApplicationUser user)
        {
            if (!CmnEndpoints.UserLockoutEnabled(user))
            {
                return false;
            }

            DateTimeOffset? lockoutEnd = CmnUserStore.GetLockoutEndDate(user);

            return lockoutEnd.HasValue && DateTimeOffset.UtcNow < lockoutEnd.Value;
        }

        /// <summary>パスワードの失敗を 1 回数える（上限に達したら断り始める）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// **`UserManager.AccessFailedAsync` と同じ段取り**にしてある
        /// （**上限に達したら期限を入れ、回数は 0 に戻す**）。
        /// **`CmnUserStore` の設定子は、物に書かない**ので、**`Update` で書く。**
        /// </remarks>
        private static void RecordUserAccessFailed(ApplicationUser user)
        {
            if (!CmnEndpoints.UserLockoutEnabled(user))
            {
                return;
            }

            int count = CmnUserStore.IncrementAccessFailedCount(user);

            if (Config.MaxFailedAccessAttemptsBeforeLockout <= count)
            {
                CmnUserStore.SetLockoutEndDate(user,
                    DateTimeOffset.UtcNow.Add(Config.DefaultAccountLockoutTimeSpanFromSeconds));

                CmnUserStore.ResetAccessFailedCount(user);

                //  **断り始めた 1 回だけ、ログに残す。**
                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) was locked out. (too many password failures at the token endpoint)",
                    user.Id, user.UserName));
            }

            CmnUserStore.Update(user);
        }

        /// <summary>成功したので、数えた分を消す</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>**書くことが無ければ、書かない**（成功のたびに UPDATE を撃たない）。</remarks>
        private static void ResetUserAccessFailed(ApplicationUser user)
        {
            if (!CmnEndpoints.UserLockoutEnabled(user))
            {
                return;
            }

            if (CmnUserStore.GetAccessFailedCount(user) == 0
                && !CmnUserStore.GetLockoutEndDate(user).HasValue)
            {
                return;
            }

            CmnUserStore.ResetAccessFailedCount(user);
            CmnUserStore.SetLockoutEndDate(user, null);

            CmnUserStore.Update(user);
        }

        #endregion

        #region CheckClientMode

        /// <summary>CheckClientMode</summary>
        /// <param name="client_id">ClientId</param>
        /// <param name="flow">経路</param>
        /// <param name="proof">その要求で、クライアントが何を証明したか</param>
        /// <param name="clientMode">クライアントに登録されたClientMode</param>
        /// <param name="jwkString">jwkString</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>継続の可否</returns>
        /// <remarks>
        /// **「経路 × 証明 → 通す登録種別」を ClientModePolicy の表で引く（#224 の段階 1）。**
        /// 以前は水準（permittedLevel）との大小で判定していた。表は、その判定をそのまま展開したもので、
        /// **判定の結果は 1 つも変えていない**（全組み合わせを突き合わせて確認した）。
        ///
        /// **トークンに載せるクレームは clientMode を使う**（#220）。
        ///
        /// 段階 2 で、拒否のエラー コードを unauthorized_client に改め（以前は unsupported_grant_type）、
        /// **既知でない登録値は fapi2 とみなさず、不正として拒否する**ようにした。
        /// </remarks>
        private static bool CheckClientMode(
            string client_id,
            ClientModePolicy.Flow flow,
            ClientModePolicy.Proof proof,
            out OAuth2AndOIDCEnum.ClientMode clientMode,
            out string jwkString,
            out Dictionary<string, string> err)
        {
            // out
            jwkString = "";
            err = new Dictionary<string, string>();
            clientMode = OAuth2AndOIDCEnum.ClientMode.normal;

            if (string.IsNullOrEmpty(client_id))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                err.Add(OAuth2AndOIDCConst.error_description, string.Format("client_id is not set."));
                return false; // NullOrEmptyだとmode無しとかになるのでここで切る。
            }

            // **登録された署名 alg が、扱える値かを確かめる**（#129 の段階 2）。
            //   **既知でない値は、不正な登録として拒否する**（#224 と同じ方針）。
            //   ここで止めないと、**発行の直前で既定（RS256）に落ちて、設定の誤りが分からない。**
            string signingAlg = Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id);

            if (!JwsFactory.IsSupported(signingAlg))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The registered id_token_signed_response_alg is not supported.");
                return false;
            }

            // **登録で許されたグラントか**（RFC 7591 §2 の `grant_types`。#307 の段階 1）。
            //   **`ClientModePolicy` の手前で絞る。**
            //   **登録が無ければ絞らない**（既存の登録を壊さないため）。
            //   RFC 6749 §5.2 : 認証済みのクライアントに許されていないグラントは unauthorized_client。
            if (!CmnEndpoints.CheckClientGrantType(client_id, flow))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "This grant_type is not registered for this client.");
                return false;
            }

            // 登録された種別
            string clientModeString = Helper.GetInstance().GetClientMode(client_id);

            // RFC 6749 5.2 : 認証済みのクライアントに許されていないグラントは unauthorized_client。
            //   以前は unsupported_grant_type（サーバがそのグラントを扱わない、の意）を返していた（#224 の段階 2）。
            if (!ClientModePolicy.TryParse(clientModeString, out clientMode))
            {
                // **既知のどれにも当たらない登録値（空・書き間違い）は、不正な登録として拒否する。**
                //   以前は fapi2 とみなしていた（#224 の段階 2）。
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);

                if (string.IsNullOrEmpty(clientModeString))
                {
                    err.Add(OAuth2AndOIDCConst.error_description, "This client is not set the mode.");
                }
                else
                {
                    err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                        "The mode of this client ({0}) is invalid.", clientModeString));
                }

                return false;
            }

            if (clientModeString == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
            {
                // fapi2 の登録は、JWK（RSA 公開鍵）も読む
                jwkString = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                    Helper.GetInstance().GetJwkRsaPublickey(client_id)), CustomEncode.us_ascii);
            }

            if (ClientModePolicy.IsAllowed(clientMode, flow, proof))
            {
                return true;
            }

            // エラーを追加（説明文は水準の言い回しをやめた。#224）
            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
            err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                "This client ({0}) is not allowed to use this flow.", clientModeString));

            return false;
        }

        #endregion

        #region DPoP（#311 の段階 1）

        /// <summary>DPoP の証明が在れば検証する（#311 の段階 1）</summary>
        /// <param name="dPoPProof">`DPoP` ヘッダの値（無ければ空）</param>
        /// <param name="jkt">out : 鍵の指紋（証明が無ければ空）</param>
        /// <param name="err">エラーを入れる辞書</param>
        /// <returns>続けてよければ true</returns>
        /// <remarks>
        /// **証明が無ければ、何もしないで true を返す** —
        /// **DPoP を使わないクライアントは、従来どおり bearer** である
        /// （**既定の挙動を変えない**）。
        ///
        /// **証明が在って通らなければ、`invalid_dpop_proof` で断る**（RFC 9449 §5）。
        /// **黙って bearer に落とさない** — **落とすと、縛ったつもりのクライアントが縛られない。**
        ///
        /// **nonce を要求する配備では、`nonce` も見る**（§8。#311 の段階 4）。
        /// **通らなければ `use_dpop_nonce`** であり、**`invalid_dpop_proof` とは区別する** —
        /// **クライアントは「貰い直して出し直す」ことになる。**
        ///
        /// **`htu` は設定から作る**（`CmnDPoP.TokenEndpointUri`。**要求の `Host` を信じない**）。
        /// </remarks>
        private static bool CheckDPoP(
            string dPoPProof, out string jkt, Dictionary<string, string> err)
        {
            jkt = "";

            if (string.IsNullOrEmpty(dPoPProof))
            {
                return true;
            }

            if (CmnDPoP.Verify(dPoPProof, "POST", CmnDPoP.TokenEndpointUri, CmnDPoP.PurposeAs,
                out jkt, out string error, out string errDescription))
            {
                return true;
            }

            //  **nonce が要るときは `use_dpop_nonce` で断る**（RFC 9449 §8。#311 の段階 4）。
            //    **応答の `DPoP-Nonce` ヘッダで新しい値を渡す**（各アプリの `OAuth2Error`）。
            err.Add(OAuth2AndOIDCConst.error, error);
            err.Add(OAuth2AndOIDCConst.error_description, errDescription);

            return false;
        }

        #endregion

        #region DPoP の鍵への紐づけ（#311 の段階 4）

        /// <summary>この code が鍵に縛られていないか、同じ鍵の証明が在るか（RFC 9449 §10）</summary>
        /// <param name="code">認可コード</param>
        /// <param name="jkt">この要求の証明の鍵の指紋（証明が無ければ空）</param>
        /// <param name="err">エラーを入れる辞書</param>
        /// <returns>続けてよければ true</returns>
        /// <remarks>
        /// **認可要求で `dpop_jkt` を送っていたら、その鍵でしか引き換えられない。**
        /// **送っていなければ、何も変わらない**（**既定の挙動を変えない**）。
        /// </remarks>
        private static bool CheckDPoPJktOfCode(
            string code, string jkt, Dictionary<string, string> err)
        {
            return CmnEndpoints.CheckDPoPJkt(
                AuthorizationCodeProvider.GetDPoPJkt(code), jkt, "code", err);
        }

        /// <summary>この refresh_token が鍵に縛られていないか、同じ鍵の証明が在るか（RFC 9449 §5）</summary>
        /// <param name="refresh_token">refresh_token</param>
        /// <param name="jkt">この要求の証明の鍵の指紋（証明が無ければ空）</param>
        /// <param name="err">エラーを入れる辞書</param>
        /// <returns>続けてよければ true</returns>
        /// <remarks>
        /// **預けた payload の `cnf.jkt` を見る**（`CmnAccessToken.JktOfPayload`）。
        /// **消費しないで読む**（`RefreshTokenProvider.Refer`） —
        /// **ローテーションを起こさずに断る**ためである。
        ///
        /// **使用済み・存在しない refresh_token では空が返る** →
        /// **ここは通り、後の `Receive` が `invalid_grant` で断る**（**従来の断り方を変えない**）。
        /// </remarks>
        private static bool CheckDPoPJktOfRefreshToken(
            string refresh_token, string jkt, Dictionary<string, string> err)
        {
            return CmnEndpoints.CheckDPoPJkt(
                CmnAccessToken.JktOfPayload(RefreshTokenProvider.Refer(refresh_token)),
                jkt, "refresh_token", err);
        }

        /// <summary>縛られているなら、同じ鍵の証明が在るか（#311 の段階 4）</summary>
        /// <param name="boundJkt">縛られている鍵の指紋（縛られていなければ空）</param>
        /// <param name="jkt">この要求の証明の鍵の指紋（証明が無ければ空）</param>
        /// <param name="what">何が縛られているか（`code` / `refresh_token`）</param>
        /// <param name="err">エラーを入れる辞書</param>
        /// <returns>続けてよければ true</returns>
        /// <remarks>
        /// **`invalid_grant` で断る**（`invalid_dpop_proof` ではない）。
        /// **証明そのものは正しく、「この資格情報のものではない」**のであり、
        /// **断られているのは grant の側**である。
        /// **証明の作りが悪いのか、持ち主が違うのかを、クライアントが区別できる。**
        ///
        /// **理由はログに残すが、指紋は出さない**（**そのクライアントを辿れる値**である）。
        /// </remarks>
        private static bool CheckDPoPJkt(
            string boundJkt, string jkt, string what, Dictionary<string, string> err)
        {
            if (string.IsNullOrEmpty(boundJkt))
            {
                // **縛られていない** ＝ 従来どおり。
                return true;
            }

            if (string.Equals(boundJkt, jkt, StringComparison.Ordinal))
            {
                return true;
            }

            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
            err.Add(OAuth2AndOIDCConst.error_description,
                string.IsNullOrEmpty(jkt)
                    ? ("A DPoP proof is required for this " + what + ".")
                    : ("The " + what + " is bound to another DPoP key."));

            Logging.MyOperationTrace(string.Format(
                "The {0} is bound to a DPoP key. ({1})", what,
                string.IsNullOrEmpty(jkt) ? "no proof" : "another key"));

            return false;
        }

        #endregion

        #region CreateAccessTokenResponse

        /// <summary>CreateAccessTokenResponse</summary>
        /// <param name="access_token">string</param>
        /// <param name="refresh_token">string</param>
        /// <param name="jwkString">string</param>
        /// <param name="jkt">DPoP の鍵の指紋（#311 の段階 1。無ければ空）</param>
        /// <returns>Dictionary(string, string)</returns>
        /// <remarks>
        /// **`token_type` は、縛ったかどうかで変わる**（RFC 9449 §5）。
        ///
        /// | | `token_type` |
        /// |---|---|
        /// | **DPoP の証明が通った** | **`DPoP`** |
        /// | それ以外 | `bearer`（従来どおり） |
        ///
        /// **クライアントは `token_type` を見て、使うときの出し方を決める**
        /// （`Authorization: DPoP …` ＋ 証明。**段階 2 で照合する**）。
        /// </remarks>
        private static Dictionary<string, string> CreateAccessTokenResponse(
            string access_token, string refresh_token, string jwkString, string jkt = null)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();

            // token_type
            ret.Add(OAuth2AndOIDCConst.token_type,
                string.IsNullOrEmpty(jkt)
                    ? OAuth2AndOIDCConst.Bearer.ToLower() : OAuth2AndOIDCConst.DPoP);

            // access_token
            ret.Add(OAuth2AndOIDCConst.AccessToken, access_token);

            // refresh_token
            if (!string.IsNullOrEmpty(refresh_token))
            {
                ret.Add(OAuth2AndOIDCConst.RefreshToken, refresh_token);
            }

            // ヘッダ
            JObject jObjHeader = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[0]), CustomEncode.us_ascii));
            // ペイロード
            JObject jObjPayload = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[1]), CustomEncode.us_ascii));

            // id_token
            JArray jAry = (JArray)jObjPayload[OAuth2AndOIDCConst.scopes];

            foreach (string s in jAry)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    string id_token = "";
                    if (string.IsNullOrEmpty(jwkString))
                    {
                        // JWS
                        //   **access_token のヘッダ alg に揃える**（#129 の段階 2）。
                        //   **渡さないと既定（RS256）に落ちて、access_token と食い違う。**
                        //   **鍵は alg から引く**（#129 の段階 3）ので、ここで alg ごとに分けない。
                        id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                            access_token, "", "", // c_hash, s_hash は /token で生成不可
                            HashClaimType.None, CmnServerParams.RsaPfxFilePath, CmnServerParams.RsaPfxPassword, "",
                            (string)jObjHeader[JwtConst.alg]);
                    }
                    else
                    {
                        // JWE
                        id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                            access_token, "", "", // c_hash, s_hash は /token で生成不可
                            HashClaimType.None, Config.EcdsaPfxFilePath, Config.EcdsaPfxPassword, jwkString);
                    }

                    if (!string.IsNullOrEmpty(id_token))
                    {
                        ret.Add(OAuth2AndOIDCConst.IDToken, id_token);
                    }
                }
            }

            // expires_in
            ret.Add(OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString());

            // scope
            // 発行したスコープを返す。要求と異なる場合は必須（RFC 6749 5.1）。
            // scopes_supported に無いスコープは発行しないので、要求と異なることがある（#198）。
            List<string> issued = new List<string>();
            foreach (string s in jAry)
            {
                if (!string.IsNullOrEmpty(s))
                {
                    issued.Add(s);
                }
            }

            if (issued.Count > 0)
            {
                ret.Add(OAuth2AndOIDCConst.scope, string.Join(" ", issued));
            }

            return ret;
        }

        #endregion

        #endregion

        #endregion
    }
}