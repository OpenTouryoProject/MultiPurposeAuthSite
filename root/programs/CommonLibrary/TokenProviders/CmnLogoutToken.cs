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
//* クラス名        ：CmnLogoutToken
//* クラス日本語名  ：logout_token（Back-Channel Logout 1.0 §2.4）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// CmnLogoutToken
    /// **ログアウトを RP へ伝えるトークン**を作る（#310 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **`id_token` に似ているが、別のトークンである**（Back-Channel Logout 1.0 §2.4）。
    ///
    /// | クレーム | 入れるか | 根拠 |
    /// |---|---|---|
    /// | `iss` / `aud` / `iat` / `jti` | **必ず** | §2.4（REQUIRED） |
    /// | `events` | **必ず**（`{"http://schemas.openid.net/event/backchannel-logout":{}}`） | §2.4（REQUIRED） |
    /// | `sub` / `sid` | **どちらか一方は必ず。** **この実装は両方入れる**（引ければ） | §2.4 |
    /// | `nonce` | **入れない**（**MUST NOT**） | §2.4 |
    /// | `exp` | **入れる**（短い） | **仕様は求めていない**が、**`iat` の新しさを見ない RP でも、使い回しを拒めるようにする** |
    ///
    /// **`typ` は `logout+jwt`**（§2.4 の RECOMMENDED）。
    /// **`id_token` と取り違えないための型**である
    /// （**RP が `id_token` の検証器にそのまま食わせると、`nonce` も `at_hash` も無い**）。
    ///
    /// **署名の鍵と `alg` は `id_token` と同じ**（`id_token_signed_response_alg` の登録に従う）。
    /// **RP は、どちらも同じ `jwks_uri` の鍵で検証できる。**
    /// </remarks>
    public class CmnLogoutToken
    {
        /// <summary>events クレームの名前（Back-Channel Logout 1.0 §2.4）</summary>
        public const string Events = "events";

        /// <summary>Back-Channel Logout の事象の型（Back-Channel Logout 1.0 §2.4）</summary>
        /// <remarks>**この URI は識別子である**（取りに行く先ではない）。</remarks>
        public const string BackChannelLogoutEvent
            = "http://schemas.openid.net/event/backchannel-logout";

        /// <summary>logout_token の寿命</summary>
        /// <remarks>
        /// **仕様は `exp` を求めていない**（§2.4 の一覧に無い）。
        /// **短くしてあるのは、拾われたトークンを使い回されないため**である
        /// （§2.6 は「`iat` が新しいことを確かめてもよい」としているが、**RP 任せ**になる）。
        /// </remarks>
        private static readonly TimeSpan ExpiresIn = TimeSpan.FromMinutes(2);

        /// <summary>logout_token を作る（#310 の段階 2）</summary>
        /// <param name="clientId">伝える相手（aud）</param>
        /// <param name="sub">その相手に名乗った sub（引けなければ空）</param>
        /// <param name="sid">その相手に名乗った sid</param>
        /// <returns>logout_token（作れなければ空）</returns>
        /// <remarks>
        /// **`sub` も `sid` も無ければ作らない**（§2.4 : **どちらか一方は必ず要る**）。
        /// **この実装では `sid` は必ず在る**（台帳の行から渡すため）。
        /// </remarks>
        public static string Create(string clientId, string sub, string sid)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                return "";
            }

            if (string.IsNullOrEmpty(sub) && string.IsNullOrEmpty(sid))
            {
                return "";
            }

            DateTimeOffset now = DateTimeOffset.Now;

            JObject payload = new JObject();

            payload.Add(OAuth2AndOIDCConst.iss, Config.IssuerId);
            payload.Add(OAuth2AndOIDCConst.aud, clientId);
            payload.Add(OAuth2AndOIDCConst.iat, now.ToUnixTimeSeconds());
            payload.Add(OAuth2AndOIDCConst.exp, now.Add(CmnLogoutToken.ExpiresIn).ToUnixTimeSeconds());
            payload.Add(OAuth2AndOIDCConst.jti, Guid.NewGuid().ToString("N"));

            if (!string.IsNullOrEmpty(sub))
            {
                payload.Add(OAuth2AndOIDCConst.sub, sub);
            }

            if (!string.IsNullOrEmpty(sid))
            {
                payload.Add(Const.Sid, sid);
            }

            // **events**（§2.4。**値は空のオブジェクト**）。
            JObject events = new JObject();
            events.Add(CmnLogoutToken.BackChannelLogoutEvent, new JObject());
            payload.Add(CmnLogoutToken.Events, events);

            //  **`nonce` は入れない**（§2.4 : MUST NOT）。
            //    **入れると「認証の応答」と区別が付かなくなる** —
            //    **RP が `id_token` として受け取ってサインインさせられる恐れが在る。**

            // 署名（**鍵は SigningKeys の表が持つ**。#129 の段階 3 / D-9）
            string alg = Helper.GetInstance().GetIdTokenSignedResponseAlg(clientId);
            SigningKeys.Entry key = SigningKeys.Of(alg);

            if (key == null)
            {
                // 扱わない alg（登録の入口で弾いてある）。
                return "";
            }

            JWS jws = key.CreateJwsFromPfx();

            // **`kid` は `id_token` と同じ引き方**（`CmnAccessToken.SelectJwsForSigning`）。
            //   **`jku` は入れない**（#302）。
            JObject jwk = key.JwkFromPfx();
            string kid = (string)jwk[JwtConst.kid];

            if (key.IsRsa)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
                ((JWS_RSA)jws).JWSHeader.typ = Const.LogoutJwtTyp;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
                ((JWS_ECDSA)jws).JWSHeader.typ = Const.LogoutJwtTyp;
            }

            return jws.Create(JsonConvert.SerializeObject(payload));
        }
    }
}
