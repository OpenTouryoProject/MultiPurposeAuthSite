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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の CIBA の受付
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         壊れた request で 500 にしない。文言・定数の置き場所・using を直した（#294）
//*  2026/10/29  玄人 幸道         poll では client_notification_token を要らず、binding_message を任意にした（#294）
//*  2026/10/30  玄人 幸道         CIBA の requested_expiry を検証し、上限で頭を打つ（CibaExpiresIn）（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（CIBA の受付）</summary>
    public partial class CmnEndpoints
    {
        #region AuthZ(N)Endpoint

        #region ReceiveCibaRequest

        /// <summary>
        /// CIBA の認証要求を受け取る（#233）
        /// </summary>
        /// <param name="client_id">client_id（client_secret_basic / post）</param>
        /// <param name="client_secret">client_secret（client_secret_basic / post）</param>
        /// <param name="assertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="request">署名付き JWT（CIBA Core §7.1.1）</param>
        /// <param name="request_uri">/ros に預けたものの参照（独自拡張。後方互換）</param>
        /// <param name="payload">要求の中身</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <returns>受け取れたか</returns>
        /// <remarks>
        /// **CIBA Core が定めているのは `request`（署名付き JWT）を直接送る形**（§7.1.1）で、
        /// **`request_uri` にあたる仕組みは無い。**
        /// これまでは `/ros` に預けて `request_uri` を渡す独自の形だけを受け付けており、
        /// 標準の CIBA クライアントからは使えなかった。
        ///
        /// **両方を受け付ける。** `request` があればそちらを使う（下位互換のため `request_uri` も残す）。
        /// `request_uri` の受け口は、`/ros` の廃止（#229 の完了報告を参照）と合わせて外す。
        ///
        /// 署名の検証は、登録された `jwk_ecdsa_publickey` で行う（FAPI-CIBA は ES256）。
        ///
        /// **クライアント認証も、ここで行う**（CIBA Core §7.1 : MUST。#234 の段階 3）。
        /// 以前は署名だけで識別しており、`/token` や `/device_authz` と違って
        /// `ClientAuthentication` を呼んでいなかった。
        /// </remarks>
        public static bool ReceiveCibaRequest(
            string client_id, string client_secret, string assertion, X509Certificate2 x509,
            string request, string request_uri,
            out JObject payload, out string err, out string errDescription)
        {
            payload = null;
            err = OAuth2AndOIDCConst.invalid_request;
            errDescription = "";

            #region クライアント認証（CIBA Core 7.1 : MUST）

            bool authned = false;

            if (!string.IsNullOrEmpty(assertion))
            {
                // private_key_jwt（FAPI-CIBA が求める方式）
                authned = CmnEndpoints.ClientAuthentication(
                    assertion, out client_id, ref x509, out ClientModePolicy.Proof _);
            }
            else
            {
                // client_secret（basic / post）または mTLS
                authned = CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509, out ClientModePolicy.Proof _);
            }

            if (!authned)
            {
                // CIBA Core 13 : クライアント認証の失敗は invalid_client（401）
                err = OAuth2AndOIDCConst.invalid_client;
                errDescription = "Invalid credential.";
                return false;
            }

            #endregion

            if (!string.IsNullOrEmpty(request))
            {
                // **CIBA Core §7.1.1 : 署名した認証要求を request で受け取る。**
                //   **JWT でない・payload がオブジェクトでない値を渡されても、例外にしない**（#185 / #241 と同じ方針）。
                //   **以前は base64 の復号だけを守っていて、JSON の配列や文字列でない `iss` で 500 になった**（#294）。
                JObject unverified = JwtReader.TryReadPayload(request);

                if (unverified == null)
                {
                    errDescription = "The request is not a JWT.";
                    return false;
                }

                string unverifiedIss = CmnEndpoints.StringClaimOf(unverified, OAuth2AndOIDCConst.iss);

                if (string.IsNullOrEmpty(unverifiedIss))
                {
                    errDescription = "The request has no iss.";
                    return false;
                }

                // 署名の検証に使う公開鍵は、登録（iss ＝ client_id）から引く。
                //   **登録の値が壊れていても例外にしない**（`DecodeRegisteredJwk` は空を返す。#294）。
                string pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkECDsaPublickey(unverifiedIss));

                if (string.IsNullOrEmpty(pubKey))
                {
                    // 登録されていないクライアント（CIBA Core 13 : invalid_client）
                    err = OAuth2AndOIDCConst.invalid_client;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }

                if (!RequestObject.VerifyCiba(request, out string _, pubKey))
                {
                    errDescription = "The request is not verified.";
                    return false;
                }

                payload = unverified;
                return CmnEndpoints.VerifyCibaRequestIssuer(
                    client_id, payload, ref err, ref errDescription);
            }

            if (!string.IsNullOrEmpty(request_uri))
            {
                // **独自拡張（後方互換）。** /ros に預けたものを引く。
                string json = RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                // 存在しない・期限切れの request_uri では空になる（#185 / #188）。
                //   **預けたものは /ros が検証した JSON**なので、オブジェクトである。
                payload = (JObject)JsonConvert.DeserializeObject(json ?? "");

                if (payload == null)
                {
                    errDescription = "Invalid request_uri.";
                    return false;
                }

                return CmnEndpoints.VerifyCibaRequestIssuer(
                    client_id, payload, ref err, ref errDescription);
            }

            errDescription = "request or request_uri is required.";
            return false;
        }

        #endregion

        #region VerifyCibaRequestIssuer

        /// <summary>認証したクライアントと、要求の iss が同じかを確かめる（#234 の段階 3）</summary>
        /// <param name="client_id">クライアント認証で確かめた client_id</param>
        /// <param name="payload">要求の中身</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **認証を入れただけでは足りない。**
        /// CIBA Core §7.1.1 は `iss` を「クライアントの client_id」と定めており、
        /// これを確かめないと、**自分の資格情報で認証し、他人の要求を代わりに送れる**。
        /// （要求の署名は、その他人の鍵で正しく検証できてしまう）
        /// </remarks>
        private static bool VerifyCibaRequestIssuer(
            string client_id, JObject payload, ref string err, ref string errDescription)
        {
            if ((string)payload[OAuth2AndOIDCConst.iss] != client_id)
            {
                // CIBA Core 13 : invalid_request
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "The iss does not match the authenticated client.";
                return false;
            }

            return true;
        }

        #endregion

        #region ConsumeCibaJti

        /// <summary>使い切りにした CIBA の jti を記録するキーの接頭辞（#234 の段階 2 / #243）</summary>
        /// <remarks>
        /// **短くしてある**（`ciba:jti:` から `ciba:` へ。#243）。
        /// 記録先の `Urn` は **38 文字**（GUID 用）なので、桁を使い切らないようにする。
        /// </remarks>
        private const string CibaJtiKeyPrefix = "ciba:";

        /// <summary>CIBA の認証要求を使い切りにする（#234 の段階 2）</summary>
        /// <param name="jti">署名した認証要求の一意な識別子</param>
        /// <returns>まだ使われていなければ true（使ったものとして記録する）</returns>
        /// <remarks>
        /// **記録先は Request Object のストアを使い回す。**
        /// #188 で入れた有効期限（`RequestObjectExpireTimeSpanFromSeconds`。既定 300 秒）と
        /// 掃除がそのまま効き、**新しい表を作らずに済む**（DDL を 3 方言とも変えなくてよい）。
        /// 名前と用途がずれるので、**キーに接頭辞を付けて**、Request Object 本体と混ざらないようにする。
        ///
        /// **保持は、このストアの有効期限まで。**
        /// 要求の `exp` がそれより長いと、記録が消えた後は同じ `jti` を受け付ける。
        /// （既定では、要求の `exp` を 300 秒以内にしておけば隙間は無い）
        ///
        /// **厳密な排他はしていない。** 同じ `jti` の要求が同時に届くと、
        /// 両方が「まだ使われていない」と判定され得る。
        /// 防ぎたいのは繰り返しの再送で、同時到着はそれに当たらない。
        ///
        /// **キーは固定長にする**（#243）。`jti` をそのまま繋ぐと、
        /// 記録先の `Urn`（**38 文字**。3 方言とも）に入らず、
        /// **DB ストアでは書き込みが失敗して HTTP 500 になっていた**
        /// （`mem` は辞書なので桁の制限が無く、気づけなかった）。
        /// **`jti` はクライアントが決める値で長さの上限が無い**ため、桁を広げるだけでは足りない。
        ///
        /// **元の `jti` は値として残す**（`Value` は可変長）。
        /// キーを見ただけでは分からなくなるが、記録を読めば再送の調査はできる。
        /// </remarks>
        private static bool ConsumeCibaJti(string jti)
        {
            string key = CmnEndpoints.CibaJtiKey(jti);

            if (!string.IsNullOrEmpty(RequestObjectProvider.Get(key)))
            {
                // 既に使われている（期限内）。
                return false;
            }

            // **期限切れで読めなくなった行が、まだ残っていることがある**（掃除は間隔を空けて行う）。
            //   そのまま Create すると、DBMS では主キーの重複になる。先に消しておく。
            RequestObjectProvider.Delete(key);

            // **元の jti を値に入れる**（#243）。キーは要約なので、ここが手掛かりになる。
            RequestObjectProvider.Create(key, jti);

            return true;
        }

        /// <summary>CIBA の jti を記録するキーを作る（固定長。#243）</summary>
        /// <param name="jti">署名した認証要求の一意な識別子</param>
        /// <returns>キー（`ciba:` ＋ 22 文字 ＝ 27 文字）</returns>
        /// <remarks>
        /// **SHA-256 の先頭 16 バイトを Base64URL にする**（22 文字）。
        /// 接頭辞と合わせて 27 文字で、`Urn` の 38 文字に収まる。
        ///
        /// **衝突は考えなくてよい。** 128 ビットの要約で、
        /// 仮に衝突しても「別の `jti` を使用済みと見なす」（**安全側**）にしかならない。
        /// 暗号学的な強度を要する用途ではない（秘密は含まず、当てても得が無い）。
        /// </remarks>
        private static string CibaJtiKey(string jti)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(
                    CustomEncode.StringToByte(jti ?? "", CustomEncode.UTF_8));

                byte[] head = new byte[16];
                Array.Copy(hash, head, head.Length);

                return CmnEndpoints.CibaJtiKeyPrefix + CustomEncode.ToBase64UrlString(head);
            }
        }

        #endregion

        #region ValidateAuthZCibaReqParam

        /// <summary>auth_req_id の有効期間（秒）を決める（#294）</summary>
        /// <param name="requested_expiry">要求の requested_expiry（`ValidateCibaAuthZReqParam` で検証済み。無ければ空）</param>
        /// <returns>有効期間（秒）</returns>
        /// <remarks>
        /// **`CibaExpireTimeSpanFromSeconds` を上限にする**（CIBA Core §7.1 は、要求の値を「望み」としている）。
        /// **無ければ、その上限を使う**（従来どおり）。
        /// </remarks>
        public static int CibaExpiresIn(string requested_expiry)
        {
            int max = Config.CibaExpireTimeSpanFromSeconds;

            if (!string.IsNullOrEmpty(requested_expiry)
                && int.TryParse(requested_expiry, out int seconds) && 0 < seconds)
            {
                return Math.Min(seconds, max);
            }

            return max;
        }

        /// <summary>ValidateCibaAuthZReqParam</summary>
        /// <param name="json">JObject</param>
        /// <param name="client_id">string</param>
        /// <param name="scope">string</param>
        /// <param name="client_notification_token">string</param>
        /// <param name="binding_message">string</param>
        /// <param name="user_code">string</param>
        /// <param name="requested_expiry">string</param>
        /// <param name="login_hint">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static bool ValidateCibaAuthZReqParam(
            JObject json, out string client_id, out string scope,
            out string client_notification_token, out string binding_message,
            out string user_code, out string requested_expiry, out string login_hint,
            out string err, out string errDescription)
        {
            #region 定義
            string aud = "";
            string exp = "";
            //string iat = "";
            string nbf = "";
            string jti = "";            
            #endregion

            #region 初期化
            client_id = "";
            scope = "";
            client_notification_token = "";
            binding_message = "";
            user_code = "";
            requested_expiry = "";
            login_hint = "";

            err = OAuth2AndOIDCConst.invalid_request;
            errDescription = "";
            #endregion

            #region 取得 → チェック
            // iss → client_id
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.iss,
                out client_id, out err, out errDescription))
            {
                return false;
            }
            else
            {
                string clientName = Helper.GetInstance().GetClientName(client_id);

                if (string.IsNullOrEmpty(clientName))
                {
                    // 登録されていないクライアント（CIBA Core 13 : invalid_client）。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_client;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }

                // **登録で許されたグラントか**（RFC 7591 §2 の `grant_types`。#307 の段階 1）。
                //   **ここでも見る** — **利用者にプッシュ通知を届ける前に断る**ため
                //   （下の `MayUse` と同じ理屈）。**登録が無ければ絞らない。**
                if (!CmnEndpoints.CheckClientGrantType(client_id, ClientModePolicy.Flow.Ciba))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = "This grant_type is not registered for this client.";
                    return false;
                }

                // **登録種別で CIBA を使えるか（#224 の段階 2）。**
                //   以前はトークンの時点（GrantCiba）で初めて拒否していたため、
                //   利用者にプッシュ通知が届き、承認させた後で失敗していた。
                //   CIBA Core 13 : このクライアントに許されていない要求は unauthorized_client。
                if (!ClientModePolicy.MayUse(
                    Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.Ciba))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = "This client is not allowed to use CIBA.";
                    return false;
                }
            }
            // aud
            // **CIBA Core 7.1.1 : aud は OP の Issuer Identifier でなければならない（#234 の段階 1）。**
            //   以前は取り出しも検証もしていなかった（この行はコメントだけだった）。
            //   見ないと、**別の認可サーバ宛てに作られた要求**を、
            //   同じクライアントの鍵が登録されているこの IdP でも受け付けてしまう。
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.aud,
                out aud, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (aud != CmnServerParams.IssuerId)
                {
                    // CIBA Core 13 : invalid_request
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The aud is not the issuer identifier.";
                    return false;
                }
            }
            // exp
            if (!CmnEndpoints.GetCibaClaim(
                    json, OAuth2AndOIDCConst.exp,
                    out exp, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyExp(exp))
                {
                    // CIBA Core 13 : invalid_request。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The request is expired.";
                    return false;
                }
            }
            // iat
            // nbf
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.nbf,
                out nbf, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyNbf(nbf))
                {
                    // CIBA Core 13 : invalid_request。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The request is not yet valid.";
                    return false;
                }
            }
            // jti
            // **同じ要求を二度受け付けない（#234 の段階 2）。**
            //   CIBA Core 7.1.1 は jti を「署名した認証要求の一意な識別子」としている。
            //   見ないと、**同じ要求 JWT を exp まで何度でも送り直せる**（利用者に通知が繰り返し届く）。
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.jti,
                out jti, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnEndpoints.ConsumeCibaJti(jti))
                {
                    // CIBA Core 13 : invalid_request
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The jti was already used.";
                    return false;
                }
            }
            // scope
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.scope,
                out scope, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    // OIDC無効（CIBA Core 13 : invalid_scope）。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_scope;
                    errDescription = string.Format(
                        "CIBA is required {0} value in scope param.",
                        OAuth2AndOIDCConst.Scope_Openid);

                    return false;
                }
            }
            // client_notification_token
            //   **poll では要らない**（CIBA Core §7.1 : ping / push のときだけ REQUIRED）。
            //   **この実装は poll だけを扱う**（Discovery の `backchannel_token_delivery_modes_supported`）。
            //   **以前は必須にしていた**ので、**標準の poll のクライアントが invalid_request で断られた**（#294）。
            //   ※ `/ros` は、これの有無で CIBA かどうかを見分ける（`RegisterRequestObject`）ので、
            //     **`request_uri` の経路では、在ることになる。**
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.client_notification_token,
                out client_notification_token, out err, out errDescription, nullable: true);
            client_notification_token = client_notification_token ?? "";
            // binding_message
            //   **OPTIONAL**（CIBA Core §7.1。#294。以前は必須にしていた）。
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.binding_message,
                out binding_message, out err, out errDescription, nullable: true);
            binding_message = binding_message ?? "";
            // user_code
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.user_code,
                out user_code, out err, out errDescription, nullable: true);
            // requested_expiry
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.requested_expiry,
                out requested_expiry, out err, out errDescription, nullable: true);

            //  **正の整数でなければ断る**（CIBA Core §7.1 : 秒数の正の整数。#294）。
            //    **以前は検証せず**、読めない値は `int.TryParse` が 0 にして、**作った瞬間に期限が切れていた。**
            //    **上限は `CibaExpiresIn` で頭を打つ**（大きな値で、待ちの要求を長く残させない）。
            if (!string.IsNullOrEmpty(requested_expiry)
                && (!int.TryParse(requested_expiry, out int requestedSeconds) || requestedSeconds <= 0))
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "requested_expiry must be a positive integer.";
                return false;
            }
            // login_hint
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.login_hint,
                out login_hint, out err, out errDescription))
            {
                return false;
            }

            return true;
        }

        /// <summary>CIBA の認証リクエストのクレームを取り出す（CmnJwtToken.CheckClaims の包み）</summary>
        /// <param name="json">JObject</param>
        /// <param name="key">クレーム名</param>
        /// <param name="value">値</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <param name="nullable">省略できるクレームか</param>
        /// <returns>取り出せたか（省略できるクレームが無い場合も true）</returns>
        /// <remarks>
        /// Open棟梁 の CheckClaims は、クレームが無いと server_error を返す。
        /// 要求の不備なので、CIBA Core 13 のとおり invalid_request にする（#196）。
        /// </remarks>
        private static bool GetCibaClaim(JObject json, string key,
            out string value, out string err, out string errDescription, bool nullable = false)
        {
            if (CmnJwtToken.CheckClaims(json, key, out value, out err, out errDescription, nullable))
            {
                return true;
            }

            err = OAuth2AndOIDCConst.invalid_request;
            return false;
        }
        #endregion

        #endregion

        #endregion
    }
}