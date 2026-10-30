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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の RP-Initiated Logout
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         using を整理した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Extensions.Sts;

using System;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（RP-Initiated Logout）</summary>
    public partial class CmnEndpoints
    {
        #region AuthZ(N)Endpoint

        #region RP-Initiated Logout（#232）

        /// <summary>
        /// RP からのログアウト要求（/end_session）を受ける（#232）
        /// </summary>
        /// <param name="idTokenHint">id_token_hint（この RP に発行した id_token）</param>
        /// <param name="clientId">client_id（任意）</param>
        /// <param name="postLogoutRedirectUri">post_logout_redirect_uri（任意）</param>
        /// <param name="state">state（任意）</param>
        /// <param name="currentUserName">いまサインインしている利用者（していなければ空）</param>
        /// <param name="verified">
        /// **id_token_hint が検証でき、いまサインインしている利用者のものだった**
        /// （false なら、利用者に確認しなければならない）
        /// </param>
        /// <param name="redirectUri">ログアウト後に戻してよい URL（state 付き。無ければ空）</param>
        /// <param name="err">error（RP へは返さない。画面で知らせる）</param>
        /// <param name="errDescription">error_description</param>
        /// <remarks>
        /// **RP-Initiated Logout 1.0 の MUST を、ここで判定する。**
        ///
        /// | 判定 | 根拠 |
        /// |---|---|
        /// | `id_token_hint` は**自分が発行したもの**か（署名と `iss`） | §2 |
        /// | **`exp` が切れていても受ける** | §2（SHOULD） |
        /// | `client_id` も来ていれば、`id_token` の `aud` と一致すること | §2 |
        /// | `post_logout_redirect_uri` は**登録値と完全一致** | §3 |
        /// | **`id_token_hint` が無ければ、RP へ戻さない** | §3 |
        /// | 検証できなければ**利用者に確認する**（`verified` が false） | §2 / §6 |
        ///
        /// **サインアウトそのものは、ここでは行わない**（枠組みが違うので各アプリで行う）。
        /// **エラーでも RP へは戻さない**（§4）。`err` は画面で知らせるためのもので、
        /// **リダイレクトの URL には載せない。**
        ///
        /// **トークンは失効させない。** 仕様は求めておらず、RP には `/revoke` がある。
        /// </remarks>
        public static void ReceiveEndSessionRequest(
            string idTokenHint, string clientId, string postLogoutRedirectUri, string state,
            string currentUserName,
            out bool verified, out string redirectUri,
            out string err, out string errDescription)
        {
            verified = false;
            redirectUri = "";
            err = "";
            errDescription = "";

            idTokenHint = idTokenHint ?? "";
            clientId = clientId ?? "";
            postLogoutRedirectUri = postLogoutRedirectUri ?? "";
            state = state ?? "";
            currentUserName = currentUserName ?? "";

            // この要求が、どのクライアントのものか
            string aud = clientId;

            if (!string.IsNullOrEmpty(idTokenHint))
            {
                if (!CmnEndpoints.VerifyIdTokenHint(idTokenHint, out aud, out string userName))
                {
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "id_token_hint is invalid.";
                    return;
                }

                // **両方来ていれば、一致すること**（§2 の MUST）。
                if (!string.IsNullOrEmpty(clientId)
                    && !string.Equals(clientId, aud, StringComparison.Ordinal))
                {
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "client_id does not match the id_token_hint.";
                    return;
                }

                // **いまサインインしている利用者のものか。**
                //   pairwise（PPID）の登録では利用者を引けないので、確認を求めることになる。
                verified = !string.IsNullOrEmpty(userName)
                    && string.Equals(userName, currentUserName, StringComparison.Ordinal);
            }

            if (string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                // 戻り先の指定が無い（ログアウトするだけ）。
                return;
            }

            if (string.IsNullOrEmpty(idTokenHint))
            {
                // **id_token_hint が無ければ、戻り先の正しさを確かめる手段が無い**（§3 の MUST）。
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "post_logout_redirect_uri requires id_token_hint.";
                return;
            }

            // **登録値と完全一致**（§3）。
            //   **redirect_uri の照合（CheckRedirectUri）も、同じ単純文字列比較である**（#263）。
            //   以前はあちらだけ大文字小文字を無視していた（C-10）。
            string registered = CmnEndpoints.GetRedirectUriFromConstr(
                Helper.GetInstance().GetClientsPostLogoutRedirectUri(aud) ?? "");

            if (string.IsNullOrEmpty(registered)
                || !string.Equals(postLogoutRedirectUri, registered, StringComparison.Ordinal))
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "post_logout_redirect_uri is not registered.";
                return;
            }

            redirectUri = postLogoutRedirectUri;

            if (!string.IsNullOrEmpty(state))
            {
                // **state は、要求に含まれた場合だけ返す**（§2）。値は必ず符号化する（#187 と同じ理由）。
                redirectUri += (redirectUri.Contains("?") ? "&" : "?")
                    + OAuth2AndOIDCConst.state + "=" + Uri.EscapeDataString(state);
            }
        }

        /// <summary>id_token_hint を検証する（#232）</summary>
        /// <param name="idTokenHint">id_token_hint</param>
        /// <param name="aud">この id_token を発行した先（client_id）</param>
        /// <param name="userName">この id_token の主体（引けなければ空）</param>
        /// <returns>自分が発行した id_token であれば true</returns>
        /// <remarks>
        /// **`exp` は見ない。** RP-Initiated Logout 1.0 §2 は
        /// 「**`exp` を過ぎていても受けるべき**」としている（ログアウトは期限切れの後こそ要る）。
        /// このため、期限と失効まで見る `CmnAccessToken.VerifyAccessToken` は使えず、
        /// **署名だけを検証する口**（`VerifySignature`）を使う。
        ///
        /// **payload を先に読む**ので、JWT でない値でも例外にしない（#241 の `TryReadJwtPayload`）。
        /// </remarks>
        private static bool VerifyIdTokenHint(string idTokenHint, out string aud, out string userName)
        {
            aud = "";
            userName = "";

            try
            {
                JObject payload = JwtReader.TryReadPayload(idTokenHint);

                if (payload == null)
                {
                    return false;
                }

                // **自分が発行したものか**（§2 の MUST）。
                if (!string.Equals(
                    (string)payload[OAuth2AndOIDCConst.iss], CmnServerParams.IssuerId, StringComparison.Ordinal))
                {
                    return false;
                }

                if (!CmnAccessToken.VerifySignature(idTokenHint))
                {
                    return false;
                }

                // aud は文字列だが、配列で来ても壊れないようにする。
                JToken audToken = payload[OAuth2AndOIDCConst.aud];

                if (audToken is JArray)
                {
                    aud = (audToken.First == null) ? "" : ((string)audToken.First ?? "");
                }
                else
                {
                    aud = (string)audToken ?? "";
                }

                string sub = (string)payload[OAuth2AndOIDCConst.sub] ?? "";

                if (string.IsNullOrEmpty(aud) || string.IsNullOrEmpty(sub))
                {
                    return false;
                }

                // **sub から利用者を引く**（登録の subject_types に従う。pairwise は引けない）。
                userName = PPIDExtension.GetUserNameFromSub(aud, sub);

                return true;
            }
            catch
            {
                // 外から来た値なので、例外にしない（#241 と同じ扱い）。
                aud = "";
                userName = "";
                return false;
            }
        }

        #endregion

        #endregion
    }
}