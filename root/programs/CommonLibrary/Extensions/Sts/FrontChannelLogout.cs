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
//* クラス名        ：FrontChannelLogout
//* クラス日本語名  ：ログアウトをブラウザ経由で RP へ伝える（Front-Channel Logout 1.0 §2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 3）
//*  2026/10/22  玄人 幸道         URL の判定を Open棟梁 の RemoteJwkSetStore に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// FrontChannelLogout
    /// **ログアウトを、ブラウザ経由で RP へ伝える**（#310 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **Back-Channel（段階 2）との違いは「誰が叩くか」である。**
    ///
    /// | | 誰が RP を叩くか | 届く相手 |
    /// |---|---|---|
    /// | **Back-Channel** | **OP のサーバ** | **受け口を持てる RP**（サーバを持っている） |
    /// | **Front-Channel** | **利用者のブラウザ**（`iframe`） | **ブラウザの中だけで動く RP** も届く |
    ///
    /// **この型が作るのは `iframe` の URL だけ**である。
    /// **並べて返すのはアプリ側**（**画面を出すのは Controller の役目**）。
    ///
    /// **`iss` と `sid` を付ける**（Front-Channel Logout 1.0 §2）。
    /// **RP は、どの OP の・どのセッションのログアウトかを、これで知る**
    /// （**Cookie が送られない文脈も在る**ので、URL に載せる）。
    ///
    /// **台帳は `SessionClientProvider` が持っている**（#310 の段階 1）。
    /// **`BackChannelLogout` も同じ表を読む** — **サインアウトで 2 回読むことになるが、
    /// サインアウトは稀なので、1 回に束ねる作りにはしていない**
    /// （**束ねると、どちらか一方だけを使う配備で、要らない方の判定が混ざる**）。
    /// </remarks>
    public class FrontChannelLogout
    {
        /// <summary>そのセッションの iframe の URL を並べる（#310 の段階 3）</summary>
        /// <param name="sessionId">セッションの識別子（`op_session` の値）</param>
        /// <returns>iframe に入れる URL（1 件も無ければ空）</returns>
        /// <remarks>
        /// **サインアウトの直前に呼ぶ**（**台帳を消す前**）。
        ///
        /// **`frontchannel_logout_uri` の登録が在る相手だけ**を返す。
        /// **登録が無ければ、その RP には伝えない**（**Back-Channel と同じ扱い**）。
        ///
        /// **読めなくてもサインアウトは続ける**（**伝えられないだけ**）。
        /// </remarks>
        public static List<string> GetIframeUrls(string sessionId)
        {
            List<string> urls = new List<string>();

            if (string.IsNullOrEmpty(sessionId))
            {
                return urls;
            }

            List<SessionClientProvider.Target> targets = null;

            try
            {
                targets = SessionClientProvider.GetBySession(sessionId);
            }
            catch (Exception ex)
            {
                // オペレーション・トレース・ログ出力
                Logging.MyOperationTrace(string.Format(
                    "The front-channel logout could not read the session. ({0})", ex.GetType().Name));

                return urls;
            }

            if (targets == null)
            {
                return urls;
            }

            foreach (SessionClientProvider.Target target in targets)
            {
                string uri = FrontChannelLogout.GetUri(target.ClientId);

                if (string.IsNullOrEmpty(uri))
                {
                    // **登録が無い**（**Front-Channel Logout に対応していない RP**）。
                    continue;
                }

                urls.Add(uri
                    + (uri.Contains("?") ? "&" : "?")
                    + OAuth2AndOIDCConst.iss + "=" + Uri.EscapeDataString(CmnServerParams.IssuerId ?? "")
                    + "&" + Const.Sid + "=" + Uri.EscapeDataString(target.Sid ?? ""));
            }

            if (0 < urls.Count)
            {
                // オペレーション・トレース・ログ出力
                //   **URL も client_id も出さない**（**どの RP と繋がっているかは配備の情報**）。
                //   **数だけ残す**（`BackChannelLogout` と同じ流儀）。
                Logging.MyOperationTrace(string.Format(
                    "The front-channel logout will notify {0} RPs.", urls.Count));
            }

            return urls;
        }

        /// <summary>その相手の frontchannel_logout_uri（送れない相手は空）</summary>
        /// <param name="clientId">ClientID</param>
        /// <returns>URL（登録が無い・使えない URL なら空）</returns>
        /// <remarks>
        /// **`https` を求め、ループバックの `http` だけ許す**
        /// （**Back-Channel と同じ規則**。`RemoteJwkSetStore.IsUsableKeySource`）。
        /// **ブラウザが開く URL** なので、**平文だと混在コンテンツとして止められることも在る。**
        /// </remarks>
        private static string GetUri(string clientId)
        {
            string registered = Helper.GetInstance().GetClientsFrontChannelLogoutUri(clientId) ?? "";

            if (string.IsNullOrEmpty(registered))
            {
                return "";
            }

            // **記号を実 URL に直す**（`test_self_fclogout`）。
            string uri = CmnEndpoints.GetRedirectUriFromConstr(registered);

            return RemoteJwkSetStore.IsUsableKeySource(uri) ? uri : "";
        }
    }
}
