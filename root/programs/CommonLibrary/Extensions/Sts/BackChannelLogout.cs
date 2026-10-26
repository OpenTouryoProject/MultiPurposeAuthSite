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
//* クラス名        ：BackChannelLogout
//* クラス日本語名  ：ログアウトを RP へ伝える（Back-Channel Logout 1.0 §2.5）
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
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Util;

#if NETCORE
//using MultiPurposeAuthSite;
#else
using MultiPurposeAuthSite.Entity;
#endif

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// BackChannelLogout
    /// **OP のセッションが終わったことを、そのセッションが触った RP へ伝える**（#310 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **伝える先は台帳が持っている**（`SessionClientProvider`。#310 の段階 1）。
    /// **「触った」＝「トークンを発行した」**である
    /// （**同意画面を出しただけ・拒否された相手は入らない**。段階 2 の冒頭で直した）。
    ///
    /// | | |
    /// |---|---|
    /// | **何を送るか** | **`logout_token`**（`CmnLogoutToken`）を、**`application/x-www-form-urlencoded` の本文**で POST する |
    /// | **どこへ** | **`backchannel_logout_uri` の登録が在る相手だけ**（**無ければ伝えない**） |
    /// | **いつ** | **サインアウトの経路**（`/Account/LogOff` / `/end_session` / 再認証 / 別アカウントでログイン） |
    /// | **待つか** | **待たない**（下の「要求の経路では待たない」） |
    ///
    /// **要求の経路では待たない。**
    /// **net48 では、同期の要求スレッドで `await` の継続を待つと
    /// `AspNetSynchronizationContext` が塞がる**（#309 の起票で踏んだ）。
    /// **相手が応答しない RP が 1 つ在るだけで、ログアウトの画面が返らなくなる**のも困る。
    /// **`Task.Run` で投げる** — **同期コンテキストを持たないスレッドで走る。**
    ///
    /// **台帳を読むのは、投げる前**（**要求のスレッドで**）である。
    /// **呼び出し側は、この直後に台帳を消す**（`DeleteBySession`）ので、
    /// **背景で読もうとすると、消えた後になることが在る。**
    ///
    /// **再送はしない。** **仕様も求めていない**（§2.5）。
    /// **届かなかったことはログに残す**（**RP の側には、トークンの期限という別の歯止めが在る**）。
    /// </remarks>
    public class BackChannelLogout
    {
        /// <summary>1 件あたりの待ち時間</summary>
        /// <remarks>
        /// **応答しない RP で、背景のスレッドを長く占めない**ため。
        /// **設定キーは増やしていない**（#310 の段階 1 の掃除と同じ扱い）。
        /// </remarks>
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        /// <summary>そのセッションが触った RP へ、ログアウトを伝える（待たない）</summary>
        /// <param name="sessionId">セッションの識別子（`op_session` の値）</param>
        /// <remarks>
        /// **サインアウトの直前に呼ぶ**（**台帳を消す前**）。
        /// **台帳の読み出しだけを、呼び出し元のスレッドで行う。**
        /// </remarks>
        public static void NotifyBySession(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
            {
                return;
            }

            List<SessionClientProvider.Target> targets = null;

            try
            {
                targets = SessionClientProvider.GetBySession(sessionId);
            }
            catch (Exception ex)
            {
                // オペレーション・トレース・ログ出力
                //   **読めなくてもサインアウトは続ける**（**伝えられないだけ**）。
                Logging.MyOperationTrace(string.Format(
                    "The back-channel logout could not read the session. ({0})", ex.GetType().Name));

                return;
            }

            if (targets == null || targets.Count == 0)
            {
                return;
            }

            Task.Run(async () =>
            {
                try
                {
                    await BackChannelLogout.SendAsync(targets);
                }
                catch (Exception ex)
                {
                    // **背景で走る**ので、**例外を外へ出さない。**
                    Logging.MyOperationTrace(string.Format(
                        "The back-channel logout failed. ({0})", ex.GetType().Name));
                }
            });
        }

        /// <summary>宛先ごとに logout_token を作って送る</summary>
        /// <param name="targets">伝える先</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **直列に送る**（**1 回のサインアウトで、外向きの接続を何十本も同時に出さない**）。
        /// **1 つが落ちても続ける。**
        /// </remarks>
        private static async Task SendAsync(List<SessionClientProvider.Target> targets)
        {
            int tried = 0;
            int sent = 0;

            foreach (SessionClientProvider.Target target in targets)
            {
                string uri = BackChannelLogout.GetUri(target.ClientId);

                if (string.IsNullOrEmpty(uri))
                {
                    // **登録が無い**（**Back-Channel Logout に対応していない RP**）。
                    continue;
                }

                string token = CmnLogoutToken.Create(
                    target.ClientId, BackChannelLogout.GetSub(target), target.Sid);

                if (string.IsNullOrEmpty(token))
                {
                    continue;
                }

                tried++;

                if (await BackChannelLogout.PostAsync(uri, token))
                {
                    sent++;
                }
            }

            if (0 < tried)
            {
                // オペレーション・トレース・ログ出力
                //   **URL も client_id も出さない**（**どの RP と繋がっているかは配備の情報**）。
                //   **数だけ残す**（`JwksUriWarmUp` と同じ流儀）。
                Logging.MyOperationTrace(string.Format(
                    "The back-channel logout notified {0} of {1} RPs.", sent, tried));
            }
        }

        /// <summary>その相手の backchannel_logout_uri（送れない相手は空）</summary>
        /// <param name="clientId">ClientID</param>
        /// <returns>URL（登録が無い・使えない URL なら空）</returns>
        /// <remarks>
        /// **`https` を求め、ループバックの `http` だけ許す**
        /// （**鍵の出どころと同じ規則**。`RemoteJwkSetStore.IsUsableKeySource`）。
        /// **`logout_token` は署名してあるが、平文で運べば「誰がいつ抜けたか」が漏れる。**
        /// **開発と試験では証明書を用意できないことが在る**ので、ループバックだけ許す。
        /// </remarks>
        private static string GetUri(string clientId)
        {
            string registered = Helper.GetInstance().GetClientsBackChannelLogoutUri(clientId) ?? "";

            if (string.IsNullOrEmpty(registered))
            {
                return "";
            }

            // **記号を実 URL に直す**（`test_self_bclogout`。#232 の戻り先と同じ扱い）。
            string uri = CmnEndpoints.GetRedirectUriFromConstr(registered);

            return RemoteJwkSetStore.IsUsableKeySource(uri) ? uri : "";
        }

        /// <summary>その相手に名乗った sub（引けなければ空）</summary>
        /// <param name="target">台帳の 1 行</param>
        /// <returns>sub</returns>
        /// <remarks>
        /// **`sub` は相手ごとに違う**（`pairwise` の登録では PPID）。
        /// **`id_token` に入れた値と同じものを入れる**ので、**同じ口で引く**（`PPIDExtension`）。
        ///
        /// **引けなくても送る** — **`sid` だけで足りる**（Back-Channel Logout 1.0 §2.4）。
        /// </remarks>
        private static string GetSub(SessionClientProvider.Target target)
        {
            try
            {
                ApplicationUser user = CmnUserStore.FindById(target.UserId);

                if (user == null)
                {
                    return "";
                }

                return PPIDExtension.GetSubForOIDC(
                    target.ClientId, user.UserName, out ApplicationUser dummy) ?? "";
            }
            catch
            {
                // **sub が引けなくても、sid で伝えられる。**
                return "";
            }
        }

        /// <summary>1 件送る</summary>
        /// <param name="uri">backchannel_logout_uri</param>
        /// <param name="logoutToken">logout_token</param>
        /// <returns>**2xx が返れば true**</returns>
        /// <remarks>
        /// **本文は `logout_token=…` の 1 項目**（§2.5）。
        /// **応答の中身は見ない**（§2.6 : **RP は 200 を返す。誤りなら 400 ＋ JSON**）。
        /// **2xx でなければ「届かなかった」として数える。**
        /// </remarks>
        private static async Task<bool> PostAsync(string uri, string logoutToken)
        {
            try
            {
                // **ID 連携や /token と同じ HttpClient**（TLS・プロキシの扱いが揃う）。
                //   **`Helper` の初期化が設定する**ので、先に初期化させてから読む。
                Helper.GetInstance();
                HttpClient client = OAuth2AndOIDCClient.HttpClient;

                if (client == null)
                {
                    return false;
                }

                FormUrlEncodedContent content = new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { Const.LogoutToken, logoutToken }
                    });

                using (CancellationTokenSource cts
                    = new CancellationTokenSource(BackChannelLogout.Timeout))
                {
                    HttpResponseMessage response = await client.PostAsync(uri, content, cts.Token);

                    return response.IsSuccessStatusCode;
                }
            }
            catch (Exception ex)
            {
                // オペレーション・トレース・ログ出力
                //   **URL は出さない**（配備の情報）。**型だけ残す。**
                Logging.MyOperationTrace(string.Format(
                    "The back-channel logout could not reach an RP. ({0})", ex.GetType().Name));

                return false;
            }
        }
    }
}
