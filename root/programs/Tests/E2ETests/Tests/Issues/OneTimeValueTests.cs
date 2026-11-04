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
//* クラス名        ：OneTimeValueTests
//* クラス日本語名  ：RT-332 使い捨ての値を同時に引き換えても、トークンは 1 回しか出ない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/04  玄人 幸道         新規（#332）
//*  2026/11/04  玄人 幸道         クライアント名を改めた（TestClient1〜4・6。TestClient5 は種データの TestClient_36 へ移した）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-332. **使い捨ての値を同時に引き換えても、トークンは 1 回しか出ない**（#332）。
    /// </summary>
    /// <remarks>
    /// **読む処理と、使用済みにする処理が別々で、使用済みにできたかを見ていなかった。**
    /// **同じ値の要求が同時に来ると、両方が読めて、両方にトークンが出る**可能性があった。
    ///
    /// **同じ値で `/token` を同時に送り、トークンを受け取ったのが 1 つだけかを数える。**
    ///
    /// **CIBA の端末の登録は利用者の行を書く**ので、CIBA のテストと同じコレクションに入れる（並行させない）。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class OneTimeValueTests : TargetTestBase
    {
        /// <summary>同時に送る数</summary>
        private const int Concurrency = 10;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public OneTimeValueTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-332.1 同じ認可コードを同時に引き換えても、トークンは 1 回しか出ない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33201_同じ認可コードを同時に引き換えてもトークンは1回(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-332.1",
                    "同じ認可コードを同時に引き換えても、トークンは 1 回しか出ない",
                    "**認可コードは 1 回しか使えない。** 読む処理と消す処理が別々で、消せたかを見ていなかったので、"
                    + "**同時に来た要求の両方が読めて、両方にトークンが出る**可能性があった。",
                    "RFC 6749 §4.1.2 / #332");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("POST /token（grant_type=authorization_code。同じ code で同時に " + Concurrency + " 回）");

                r.Step("(1) 認可コードを得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state-rt3321", "nonce-rt3321", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                r.Step("(2) 同じ認可コードで、同時に " + Concurrency + " 回引き換える");

                JsonResponse[] results = await OneTimeValueTests.SendAsync(
                    () => Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri));

                OneTimeValueTests.VerifyOnce(r, results);

                r.Done();
            }
        }

        /// <summary>RT-332.2 同じリフレッシュトークンを同時に使っても、トークンは 1 回しか出ない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33202_同じリフレッシュトークンを同時に使ってもトークンは1回(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-332.2",
                    "同じリフレッシュトークンを同時に使っても、トークンは 1 回しか出ない",
                    "**リフレッシュトークンは 1 回しか使えない**（使用済みを再び使うと、一族ごと失効させる。#188）。"
                    + "**読む処理と使用済みにする処理が別々で、使用済みにできたかを見ていなかった**ので、"
                    + "**同時に来た要求の両方が「未使用」と読めて、両方にトークンが出る**可能性があった。",
                    "#332 / #188");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("POST /token（grant_type=refresh_token。同じ refresh_token で同時に " + Concurrency + " 回）");

                r.Step("(1) refresh_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.RefreshToken), "前提: refresh_token が返ること（" + token.ToString() + "）");

                r.Step("(2) 同じ refresh_token で、同時に " + Concurrency + " 回更新する");

                JsonResponse[] results = await OneTimeValueTests.SendAsync(
                    () => Flows.RefreshAsync(client, reg, token.RefreshToken));

                OneTimeValueTests.VerifyOnce(r, results);

                r.Done();
            }
        }

        /// <summary>RT-332.3 同じ device_code を同時に引き換えても、トークンは 1 回しか出ない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33203_同じdevice_codeを同時に引き換えてもトークンは1回(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(
                    client, "urn:ietf:params:oauth:grant-type:device_code");

                TestReport r = this.Report("RT-332.3",
                    "同じ device_code を同時に引き換えても、トークンは 1 回しか出ない",
                    "**承認された device_code は、トークンを出したら使えなくなる**（引き換えた行を消している）。"
                    + "**読む処理と消す処理が別々で、消せたかを見ていなかった**ので、"
                    + "**同時に来た要求の両方にトークンが出る**可能性があった。",
                    "#332");

                ClientRegistration reg = Flows.Registration(client, KnownClients.DeviceClient);

                r.Target("POST /token（grant_type=device_code。同じ device_code で同時に " + Concurrency + " 回）");

                r.Step("(1) 機器 : device_code と user_code を得て、ユーザが許可する");

                JsonResponse start = await DeviceAuthorizationTests.StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が返ること（" + start.ToString() + "）");

                Assert.True(await client.SubmitDeviceUserCodeAsync(userCode, true),
                    "前提: user_code を許可できること");

                r.Step("(2) 同じ device_code で、同時に " + Concurrency + " 回トークンを要求する");

                JsonResponse[] results = await OneTimeValueTests.SendAsync(
                    () => DeviceAuthorizationTests.PollAsync(client, reg.ClientId, deviceCode));

                OneTimeValueTests.VerifyOnce(r, results);

                r.Done();
            }
        }

        /// <summary>RT-332.4 同じ auth_req_id を同時に引き換えても、トークンは 1 回しか出ない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33204_同じauth_req_idを同時に引き換えてもトークンは1回(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "urn:openid:params:grant-type:ciba");

                //  **プッシュ通知の送信箱が無いと、CIBA は測れない**（`EX-8.*` と同じ前提）。
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-332.4",
                    "同じ auth_req_id を同時に引き換えても、トークンは 1 回しか出ない",
                    "**許可された auth_req_id は、トークンを出したら使えなくなる**（引き換えた行を消している）。"
                    + "**読む処理と消す処理が別々で、消せたかを見ていなかった**ので、"
                    + "**同時に来た要求の両方にトークンが出る**可能性があった。",
                    "#332");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);

                r.Target("POST /token（grant_type=ciba。同じ auth_req_id で同時に " + Concurrency + " 回）");

                r.Step("(1) ユーザ : 認証デバイスを登録する");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : CIBA の認証リクエストを送り、ユーザが認証デバイスで許可する");

                JsonResponse start = await CibaTests.StartAsync(client, reg, "rt332-4");
                string authReqId = start.String("auth_req_id");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること（" + start.ToString() + "）");

                await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                Assert.True(answer.Text == "OK", "前提: 許可を返せること（" + answer.ToString() + "）");

                r.Step("(3) 同じ auth_req_id で、同時に " + Concurrency + " 回トークンを要求する");

                JsonResponse[] results = await OneTimeValueTests.SendAsync(
                    () => CibaTests.PollAsync(client, reg, authReqId));

                OneTimeValueTests.VerifyOnce(r, results);

                r.Done();
            }
        }

        /// <summary>同じ要求を同時に送る</summary>
        /// <param name="request">要求</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse[]> SendAsync(Func<Task<JsonResponse>> request)
        {
            List<Task<JsonResponse>> requests = new List<Task<JsonResponse>>();

            for (int i = 0; i < OneTimeValueTests.Concurrency; i++)
            {
                requests.Add(request());
            }

            return Task.WhenAll(requests);
        }

        /// <summary>トークンを受け取ったのが 1 つだけか</summary>
        /// <param name="r">TestReport</param>
        /// <param name="results">応答</param>
        private static void VerifyOnce(TestReport r, JsonResponse[] results)
        {
            int issued = results.Count(x => !string.IsNullOrEmpty(x.AccessToken));

            //  **断られた応答の内訳を残す**（500 で落ちていないかも、ここで分かる）。
            string others = string.Join(", ", results
                .Where(x => string.IsNullOrEmpty(x.AccessToken))
                .GroupBy(x => (int)x.StatusCode + " " + (x.Error ?? "（error なし）"))
                .Select(g => g.Key + " × " + g.Count()));

            r.Verify("**トークンを受け取ったのは 1 つだけ**", issued == 1,
                "1", issued + "（ほか：" + others + "）");
        }
    }
}
