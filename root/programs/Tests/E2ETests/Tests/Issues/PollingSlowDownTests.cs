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
//* クラス名        ：PollingSlowDownTests
//* クラス日本語名  ：RT-305 ポーリングが速すぎたら slow_down を返す
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 1）
//**********************************************************************************

using System;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-305. **ポーリングが速すぎたら `slow_down` を返す**（#305 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **Device Authorization Grant と CIBA は、クライアントが `/token` を繰り返し叩く。**
    /// **間隔は `interval` で伝えてある**が、**守らなくても何も起きなかった。**
    ///
    /// | | |
    /// |---|---|
    /// | RFC 8628 §3.5 | **速すぎる要求には `slow_down`**（クライアントは間隔を 5 秒伸ばす） |
    /// | CIBA §11 | 同じ |
    ///
    /// **判定は「最後にポーリングされた時刻」だけ**（`LastPolledAt`。**表に持つ**ので、
    /// インスタンスを増やしても効く）。**初回は `slow_down` にしない。**
    ///
    /// **`slow_down` でも、要求は生きている**（まだ承認待ち）。
    /// **待ってから叩けば `authorization_pending` に戻る** — **それをこのケースで測る。**
    /// </remarks>
    //  **認証デバイスの登録を、他のテストと同時にやらない**（#305 の段階 1）。
    //    **`DeviceToken` は利用者の 1 つの列**なので、**並行して書くと互いの宛先を壊す**
    //    （実測 : `RT-233.1` が「別の宛先」で落ちた）。**CIBA 系と同じ collection に入れる。**
    [Collection(Tests.Extended.CibaTests.DeviceCollection)]
    public class PollingSlowDownTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PollingSlowDownTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-305.1

        /// <summary>RT-305.1 Device : 速すぎるポーリングは slow_down</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30501_Deviceの速すぎるポーリングはslow_down(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(
                    client, "urn:ietf:params:oauth:grant-type:device_code");

                TestReport r = this.Report("RT-305.1",
                    "Device Authorization Grant : `interval` より短い間隔のポーリングに `slow_down` を返す",
                    "**機器は `interval` を守る義務があるが、守らなくても何も起きなかった**"
                    + "（`ANALYSIS-IdP.md` の D-13。**コードにも「slow_down を検討する」と"
                    + "コメントだけ残っていた**）。"
                    + "**叩き続けられると、`/token` が総当たりの的になる。**"
                    + "**`slow_down` は、仕様が用意した断り方**である。",
                    "RFC 8628 §3.5（slow_down）/ #305 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);
                int interval = PollingSlowDownTests.IntervalOf(client, "DeviceAuthZPollingIntervalSeconds");

                r.Target("client_name=" + KnownClients.TestClient3
                    + " / interval=" + interval + " 秒");

                r.Step("(1) 機器 : POST /device_authz で device_code を得る");

                JsonResponse start = await DeviceAuthorizationTests.StartAsync(client, reg.ClientId);
                string deviceCode = start.String("device_code");

                Assert.False(string.IsNullOrEmpty(deviceCode), "前提: device_code が発行されること");

                r.Observe("応答の interval", start.String("interval") ?? "（無し）",
                    "**機器はこの秒数だけ待つ**（RFC 8628 §3.2）。");

                r.Step("(2) 1 回目のポーリング（初回は slow_down にしない）");

                JsonResponse first = await DeviceAuthorizationTests.PollAsync(
                    client, reg.ClientId, deviceCode);

                r.VerifyEqual("authorization_pending を返す", "authorization_pending", first.Error);

                r.Step("(3) 続けて 2 回目（間隔を守っていない）");

                JsonResponse second = await DeviceAuthorizationTests.PollAsync(
                    client, reg.ClientId, deviceCode);

                r.VerifyEqual("slow_down を返す", "slow_down", second.Error);

                r.Verify("トークンは発行しない", string.IsNullOrEmpty(second.AccessToken),
                    "返さない",
                    string.IsNullOrEmpty(second.AccessToken) ? "返さなかった" : "**返してしまった**");

                r.Step("(4) interval ＋ 1 秒待ってから、3 回目");

                await Task.Delay(TimeSpan.FromSeconds(interval + 1));

                JsonResponse third = await DeviceAuthorizationTests.PollAsync(
                    client, reg.ClientId, deviceCode);

                r.VerifyEqual("authorization_pending に戻る（要求は生きている）",
                    "authorization_pending", third.Error);

                r.Note("**`slow_down` で要求を消していない**ことが、(4) で分かる。"
                    + "**消していたら `invalid_grant` か `expired_token` になる。**");

                r.Done();
            }
        }

        #endregion

        #region RT-305.2

        /// <summary>RT-305.2 CIBA : 速すぎるポーリングは slow_down</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30502_CIBAの速すぎるポーリングはslow_down(string targetKey)
        {
            //  **サインイン済みの client が要る**（認証デバイスの登録が、利用者のトークンで行われる）。
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(
                    client, "urn:openid:params:grant-type:ciba");

                //  **プッシュ通知の送信箱が無いと、CIBA は測れない**（`EX-8.*` と同じ前提）。
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-305.2",
                    "CIBA : `interval` より短い間隔のポーリングに `slow_down` を返す",
                    "**CIBA も、クライアントが `/token` を繰り返し叩く。**"
                    + "**Device と同じ判定**（`LastPolledAt`）で、**同じ断り方**をする。",
                    "CIBA Core §11（slow_down）/ #305 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                int interval = PollingSlowDownTests.IntervalOf(client, "CibaPollingIntervalSeconds");

                r.Target("client_name=" + KnownClients.TestClient4
                    + " / interval=" + interval + " 秒");

                r.Step("(1) ユーザ : 認証デバイスを登録する（POST /SetDeviceToken）");

                //  **CIBA は、認証デバイスへ通知できないと始まらない**（`EX-8.*` と同じ段取り）。
                await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : CIBA の認証リクエストを送る");

                JsonResponse start = await CibaTests.StartAsync(client, reg, "rt305-2");
                string authReqId = start.String("auth_req_id");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が発行されること");

                r.Step("(3) 1 回目のポーリング（初回は slow_down にしない）");

                JsonResponse first = await CibaTests.PollAsync(client, reg, authReqId);

                r.VerifyEqual("authorization_pending を返す", "authorization_pending", first.Error);

                r.Step("(4) 続けて 2 回目（間隔を守っていない）");

                JsonResponse second = await CibaTests.PollAsync(client, reg, authReqId);

                r.VerifyEqual("slow_down を返す", "slow_down", second.Error);

                r.Step("(5) interval ＋ 1 秒待ってから、3 回目");

                await Task.Delay(TimeSpan.FromSeconds(interval + 1));

                JsonResponse third = await CibaTests.PollAsync(client, reg, authReqId);

                r.VerifyEqual("authorization_pending に戻る（要求は生きている）",
                    "authorization_pending", third.Error);

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>この配備の interval（秒。読めなければ 5）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">設定キー</param>
        /// <returns>秒数</returns>
        /// <remarks>
        /// **環境変数が構成ファイルより強い**（`FxContainerization`）。
        /// **そちらを先に見る**（`RT-303.1` と同じ理由）。
        /// </remarks>
        private static int IntervalOf(IdPClient client, string key)
        {
            string value = Environment.GetEnvironmentVariable(key);

            if (string.IsNullOrEmpty(value))
            {
                value = client.Config.Get(key);
            }

            int seconds = 0;
            return (int.TryParse(value ?? "", out seconds) && 0 < seconds) ? seconds : 5;
        }

        #endregion
    }
}
