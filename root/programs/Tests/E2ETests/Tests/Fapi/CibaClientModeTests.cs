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
//* クラス名        ：CibaClientModeTests
//* クラス日本語名  ：FA CIBA を fapi_ciba 以外の登録で使ったとき（#224）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/22  玄人 幸道         新規（#224 の段階 0 : CIBA × 登録種別）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Fapi
{
    /// <summary>
    /// FA-5. CIBA を、fapi_ciba 以外の登録種別のクライアントで使ったときの振る舞い。
    /// </summary>
    /// <remarks>
    /// **CIBA の要求は、クライアントの鍵で署名して /ros に登録する。** サーバは登録済みの
    /// jwk_ecdsa_publickey で検証するので、鍵を持たないクライアントでは署名検証で先に落ち、
    /// 登録種別の判定まで届かない。**そこで test.ps1 -Launch が、TestClient4（fapi_ciba）を写して
    /// 登録種別だけ normal にした TestClient4_2 を、環境変数でサイトへ差し込む**（設定ファイルは変えない）。
    ///
    /// **EX-8（CibaTests）と同じコレクションに入れる。** どちらも既定の利用者に端末（device_token）を
    /// 登録してプッシュ通知を受けるので、並行して動くと端末の登録を奪い合う。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class CibaClientModeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaClientModeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>FA-5.1 CIBA は fapi_ciba の登録にだけトークンを出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0501_CIBAはfapi_cibaの登録にだけトークンを出す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_2);

                TestReport r = this.Report("FA-5.1",
                    "CIBA を normal 登録のクライアントで使うと、トークンの段階で拒否される",
                    "**CIBA のトークン発行（GrantCiba）は、登録種別が fapi_ciba と一致するときだけ通す。**"
                    + "一方、開始（/ciba_authz）は登録種別を見ていない。"
                    + "そのため**利用者にプッシュ通知が届き、承認させた後で**拒否になる。"
                    + "本テストは**今の振る舞いを記録する**（#224 の段階 0）。",
                    "OpenID Connect CIBA Core / #224");

                r.Target("client_name=" + KnownClients.TestClient4_2
                    + "（TestClient4 の写し。登録種別だけ normal。test.ps1 が差し込む）");

                r.Step("(1) 利用者 : 認証デバイスを登録する");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) normal 登録のクライアントで、CIBA の認証リクエストを送る");

                JsonResponse start = await CibaTests.StartAsync(client, reg, "FA-5.1");
                string authReqId = start.String("auth_req_id");

                r.Verify("開始は受け付けられる（登録種別を見ていない）",
                    !string.IsNullOrEmpty(authReqId),
                    "auth_req_id あり",
                    string.IsNullOrEmpty(authReqId)
                        ? "**無し**（" + (int)start.StatusCode + " / " + (start.Error ?? "なし") + "）"
                        : "あり（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること");

                r.Step("(3) 利用者 : プッシュ通知を受け、認証デバイスで「許可」を押す");

                await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                r.VerifyEqual("返答 : HTTP 200", "200", ((int)answer.StatusCode).ToString());

                r.Step("(4) クライアント : ポーリングする");

                JsonResponse token = await CibaTests.PollAsync(client, reg, authReqId);

                r.Verify("トークンを返さない",
                    string.IsNullOrEmpty(token.AccessToken),
                    "返さない",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "返さなかった（error=" + (token.Error ?? "なし") + "）" : "**返してしまった**");

                r.Verify("エラーは unsupported_grant_type",
                    token.Error == "unsupported_grant_type",
                    "unsupported_grant_type", token.Error ?? "（無し）");

                r.Note("**拒否が遅い。** 利用者はプッシュ通知を受け、承認まで済ませている。"
                    + "開始（/ciba_authz）で登録種別を見れば、利用者を煩わせずに済む"
                    + "（#224 の段階 2 の候補。Device AuthZ は開始でも弾くようにした。C-18）。");

                r.Done();
            }
        }
    }
}
