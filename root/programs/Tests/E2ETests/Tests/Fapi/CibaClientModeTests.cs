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
//*  2026/09/22  玄人 幸道         FA-5.1 を開始（/ciba_authz）での拒否に改め、FA-5.2（既知でない登録値）を追加（#224 の段階 2）
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
    /// 登録種別だけ変えたクライアントを、環境変数でサイトへ差し込む**（設定ファイルは変えない）。
    ///   TestClient4_2 : normal / TestClient4_3 : fapi_1（既知でない値）
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

        /// <summary>FA-5.1 CIBA は fapi_ciba 以外の登録を、開始の時点で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0501_CIBAはfapi_ciba以外の登録を開始で断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_2);

                TestReport r = this.Report("FA-5.1",
                    "CIBA を normal 登録のクライアントで使うと、開始（/ciba_authz）で unauthorized_client になる",
                    "**利用者にプッシュ通知を送る前に断る。**"
                    + "以前は開始で登録種別を見ておらず、利用者に通知が届き、承認させた後で"
                    + "トークンの段階（unsupported_grant_type）で拒否していた（#224 の段階 0 で記録）。"
                    + "段階 2 で、開始の時点で判定するようにした（Device AuthZ の C-18 と同じ考え方）。",
                    "OpenID Connect CIBA Core §13 / #224");

                r.Target("client_name=" + KnownClients.TestClient4_2
                    + "（TestClient4 の写し。登録種別だけ normal。test.ps1 が差し込む）");

                r.Step("(1) 利用者 : 認証デバイスを登録する（通知を受けられる状態にしておく）");

                await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) normal 登録のクライアントで、CIBA の認証リクエストを送る");

                JsonResponse start = await CibaTests.StartAsync(client, reg, "FA-5.1");

                CibaClientModeTests.VerifyRejectedAtStart(r, start);

                r.Note("**(1) で端末を登録してあるので、以前の実装なら通知が送られていた。**"
                    + "開始で断ったので、auth_req_id は発行されず、利用者は何も操作しない。");

                r.Done();
            }
        }

        /// <summary>FA-5.2 登録種別が既知でない値なら、CIBA を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0502_登録種別が既知でない値ならCIBAを断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_3);

                TestReport r = this.Report("FA-5.2",
                    "oauth2_oidc_mode が既知でない値（fapi_1）のクライアントは、開始（/ciba_authz）で unauthorized_client になる",
                    "**既知でない登録値は、不正な登録として拒否する**（#224 の段階 2）。"
                    + "以前は fapi2 とみなしていた。「一番厳しい種別」に倒す作りは、"
                    + "種別が増えると意味が変わるため、やめた。"
                    + "なお oauth2_oidc_mode を書いていない登録は normal で、これには当たらない。",
                    "#224");

                r.Target("client_name=" + KnownClients.TestClient4_3
                    + "（TestClient4 の写し。登録種別だけ fapi_1＝書き間違い。test.ps1 が差し込む）");

                r.Step("(1) 利用者 : 認証デバイスを登録する");

                await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) 登録値が不正なクライアントで、CIBA の認証リクエストを送る");

                JsonResponse start = await CibaTests.StartAsync(client, reg, "FA-5.2");

                CibaClientModeTests.VerifyRejectedAtStart(r, start);

                r.Done();
            }
        }

        /// <summary>開始（/ciba_authz）で unauthorized_client により断られたことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="start">/ciba_authz の応答</param>
        private static void VerifyRejectedAtStart(TestReport r, JsonResponse start)
        {
            string authReqId = start.String("auth_req_id");

            r.Verify("auth_req_id を返さない（利用者へ通知しない）",
                string.IsNullOrEmpty(authReqId),
                "返さない",
                string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

            r.VerifyEqual("HTTP 400", "400", ((int)start.StatusCode).ToString());

            r.VerifyEqual("エラーは unauthorized_client", "unauthorized_client", start.Error ?? "（無し）");
        }
    }
}
