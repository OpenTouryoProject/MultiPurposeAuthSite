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
//* クラス名        ：CibaNbfClockSkewTests
//* クラス日本語名  ：RT-412 CIBA の署名した要求の nbf は、時計のずれの許容幅まで未来でも受ける
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/20  玄人 幸道         新規（#412）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-412. **CIBA の署名した要求（`request`）の `nbf` は、時計のずれの許容幅（既定 10 秒）まで未来でも受ける。**
    /// </summary>
    /// <remarks>
    /// **Open棟梁 の `RequestObject.VerifyCiba` は、許容幅（`CmnJwtToken.ClockSkewSeconds`）まで未来の `nbf` を受ける**（OpenTouryo#689）。
    /// **MPAS は、その後に自前でも `nbf` を確かめていて、そちらは許容幅を取らなかった**ので、
    /// **部品が受けた要求を、CIBA だけ「The request is not yet valid.」で断っていた**（`client_assertion`・`/ros`・PAR は受ける）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-412.1`** | **`nbf` が 5 秒先の要求は、`nbf` では断らない**。**30 秒先（許容幅の外）の要求は、`400` ＋ `invalid_request` で断り、`auth_req_id` を返さない** |
    ///
    /// **サイトとテストは同じ機械で動く**ので、時計はずれていない。5 秒先・30 秒先は、どちらも送ってから着くまでの時間より十分に大きい。
    /// **`CibaTests` のコレクションに入れる。** 5 秒先の要求は `nbf` では断られず、その先（端末への通知）へ進みうるので、
    /// 端末を登録するテストと並行して動かさない（`RT-388.2` と同じ）。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class CibaNbfClockSkewTests : TargetTestBase
    {
        /// <summary>許容幅の中の nbf（秒。既定の許容幅は 10 秒）</summary>
        private const long WithinSkewSeconds = 5;

        /// <summary>許容幅の外の nbf（秒）</summary>
        private const long BeyondSkewSeconds = 30;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaNbfClockSkewTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-412.1 CIBA の要求の nbf が許容幅の中なら受け、外なら断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT41201_CIBAの要求のnbfが許容幅の中なら受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-412.1",
                    "CIBA の署名した要求の nbf が 5 秒先なら nbf では断らず、30 秒先なら invalid_request で断る",
                    "**認可サーバは、時計のずれを見込んで、nbf が 0〜10 秒先の JWT を受け、60 秒より先のものを断る。**"
                    + "**以前は、部品（VerifyCiba）が受けた要求を、MPAS の自前の確かめが許容幅なしで断っていた**（OpenTouryo#689 の取り込み）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 7519 §4.1.5 / #412");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ciba_authz（client_name=" + KnownClients.FapiCibaClient + "。request に署名付き JWT）");

                r.Step("(1) nbf が " + CibaNbfClockSkewTests.WithinSkewSeconds + " 秒先（exp は 5 分先）は、nbf では断らない");

                JsonResponse within = await CibaNbfClockSkewTests.SendAsync(
                    client, reg, now + CibaNbfClockSkewTests.WithinSkewSeconds, now + 5 * 60);
                string withinDescription = within.String("error_description") ?? "";

                // **nbf で断ると、部品は「not verified」、MPAS は「not yet valid」を返す。** どちらでもないこと。
                //   **その先（端末の登録など）で止まるのはよい**（RT-388.2 と同じ）。
                bool rejectedByNbf = withinDescription.Contains("not yet valid") || withinDescription.Contains("not verified");

                r.Verify(CibaNbfClockSkewTests.WithinSkewSeconds + " 秒先 : nbf では断らない", !rejectedByNbf,
                    "nbf では断らない",
                    rejectedByNbf ? "**nbf で断った**（" + withinDescription + "）"
                        : "HTTP " + (int)within.StatusCode + " / " + (within.Error ?? "error 無し"));

                r.Step("(2) nbf が " + CibaNbfClockSkewTests.BeyondSkewSeconds + " 秒先（exp は 5 分先）は、断る");

                JsonResponse beyond = await CibaNbfClockSkewTests.SendAsync(
                    client, reg, now + CibaNbfClockSkewTests.BeyondSkewSeconds, now + 5 * 60);
                string authReqId = beyond.String("auth_req_id");
                string label = CibaNbfClockSkewTests.BeyondSkewSeconds + " 秒先";

                r.Verify(label + " : auth_req_id を返さない（利用者へ通知しない）", string.IsNullOrEmpty(authReqId),
                    "返さない", string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

                r.VerifyEqual(label + " : HTTP 400", "400", ((int)beyond.StatusCode).ToString());
                r.VerifyEqual(label + " : invalid_request", "invalid_request", beyond.Error ?? "（無し）");

                r.Done();
            }
        }

        #region 補助

        /// <summary>exp・nbf を指定した要求を送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="nbf">nbf</param>
        /// <param name="exp">exp</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> SendAsync(IdPClient client, ClientRegistration reg, long nbf, long exp)
        {
            string jws = await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId, new Dictionary<string, object>()
            {
                { "login_hint", TestEnv.TestUserName(client.Target.Key) },
                { "binding_message", "E2E-nbf-skew" },
                { "nbf", nbf },
                { "exp", exp }
            });

            return await client.CibaAuthorizeWithBasicAuthAsync(new Dictionary<string, string>()
            {
                { "request", jws }
            }, reg.ClientId, reg.ClientSecret);
        }

        #endregion
    }
}
