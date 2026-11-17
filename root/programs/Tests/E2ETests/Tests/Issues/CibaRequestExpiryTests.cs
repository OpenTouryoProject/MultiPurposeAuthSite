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
//* クラス名        ：CibaRequestExpiryTests
//* クラス日本語名  ：RT-388 CIBA の署名した要求の寿命は 60 分まで（FAPI-CIBA ID1 §5.2.2 の 9）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#388）
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
    /// RT-388. **CIBA の署名した要求（`request`）の寿命は 60 分まで**（FAPI-CIBA ID1 §5.2.2 の 9）。
    /// </summary>
    /// <remarks>
    /// **以前は、`exp` が過ぎていないこと・`nbf` が先でないことだけを見ていた**ので、
    /// **寿命の長い要求を受けていた**（適合性テストの `ensure-request-object-exp-is-70-minutes-in-future-fails`・
    /// `ensure-request-object-nbf-is-70-minutes-in-past-fails`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-388.1`** | **`exp` が `nbf` から 70 分先・`nbf` が 70 分前の要求は、`400` ＋ `invalid_request`**（理由が寿命であることも確かめる）。**`auth_req_id` を返さない** |
    /// | **`RT-388.2`** | **境界**：寿命がちょうど 60 分の要求は寿命では断らず、60 分 1 秒なら断る |
    ///
    /// **寿命の短い要求（既定の 10 分）が通ることは `RT-233.1`・`EX-8` が測る。**
    /// **`CibaTests` のコレクションに入れる。** `RT-388.2` の 60 分ちょうどの要求は寿命では断られず、その先（端末への通知）へ進みうるので、
    /// 端末を登録するテストと並行して動かさない。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class CibaRequestExpiryTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaRequestExpiryTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-388.1 CIBA の署名した要求の寿命が 60 分を超えるなら断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38801_CIBAの要求の寿命が60分を超えるなら断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-388.1",
                    "CIBA の署名した要求の寿命が 60 分を超える（exp が nbf から 70 分先・nbf が 70 分前）なら、invalid_request で断る",
                    "**FAPI-CIBA は、署名した認証要求に nbf・exp を求め、寿命を 60 分以内に限ることを求める。**"
                    + "**以前は exp が過ぎていないこと・nbf が先でないことだけを見ていた**"
                    + "（適合性テストの ensure-request-object-exp-is-70-minutes-in-future-fails・nbf-is-70-minutes-in-past-fails）。",
                    "FAPI-CIBA ID1 §5.2.2 / CIBA Core §13 / #388");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ciba_authz（client_name=" + KnownClients.FapiCibaClient + "。request に署名付き JWT）");

                r.Step("(1) exp が nbf から 70 分先（nbf は今）");

                await CibaRequestExpiryTests.VerifyRejectedAsync(r, client, reg, "exp が 70 分先", now, now + 70 * 60);

                r.Step("(2) nbf が 70 分前（exp は 5 分先）");

                await CibaRequestExpiryTests.VerifyRejectedAsync(r, client, reg, "nbf が 70 分前", now - 70 * 60, now + 5 * 60);

                r.Done();
            }
        }

        /// <summary>RT-388.2 寿命がちょうど 60 分なら寿命では断らず、60 分 1 秒なら断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38802_寿命がちょうど60分なら寿命では断らない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-388.2",
                    "CIBA の署名した要求の寿命がちょうど 60 分なら寿命では断らず、60 分 1 秒なら invalid_request で断る",
                    "**FAPI-CIBA は寿命を「60 分以内」に限る**（60 分ちょうどは許す）。"
                    + "**境界の取り違え（< と <=）を測る。** 60 分ちょうどの要求は、寿命の後の確かめ（端末の登録など）で止まってよい。",
                    "FAPI-CIBA ID1 §5.2.2 / #388");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ciba_authz（client_name=" + KnownClients.FapiCibaClient + "。request に署名付き JWT）");

                r.Step("(1) 寿命がちょうど 60 分（nbf は今、exp は 3600 秒先）は、寿命では断らない");

                JsonResponse exact = await CibaRequestExpiryTests.SendAsync(client, reg, now, now + 3600);
                string exactDescription = exact.String("error_description") ?? "";

                r.Verify("60 分ちょうど : 寿命では断らない", !exactDescription.Contains("60 minutes"),
                    "寿命では断らない",
                    exactDescription.Contains("60 minutes") ? "**寿命で断った**"
                        : "HTTP " + (int)exact.StatusCode + " / " + (exact.Error ?? "error 無し"));

                r.Step("(2) 寿命が 60 分 1 秒（exp は 3601 秒先）は、断る");

                await CibaRequestExpiryTests.VerifyRejectedAsync(r, client, reg, "60 分 1 秒", now, now + 3601);

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
                { "binding_message", "E2E-lifetime" },
                { "nbf", nbf },
                { "exp", exp }
            });

            return await client.CibaAuthorizeWithBasicAuthAsync(new Dictionary<string, string>()
            {
                { "request", jws }
            }, reg.ClientId, reg.ClientSecret);
        }

        /// <summary>exp・nbf を指定した要求を送り、invalid_request で断ることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="label">何の要求か</param>
        /// <param name="nbf">nbf</param>
        /// <param name="exp">exp</param>
        /// <returns>Task</returns>
        private static async Task VerifyRejectedAsync(
            TestReport r, IdPClient client, ClientRegistration reg, string label, long nbf, long exp)
        {
            JsonResponse start = await CibaRequestExpiryTests.SendAsync(client, reg, nbf, exp);

            string authReqId = start.String("auth_req_id");

            r.Verify(label + " : auth_req_id を返さない（利用者へ通知しない）", string.IsNullOrEmpty(authReqId),
                "返さない", string.IsNullOrEmpty(authReqId) ? "返さなかった" : "**返した**（値は伏せる）");

            r.VerifyEqual(label + " : HTTP 400", "400", ((int)start.StatusCode).ToString());
            r.VerifyEqual(label + " : invalid_request", "invalid_request", start.Error ?? "（無し）");

            string description = start.String("error_description");
            bool isLifetime = !string.IsNullOrEmpty(description) && description.Contains("60 minutes");

            r.Verify(label + " : 断る理由は寿命", isLifetime,
                "寿命", isLifetime ? "寿命" : "**" + (description ?? "（無い）") + "**");
        }

        #endregion
    }
}
