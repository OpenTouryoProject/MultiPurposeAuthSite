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
//* クラス名        ：CibaClaimTests
//* クラス日本語名  ：RT CIBA の認証要求のクレームの読み方（#337）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/06  玄人 幸道         新規（#337）
//*  2026/11/06  玄人 幸道         RT-337.2（任意のクレームも、オブジェクト・配列なら断る）を足した（#337）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-337. CIBA の認証要求のクレームを、Open棟梁 の `TryGetStringClaim`（OpenTouryo#662）で取り出す。
    /// </summary>
    /// <remarks>
    /// | 値 | 以前（`CheckClaims`） | いま（`TryGetStringClaim`） |
    /// |---|---|---|
    /// | 日付の形の文字列 | 日付に変えてから、書式の違う文字列にした | **そのままの文字列**（payload を日付に変えずに読む） |
    /// | 明示的な `null`（必須のクレーム） | 値を null として通した | **無いのと同じに断る**（invalid_request） |
    /// | オブジェクト・配列 | 例外（Open棟梁 の取り込みの後は server_error） | **invalid_request**（任意のクレームも同じ。RT-337.2） |
    /// </remarks>
    public class CibaClaimTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CibaClaimTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>HTTP ステータスと、本文の error を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        /// <param name="status">期待する HTTP ステータス</param>
        /// <param name="error">期待する error</param>
        private static void VerifyError(
            TestReport r, string label, JsonResponse res, int status, string error)
        {
            r.VerifyEqual(label + " : HTTP " + status + " で返る",
                status.ToString(), ((int)res.StatusCode).ToString());

            r.VerifyEqual(label + " : error", error, res.Error);
        }

        #region RT-337.1

        /// <summary>RT-337.1 /ciba_authz は、login_hint を JSON の文字列のまま読み、null・オブジェクトは invalid_request で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33701_ciba_authzはlogin_hintを文字列のまま読みnullとオブジェクトを断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-337.1",
                    "/ciba_authz : login_hint は、日付の形でも文字列のまま読む。null・オブジェクトは invalid_request で断る",
                    "**login_hint は文字列のクレーム**で、日付の形をしていても、利用者を指す値として読む（日付として読めずに断らない）。"
                    + "**必須のクレームが null・オブジェクトなら、要求の誤り**として invalid_request（HTTP 400）で返す（500・server_error にしない）。",
                    "CIBA Core §7.1 / §13 / #337");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);

                r.Target("client_name=" + KnownClients.FapiCibaClient + "（fapi_ciba。要求は ES256 で署名し、request で送る）");

                r.Step("(1) login_hint が日付の形の文字列（その利用者は居ない）");

                //  **文字列のまま読めれば、利用者を引きに行き unknown_user_id になる。**
                //    日付に変えて読めなくなると、手前で invalid_request になる。
                VerifyError(r, "日付の形の login_hint", await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                            new Dictionary<string, object>() { { "login_hint", "2026-11-06T00:00:00Z" } }) }
                    },
                    reg.ClientId, reg.ClientSecret), 400, "unknown_user_id");

                r.Step("(2) login_hint が null");

                VerifyError(r, "null の login_hint", await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                            new Dictionary<string, object>() { { "login_hint", null } }) }
                    },
                    reg.ClientId, reg.ClientSecret), 400, "invalid_request");

                r.Step("(3) login_hint がオブジェクト");

                VerifyError(r, "オブジェクトの login_hint", await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                            new Dictionary<string, object>()
                            {
                                { "login_hint", new Dictionary<string, object>() { { "sub", "x" } } }
                            }) }
                    },
                    reg.ClientId, reg.ClientSecret), 400, "invalid_request");

                r.Done();
            }
        }

        #endregion

        #region RT-337.2

        /// <summary>RT-337.2 /ciba_authz は、任意のクレームでも、オブジェクト・配列なら invalid_request で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33702_ciba_authzは任意のクレームでもオブジェクトと配列を断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-337.2",
                    "/ciba_authz : 任意のクレーム（binding_message・user_code・requested_expiry・client_notification_token）でも、オブジェクト・配列なら invalid_request で断る",
                    "**任意のクレームは、無いのはよいが、在るなら文字列（requested_expiry は正の整数）でなければならない。**"
                    + "読めない値を無いものとして受けると、requested_expiry の {} が既定の期限で通るなど、要求の誤りを握りつぶす。",
                    "CIBA Core §7.1 / §13 / #337");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);

                r.Target("client_name=" + KnownClients.FapiCibaClient + "（fapi_ciba。要求は ES256 で署名し、request で送る。login_hint の利用者は居ない）");

                //  **対照：正しい要求は、クレームの確認を抜けて利用者を引きに行き、unknown_user_id になる。**
                //    **読めない任意のクレームを受けてしまうと、同じく unknown_user_id になる**ので、invalid_request との違いで見分けられる。
                r.Step("(1) 対照：任意のクレームが正しい要求");

                VerifyError(r, "正しい要求", await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                            new Dictionary<string, object>()) }
                    },
                    reg.ClientId, reg.ClientSecret), 400, "unknown_user_id");

                foreach (string claim in new string[]
                {
                    "binding_message", "user_code", "requested_expiry", "client_notification_token"
                })
                {
                    r.Step("(2) " + claim + " がオブジェクト・配列");

                    VerifyError(r, claim + " がオブジェクト", await client.CibaAuthorizeWithBasicAuthAsync(
                        new Dictionary<string, string>()
                        {
                            { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                                new Dictionary<string, object>()
                                {
                                    { claim, new Dictionary<string, object>() { { "x", "y" } } }
                                }) }
                        },
                        reg.ClientId, reg.ClientSecret), 400, "invalid_request");

                    VerifyError(r, claim + " が配列", await client.CibaAuthorizeWithBasicAuthAsync(
                        new Dictionary<string, string>()
                        {
                            { "request", await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                                new Dictionary<string, object>()
                                {
                                    { claim, new string[] { "x" } }
                                }) }
                        },
                        reg.ClientId, reg.ClientSecret), 400, "invalid_request");
                }

                r.Done();
            }
        }

        #endregion
    }
}
