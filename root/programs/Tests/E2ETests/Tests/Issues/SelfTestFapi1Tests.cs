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
//* クラス名        ：SelfTestFapi1Tests
//* クラス日本語名  ：RT 自己テストの FAPI1 のボタンを、結果の画面まで通す（#341）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/07  玄人 幸道         新規（#341）
//**********************************************************************************

using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-341. 自己テストの FAPI1 のボタンが、`private_key_jwt` で認可コードを引き換え、結果の画面まで進む。
    /// </summary>
    /// <remarks>
    /// **`RT-324.7`（FAPI1・FAPI1_OIDC）と `RT-245.6`（FAPI1_PKCE）は、`/authorize` へ送るところまで**を見ていた。
    /// 戻り（`/Account/OAuth2AuthorizationCodeGrantClient`）のトークン要求は、
    /// **方法を明示していない `FAPI1_Client` では `invalid_client` になっていた**（#307 の段階 3 から。#341）。
    ///
    /// **「FAPI1 PC, PKCE」は、ここでは測らない。** アサーションと `code_verifier` を一緒に送る口が、
    /// Open棟梁 のクライアントに無いため（#341 の案 2。Open棟梁 に足してから測る）。
    /// </remarks>
    public class SelfTestFapi1Tests : TargetTestBase
    {
        /// <summary>エラー画面の見出し</summary>
        private const string ErrorHeading = "<h2 class=\"text-danger\">";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SelfTestFapi1Tests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-341.1

        /// <summary>RT-341.1 自己テストの FAPI1 のボタンが、private_key_jwt で引き換えて、結果の画面まで進む</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34101_自己テストのFAPI1のボタンが結果の画面まで進む(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-341.1",
                    "自己テストの FAPI1 のボタン（FAPI1・FAPI1, OIDC）が、private_key_jwt を明示した fapi1 の登録を選び、トークンを得て結果の画面まで進む",
                    "**自己テストは、FAPI1 の認可コードを `private_key_jwt`（`client_assertion`）で引き換える。**"
                    + "**登録が方法を明示していないと、`private_key_jwt` は通らない**（登録が空なら `client_secret` だけ）。"
                    + "**fapi1 の登録は `client_secret` では引き換えられない**ので、**明示した登録を選ぶ必要がある。**",
                    "RFC 7523 §2.2 / RFC 7591 §2 / #341");

                string configured = client.Config.FindClientIdByName(KnownClients.Fapi1PrivateKeyJwtClient);

                Skip.If(string.IsNullOrEmpty(configured),
                    "client_name=" + KnownClients.Fapi1PrivateKeyJwtClient + " が構成ファイルに在りません（雛形から写してください。#341）: "
                    + client.Config.Path);

                await client.SignInAsync();

                r.Target("自己テスト（ClientType=fapi1）: " + KnownClients.Fapi1PrivateKeyJwtClient + "（fapi1。token_endpoint_auth_method=private_key_jwt）");

                foreach (string starter in new string[] { "AuthorizationCodeFAPI1", "AuthorizationCodeFAPI1_OIDC" })
                {
                    r.Step("「" + starter + "」を押し、認可して、戻りの画面を開く");

                    HttpResponseMessage start = await client.StartSelfTestAsync(starter, "fapi1");
                    string authorizeUrl = (start.Headers.Location == null) ? null : start.Headers.Location.OriginalString;

                    Skip.If(string.IsNullOrEmpty(authorizeUrl),
                        "自己テストが認可リクエストへ飛びません（HTTP " + (int)start.StatusCode + "。IsLockedDownTestEndpoints を確認）。");

                    //  **選んだのは、private_key_jwt を明示した登録**（FAPI1_Client ではない）。
                    r.VerifyEqual(starter + " : client_id は " + KnownClients.Fapi1PrivateKeyJwtClient, configured,
                        Saml2.QueryValue(authorizeUrl, "client_id"));

                    AuthZResponse authz = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(authorizeUrl));
                    Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                    HttpResponseMessage screen = await client.GetAsync(authz.Location);
                    string html = await screen.Content.ReadAsStringAsync();

                    r.Verify(starter + " : 結果の画面が返る（エラー画面にならない）",
                        screen.StatusCode == HttpStatusCode.OK && !html.Contains(ErrorHeading),
                        "HTTP 200 / エラー画面ではない", "HTTP " + (int)screen.StatusCode + " / " + Html.Describe(html));

                    string accessToken = Html.FieldValue(html, "AccessToken");

                    r.Verify(starter + " : access_token が出る（トークン要求が通った）", !string.IsNullOrEmpty(accessToken),
                        "出る", string.IsNullOrEmpty(accessToken) ? "**出ない**（" + Html.FieldValue(html, "Response") + "）" : "出る");

                    if (starter.EndsWith("_OIDC"))
                    {
                        string idToken = Html.FieldValue(html, "IdToken");

                        r.Verify(starter + " : id_token が出る", !string.IsNullOrEmpty(idToken),
                            "出る", string.IsNullOrEmpty(idToken) ? "**出ない**" : "出る");
                    }
                }

                r.Done();
            }
        }

        #endregion
    }
}
