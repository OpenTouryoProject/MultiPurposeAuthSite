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
//* クラス名        ：PasswordTests
//* クラス日本語名  ：TC ROPC（OAuth 2.1 では廃止。#220）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/18  玄人 幸道         #220 でファイルを分けた（元 : Basic/PasswordAndClientCredentialsTests.cs）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Obsolete
{
    /// <summary>
    /// TC-4. ROPC（Resource Owner Password Credentials）。
    /// </summary>
    /// <remarks>
    /// **OAuth 2.1 では廃止されたフロー。** 雛形の既定でも無効にした（#220）。
    /// 有効にしている環境のために残してあり、無効なら Skip する。
    /// </remarks>
    public class PasswordTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PasswordTests(ITestOutputHelper output) : base(output)
        {
        }

        #region TC-4 パスワード グラント（ROPC）

        /// <summary>TC-4.1 正常系</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0401_正しい資格情報でトークンを取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                // **ROPC は雛形の既定で無効**（#220）。有効な環境でだけ測る。
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "password");

                TestReport r = this.Report("TC-4.1",
                    "正しい username / password でトークンを取得できる",
                    "トークン エンドポイントへ資格情報を直接送り、access_token を得られること。",
                    "RFC 6749 §4.3（Resource Owner Password Credentials Grant）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample
                    + " / username=" + TestEnv.TestUserName + "（パスワードは構成ファイルから読む）");
                r.Step("POST /token に grant_type=password と username / password を送る");

                // テスト ユーザは、サインイン画面への初回アクセスで作られる。
                await client.GetAsync("/Account/Login");

                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "email profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                JsonResponse token = await client.TokenAsync(form);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(token.AccessToken))
                {
                    JsonElement payload = Jwt.Payload(token.AccessToken);

                    r.Verify("sub がテスト ユーザである",
                        Jwt.String(payload, "sub") == TestEnv.TestUserName,
                        TestEnv.TestUserName, "sub = " + (Jwt.String(payload, "sub") ?? "なし"));
                }

                r.Done();
            }
        }

        /// <summary>TC-4.2 誤った資格情報</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0402_誤った資格情報が拒否される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                // **ROPC は雛形の既定で無効**（#220）。有効な環境でだけ測る。
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "password");

                TestReport r = this.Report("TC-4.2",
                    "誤ったパスワード / 存在しないユーザが拒否される",
                    "誤った資格情報でトークンが出てはならない。"
                    + "また、**「ユーザが居ない」と「パスワードが違う」を応答で区別できると、"
                    + "ユーザ名の存在を調べられる。**両者の応答が同じであることも見る。",
                    "RFC 6749 §4.3.2 / §5.2（invalid_grant）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 実在するユーザ ＋ 誤ったパスワード");

                Dictionary<string, string> wrongPassword = new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", "WRONG-PASSWORD-WRONG-PASSWORD" },
                    { "scope", "email" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                JsonResponse t1 = await client.TokenAsync(wrongPassword);

                r.Verify("誤ったパスワードでトークンを発行しない",
                    string.IsNullOrEmpty(t1.AccessToken),
                    "access_token を返さない",
                    t1.AccessToken == null ? "返さなかった（error=" + (t1.Error ?? "なし") + "）"
                                           : "**返してしまった**");

                r.Step("(2) 存在しないユーザ");

                Dictionary<string, string> unknownUser = new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", "no-such-user@example.com" },
                    { "password", "WRONG-PASSWORD-WRONG-PASSWORD" },
                    { "scope", "email" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                JsonResponse t2 = await client.TokenAsync(unknownUser);

                r.Verify("存在しないユーザでトークンを発行しない",
                    string.IsNullOrEmpty(t2.AccessToken),
                    "access_token を返さない",
                    t2.AccessToken == null ? "返さなかった（error=" + (t2.Error ?? "なし") + "）"
                                           : "**返してしまった**");

                r.Observe("2 つの応答を区別できるか",
                    "誤パスワード = error:" + (t1.Error ?? "なし")
                    + " / desc:" + (t1.ErrorDescription ?? "なし")
                    + "  ||  未知ユーザ = error:" + (t2.Error ?? "なし")
                    + " / desc:" + (t2.ErrorDescription ?? "なし"),
                    "同じ応答であることが望ましい（ユーザ名の存在が漏れないため）。");

                r.Note("ブルート フォース対策（連続失敗でのロックアウト）と、"
                    + "HTTPS 非適用時の拒否は、このテストでは扱わない。"
                    + "前者は試行を繰り返す必要があり、後者は待ち受け構成の話であるため。");

                r.Done();
            }
        }

        #endregion

    }
}
