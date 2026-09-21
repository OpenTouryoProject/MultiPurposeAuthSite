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
//* クラス名        ：ClientCredentialsTests
//* クラス日本語名  ：TC クライアント資格情報グラント
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

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-5. クライアント資格情報グラント。
    /// </summary>
    /// <remarks>
    /// **OAuth 2.1 でも有効なグラント**なので、Basic に残す（#220）。
    /// </remarks>
    public class ClientCredentialsTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientCredentialsTests(ITestOutputHelper output) : base(output)
        {
        }

        #region TC-5 クライアント クレデンシャル

        /// <summary>TC-5.1 正常系</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0501_クライアント資格情報でトークンを取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("TC-5.1",
                    "client_id / client_secret だけでトークンを取得できる",
                    "ユーザの文脈を持たない、アプリケーション自身のためのトークンが得られること。",
                    "RFC 6749 §4.4（Client Credentials Grant）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("POST /token に grant_type=client_credentials を送る");

                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
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

                r.Observe("refresh_token の有無",
                    string.IsNullOrEmpty(token.RefreshToken) ? "返らない" : "**返っている**",
                    "RFC 6749 §4.4.3 は「refresh_token を含めるべきではない」としている"
                    + "（クライアントは同じ資格情報でいつでも再取得できるため）。");

                if (!string.IsNullOrEmpty(token.AccessToken))
                {
                    JsonElement payload = Jwt.Payload(token.AccessToken);

                    r.Observe("sub（このトークンの主体）",
                        Jwt.String(payload, "sub") ?? "なし",
                        "ユーザの文脈を持たないので、クライアント自身を指すのが自然。");
                }

                r.Done();
            }
        }

        /// <summary>TC-5.2 権限範囲</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0502_クライアント資格情報のトークンでUserInfoを取得できない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("TC-5.2",
                    "クライアント クレデンシャルのトークンで /userinfo を取得できない",
                    "このトークンには**エンドユーザの文脈が無い**。"
                    + "/userinfo はエンドユーザの Claim を返す口なので、"
                    + "**email や phone_number といったユーザの属性が返ってはならない。**"
                    + "sub をどう扱うかは実装差があるため、そちらは観測にとどめる。",
                    "RFC 6749 §4.4 / OIDC Core §5.3（UserInfo はエンドユーザの Claim を返す）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) grant_type=client_credentials でトークンを取得する");

                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile email" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                JsonResponse token = await client.TokenAsync(form);

                Assert.True(!string.IsNullOrEmpty(token.AccessToken),
                    "前提: client_credentials でトークンが取得できること");

                r.Step("(2) そのトークンで GET /userinfo を叩く");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.Observe("/userinfo の応答",
                    "HTTP " + (int)userInfo.StatusCode + " / " + userInfo.ToString(),
                    "エンドユーザの Claim が返るなら、そのトークンの権限範囲が広すぎる。");

                // **ここが本題。** ユーザの属性が漏れていないか。
                string[] userClaims = new string[]
                {
                    "email", "email_verified", "phone_number", "phone_number_verified",
                    "name", "given_name", "family_name", "address"
                };

                List<string> leaked = new List<string>();

                foreach (string c in userClaims)
                {
                    if (userInfo.KindOf(c) != JsonValueKind.Undefined)
                    {
                        leaked.Add(c);
                    }
                }

                r.Verify("エンドユーザの属性が返らない", leaked.Count == 0,
                    "email / phone_number などを返さない",
                    leaked.Count == 0 ? "いずれも返らなかった"
                                      : "**返してしまった: " + string.Join(", ", leaked) + "**");

                // sub の扱いは実装差がある。判定せず、何が入っていたかを残す。
                r.Observe("sub に何が入るか",
                    userInfo.String("sub") ?? "（返らない）",
                    "エンドユーザが居ないので、クライアントの識別子が入るのが自然。"
                    + "ただし OIDC Core §5.3 の UserInfo は"
                    + "**エンドユーザの sub を返す口**であり、"
                    + "RP がこれをユーザ識別子と取り違える余地がある。"
                    + "openid スコープを伴わない要求は拒否する（403 insufficient_scope）方が安全。");

                r.Done();
            }
        }

        #endregion
    }
}
