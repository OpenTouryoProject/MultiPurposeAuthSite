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
//* クラス名        ：RevocationTests
//* クラス日本語名  ：EX-2 トークンの失効（RFC 7009）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-2. トークンの失効（RFC 7009 / POST /revoke）。
    ///
    /// 失効の応答が「成功」でも、実際にトークンが使えてしまっては意味がない。
    /// **失効させた後に、使えなくなったことまで**確かめる。
    /// </summary>
    public class RevocationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RevocationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>POST /revoke を呼ぶ</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">認証に使うクライアント</param>
        /// <param name="token">失効させるトークン</param>
        /// <param name="tokenTypeHint">token_type_hint（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        internal static Task<JsonResponse> RevokeAsync(
            IdPClient client, ClientRegistration reg, string token, string tokenTypeHint)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenTypeHint },
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret }
            });
        }

        /// <summary>/userinfo がユーザ情報を返したか</summary>
        /// <param name="res">/userinfo の応答</param>
        /// <returns>返したら true</returns>
        internal static bool UserInfoAccepted(JsonResponse res)
        {
            return res.IsJson && res.KindOf("sub") != JsonValueKind.Undefined;
        }

        /// <summary>EX-2.1 access_token の失効</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0201_access_tokenを失効させると使えなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-2.1",
                    "access_token を失効させると、以後そのトークンは使えない",
                    "ログアウトや漏えいのときに、**期限を待たずに**トークンを無効にできること。"
                    + "失効の応答が成功しても、実際に使えてしまっては意味がないので、"
                    + "**使えなくなったことまで確かめる。**",
                    "RFC 7009 §2.1 / §2.2");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得て、/userinfo が応答することを確かめる");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                JsonResponse before = await client.UserInfoAsync(token.AccessToken);

                Assert.True(UserInfoAccepted(before), "前提: 失効させる前は /userinfo が応答すること");

                r.Step("(2) POST /revoke に token と token_type_hint=access_token を送る");

                JsonResponse revoke = await RevokeAsync(client, reg, token.AccessToken, "access_token");

                r.Verify("失効要求がエラーにならない", string.IsNullOrEmpty(revoke.Error),
                    "error なし",
                    revoke.Error == null ? "error なし"
                                         : "error=" + revoke.Error + " / " + revoke.ErrorDescription);

                r.Observe("失効要求の HTTP ステータス", "HTTP " + (int)revoke.StatusCode,
                    "RFC 7009 §2.2 は、成功したら 200 を返すとしている。");

                r.Step("(3) 同じ access_token で、もう一度 /userinfo を叩く");

                JsonResponse after = await client.UserInfoAsync(token.AccessToken);

                r.Verify("失効後は /userinfo がユーザ情報を返さない", !UserInfoAccepted(after),
                    "sub を含む応答を返さない",
                    UserInfoAccepted(after) ? "**返してしまった**" : "拒否した（" + after.ToString() + "）");

                r.Done();
            }
        }

        /// <summary>EX-2.2 refresh_token の失効</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0202_refresh_tokenを失効させると更新できなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-2.2",
                    "refresh_token を失効させると、以後それで更新できない",
                    "refresh_token は長く生きるので、**失効できることの重みは access_token より大きい。**"
                    + "失効させた refresh_token で、新しいトークンが出てはならない。",
                    "RFC 7009 §2.1 / §2.2");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token と refresh_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(token.RefreshToken),
                    "前提: refresh_token が発行されること");

                r.Step("(2) POST /revoke に token と token_type_hint=refresh_token を送る");

                JsonResponse revoke = await RevokeAsync(client, reg, token.RefreshToken, "refresh_token");

                r.Verify("失効要求がエラーにならない", string.IsNullOrEmpty(revoke.Error),
                    "error なし",
                    revoke.Error == null ? "error なし"
                                         : "error=" + revoke.Error + " / " + revoke.ErrorDescription);

                r.Step("(3) 失効させた refresh_token で更新を試みる");

                JsonResponse refresh = await RefreshTokenTests.RefreshAsync(client, reg, token.RefreshToken);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(refresh.AccessToken),
                    "access_token を返さない",
                    refresh.AccessToken == null
                        ? "返さなかった（error=" + (refresh.Error ?? "なし") + "）"
                        : "**返してしまった**");

                r.Step("(4) 一緒に発行されていた access_token で /userinfo を叩く");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.Observe("同じ認可から出た access_token は、まだ使えるか",
                    UserInfoAccepted(userInfo) ? "使える" : "使えない",
                    "RFC 7009 §2.1 は、refresh_token を失効させたら、"
                    + "同じ認可に基づく access_token も無効にすべき（SHOULD）としている。");

                r.Done();
            }
        }

        /// <summary>EX-2.3 他クライアントのトークン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0203_他のクライアントのトークンは失効させられない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-2.3",
                    "他のクライアントに発行されたトークンは、失効させられない",
                    "失効は、そのトークンの発行先だけが行える。"
                    + "誰でも失効させられるなら、**他人のトークンを無効にして利用を妨害できる。**",
                    "RFC 7009 §2.1（発行先のクライアントかを確かめ、違えば要求を拒否する）/ #194");

                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                Assert.False(string.IsNullOrEmpty(other.ClientSecret),
                    "前提: " + KnownClients.TestClient + " に client_secret が登録されていること");

                r.Target("発行先 client_name=" + KnownClients.MvcSample
                    + " / 失効を要求する側 client_name=" + KnownClients.TestClient);
                r.Step("(1) " + KnownClients.MvcSample + " で access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) " + KnownClients.TestClient + " の資格情報で、その access_token の失効を要求する");

                JsonResponse revoke = await RevokeAsync(client, other, token.AccessToken, "access_token");

                r.Verify("要求を拒否する（error を返す）", !string.IsNullOrEmpty(revoke.Error),
                    "error が返る", "error = " + (revoke.Error ?? "なし"));

                r.Step("(3) 元の access_token で /userinfo を叩く");

                JsonResponse after = await client.UserInfoAsync(token.AccessToken);

                r.Verify("トークンは失効していない（/userinfo が応答する）", UserInfoAccepted(after),
                    "sub を含む応答",
                    UserInfoAccepted(after) ? "応答した" : "**失効してしまった**（" + after.ToString() + "）");

                r.Done();
            }
        }

        /// <summary>EX-2.4 token_type_hint の省略</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（#200）。実測（2026/09/10, net10.0 / net48）では、"
            + "token_type_hint を省略すると invalid_request（invalid token_type_hint.）で拒否され、失効しない。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0204_token_type_hintを省略しても失効できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-2.4",
                    "token_type_hint を省略しても、失効できる",
                    "token_type_hint は**任意のヒント**にすぎない。省略されたら、"
                    + "サーバがトークンの種類を調べて失効させる。"
                    + "ヒントが無いことを理由に断ると、トークンを無効にできないまま残る。",
                    "RFC 7009 §2.1（token_type_hint は OPTIONAL。"
                    + "ヒントで見つからなければ、対応する全種類から探す）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) POST /revoke に token だけを送る（token_type_hint なし）");

                JsonResponse revoke = await RevokeAsync(client, reg, token.AccessToken, null);

                r.Verify("失効要求がエラーにならない", string.IsNullOrEmpty(revoke.Error),
                    "error なし",
                    revoke.Error == null ? "error なし"
                                         : "error=" + revoke.Error + " / " + revoke.ErrorDescription);

                r.Step("(3) 同じ access_token で /userinfo を叩く");

                JsonResponse after = await client.UserInfoAsync(token.AccessToken);

                r.Verify("失効後は /userinfo がユーザ情報を返さない", !UserInfoAccepted(after),
                    "sub を含む応答を返さない",
                    UserInfoAccepted(after) ? "**返してしまった**（失効していない）"
                                            : "拒否した（" + after.ToString() + "）");

                r.Done();
            }
        }

        /// <summary>EX-2.5 無効なトークン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（#200）。実測（2026/09/10, net10.0 / net48）では、"
            + "存在しないトークンの失効要求に invalid_request（Invalid token.）を返す。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0205_無効なトークンの失効要求はエラーにしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("EX-2.5",
                    "無効なトークンの失効要求を、エラーにしない",
                    "**失効させたいトークンが既に無効なら、目的は達している。**"
                    + "クライアントはこのエラーに対してできることが無いので、エラーを返さない。",
                    "RFC 7009 §2.2（無効なトークンでも 200。invalid token はエラー応答の理由にならない）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("POST /revoke に、存在しないトークン（token_type_hint=access_token）を送る");

                JsonResponse revoke = await RevokeAsync(client, reg, "NOT-A-REAL-TOKEN", "access_token");

                r.Verify("エラーを返さない", string.IsNullOrEmpty(revoke.Error),
                    "error なし",
                    revoke.Error == null ? "error なし"
                                         : "error=" + revoke.Error + " / " + revoke.ErrorDescription);

                r.Observe("HTTP ステータス", "HTTP " + (int)revoke.StatusCode,
                    "RFC 7009 §2.2 は 200 を求める。");

                r.Done();
            }
        }
    }
}
