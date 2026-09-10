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
//* クラス名        ：RefreshTokenTests
//* クラス日本語名  ：EX-1 リフレッシュ トークンとローテーション
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-1. リフレッシュ トークン。
    ///
    /// 発行そのものは RFC 6749 §6 にあるが、発行は任意（OPTIONAL）で、
    /// ローテーションや発行先との結び付けの扱いは Security BCP（RFC 9700）で定まった。
    /// 基本テストケース（TC-2.1）は「返ること」だけを見ている。ここでは、その先を見る。
    /// </summary>
    public class RefreshTokenTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RefreshTokenTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>grant_type=refresh_token でトークンを取り直す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">認証に使うクライアント</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <returns>JsonResponse</returns>
        internal static Task<JsonResponse> RefreshAsync(
            IdPClient client, ClientRegistration reg, string refreshToken)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret }
            });
        }

        /// <summary>access_token の scopes クレームを、並べ替えて 1 つの文字列にする</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>scopes（無ければ "(なし)"）</returns>
        private static string ScopesOf(string accessToken)
        {
            JsonElement payload = Jwt.Payload(accessToken);
            JsonElement scopes;

            if (!payload.TryGetProperty("scopes", out scopes)
                || scopes.ValueKind != JsonValueKind.Array)
            {
                return "(なし)";
            }

            List<string> list = new List<string>();

            foreach (JsonElement s in scopes.EnumerateArray())
            {
                list.Add(s.ToString());
            }

            list.Sort(StringComparer.Ordinal);

            return string.Join(" ", list);
        }

        /// <summary>EX-1.1 更新できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0101_refresh_tokenで新しいaccess_tokenを得られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-1.1",
                    "refresh_token で、新しい access_token を得られる",
                    "access_token の期限が切れても、**ユーザに再び認可を求めずに**取り直せること。"
                    + "refresh_token の存在理由そのもの。"
                    + "取り直したトークンは、**同じユーザの、同じ範囲の**ものでなければならない。",
                    "RFC 6749 §6（scope を省略したら、元と同じ範囲とみなす）/ §1.5");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / scope=openid email");
                r.Step("(1) 認可コード フローで access_token と refresh_token を得る");

                JsonResponse first = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(first.RefreshToken),
                    "前提: refresh_token が発行されること");

                r.Step("(2) POST /token に grant_type=refresh_token を送る（scope は省略）");

                JsonResponse second = await RefreshAsync(client, reg, first.RefreshToken);

                r.Verify("エラーにならない", string.IsNullOrEmpty(second.Error),
                    "error なし",
                    second.Error == null ? "error なし"
                                         : "error=" + second.Error + " / " + second.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(second.AccessToken),
                    "access_token あり", second.AccessToken == null ? "なし" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(second.AccessToken))
                {
                    r.Verify("元とは別の access_token である",
                        second.AccessToken != first.AccessToken,
                        "元と異なる",
                        second.AccessToken != first.AccessToken ? "異なる" : "**同じものが返った**");

                    r.VerifyEqual("同じユーザのトークンである（sub）",
                        Jwt.String(Jwt.Payload(first.AccessToken), "sub"),
                        Jwt.String(Jwt.Payload(second.AccessToken), "sub"));

                    r.VerifyEqual("元と同じ範囲である（scopes）",
                        ScopesOf(first.AccessToken), ScopesOf(second.AccessToken));
                }

                r.Observe("新しい refresh_token",
                    string.IsNullOrEmpty(second.RefreshToken) ? "返らない" : "返る（ローテーション）",
                    "発行し直すかどうかは任意（RFC 6749 §6）。"
                    + "発行し直すなら、古い方は使えなくするのが望ましい（EX-1.2）。");

                r.Done();
            }
        }

        /// <summary>EX-1.2 ローテーション</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0102_使用済みのrefresh_tokenは再利用できない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-1.2",
                    "一度使った refresh_token は、もう使えない（ローテーション）",
                    "この実装は、更新のたびに新しい refresh_token を発行する（ローテーション）。"
                    + "**ならば古い方は使えなくなっていなければならない。**"
                    + "使えるなら、漏れた refresh_token を、正規のクライアントと並行して使い続けられる。",
                    "RFC 9700（OAuth 2.0 Security BCP）§4.14.2 / RFC 6749 §10.4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで refresh_token（旧）を得る");

                JsonResponse first = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(first.RefreshToken),
                    "前提: refresh_token が発行されること");

                r.Step("(2) 旧で更新し、新しい refresh_token（新）を得る");

                JsonResponse second = await RefreshAsync(client, reg, first.RefreshToken);

                Assert.False(string.IsNullOrEmpty(second.RefreshToken),
                    "前提: 1 回目の更新が成功し、新しい refresh_token が返ること");

                r.Step("(3) 旧を、もう一度使う");

                JsonResponse reuse = await RefreshAsync(client, reg, first.RefreshToken);

                r.VerifyEqual("invalid_grant で拒否される", "invalid_grant", reuse.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(reuse.AccessToken),
                    "access_token を返さない",
                    reuse.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Step("(4) 新で更新する");

                JsonResponse third = await RefreshAsync(client, reg, second.RefreshToken);

                r.Observe("旧が再び提示された後も、新は使えるか",
                    !string.IsNullOrEmpty(third.AccessToken)
                        ? "使えた"
                        : "使えない（error=" + (third.Error ?? "なし") + "）",
                    "BCP は、使用済みの refresh_token が再び提示されたら、"
                    + "**どちらが正規か分からないので、有効な方も失効させる**ことを勧めている。");

                r.Done();
            }
        }

        /// <summary>EX-1.3 発行先との結び付け</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0103_他のクライアントのrefresh_tokenは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-1.3",
                    "別のクライアントに発行された refresh_token は使えない",
                    "refresh_token は、発行先のクライアントに結び付いている。"
                    + "他のクライアントが（自分の正しい資格情報で認証したうえで）提示しても、"
                    + "トークンを出してはならない。",
                    "RFC 6749 §6（提示したクライアントが発行先であることを確かめる）/ §10.4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                Assert.False(string.IsNullOrEmpty(other.ClientSecret),
                    "前提: " + KnownClients.TestClient + " に client_secret が登録されていること");

                r.Target("発行先 client_name=" + KnownClients.MvcSample
                    + " / 提示する側 client_name=" + KnownClients.TestClient);
                r.Step("(1) " + KnownClients.MvcSample + " で refresh_token を得る");

                JsonResponse first = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(first.RefreshToken),
                    "前提: refresh_token が発行されること");

                r.Step("(2) " + KnownClients.TestClient + " の資格情報で、その refresh_token を提示する");

                JsonResponse stolen = await RefreshAsync(client, other, first.RefreshToken);

                r.VerifyEqual("invalid_grant で拒否される", "invalid_grant", stolen.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(stolen.AccessToken),
                    "access_token を返さない",
                    stolen.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Step("(3) 発行先の " + KnownClients.MvcSample + " が、その refresh_token を使う");

                JsonResponse legit = await RefreshAsync(client, reg, first.RefreshToken);

                r.Observe("他者に提示された後も、正規のクライアントが使えるか",
                    !string.IsNullOrEmpty(legit.AccessToken)
                        ? "使えた"
                        : "**使えなくなった**（error=" + (legit.Error ?? "なし") + "）",
                    "拒否する前に refresh_token を消費していると、正規の利用者が巻き添えで失う。"
                    + "他者はトークンを奪えないが、正規の利用を妨害できることになる。");

                r.Done();
            }
        }
    }
}
