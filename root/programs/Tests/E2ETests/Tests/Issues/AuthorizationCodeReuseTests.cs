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
//* クラス名        ：AuthorizationCodeReuseTests
//* クラス日本語名  ：RT-421 認可コードが再利用されたら、そのコードから出したトークンを失効させる（RFC 6749 §4.1.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/23  玄人 幸道         新規（#421）
//*  2026/11/23  玄人 幸道         refresh_token を失効させたとき、同じ認可の access_token も失効することを足した（RT-421.4・.5。E-13）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-421. **認可コードが再利用されたら、そのコードから出したトークンを失効させる**（RFC 6749 §4.1.2 の SHOULD）。
    /// </summary>
    /// <remarks>
    /// **以前は、2 回目の引き換えを断る（MUST）だけで、1 回目で出したトークンは期限まで使えた**
    /// （適合性テストの `attempt-reuse-authorisation-code-after-one-second` の WARNING）。
    /// **引き換えたコードの行を消していた**ので再利用に気付けず、**コードと出したトークンを結ぶものも無かった。**
    ///
    /// **今は、コードに認可の ID を持たせ、出したトークン（更新したものも含む）に引き継ぐ。**
    /// **再利用に気付いたら、その ID を失効させる**（access_token は資源の側の検証で、refresh_token は一族ごと）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-421.1`** | **2 回目の引き換えは `invalid_grant` で断り、1 回目の access_token（`/userinfo`）と refresh_token が使えなくなる** |
    /// | **`RT-421.2`** | **更新で出した access_token・refresh_token も使えなくなる**（「そのコードに基づいて出したトークン」） |
    /// | **`RT-421.3`** | **別のクライアントがそのコードを出しても、失効させない**（そのクライアントに出したコードではない） |
    /// | **`RT-421.4`** | **refresh_token を `/revoke` で失効させると、同じ認可の access_token も使えなくなる**（RFC 7009 §2.1。`ANALYSIS-IdP.md` の E-13） |
    /// | **`RT-421.5`** | **使用済みの refresh_token が出されたら、同じ認可の access_token（更新の前と後）も使えなくなる**（E-13。一族の失効は #188） |
    ///
    /// **E-13 も、同じ仕組み（refresh_token の一族の識別子 ＝ 認可の ID）で直した**（#421 で決めた）。
    /// </remarks>
    public class AuthorizationCodeReuseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AuthorizationCodeReuseTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-421.1

        /// <summary>RT-421.1 認可コードを再利用すると、1 回目で出したトークンが使えなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42101_認可コードを再利用すると1回目のトークンが使えなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-421.1",
                    "認可コードの 2 回目の引き換えは invalid_grant で断り、1 回目で出した access_token（/userinfo）と refresh_token が使えなくなる",
                    "**RFC 6749 §4.1.2**：コードが 2 回以上使われたら、要求を断らなければならず（MUST）、"
                    + "**そのコードに基づいて出したトークンを、できれば失効させるべき（SHOULD）。**"
                    + "**コードが漏れて攻撃者が先に引き換えても、正規のクライアントが引き換えを試みた時点で、攻撃者のトークンを止められる。**"
                    + "**以前は 2 回目を断るだけで、1 回目のトークンは期限まで使えた。**",
                    "RFC 6749 §4.1.2 / #421");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コードを得て、引き換える");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state-rt4211", "nonce-rt4211", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                JsonResponse first = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(first.AccessToken), "前提: access_token が返ること（" + first.ToString() + "）");
                Assert.False(string.IsNullOrEmpty(first.RefreshToken), "前提: refresh_token が返ること（" + first.ToString() + "）");

                r.Verify("access_token に認可の ID（urn:mpas:authorization_id）が在る",
                    AuthorizationCodeReuseTests.HasAuthorizationId(first.AccessToken),
                    "在る", AuthorizationCodeReuseTests.HasAuthorizationId(first.AccessToken) ? "在る" : "**無い**");

                JsonResponse before = await client.UserInfoAsync(first.AccessToken);

                r.VerifyEqual("引き換えた直後は /userinfo が HTTP 200", "200", ((int)before.StatusCode).ToString());

                r.Step("(2) 同じ認可コードを、もう一度引き換える");

                JsonResponse second = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant", "400 invalid_grant",
                    ((int)second.StatusCode).ToString() + " " + (second.Error ?? "（無し）"));
                r.Verify("トークンは出ない", string.IsNullOrEmpty(second.AccessToken),
                    "出ない", string.IsNullOrEmpty(second.AccessToken) ? "出ない" : "**出た**");

                r.Step("(3) 1 回目の access_token で /userinfo を呼ぶ");

                JsonResponse after = await client.UserInfoAsync(first.AccessToken);

                r.VerifyEqual("HTTP 401（失効した）", "401", ((int)after.StatusCode).ToString());

                r.Step("(4) 1 回目の refresh_token で更新する");

                JsonResponse refreshed = await Flows.RefreshAsync(client, reg, first.RefreshToken);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant（失効した）", "400 invalid_grant",
                    ((int)refreshed.StatusCode).ToString() + " " + (refreshed.Error ?? "（無し）"));

                r.Done();
            }
        }

        #endregion

        #region RT-421.2

        /// <summary>RT-421.2 更新で出したトークンも、認可コードの再利用で使えなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42102_更新で出したトークンも認可コードの再利用で使えなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-421.2",
                    "認可コードから出した refresh_token で更新した access_token・refresh_token も、そのコードの再利用で使えなくなる",
                    "**更新で出したトークンも「そのコードに基づいて出したトークン」である**（RFC 6749 §4.1.2）。"
                    + "**認可の ID は payload に入り、更新しても引き継がれる**ので、まとめて失効させられる。"
                    + "**refresh_token の一族（FamilyId）も同じ値**で、一族ごと消す（#188 の段階 3 と同じ失効）。",
                    "RFC 6749 §4.1.2 / #421");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コードを引き換え、refresh_token で 1 回更新する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state-rt4212", "nonce-rt4212", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                JsonResponse first = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(first.RefreshToken), "前提: refresh_token が返ること（" + first.ToString() + "）");

                JsonResponse renewed = await Flows.RefreshAsync(client, reg, first.RefreshToken);

                Assert.False(string.IsNullOrEmpty(renewed.AccessToken), "前提: 更新で access_token が返ること（" + renewed.ToString() + "）");
                Assert.False(string.IsNullOrEmpty(renewed.RefreshToken), "前提: 更新で refresh_token が返ること（" + renewed.ToString() + "）");

                JsonResponse before = await client.UserInfoAsync(renewed.AccessToken);

                r.VerifyEqual("更新した直後は /userinfo が HTTP 200", "200", ((int)before.StatusCode).ToString());

                r.Step("(2) 同じ認可コードを、もう一度引き換える");

                JsonResponse second = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant", "400 invalid_grant",
                    ((int)second.StatusCode).ToString() + " " + (second.Error ?? "（無し）"));

                r.Step("(3) 更新で出した access_token と refresh_token を使う");

                JsonResponse after = await client.UserInfoAsync(renewed.AccessToken);

                r.VerifyEqual("更新で出した access_token の /userinfo は HTTP 401（失効した）", "401", ((int)after.StatusCode).ToString());

                JsonResponse refreshed = await Flows.RefreshAsync(client, reg, renewed.RefreshToken);

                r.VerifyEqual("更新で出した refresh_token は HTTP 400 ＋ invalid_grant（失効した）", "400 invalid_grant",
                    ((int)refreshed.StatusCode).ToString() + " " + (refreshed.Error ?? "（無し）"));

                r.Done();
            }
        }

        #endregion

        #region RT-421.3

        /// <summary>RT-421.3 別のクライアントが使用済みのコードを出しても、失効させない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42103_別のクライアントが使用済みのコードを出しても失効させない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-421.3",
                    "使用済みの認可コードを、別のクライアントが自分の資格情報で出しても invalid_grant で断るだけで、コードを出したクライアントのトークンは失効させない",
                    "**そのクライアントに出したコードではない**ので、再利用（同じコードの 2 回目の引き換え）に当たらない。"
                    + "**別のクライアントの要求で、正規のクライアントのトークンを止められない**ようにする"
                    + "（コードを出したクライアントの照合は、以前から `aud` で行っている）。",
                    "RFC 6749 §4.1.2・§4.1.3 / #421");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                r.Target("コードを出したクライアント：" + KnownClients.MvcSample + "、出し直すクライアント：" + KnownClients.TestClient);

                r.Step("(1) " + KnownClients.MvcSample + " で認可コードを得て、引き換える");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state-rt4213", "nonce-rt4213", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                JsonResponse first = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(first.AccessToken), "前提: access_token が返ること（" + first.ToString() + "）");

                r.Step("(2) 同じ認可コードを、" + KnownClients.TestClient + " の資格情報で引き換える");

                JsonResponse byOther = await Flows.ExchangeCodeAsync(client, other, authz.Code, reg.RedirectUri);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant", "400 invalid_grant",
                    ((int)byOther.StatusCode).ToString() + " " + (byOther.Error ?? "（無し）"));

                r.Step("(3) " + KnownClients.MvcSample + " の access_token で /userinfo を呼ぶ");

                JsonResponse after = await client.UserInfoAsync(first.AccessToken);

                r.VerifyEqual("HTTP 200（失効していない）", "200", ((int)after.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-421.4 E-13（/revoke）

        /// <summary>RT-421.4 refresh_token を /revoke で失効させると、同じ認可の access_token も使えなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42104_refresh_tokenを失効させると同じ認可のaccess_tokenも使えなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-421.4",
                    "refresh_token を /revoke で失効させると、同じ認可から出した access_token も使えなくなる",
                    "**RFC 7009 §2.1**：refresh_token を失効させるなら、**同じ認可グラントに基づく access_token も無効にすべき（SHOULD）。**"
                    + "**以前は refresh_token の一族だけを消し、access_token は期限まで使えた**（`ANALYSIS-IdP.md` の E-13）。"
                    + "**一族の識別子を認可の ID にしたので、同じ仕組みで止められる**（#421）。",
                    "RFC 7009 §2.1 / #421");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コードを引き換える");

                JsonResponse token = await AuthorizationCodeReuseTests.ExchangeAsync(client, reg, "rt4214");

                JsonResponse before = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("失効させる前は /userinfo が HTTP 200", "200", ((int)before.StatusCode).ToString());

                r.Step("(2) refresh_token を /revoke で失効させる");

                JsonResponse revoked = await Flows.RevokeAsync(client, reg, token.RefreshToken, "refresh_token");

                r.VerifyEqual("HTTP 200", "200", ((int)revoked.StatusCode).ToString());

                r.Step("(3) 同じ認可の access_token で /userinfo を呼ぶ");

                JsonResponse after = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("HTTP 401（失効した）", "401", ((int)after.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-421.5 E-13（refresh_token の再利用）

        /// <summary>RT-421.5 使用済みの refresh_token が出されたら、同じ認可の access_token も使えなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42105_使用済みのrefresh_tokenが出されたら同じ認可のaccess_tokenも使えなくなる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-421.5",
                    "使用済みの refresh_token が再び出されたら、一族に加えて、同じ認可から出した access_token（更新の前と後の両方）も使えなくなる",
                    "**使用済みの refresh_token が出されたら、一族ごと失効させる**（漏れたトークンと正規のトークンを見分けられないため。#188 の段階 3）。"
                    + "**以前は一族だけで、access_token は期限まで使えた**（E-13）。**漏れた refresh_token で攻撃者が取った access_token も止める。**",
                    "RFC 7009 §2.1 / #188 / #421");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（refresh_token を入れ替える登録）");

                r.Step("(1) 認可コードを引き換え、refresh_token で 1 回更新する");

                JsonResponse first = await AuthorizationCodeReuseTests.ExchangeAsync(client, reg, "rt4215");

                JsonResponse renewed = await Flows.RefreshAsync(client, reg, first.RefreshToken);

                Assert.False(string.IsNullOrEmpty(renewed.AccessToken), "前提: 更新で access_token が返ること（" + renewed.ToString() + "）");

                r.Step("(2) 使用済みの（1 回目の）refresh_token で、もう一度更新する");

                JsonResponse reused = await Flows.RefreshAsync(client, reg, first.RefreshToken);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant", "400 invalid_grant",
                    ((int)reused.StatusCode).ToString() + " " + (reused.Error ?? "（無し）"));

                r.Step("(3) 更新の前と後の access_token で /userinfo を呼ぶ");

                JsonResponse afterFirst = await client.UserInfoAsync(first.AccessToken);
                JsonResponse afterRenewed = await client.UserInfoAsync(renewed.AccessToken);

                r.VerifyEqual("最初の access_token は HTTP 401（失効した）", "401", ((int)afterFirst.StatusCode).ToString());
                r.VerifyEqual("更新で出した access_token も HTTP 401（失効した）", "401", ((int)afterRenewed.StatusCode).ToString());

                r.Step("(4) 更新で出した refresh_token で更新する");

                JsonResponse refreshed = await Flows.RefreshAsync(client, reg, renewed.RefreshToken);

                r.VerifyEqual("HTTP 400 ＋ invalid_grant（一族ごと失効した。#188 から）", "400 invalid_grant",
                    ((int)refreshed.StatusCode).ToString() + " " + (refreshed.Error ?? "（無し）"));

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>認可コードを得て、引き換える（access_token と refresh_token が返ることを前提にする）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="suffix">state・nonce の接尾辞</param>
        /// <returns>トークン応答</returns>
        private static async Task<JsonResponse> ExchangeAsync(IdPClient client, ClientRegistration reg, string suffix)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state-" + suffix, "nonce-" + suffix, reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

            JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること（" + token.ToString() + "）");
            Assert.False(string.IsNullOrEmpty(token.RefreshToken), "前提: refresh_token が返ること（" + token.ToString() + "）");

            return token;
        }

        /// <summary>access_token に認可の ID が在るか</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>在れば true</returns>
        private static bool HasAuthorizationId(string accessToken)
        {
            JsonElement payload = Jwt.Payload(accessToken);

            return payload.ValueKind == JsonValueKind.Object
                && payload.TryGetProperty("urn:mpas:authorization_id", out JsonElement value)
                && value.ValueKind == JsonValueKind.String
                && !string.IsNullOrEmpty(value.GetString());
        }

        #endregion
    }
}
