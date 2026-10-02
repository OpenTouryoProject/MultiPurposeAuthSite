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
//* クラス名        ：SigningAlgRegistrationTests
//* クラス日本語名  ：RT-129 登録した署名アルゴリズム（id_token_signed_response_alg）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（#129 の段階 2）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-129.3 / .4 登録した署名アルゴリズムで署名する（#129 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **クライアントの登録 `id_token_signed_response_alg` で、署名の alg が決まる。**
    /// **未登録なら `RS256`**（＝ 従来どおり）。
    ///
    /// **鍵は 1 つで、ダイジェストだけが違う。**
    /// **`kid` は鍵から作る**（RFC 7638 : kty / n / e）ので、**RS256 と RS512 で同じ値**になる。
    /// ＝ **RP は `jwkcerts` の同じ鍵で検証でき、どのダイジェストかはヘッダの `alg` が伝える。**
    ///
    /// **`/token` の id_token は、access_token のヘッダ alg に従って署名する**実装なので、
    /// **2 つは揃う**（CIBA が ES256 を使う既存の作りと同じ形）。
    /// </remarks>
    public class SigningAlgRegistrationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SigningAlgRegistrationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-129.3 登録した alg（RS512）で署名され、同じ鍵で検証できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12903_登録したalgで署名され同じ鍵で検証できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **TestClient_8 は構成ファイルに無い**（test.ps1 -Launch が差し込む）。
                ClientRegistration rs512 = Flows.InjectedRegistration(client, KnownClients.TestClient_8);

                TestReport r = this.Report("RT-129.3",
                    "登録した alg（RS512）で署名され、jwkcerts の同じ鍵で検証できる",
                    "**#129 の段階 2 で RS384 / RS512 を足した。**"
                    + "**鍵は RS256 と同じ**で、**ダイジェストだけが違う。**"
                    + "**`kid` は鍵から作る**（RFC 7638）ので**同じ値**になり、"
                    + "**RP は `jwkcerts` の同じ鍵で検証できる**（どのダイジェストかは `alg` が伝える）。"
                    + "**自分の検証経路（C-8 で固定した受ける集合）も、これを受けること**まで見る。",
                    "OIDC Dynamic Registration §2（id_token_signed_response_alg）/ RFC 7638 / #129 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient_8 + "（id_token_signed_response_alg=RS512）");

                r.Step("(1) 認可コード フローでトークンを取る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, rs512, scope: "openid email", redirectUri: rs512.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, rs512, authz.Code, redirectUri: rs512.RedirectUri);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");
                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること");

                r.Step("(2) ヘッダの alg を見る");

                r.VerifyEqual("access_token の alg が RS512",
                    "RS512", Jwt.String(Jwt.Header(token.AccessToken), "alg") ?? "（無し）");

                r.VerifyEqual("id_token の alg も RS512（access_token に揃う）",
                    "RS512", Jwt.String(Jwt.Header(token.IdToken), "alg") ?? "（無し）");

                r.Step("(3) jwkcerts の公開鍵で、RP の立場で検証する");

                JsonResponse jwks = await client.GetJsonAsync("/jwkcerts");
                Jwks.Result verify = Jwks.Verify(token.IdToken, jwks.Json);

                r.Verify("JWK Set の公開鍵で検証できる",
                    verify.Verified, "検証できる", verify.Detail);

                r.Step("(4) kid は RS256 のクライアントと同じ（鍵が 1 つだから）");

                ClientRegistration rs256 = Flows.Registration(client, KnownClients.TestClient);

                AuthZResponse authz2 = await Flows.AuthorizeCodeAsync(
                    client, rs256, scope: "openid email", redirectUri: rs256.RedirectUri);

                JsonResponse token2 = await Flows.ExchangeCodeAsync(
                    client, rs256, authz2.Code, redirectUri: rs256.RedirectUri);

                r.VerifyEqual("RS256 のクライアントの alg は RS256（対照）",
                    "RS256", Jwt.String(Jwt.Header(token2.IdToken), "alg") ?? "（無し）");

                r.VerifyEqual("**kid は 2 つのクライアントで同じ**",
                    Jwt.String(Jwt.Header(token2.IdToken), "kid") ?? "（無し）",
                    Jwt.String(Jwt.Header(token.IdToken), "kid") ?? "（無し）");

                r.Step("(5) 自分の検証経路も、RS512 の access_token を受ける");

                JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                r.Verify("/userinfo が応答する（受ける集合に RS512 が入っている）",
                    userinfo.IsJson && userinfo.KindOf("sub") != JsonValueKind.Undefined,
                    "sub を含む JSON", userinfo.ToString());

                r.Note("**C-8 で「受ける alg」を固定した**（#129 の段階 1）。"
                    + "**段階 2 で RS384 / RS512 を足した**ので、**ここが通ることが、その証拠**になる。"
                    + "**受ける集合は `CmnAccessToken.SupportedAlgs` の 1 か所**で、"
                    + "**Discovery の `id_token_signing_alg_values_supported` も、そこから作っている。**");

                r.Done();
            }
        }

        /// <summary>RT-129.4 Discovery が RS384 / RS512 を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12904_Discoveryが広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-129.4",
                    "Discovery の id_token_signing_alg_values_supported が、実際に発行する alg と一致する",
                    "**広告と実装が食い違うと、RP は使えない alg を選ぶ。**"
                    + "**#129 の段階 0 で作った対照表の続き**で、"
                    + "**段階 2 で増やした RS384 / RS512 が広告に出ている**ことを見る。",
                    "OIDC Discovery 1.0 §3 / #129 の段階 0・2");

                r.Target(client.Target.DisplayName);

                r.Step("Discovery 文書を読む");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                string[] algs = discovery.Strings("id_token_signing_alg_values_supported");
                string joined = (algs == null) ? "（無し）" : string.Join(" ", algs);

                r.VerifyEqual("id_token_signing_alg_values_supported が 4 つ（RS256 RS384 RS512 ES256）",
                    "RS256 RS384 RS512 ES256", joined);

                r.Note("**順序まで固定している。** 一覧は `CmnAccessToken.SupportedAlgs` 1 か所から作っており、"
                    + "**順序が変わるときは、そこを触ったとき**である（気付けた方がよい）。");

                r.Done();
            }
        }
    }
}
