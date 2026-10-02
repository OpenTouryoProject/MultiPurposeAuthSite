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
//*  2026/10/02  玄人 幸道         ES384 / ES512 と、広告と鍵の突き合わせを追加（#129 の段階 3）
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

                r.VerifyEqual("id_token_signing_alg_values_supported が 6 つ（RS256 RS384 RS512 ES256 ES384 ES512）",
                    "RS256 RS384 RS512 ES256 ES384 ES512", joined);

                r.Note("**順序まで固定している。** 一覧は `SigningKeys` の表 1 か所から作っており、"
                    + "**順序が変わるときは、そこを触ったとき**である（気付けた方がよい）。");

                r.Done();
            }
        }

        /// <summary>RT-129.5 ES384 / ES512 で署名され、曲線の合う鍵で検証できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12905_ECは曲線の合う鍵で検証できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-129.5",
                    "ES384 / ES512 で署名され、jwkcerts の曲線の合う鍵で検証できる",
                    "**EC は曲線が alg に紐づく**（JWA : `ES256`→P-256、`ES384`→P-384、`ES512`→P-521）。"
                    + "**RSA と違って鍵が分かれる**ので、**`kid` も曲線ごとに違う。**"
                    + "**`jwkcerts` に 3 本とも載っていること**と、"
                    + "**曲線が食い違うトークンを受けないこと**（`kty` だけでは足りない）まで見る。",
                    "JWA（RFC 7518）§3.4 / RFC 7638 / #129 の段階 3");

                r.Target(client.Target.DisplayName);

                // **TestClient_9 / _10 は構成ファイルに無い**（test.ps1 -Launch が差し込む）。
                ClientRegistration es384 = Flows.InjectedRegistration(client, KnownClients.TestClient_9);
                ClientRegistration es512 = Flows.InjectedRegistration(client, KnownClients.TestClient_10);

                JsonResponse jwks = await client.GetJsonAsync("/jwkcerts");

                string es384IdToken = null;
                string es384Kid = null;
                string es512Kid = null;

                foreach (string[] c in new string[][] {
                    new string[] { "ES384", "P-384", KnownClients.TestClient_9 },
                    new string[] { "ES512", "P-521", KnownClients.TestClient_10 } })
                {
                    string alg = c[0];
                    ClientRegistration reg = (alg == "ES384") ? es384 : es512;

                    r.Step("(" + alg + ") 認可コード フローでトークンを取り、ヘッダと署名を見る");

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, scope: "openid email", redirectUri: reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                    JsonResponse token = await Flows.ExchangeCodeAsync(
                        client, reg, authz.Code, redirectUri: reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること");

                    r.VerifyEqual("access_token の alg が " + alg,
                        alg, Jwt.String(Jwt.Header(token.AccessToken), "alg") ?? "（無し）");

                    r.VerifyEqual("id_token の alg も " + alg + "（access_token に揃う）",
                        alg, Jwt.String(Jwt.Header(token.IdToken), "alg") ?? "（無し）");

                    Jwks.Result verify = Jwks.Verify(token.IdToken, jwks.Json);

                    r.Verify("JWK Set の " + c[1] + " の公開鍵で検証できる",
                        verify.Verified, "検証できる", verify.Detail);

                    r.Step("(" + alg + ") 自分の検証経路も、この access_token を受ける");

                    JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                    r.Verify("/userinfo が応答する（受ける集合に " + alg + " が入っている）",
                        userinfo.IsJson && userinfo.KindOf("sub") != JsonValueKind.Undefined,
                        "sub を含む JSON", userinfo.ToString());

                    if (alg == "ES384")
                    {
                        es384IdToken = token.IdToken;
                        es384Kid = Jwt.String(Jwt.Header(token.IdToken), "kid") ?? "（無し）";
                    }
                    else
                    {
                        es512Kid = Jwt.String(Jwt.Header(token.IdToken), "kid") ?? "（無し）";
                    }
                }

                r.Step("(kid) 曲線ごとに kid が違う（鍵が別だから）");

                r.Verify("ES384 と ES512 で kid が違う",
                    es384Kid != es512Kid, "違う",
                    "ES384=" + es384Kid + " / ES512=" + es512Kid);

                r.Note("**`RS256` / `RS384` / `RS512` は kid が同じ**（1 本の鍵で、ダイジェストだけが違う。"
                    + "`RT-129.3` で見ている）。**EC は曲線ごとに鍵が違う**ので、**kid も違う。**"
                    + "＝ **`jwkcerts` に載る鍵は 4 本**（RSA 1 本 ＋ EC 3 本。`RT-129.6`）。");

                r.Step("(crv) ES384 のトークンの alg を ES512 に書き換えると受けない（#129 の段階 3）");

                JsonResponse spoofed = await client.UserInfoAsync(
                    Jwks.WithAlg(es384IdToken, "ES512"));

                bool accepted = spoofed.IsJson && spoofed.KindOf("sub") != JsonValueKind.Undefined;

                r.Verify("曲線が食い違うトークンを受けない",
                    !accepted, "受けない", accepted ? "**受理してしまった**" : "拒否した");

                r.Note("**`kty` だけで判定していると、ここが通ってしまう**（どちらも `kty=EC`）。"
                    + "**`crv` まで突き合わせる**ようにした（`CmnAccessToken.IsSameKeyType`）。"
                    + "**実害が出る前に入れた**（ES384 / ES512 を発行し始めるのと同じ段階）。");

                r.Done();
            }
        }

        /// <summary>RT-129.6 広告する alg すべてに、jwkcerts の鍵が在る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12906_広告するalgすべてに鍵が在る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-129.6",
                    "Discovery が広告する alg すべてについて、jwkcerts に検証できる鍵が在る",
                    "**広告・発行・公開鍵の 3 つが揃っていること**を見る（D-9）。"
                    + "**鍵と alg の対応は `SigningKeys` の表 1 か所**にあり、"
                    + "**`jwkcerts`（`JwkSet.json`）は `CreateJwkSetJson` がその表を回して作る。**"
                    + "**表に足したのに JWK Set を作り直していない**という食い違いは、ここで落ちる。",
                    "OIDC Discovery 1.0 §3 / RFC 7517 / D-9");

                r.Target(client.Target.DisplayName);

                r.Step("Discovery と jwkcerts を読み、突き合わせる");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                JsonResponse jwks = await client.GetJsonAsync("/jwkcerts");

                string[] algs = discovery.Strings("id_token_signing_alg_values_supported");

                Assert.NotNull(algs);
                Assert.NotEmpty(algs);

                foreach (string alg in algs)
                {
                    r.Verify("alg=" + alg + " を検証できる公開鍵が jwkcerts に在る",
                        Jwks.HasKeyFor(jwks.Json, alg),
                        "在る", Jwks.HasKeyFor(jwks.Json, alg) ? "在る" : "**無い**");
                }

                r.Note("**鍵の本数は alg の数と一致しない。**"
                    + "**`RS256` / `RS384` / `RS512` は 1 本の鍵を共有する**ので、"
                    + "**6 つの alg に対して鍵は 4 本**（RSA 1 本 ＋ EC 3 本）である。");

                r.Note("**鍵を入れ替えるとき（D-9）も、この関係は変わらない。**"
                    + "**新しい鍵を `jwkcerts` に先に載せ、RP のキャッシュが切れてから署名に使う**"
                    + "（手順は `CONFIGURATION.md`）。**`JwkSet.json` は追記式**なので、"
                    + "**退役した鍵も、消すまで載り続ける。**");

                r.Done();
            }
        }
    }
}
