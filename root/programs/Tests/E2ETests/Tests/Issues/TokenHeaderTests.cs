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
//* クラス名        ：TokenHeaderTests
//* クラス日本語名  ：RT-302 発行するトークンの JWS ヘッダ（kid / jku / typ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/15  玄人 幸道         新規（#302 の段階 1。jku を出さない）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-302. **発行するトークンの JWS ヘッダ**（#302。D-10 / RFC 9068）。
    /// </summary>
    /// <remarks>
    /// **`jku` は入れない。**
    /// **ヘッダに「鍵の在り処」を書くと、検証する側はその URL を取りに行く** —
    /// **出どころを発行者が自由に指し示せる**ので、**検証側の SSRF を誘発しうる。**
    /// **鍵は `kid` ＋ discovery の `jwks_uri` で引く**のが標準の経路である。
    ///
    /// **消しても、他のテストは落ちない**（**検証は `kid` で引いている**）ので、
    /// **「消えたこと」を測るのはこのケースだけ**である。
    ///
    /// **`typ` は、まだ `JWT` のまま。**
    /// **`at+jwt`（RFC 9068 §2.1）にするには Open棟梁 側の口が要る**
    /// （`JWS_Header.typ` が `readonly`、`Verify` が `typ == "JWT"` を要求。
    /// Open棟梁 #611。#302 の段階 2）。**ここでは観測だけして、期待値は固定しない。**
    /// </remarks>
    public class TokenHeaderTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TokenHeaderTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-302.1

        /// <summary>RT-302.1 発行するトークンのヘッダに jku を入れず、kid で引けるようにする</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30201_トークンのヘッダにjkuを入れない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-302.1",
                    "発行するトークンのヘッダに `jku` を入れず、`kid` で鍵を引けるようにする",
                    "**`jku` は、検証する側に「ヘッダに書かれた URL を取りに行く」動作を誘う。**"
                    + "**鍵の出どころを発行者が自由に指し示せる**ことになり、"
                    + "**検証側の SSRF を誘発しうる**（`ANALYSIS-IdP.md` の D-10）。"
                    + "**標準の経路は `kid` ＋ discovery の `jwks_uri`** である。"
                    + "**消しても他のテストは落ちない**（検証は `kid` で引く）ので、"
                    + "**ここだけが「消えたこと」を測る。**",
                    "RFC 9068 §2.1 / #302 の段階 1 / D-10");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コード フローで access_token と id_token を取る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: access_token が返ること");
                Assert.False(string.IsNullOrEmpty(token.IdToken),
                    "前提: id_token が返ること");

                this.VerifyHeader(r, "access_token", token.AccessToken);
                this.VerifyHeader(r, "id_token", token.IdToken);

                r.Step("(2) JARM（`response_mode=query.jwt`）の応答も見る");

                AuthZResponse jarm = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state-rt302", "nonce-rt302",
                    reg.RedirectUri,
                    new Dictionary<string, string>() { { "response_mode", "query.jwt" } });

                string responseJwt = jarm.Get("response");

                if (string.IsNullOrEmpty(responseJwt))
                {
                    r.Note("**JARM の応答が返らなかったので、この分は測っていない**"
                        + "（`response_mode=query.jwt`。`EX-6.3` が別に測っている）。");
                }
                else
                {
                    this.VerifyHeader(r, "JARM の response", responseJwt);
                }

                r.Note("**`typ` は、まだ `JWT` のまま**である（上の観測）。"
                    + "**`at+jwt`（RFC 9068 §2.1）にするには Open棟梁 側の口が要る** — "
                    + "**`JWS_Header.typ` が `readonly`** で、"
                    + "**`Verify` が `typ == \"JWT\"` を要求する**（Open棟梁 #611。#302 の段階 2）。");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>ヘッダを測る（jku が無い / kid が在る / typ は観測）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="name">トークンの名前（報告に出す）</param>
        /// <param name="jwt">JWT</param>
        private void VerifyHeader(TestReport r, string name, string jwt)
        {
            JsonElement header = Jwt.Header(jwt);

            bool hasJku = Jwt.Has(header, "jku");
            bool hasKid = Jwt.Has(header, "kid");

            r.Verify(name + " のヘッダに `jku` が無い", !hasJku,
                "無い", hasJku ? "**在る（" + Jwt.String(header, "jku") + "）**" : "無い");

            r.Verify(name + " のヘッダに `kid` が在る", hasKid,
                "在る", hasKid ? "在る" : "**無い（鍵を引けない）**");

            r.Observe(name + " の `typ`", Jwt.String(header, "typ"),
                "**`at+jwt` にするのは #302 の段階 2**（Open棟梁 #611 待ち）。");
        }

        #endregion
    }
}
