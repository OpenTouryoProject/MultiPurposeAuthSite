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
//* クラス名        ：PkceTests
//* クラス日本語名  ：RT PKCEの扱い（#220）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/17  玄人 幸道         新規（#220 : client_secret と PKCE の併用）
//*  2026/09/17  玄人 幸道         RT-220.2（plain の PKCE）を追加（#220）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-220. PKCE の扱いの回帰テスト。
    /// </summary>
    /// <remarks>
    /// PKCE そのもの（検証の失敗）は TC-2.4 で測る。
    /// **本クラスは「クライアント認証と併用できるか」**を測る。
    /// </remarks>
    public class PkceTests : TargetTestBase
    {
        /// <summary>RFC 7636 附録 B の例</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の例（SHA256(verifier) を BASE64URL したもの）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>誤った code_verifier</summary>
        private const string WrongVerifier = "WRONG-VERIFIER-WRONG-VERIFIER-WRONG-VERIFIER";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PkceTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-220.1 client_secret と PKCE の併用</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT220_01_client_secretとPKCEを併用できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-220.1",
                    "コンフィデンシャル クライアントでも、client_secret と PKCE を併用できる",
                    "PKCE は当初「client_secret を持てないクライアントの代わり」だったが、"
                    + "**いまは種別によらない標準的な防壁**で、client_secret と併用される"
                    + "（OAuth 2.1 / 最近の RP ライブラリ）。"
                    + "**以前は、両方を送るとどの分岐にも入らず invalid_client になっていた**（#220）。",
                    "RFC 7636 / OAuth 2.1 §4.1.1（PKCE は全クライアント種別で必須）/ #220");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（client_secret 有り）");

                Dictionary<string, string> pkce = new Dictionary<string, string>()
                {
                    { "code_challenge", PkceTests.Challenge },
                    { "code_challenge_method", "S256" }
                };

                r.Step("(1) code_challenge_method=S256 で認可コードを得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: pkce);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                r.Step("(2) client_secret と code_verifier の**両方**を送って交換する");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "code_verifier", PkceTests.Verifier },
                    { "redirect_uri", reg.RedirectUri }
                });

                r.Verify("トークンが返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "**返らなかった**（error=" + (token.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Step("(3) 対照 : client_secret は正しく、code_verifier だけ誤った要求を送る");

                r.Note("**PKCE を素通りさせていないこと**を確かめる。"
                    + "client_secret で認証が通っても、PKCE の検証に失敗すれば発行してはならない。");

                AuthZResponse authz2 = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: pkce);

                Assert.False(string.IsNullOrEmpty(authz2.Code), "前提: code が取得できること");

                JsonResponse bad = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz2.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "code_verifier", PkceTests.WrongVerifier },
                    { "redirect_uri", reg.RedirectUri }
                });

                r.Verify("誤った code_verifier ではトークンを発行しない",
                    string.IsNullOrEmpty(bad.AccessToken),
                    "access_token を返さない",
                    string.IsNullOrEmpty(bad.AccessToken)
                        ? "返さなかった（error=" + (bad.Error ?? "なし") + "）" : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>RT-220.2 plain の PKCE</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT220_02_plainのPKCEは既定では受理される(string targetKey)
        {
            // plain は「challenge == verifier」。
            const string PlainVerifier = "plain-verifier-0123456789-0123456789-0123456789";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-220.2",
                    "plain の PKCE は、既定では受理される（設定で拒否できる）",
                    "**plain は保護にならない**（横取りした者が challenge をそのまま送れる）。"
                    + "OAuth 2.1 / FAPI は S256 のみを許すが、**下位互換のため既定では受理する**。"
                    + "設定 RequirePkceS256 を true にすると拒否する（#220）。",
                    "RFC 7636 §4.2（plain は非推奨）/ OAuth 2.1 / #220");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（client_secret は送らない）");
                r.Step("(1) code_challenge_method=plain で認可コードを得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", PlainVerifier },
                        { "code_challenge_method", "plain" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                r.Step("(2) 同じ値を code_verifier として交換する");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "code_verifier", PlainVerifier },
                    { "redirect_uri", reg.RedirectUri }
                });

                r.Verify("既定（RequirePkceS256=false）では受理される",
                    !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "**返らなかった**（error=" + (token.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Note("**RequirePkceS256=true のときに拒否すること**は、E2E では測っていない"
                    + "（設定ファイルを変えて起動し直す必要があるため）。設定は CONFIGURATION.md を参照。");

                r.Done();
            }
        }
    }
}
