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
//* クラス名        ：ScopeTests
//* クラス日本語名  ：RT 宣言外のスコープを発行しないことの回帰（#198）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/11  玄人 幸道         新規（#198 の前半）
//*  2026/09/11  玄人 幸道         クライアントごとの制限（RT-198.3 / 198.4）を追加（#198 の後半）
//**********************************************************************************

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// RT-198. 要求したスコープを、そのまま発行しない（#198 の前半）。
    ///
    /// 認可コード フローは TC-1.4 で見ている。ここでは、スコープをトークン要求で直接渡す
    /// client_credentials と password を見る（サーバ側の経路が別）。
    ///
    /// 期待値は決め打ちにせず、**サーバ自身が Discovery で宣言した scopes_supported** を基準にする。
    /// クライアントごとの制限（#198 の後半）は、scope を登録した TestClient5 で確かめる（RT-198.3 / 198.4）。
    /// 登録の無いクライアント（MVC_Sample）が制限されないことは、RT-198.1 / 198.2 が示している。
    /// </summary>
    public class ScopeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ScopeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Discovery の scopes_supported を読む</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>scopes_supported</returns>
        private static async Task<List<string>> ScopesSupportedAsync(IdPClient client)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            List<string> supported = new List<string>();
            JsonElement array;

            if (discovery.IsJson
                && discovery.Json.TryGetProperty("scopes_supported", out array)
                && array.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement s in array.EnumerateArray())
                {
                    supported.Add(s.GetString());
                }
            }

            return supported;
        }

        /// <summary>access_token の scopes クレームを読む</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>scopes</returns>
        private static List<string> ScopesOf(string accessToken)
        {
            JsonElement payload = Jwt.Payload(accessToken);
            List<string> scopes = new List<string>();
            JsonElement array;

            if (payload.TryGetProperty("scopes", out array) && array.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement s in array.EnumerateArray())
                {
                    scopes.Add(s.GetString());
                }
            }

            return scopes;
        }

        /// <summary>
        /// 発行されたスコープを確かめる。
        /// 「宣言外を外す」だけを見ると、全部落とす実装でも通ってしまうので、
        /// 「宣言済みを残す」と「応答の scope が発行と一致する」も併せて見る。
        /// </summary>
        /// <param name="r">TestReport</param>
        /// <param name="token">トークン応答</param>
        /// <param name="supported">scopes_supported</param>
        /// <param name="mustKeep">要求した中で、scopes_supported にあるもの</param>
        private static void VerifyIssuedScopes(
            TestReport r, JsonResponse token, List<string> supported, string[] mustKeep)
        {
            List<string> granted = ScopesOf(token.AccessToken);
            List<string> outside = granted.Where(g => !supported.Contains(g)).ToList();

            r.Verify("発行されたスコープが scopes_supported の範囲に収まる", outside.Count == 0,
                "すべて scopes_supported に含まれる",
                "発行 = [" + string.Join(", ", granted) + "] / 宣言外 = [" + string.Join(", ", outside) + "]");

            List<string> lost = mustKeep.Where(k => !granted.Contains(k)).ToList();

            r.Verify("宣言済みのスコープは落とさない（絞り込みすぎない）", lost.Count == 0,
                "[" + string.Join(", ", mustKeep) + "] が残る",
                lost.Count == 0 ? "残った" : "**落ちた : [" + string.Join(", ", lost) + "]**");

            string scopeParam = token.String("scope");
            List<string> answered = (scopeParam ?? "").Split(' ').Where(x => x.Length > 0).ToList();
            bool same = scopeParam != null
                && answered.Count == granted.Count
                && answered.All(a => granted.Contains(a));

            r.Verify("トークン応答の scope が、発行したスコープと一致する", same,
                "scope = " + string.Join(" ", granted) + "（要求と異なるので必須）",
                "scope = " + (scopeParam ?? "（返らない）"));
        }

        /// <summary>RT-198.1 client_credentials</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT198_01_client_credentialsで宣言外のスコープを発行しない(string targetKey)
        {
            const string Requested = "roles userid auth admin superuser whatever";

            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-198.1",
                    "client_credentials : scopes_supported に無いスコープを発行しない",
                    "起票時の再現手順そのもの。宣言外の `admin` `superuser` `whatever` まで、"
                    + "認可サーバの署名付きで発行されていた。"
                    + "**宣言済みのものは残し、宣言外のものだけを外す**こと、"
                    + "そして**要求と異なる発行をしたことを、トークン応答の scope で伝える**ことを確かめる。",
                    "RFC 6749 §3.3（発行スコープは要求と異なってよい）/ §5.1（異なる場合は scope が必須）"
                    + " / RFC 8414 §2（scopes_supported）/ #198");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                List<string> supported = await ScopesSupportedAsync(client);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Note("Discovery の scopes_supported = [" + string.Join(", ", supported) + "]");
                r.Step("POST /token に grant_type=client_credentials、scope=\"" + Requested + "\" を送る");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", Requested },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: トークンが発行されること（" + token.ToString() + "）");

                VerifyIssuedScopes(r, token, supported, new string[] { "roles", "userid", "auth" });

                r.Done();
            }
        }

        /// <summary>RT-198.2 password</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT198_02_passwordで宣言外のスコープを発行しない(string targetKey)
        {
            const string Requested = "email profile admin";

            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-198.2",
                    "password : scopes_supported に無いスコープを発行しない",
                    "ユーザの文脈を持つトークンでも同じであること。"
                    + "RT-198.1（client_credentials）とはサーバ側の発行経路が別なので、個別に確かめる。",
                    "RFC 6749 §3.3 / §5.1 / #198");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                List<string> supported = await ScopesSupportedAsync(client);

                r.Target("client_name=" + KnownClients.MvcSample
                    + " / username=" + TestEnv.TestUserName + "（パスワードは構成ファイルから読む）");
                r.Note("Discovery の scopes_supported = [" + string.Join(", ", supported) + "]");
                r.Step("POST /token に grant_type=password、scope=\"" + Requested + "\" を送る");

                // テスト ユーザは、サインイン画面への初回アクセスで作られる。
                await client.GetAsync("/Account/Login");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", Requested },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: トークンが発行されること（" + token.ToString() + "）");

                VerifyIssuedScopes(r, token, supported, new string[] { "email", "profile" });

                r.Done();
            }
        }

        /// <summary>
        /// scope を登録したクライアント（TestClient5）を返す。登録が無ければ Skip する。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="permitted">登録の scope</param>
        /// <returns>ClientRegistration</returns>
        private static ClientRegistration RestrictedClient(IdPClient client, out List<string> permitted)
        {
            string clientId = client.Config.FindClientIdByName(KnownClients.TestClient5);

            Skip.If(string.IsNullOrEmpty(clientId),
                KnownClients.TestClient5 + " が構成ファイルに登録されていません。"
                + "雛形（_appsettings.json / _app.config）を参照して追加してください。");

            string scope = client.Config.GetClientAttribute(clientId, "scope");

            Skip.If(string.IsNullOrEmpty(scope),
                KnownClients.TestClient5 + " に scope が登録されていません。");

            permitted = scope.Split(' ').Where(x => x.Length > 0).ToList();

            return Flows.Registration(client, KnownClients.TestClient5);
        }

        /// <summary>登録の scope に無いスコープを発行していないことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="token">トークン応答</param>
        /// <param name="permitted">登録の scope</param>
        private static void VerifyWithinRegistration(TestReport r, JsonResponse token, List<string> permitted)
        {
            List<string> granted = ScopesOf(token.AccessToken);
            List<string> notPermitted = granted.Where(g => !permitted.Contains(g)).ToList();

            r.Verify("登録の scope に無いスコープを発行しない", notPermitted.Count == 0,
                "登録の範囲 [" + string.Join(", ", permitted) + "] に収まる",
                "発行 = [" + string.Join(", ", granted) + "] / 範囲外 = [" + string.Join(", ", notPermitted) + "]");
        }

        /// <summary>RT-198.3 登録の scope（client_credentials）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT198_03_登録したscopeの範囲に収める_client_credentials(string targetKey)
        {
            const string Requested = "profile email phone roles admin";

            using (IdPClient client = this.Client(targetKey))
            {
                List<string> permitted;
                ClientRegistration reg = RestrictedClient(client, out permitted);

                TestReport r = this.Report("RT-198.3",
                    "クライアントの登録（scope）の範囲に収める : client_credentials",
                    "scopes_supported に載っていても、**そのクライアントに許していないスコープは発行しない。**"
                    + "登録の scope は、RFC 7591 §2 の client metadata と同じく、要求してよいスコープの一覧。"
                    + "許した範囲は残し、許していないもの（phone / roles）と宣言外のもの（admin）だけを外すことを確かめる。",
                    "RFC 6749 §3.3 / §5.1 / RFC 7591 §2（scope）/ #198");

                List<string> supported = await ScopesSupportedAsync(client);
                string[] expected = Requested.Split(' ')
                    .Where(x => permitted.Contains(x) && supported.Contains(x)).ToArray();

                r.Target("client_name=" + KnownClients.TestClient5
                    + " / 登録の scope = " + string.Join(" ", permitted));
                r.Note("Discovery の scopes_supported = [" + string.Join(", ", supported) + "]");
                r.Step("POST /token に grant_type=client_credentials、scope=\"" + Requested + "\" を送る");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", Requested },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: トークンが発行されること（" + token.ToString() + "）");

                VerifyWithinRegistration(r, token, permitted);
                VerifyIssuedScopes(r, token, supported, expected);

                r.Done();
            }
        }

        /// <summary>RT-198.4 登録の scope（認可コード）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT198_04_登録したscopeの範囲に収める_認可コード(string targetKey)
        {
            const string Requested = "openid profile email phone roles";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                List<string> permitted;
                ClientRegistration reg = RestrictedClient(client, out permitted);

                TestReport r = this.Report("RT-198.4",
                    "クライアントの登録（scope）の範囲に収める : 認可コード フロー",
                    "認可エンドポイントを通る経路（CreateCodeInAuthZNRes）でも同じであること。"
                    + "この経路は device / CIBA も通る。"
                    + "openid は許しているので、id_token も発行されることを確かめる（絞り込みすぎていない）。",
                    "RFC 6749 §3.3 / OIDC Core §3.1.2.1 / RFC 7591 §2（scope）/ #198");

                List<string> supported = await ScopesSupportedAsync(client);
                string[] expected = Requested.Split(' ')
                    .Where(x => permitted.Contains(x) && supported.Contains(x)).ToArray();

                r.Target("client_name=" + KnownClients.TestClient5
                    + " / 登録の scope = " + string.Join(" ", permitted));
                r.Step("(1) GET /authorize に scope=\"" + Requested + "\" を付けて code を得る");
                r.Step("(2) code をトークンに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: Requested, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: code が発行されること（" + authz.ToString() + "）");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: トークンが発行されること（" + token.ToString() + "）");

                VerifyWithinRegistration(r, token, permitted);
                VerifyIssuedScopes(r, token, supported, expected);

                r.Verify("id_token が返る（openid は許している）", !string.IsNullOrEmpty(token.IdToken),
                    "id_token あり", token.IdToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }
    }
}
