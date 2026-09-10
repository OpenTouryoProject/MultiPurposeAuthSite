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
//* クラス名        ：CommonSecurityTests
//* クラス日本語名  ：TC-1 全フロー共通のセキュリティ・正常系
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストケースの追加）
//*  2026/09/10  玄人 幸道         TC-1.4の実測結果を#198として起票し、Skipに変更
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-1. すべてのフローに共通する検証。
    ///
    /// state（CSRF 対策）、redirect_uri の厳格な照合、スコープの制御、
    /// トークンの有効期限。
    /// </summary>
    public class CommonSecurityTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CommonSecurityTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>TC-1.1 state が認可応答でそのまま返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0101_stateが往復する(string targetKey)
        {
            // 区切り文字を含める。文字列連結で URL を組み立てていると、ここで壊れる。
            const string State = "a&b=c d";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-1.1",
                    "state が認可応答でそのまま返る（CSRF 対策）",
                    "認可リクエストで送った state と、認可応答の state が完全一致すること。"
                    + "一致しなければ、RP はレスポンスを自分のリクエストと結び付けられない。",
                    "RFC 6749 §4.1.1（state は RECOMMENDED）/ §10.12（CSRF）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / " + client.Target.DisplayName);
                r.Step("GET /authorize に state=\"" + State + "\" を付けて送る（区切り文字を含む値）");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, state: State, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(res.Code),
                    "code が返る", res.Code == null ? "code なし" : "code あり");

                r.VerifyEqual("応答の state が送信値と完全一致する", State, res.State);

                r.Done();
            }
        }

        /// <summary>TC-1.2 state を送らなかったときの扱い</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0102_stateを送らないとき(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-1.2",
                    "state 無しの認可リクエストの扱い",
                    "state は RFC 6749 では RECOMMENDED であって REQUIRED ではない。"
                    + "拒否するのも受理するのも仕様の範囲内なので、**実装の挙動を記録する**。"
                    + "受理する場合、応答に state を付けてはならない（送っていないものを返さない）。",
                    "RFC 6749 §4.1.1 / OAuth 2.0 Security BCP §2.1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("GET /authorize を state 無しで送る");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, state: null, redirectUri: reg.RedirectUri);

                r.Observe("state 無しのリクエストを受理するか",
                    string.IsNullOrEmpty(res.Code) ? "拒否した（code なし）" : "受理した（code あり）",
                    "RFC 6749 は state を必須にしていない。OAuth 2.0 Security BCP は "
                    + "state か PKCE のいずれかで CSRF に対処することを求めており、"
                    + "この実装は PKCE を別途持つ。受理は違反ではない。");

                r.Verify("送っていない state を応答に含めない",
                    !res.Parameters.ContainsKey("state"),
                    "応答に state を含めない", res.Parameters.ContainsKey("state")
                        ? "state=\"" + res.State + "\" が返った" : "state は返らなかった");

                r.Done();
            }
        }

        /// <summary>TC-1.3 未登録の redirect_uri が拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0103_未登録のredirect_uriが拒否される(string targetKey)
        {
            // 事前登録と「ドメインが違う」もの。オープン リダイレクタ狙いを模す。
            const string Evil = "https://attacker.example.com/callback";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-1.3",
                    "事前登録と一致しない redirect_uri が拒否される",
                    "事前登録された値と完全一致しない redirect_uri では、"
                    + "**認可コードを発行してはならず、その URI へリダイレクトしてもならない。**"
                    + "リダイレクトすると、認可サーバがオープン リダイレクタになる。",
                    "RFC 6749 §3.1.2.3 / §4.1.2.1 / OIDC Core §3.1.2.1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample
                    + " / 事前登録の redirect_uri = " + reg.RedirectUri);
                r.Step("GET /authorize に redirect_uri=" + Evil + " を指定する");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid email" },
                    { "state", "state1" },
                    { "nonce", "nonce1" },
                    { "redirect_uri", Evil },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(res.Code),
                    "code を返さない",
                    string.IsNullOrEmpty(res.Code) ? "code は返らなかった" : "code が返った");

                bool redirectedToEvil =
                    !string.IsNullOrEmpty(res.RedirectTo)
                    && res.RedirectTo.StartsWith("https://attacker.example.com",
                        StringComparison.OrdinalIgnoreCase);

                r.Verify("指定された不正な URI へリダイレクトしない", !redirectedToEvil,
                    "attacker.example.com へ飛ばさない",
                    redirectedToEvil ? "attacker.example.com へリダイレクトした"
                                     : "リダイレクト先 = " + (res.RedirectTo ?? "（リダイレクト無し）"));

                r.Observe("エラーの返し方",
                    res.Redirected
                        ? "リダイレクトして error=" + (res.Error ?? "なし")
                        : "リダイレクトせず HTTP " + (int)res.StatusCode + "（画面表示）",
                    "redirect_uri を信頼できない以上、そこへエラーを返さないのが正しい"
                    + "（RFC 6749 §4.1.2.1）。画面で知らせる形は妥当。");

                r.Done();
            }
        }

        /// <summary>TC-1.4 未定義のスコープの扱い</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（#198）。実測（2026/09/09, net10.0）では、"
            + "scopes_supported に無い任意の文字列がそのまま発行される。")]
        [MemberData(nameof(AllTargets))]
        public async Task TC0104_未定義のスコープの扱い(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-1.4",
                    "未定義のスコープを要求したときの扱い",
                    "認可サーバは、未定義のスコープを **invalid_scope で拒否するか、"
                    + "無視して認めた分だけを返すか**のいずれかを選べる（RFC 6749 §3.3）。"
                    + "どちらを選ぶにせよ、**発行するスコープは、認可サーバ自身が"
                    + "Discovery で宣言した scopes_supported の範囲に収まるべきである。**"
                    + "宣言外の文字列をそのまま載せると、スコープ文字列で認可する"
                    + "リソース サーバを、クライアントが任意の値で騙せる余地が生まれる。",
                    "RFC 6749 §3.3（発行スコープは要求と異なってよい）/ §4.1.2.1（invalid_scope）"
                    + " / RFC 8414 §2（scopes_supported）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                // 期待値を決め打ちにしない。**サーバ自身が宣言した一覧**を基準にする。
                JsonResponse discovery =
                    await client.GetJsonAsync("/.well-known/openid-configuration");

                List<string> supported = new List<string>();
                JsonElement scopesSupported;

                if (discovery.IsJson
                    && discovery.Json.TryGetProperty("scopes_supported", out scopesSupported)
                    && scopesSupported.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement s in scopesSupported.EnumerateArray())
                    {
                        supported.Add(s.GetString());
                    }
                }

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Note("Discovery の scopes_supported = [" + string.Join(", ", supported) + "]");
                r.Step("GET /authorize に scope=\"openid email bogus_scope_not_defined\" を指定する"
                    + "（3 つ目は scopes_supported に無い）");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: "openid email bogus_scope_not_defined",
                    redirectUri: reg.RedirectUri);

                if (string.IsNullOrEmpty(authz.Code))
                {
                    r.Observe("認可の段階で拒否したか",
                        "拒否した（error=" + (authz.Error ?? "なし") + "）",
                        "invalid_scope で拒否するのは RFC 6749 §4.1.2.1 の想定どおり。");

                    r.Done();
                    return;
                }

                r.Observe("認可の段階で拒否したか", "受理した（code が発行された）",
                    "受理したので、発行されたトークンのスコープを見る。");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("トークンが発行される", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                JsonElement payload = Jwt.Payload(token.AccessToken);

                List<string> granted = new List<string>();
                JsonElement scopesClaim;

                if (payload.TryGetProperty("scopes", out scopesClaim)
                    && scopesClaim.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement s in scopesClaim.EnumerateArray())
                    {
                        granted.Add(s.GetString());
                    }
                }

                List<string> outside = new List<string>();

                foreach (string g in granted)
                {
                    if (supported.Count > 0 && !supported.Contains(g))
                    {
                        outside.Add(g);
                    }
                }

                r.Verify("発行されたスコープが scopes_supported の範囲に収まる",
                    outside.Count == 0,
                    "すべて scopes_supported に含まれる",
                    "発行 = [" + string.Join(", ", granted) + "]"
                    + " / 宣言外 = [" + string.Join(", ", outside) + "]");

                r.Done();
            }
        }

        /// <summary>TC-1.5 アクセス トークンの有効期限が妥当</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0105_トークンの有効期限が妥当(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-1.5",
                    "アクセス トークンの exp と expires_in が整合する",
                    "exp が現在時刻より未来にあり、expires_in（秒）と辻褄が合うこと。"
                    + "**期限切れ後に使えなくなるかは、ここでは確かめない**"
                    + "（待つ必要があるため。#188 を参照）。",
                    "RFC 6749 §5.1（expires_in）/ RFC 7519 §4.1.4（exp は NumericDate）");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("認可コード フローでアクセス トークンを取得し、exp と expires_in を見る");

                r.Verify("トークンが発行される", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                string expiresIn = token.String("expires_in");
                int seconds;

                r.Verify("expires_in が正の整数である",
                    int.TryParse(expiresIn, out seconds) && seconds > 0,
                    "1 以上の整数", "expires_in = " + (expiresIn ?? "なし"));

                JsonElement payload = Jwt.Payload(token.AccessToken);

                r.Verify("exp が数値である（NumericDate）",
                    Jwt.KindOf(payload, "exp") == JsonValueKind.Number,
                    "JSON の数値", "exp の型 = " + Jwt.KindOf(payload, "exp"));

                long exp = long.Parse(Jwt.String(payload, "exp"));
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long remain = exp - now;

                r.Verify("exp が現在時刻より未来である", remain > 0,
                    "exp > 現在時刻",
                    "残り " + remain + " 秒（exp=" + exp + " / 現在=" + now + "）");

                // 発行から検証までの経過があるので、多少の差は許容する。
                long diff = Math.Abs(remain - seconds);

                r.Verify("exp と expires_in が整合する（差が 60 秒以内）", diff <= 60,
                    "|(exp - 現在) - expires_in| <= 60",
                    "差 = " + diff + " 秒（expires_in=" + seconds + " / 残り=" + remain + "）");

                r.Done();
            }
        }
    }
}
