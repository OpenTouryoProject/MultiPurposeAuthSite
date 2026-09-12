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
//* クラス名        ：IntrospectionTests
//* クラス日本語名  ：EX-3 トークンの問い合わせ（RFC 7662）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//*  2026/09/11  玄人 幸道         EX-3.2 / 3.4 の Skip を解除、EX-3.7 を追加（#200）
//*  2026/09/11  玄人 幸道         IntrospectAsync を Flows へ移す（RevocationTests への依存も解消）
//*  2026/09/11  玄人 幸道         EX-3.6 の観測の注記を、#196（/introspect の 401）の対応に合わせる
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
    /// EX-3. トークンの問い合わせ（RFC 7662 / POST /introspect）。
    ///
    /// リソース サーバが「このトークンは今使えるか」を認可サーバに問い合わせる口。
    /// **使えないトークンについての「使えない」も、正常な答えである**ことに注意する。
    /// </summary>
    public class IntrospectionTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IntrospectionTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>active の値を、読み手向けに書く</summary>
        /// <param name="res">応答</param>
        /// <returns>説明</returns>
        private static string ActiveOf(JsonResponse res)
        {
            JsonValueKind kind = res.KindOf("active");

            switch (kind)
            {
                case JsonValueKind.True:
                    return "active=true";
                case JsonValueKind.False:
                    return "active=false";
                case JsonValueKind.Undefined:
                    return "active なし（" + res.ToString() + "）";
                default:
                    return "active=" + res.String("active") + "（" + kind + "）";
            }
        }

        /// <summary>応答の項目名の一覧</summary>
        /// <param name="res">応答</param>
        /// <returns>項目名</returns>
        private static List<string> NamesOf(JsonResponse res)
        {
            List<string> names = new List<string>();

            if (res.IsJson && res.Json.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty p in res.Json.EnumerateObject())
                {
                    names.Add(p.Name);
                }
            }

            return names;
        }

        /// <summary>EX-3.1 有効な access_token</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0301_有効なaccess_tokenはactiveがtrue(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.1",
                    "有効な access_token について、active=true と答える",
                    "リソース サーバが「このトークンは今使えるか」を認可サーバに問い合わせる口。"
                    + "**active は必ず返す真偽値。**それ以外の項目（scope / sub / exp など）は任意。",
                    "RFC 7662 §2.1 / §2.2（active は REQUIRED の boolean）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) POST /introspect に token と token_type_hint=access_token を送る（発行先の資格情報で）");

                JsonResponse res = await Flows.IntrospectAsync(client, reg, token.AccessToken, "access_token");

                r.Verify("active が true（JSON の真偽値）", res.KindOf("active") == JsonValueKind.True,
                    "active=true", ActiveOf(res));

                r.Observe("返った項目", res.ToString(), "active 以外は任意（§2.2）。");
                r.Observe("scope", res.String("scope") ?? "（返らない）");

                r.Done();
            }
        }

        /// <summary>EX-3.2 有効な refresh_token</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0302_有効なrefresh_tokenもactiveがtrue(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.2",
                    "有効な refresh_token についても、active=true と答える",
                    "問い合わせの対象は access_token に限らない。"
                    + "この実装は token_type_hint=refresh_token を受け付けている。",
                    "RFC 7662 §2.1（token は access_token または refresh_token の値）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで refresh_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                Assert.False(string.IsNullOrEmpty(token.RefreshToken),
                    "前提: refresh_token が発行されること");

                r.Step("(2) POST /introspect に token と token_type_hint=refresh_token を送る");

                JsonResponse res = await Flows.IntrospectAsync(client, reg, token.RefreshToken, "refresh_token");

                r.Verify("active が true（JSON の真偽値）", res.KindOf("active") == JsonValueKind.True,
                    "active=true", ActiveOf(res));

                r.Observe("返った項目", res.ToString());

                r.Done();
            }
        }

        /// <summary>EX-3.3 他クライアントのトークン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0303_他のクライアントのトークンはactiveがfalseだけ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.3",
                    "他のクライアントに発行されたトークンには、active=false とだけ答える",
                    "問い合わせ元に知る権限の無いトークンについて、"
                    + "**中身（ユーザや範囲）を漏らさない。**active=false だけを返すのが仕様の答え方。",
                    "RFC 7662 §2.2（知る権限が無ければ active=false）/ §4 / #194");

                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                Assert.False(string.IsNullOrEmpty(other.ClientSecret),
                    "前提: " + KnownClients.TestClient + " に client_secret が登録されていること");

                r.Target("発行先 client_name=" + KnownClients.MvcSample
                    + " / 問い合わせる側 client_name=" + KnownClients.TestClient);
                r.Step("(1) " + KnownClients.MvcSample + " で access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) " + KnownClients.TestClient + " の資格情報で、その access_token を問い合わせる");

                JsonResponse res = await Flows.IntrospectAsync(client, other, token.AccessToken, "access_token");

                r.Verify("active が false", res.KindOf("active") == JsonValueKind.False,
                    "active=false", ActiveOf(res));

                List<string> names = NamesOf(res);

                r.Verify("active 以外を返さない", names.Count == 1 && names[0] == "active",
                    "active のみ", "[" + string.Join(", ", names) + "]");

                r.Done();
            }
        }

        /// <summary>EX-3.4 無効なトークン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0304_無効なトークンにはactiveがfalseで答える(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.4",
                    "無効なトークンには、エラーではなく active=false で答える",
                    "存在しない・失効したトークンについての「使えない」は、**問い合わせの正常な答え**である。"
                    + "エラーにすると、リソース サーバは「問い合わせに失敗した」のか"
                    + "「トークンが使えない」のかを区別できない。",
                    "RFC 7662 §2.2（無効なトークンには active=false を返す。MUST）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 存在しないトークンを問い合わせる");

                JsonResponse unknown = await Flows.IntrospectAsync(client, reg, "NOT-A-REAL-TOKEN", "access_token");

                r.Verify("存在しないトークン : active=false と答える",
                    unknown.KindOf("active") == JsonValueKind.False,
                    "active=false",
                    ActiveOf(unknown) + " / error=" + (unknown.Error ?? "なし"));

                r.Step("(2) access_token を得て失効させ、それを問い合わせる");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                JsonResponse revoke = await Flows.RevokeAsync(
                    client, reg, token.AccessToken, "access_token");

                Assert.True(string.IsNullOrEmpty(revoke.Error), "前提: 失効させられること");

                JsonResponse revoked = await Flows.IntrospectAsync(client, reg, token.AccessToken, "access_token");

                r.Verify("失効させたトークン : active=false と答える",
                    revoked.KindOf("active") == JsonValueKind.False,
                    "active=false",
                    ActiveOf(revoked) + " / error=" + (revoked.Error ?? "なし"));

                r.Done();
            }
        }

        /// <summary>EX-3.5 token_type_hint の省略</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0305_token_type_hintを省略しても答えられる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.5",
                    "token_type_hint を省略しても、答えられる",
                    "token_type_hint は**任意のヒント**。省略されたら、サーバが種類を調べて答える。"
                    + "ヒントが無いことを理由に答えないと、リソース サーバはトークンを確かめられない。",
                    "RFC 7662 §2.1（token_type_hint は OPTIONAL）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) POST /introspect に token だけを送る（token_type_hint なし）");

                JsonResponse res = await Flows.IntrospectAsync(client, reg, token.AccessToken, null);

                r.Verify("active が true（JSON の真偽値）", res.KindOf("active") == JsonValueKind.True,
                    "active=true",
                    ActiveOf(res) + " / error=" + (res.Error ?? "なし"));

                r.Done();
            }
        }

        /// <summary>EX-3.6 クライアント認証なし</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0306_クライアント認証が無ければトークンの情報を返さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.6",
                    "クライアント認証の無い問い合わせには、トークンの情報を返さない",
                    "イントロスペクションは、トークンの中身（ユーザ・範囲）を明かす口。"
                    + "**誰でも問い合わせられると、拾ったトークンの持ち主や権限を調べられる。**",
                    "RFC 7662 §2.1（問い合わせ元の認可を要求する。MUST）/ §4");

                r.Target("client_name=" + KnownClients.MvcSample + " のトークン / 問い合わせ側は認証しない");
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) client_id / client_secret を付けずに POST /introspect を送る");

                JsonResponse res = await Flows.IntrospectAsync(client, null, token.AccessToken, "access_token");

                r.Verify("active=true を返さない", res.KindOf("active") != JsonValueKind.True,
                    "active=true を返さない", ActiveOf(res));

                bool leaked = res.KindOf("sub") != JsonValueKind.Undefined
                    || res.KindOf("scope") != JsonValueKind.Undefined;

                r.Verify("sub や scope を返さない", !leaked,
                    "返さない", leaked ? "**返してしまった**（" + res.ToString() + "）" : res.ToString());

                r.Observe("拒否のしかた",
                    "HTTP " + (int)res.StatusCode + " / error=" + (res.Error ?? "なし"),
                    "RFC 7662 §2.3 は、認証に失敗したら 401 を返すとしている（#196 で対応。RT-196.11 で検証）。");

                r.Done();
            }
        }

        /// <summary>EX-3.7 token_type_hint の取り違え</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0307_token_type_hintが違っていても答えられる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-3.7",
                    "token_type_hint が実際の種類と違っていても、答えられる",
                    "ヒントは手掛かりにすぎない。**外れていても探し当てて答える。**"
                    + "取り違えただけで active=false になると、リソース サーバは使えるトークンを拒んでしまう。",
                    "RFC 7662 §2.1（ヒントで見つからなければ、対応する全種類から探す。MUST）/ #200");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email");

                r.Step("(2) access_token を、token_type_hint=refresh_token（取り違え）で問い合わせる");

                JsonResponse res = await Flows.IntrospectAsync(client, reg, token.AccessToken, "refresh_token");

                r.Verify("active が true（JSON の真偽値）", res.KindOf("active") == JsonValueKind.True,
                    "active=true",
                    ActiveOf(res) + " / error=" + (res.Error ?? "なし"));

                r.Observe("token_type", res.String("token_type") ?? "（返らない）",
                    "見つかった種類が入る。RFC 7662 §2.2 の token_type は Bearer などの型を指すので、意味がずれている。");

                r.Done();
            }
        }
    }
}
