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
//* クラス名        ：IdFederationTests
//* クラス日本語名  ：RT ID フェデレーション（#140 / #250 の段階 5）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/30  玄人 幸道         新規（#250 の段階 5 : ID フェデレーションを E2E で駆動する）
//*  2026/10/03  玄人 幸道         テスト利用者をターゲットごとに引く（#260）
//*  2026/10/08  玄人 幸道         上流の同意の記録が無ければ、準備するようにした（#280）
//*  2026/10/08  玄人 幸道         手順を Infrastructure/IdFederation へ移した（#284）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-140. ID フェデレーション（他の IdP へ委譲するサインイン）。
    /// </summary>
    /// <remarks>
    /// **この経路は、長いあいだ E2E で駆動していなかった**（`TESTING.md` 5 節）。
    /// **上流の IdP が要る**ためで、#250 の段階 2〜4 でコンテナとして建てられるようにした。
    ///
    /// **上流は `store/` のコンテナ**（既定 `https://localhost:44301`）で、
    /// **`test.ps1` の管理外**である。**建っていなければ Skip する**
    /// （DB ストアや IIS Express と同じ扱い）。
    ///
    /// **下流（テスト対象）は、`test.ps1` が上流を向くように起動する**
    /// （`OAuth2AndOidcClientID` / `IdFederationRedirectEndpoint` を差し込む）。
    ///
    /// **目視で見つかった欠陥は、どれもここで出るはずのものだった**（#250 の段階 4）。
    ///
    /// **上流には「同意の記録」という前提がある**（#280）。
    /// **上流は `UserStoreType=mem` なので、コンテナを作り直すと記録が消える。**
    /// **この E2E は `prompt=none` で委譲する**ので、
    /// **記録が無い上流に対しては `consent_required` になる**
    /// （OIDC Core §3.1.2.6。#272 の段階 2。**IdP の側は仕様どおり**）。
    ///
    /// **それは前提が整っていないだけ**なので、
    /// `EnsureUpstreamConsentAsync` で整える。**測るのは ID 連携の一巡である。**
    /// </remarks>
    public class IdFederationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdFederationTests(ITestOutputHelper output) : base(output)
        {
        }


        /// <summary>RT-140.4 ID 連携でサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14004_ID連携でサインインできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.4",
                    "上流の IdP へ委譲して、下流にサインインできる",
                    "**下流は自分で認証せず、上流の認証結果を受け取る。**"
                    + "認可コード ＋ PKCE(S256) で `code` を受け、`/token`・`/userinfo` で"
                    + "利用者を特定し、**下流のアカウントに結び付けてサインインさせる。**"
                    + "**この経路は #140 の段階 3 で直したが、長く E2E で駆動できていなかった**（#250）。",
                    "OIDC Core §3.1 / #140 / #250 の段階 5");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインしておく（下流は prompt=none で委譲する）");

                bool upstreamSignedIn =
                    await IdFederation.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流で「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederation.FederateAsync(client, TestEnv.TestUserName(targetKey));

                r.Verify("上流の認可エンドポイントへ送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    fed.AuthorizeUrl == null ? "**リダイレクトしない**" : fed.AuthorizeUrl);

                bool pkce = (fed.AuthorizeUrl ?? "").Contains("code_challenge_method=S256");

                r.Verify("PKCE(S256) を付けて要求する", pkce,
                    "code_challenge_method=S256", pkce ? "付いている" : "**付いていない**");

                bool promptNone = (fed.AuthorizeUrl ?? "").Contains("prompt=none");

                r.Verify("prompt=none で要求する（画面を出させない）", promptNone,
                    "prompt=none", promptNone ? "付いている" : "**付いていない**");

                r.Step("(3) 上流が認可応答（form_post）を返す");

                r.Verify("code が返る", fed.Authorized,
                    "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                r.Step("(4) 下流の Redirect エンドポイントへ渡す");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("下流にサインインできている", signedIn,
                    "保護された画面が開く",
                    signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Done();
            }
        }

        /// <summary>RT-140.5 連携キーは (iss, sub)。二度目も同じ利用者になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#140 の段階 3 で、連携キーを独自の `userid` から `(iss, sub)` へ移した。**
        /// **同じ上流・同じ利用者なら、何度連携しても同じ下流アカウントになる**
        /// （毎回新しいアカウントが作られない）ことを確かめる。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14005_二度目の連携でも同じ利用者になる(string targetKey)
        {
            string firstSub = null;

            for (int round = 1; round <= 2; round++)
            {
                // **毎回、新しい入れ物で始める**（Cookie を持ち越さない）。
                using (IdPClient client = this.Client(targetKey))
                {
                    string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                    Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                        "前提: 上流にサインインできること（" + round + " 回目）");

                    FederationResult fed = await IdFederation.FederateAsync(client, TestEnv.TestUserName(targetKey));

                    Assert.True(fed.Authorized,
                        "前提: 上流が認可コードを返すこと（" + round + " 回目）");

                    Assert.True(await IdFederation.IsSignedInAsync(client),
                        "前提: 下流にサインインできること（" + round + " 回目）");

                    // **下流の sub を、下流自身の /userinfo から引く。**
                    //   連携で作られた（または結び付いた）アカウントの識別子である。
                    //
                    //   **pairwise のクライアントを使う**（test.ps1 -Launch が差し込む）。
                    //   **pairwise の sub は、利用者の ID から作る**ので、
                    //   **アカウントが違えば必ず違う**（既定の public でも同じことが言えるが、
                    //   **設定に依らない方を選んでおく**）。
                    ClientRegistration reg =
                        Flows.InjectedRegistration(client, KnownClients.TestClient_5);

                    // **RunAuthorizationCodeFlowAsync は使えない。**
                    //   あれはクライアント名から Registration を引くが、
                    //   **TestClient_5 は構成ファイルに無い**（差し込みなので InjectedRegistration）。
                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid email", "state-rt1405", "nonce-rt1405", reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(authz.Code),
                        "前提: 下流で認可コードを取れること（" + round + " 回目）");

                    JsonResponse token = await Flows.ExchangeCodeAsync(
                        client, reg, authz.Code, reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(token.AccessToken),
                        "前提: 下流でトークンを取れること（" + round + " 回目）");

                    JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);
                    string sub = userInfo.String("sub");

                    if (round == 1)
                    {
                        firstSub = sub;
                        continue;
                    }

                    TestReport r = this.Report("RT-140.5",
                        "二度目の ID 連携でも、同じ下流アカウントになる",
                        "**連携キーは `(iss, sub)` である**（#140 の段階 3。以前は独自の `userid`）。"
                        + "**同じ上流の同じ利用者なら、何度連携しても同じアカウント**に結び付く。"
                        + "毎回新しいアカウントが作られるなら、連携キーが効いていない。",
                        "OIDC Core §2（sub は Issuer 内で一意）/ #140 の段階 3");

                    r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                    r.Step("ID 連携を 2 回行い、下流の /userinfo が返す sub を比べる");

                    r.Verify("1 回目の sub が取れる", !string.IsNullOrEmpty(firstSub),
                        "sub あり", string.IsNullOrEmpty(firstSub) ? "**無し**" : "あり（値は伏せる）");

                    r.Verify("2 回目の sub が、1 回目と一致する",
                        !string.IsNullOrEmpty(sub) && sub == firstSub,
                        "一致する", (sub == firstSub) ? "一致した" : "**違う利用者になった**");

                    r.Done();
                }
            }
        }

        /// <summary>RT-140.6 上流にセッションが無ければ、連携は成立しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **下流は `prompt=none` で委譲する**ので、**上流が「黙って」認証できるときだけ通る。**
        ///
        /// **上流は `login_required` を `redirect_uri` へ返す**（#254 で直した。OIDC Core §3.1.2.6）。
        /// **直す前はログイン画面を出していた**が、**どちらでも「下流はサインインしない」**ので、
        /// **この判定は修正の前後で変わらない**（実際、両方で通ることを確かめた）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14006_上流が未サインインなら連携は成立しない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.6",
                    "上流にセッションが無ければ、ID 連携は成立しない",
                    "**下流は prompt=none で委譲する。** 上流が黙って認証できないときに"
                    + "**勝手にサインインさせてしまっては、委譲の意味が無い。**"
                    + "**上流が画面を出すか login_required を返すかは #254 の論点**で、"
                    + "**どちらでも下流はサインインしない。**",
                    "OIDC Core §3.1.2.1 / §3.1.2.6 / #140 / #254");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + "（未サインイン）");

                r.Step("上流にサインインせずに、下流で「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederation.FederateAsync(client, TestEnv.TestUserName(targetKey));

                r.Verify("上流の認可エンドポイントへは送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    fed.AuthorizeUrl == null ? "**リダイレクトしない**" : "リダイレクトした");

                r.Verify("認可コードは返らない", !fed.Authorized,
                    "code なし", fed.Authorized ? "**code が返った**" : "返らなかった");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("下流はサインインしない", !signedIn,
                    "サインインしない", signedIn ? "**サインインしてしまった**" : "しなかった");

                r.Done();
            }
        }

        /// <summary>RT-140.7 連携の認可応答にも iss が付く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#252 で form_post に `iss` を付けるようにした。**
        /// **ID 連携はまさに form_post を使う**ので、実経路でも付くことを確かめる。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14007_連携の認可応答にもissが付く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.7",
                    "ID 連携の認可応答（form_post）にも、iss が付く",
                    "**下流は認可応答の `iss` を照合する**（#140 の段階 3。Mix-Up 対策）。"
                    + "**上流が返さなければ、その照合は一度も働かない。**"
                    + "**form_post だけ `iss` が抜けていた**（#252）ので、実経路で確かめる。",
                    "RFC 9207 §2 / #252 / #140 の段階 3");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流の Discovery から issuer を読む");

                JsonResponse discovery = await client.GetJsonAsync(
                    upstream + "/.well-known/openid-configuration");

                Assert.True(discovery.IsJson, "前提: 上流の Discovery が JSON であること");

                string issuer = discovery.String("issuer");
                r.Note("上流の issuer = " + (issuer ?? "（無し）"));

                r.Step("(2) ID 連携を行い、認可応答の hidden を見る");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                FederationResult fed = await IdFederation.FederateAsync(client, TestEnv.TestUserName(targetKey));

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                string iss;
                fed.Hidden.TryGetValue("iss", out iss);

                r.VerifyEqual("iss が上流の issuer と一致する",
                    issuer ?? "（無し）", iss ?? "**無し**");

                r.Done();
            }
        }
    }
}
