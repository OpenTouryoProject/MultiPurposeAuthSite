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
//* クラス名        ：IdFederation, FederationResult
//* クラス日本語名  ：ID フェデレーション（上流へ委譲するサインイン）の手順
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         IdFederationTests から移した（#284）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Xunit;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// ID フェデレーション（他の IdP へ委譲するサインイン）の手順。
    /// </summary>
    /// <remarks>
    /// **「下流」を駆動する**。上流は URL でしか扱わない。
    ///
    /// **下流が 2 通りある**ので、実装をここに 1 つだけ置く（#284）。
    ///
    /// | 下流 | 使う側 |
    /// |---|---|
    /// | **ホストの core / netfx** | `RT-140.*`（`Tests/Issues/IdFederationTests.cs`） |
    /// | **下流コンテナ** | `CN-5.*`（`Tests/Container/HybridFlowTests.cs`） |
    ///
    /// **上流は、下流の構成の `IdFederationAuthorizeEndpoint` から引く。**
    /// **テストに URL を書かない**（どちらの下流でも、構成がそのまま向き先である）。
    /// </remarks>
    public static class IdFederation
    {
        /// <summary>AntiForgery トークンを拾う</summary>
        private static readonly Regex AntiforgeryRegex = new Regex(
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>上流の URL（スキーム＋ホスト＋ポート）</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>上流の URL。分からなければ null</returns>
        /// <remarks>
        /// **構成ファイルの `IdFederationAuthorizeEndpoint` から引く。**
        /// **テストに URL を書かない**（`test.ps1` はここを上書きしないので、
        /// 構成ファイルの値が、そのままサイトの向き先である）。
        ///
        /// **コンテナの下流では、compose の環境変数が重ねられている**（#284。`AppConfig.Overlay`）。
        /// </remarks>
        public static string UpstreamOrigin(IdPClient client)
        {
            string endpoint = client.Config.Get("IdFederationAuthorizeEndpoint");

            if (string.IsNullOrEmpty(endpoint))
            {
                return null;
            }

            return new System.Uri(endpoint).GetLeftPart(System.UriPartial.Authority);
        }

        /// <summary>上流が起動していなければ Skip する</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>上流の URL</returns>
        public static async Task<string> SkipIfUpstreamIsDownAsync(IdPClient client)
        {
            string origin = IdFederation.UpstreamOrigin(client);

            Skip.If(string.IsNullOrEmpty(origin),
                "IdFederationAuthorizeEndpoint が構成ファイルにありません。");

            bool up = false;

            try
            {
                HttpResponseMessage res = await client.GetAsync(
                    origin + "/.well-known/openid-configuration");

                up = res.IsSuccessStatusCode;
            }
            catch (HttpRequestException)
            {
                up = false;
            }
            catch (TaskCanceledException)
            {
                up = false;
            }

            Skip.IfNot(up,
                "上流の IdP（" + origin + "）が起動していません。"
                + "store\\1_DockerComposeUp.bat で建ててください（#250 の段階 5）。");

            return origin;
        }

        /// <summary>上流でサインインする（<c>prompt=none</c> の前提）</summary>
        /// <param name="client">IdPClient（Cookie は下流と同じ入れ物）</param>
        /// <param name="origin">上流の URL</param>
        /// <returns>サインインできたら true</returns>
        /// <remarks>
        /// **下流と同じ `IdPClient` を使う。** `CookieContainer` が 1 つなので、
        /// **ブラウザと同じ状態**（上流・下流の Cookie を同時に持つ）になる。
        /// </remarks>
        public static async Task<bool> SignInUpstreamAsync(IdPClient client, string origin)
        {
            HttpResponseMessage get = await client.GetAsync(origin + "/Account/Login");
            string html = await get.Content.ReadAsStringAsync();

            Match m = IdFederation.AntiforgeryRegex.Match(html);

            if (!m.Success)
            {
                return false;
            }

            HttpResponseMessage post = await client.PostFormAsync(
                origin + "/Account/Login",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", m.Groups["value"].Value },
                    // **上流の利用者である**（#260）。**下流の接尾辞を渡してはならない。**
                    //   上流は自分のストアを持ち、種データは super_tanaka である。
                    { "Email", TestEnv.UpstreamUserName },
                    { "Password", client.Config.Get("TestUserPWD") },
                    { "RememberMe", "false" },
                    { "submitButtonName", "normal_signin" }
                });

            // 成功時はリダイレクト。失敗時はログイン画面を返す（HTTP 200）。
            return post.StatusCode == HttpStatusCode.Found
                || post.StatusCode == HttpStatusCode.Redirect
                || post.StatusCode == HttpStatusCode.SeeOther;
        }

        /// <summary>上流に同意の記録が無ければ、1 度だけ「許可」を押して整える（#280）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="authorizeUrl">下流が組み立てた認可要求の URL（<c>prompt=none</c> 付き）</param>
        /// <returns>押したら true（記録が在った・押せなかったなら false）</returns>
        /// <remarks>
        /// **上流は `UserStoreType=mem` なので、コンテナを作り直すと同意の記録が消える**
        /// （`Sts.ConsentProvider.ConsentGrants` は静的な辞書）。
        /// **この E2E は `prompt=none` で委譲し、どこでも「許可」を押さない**ため、
        /// **記録が無い上流に対しては必ず `consent_required` になる**
        /// （OIDC Core §3.1.2.6。IdP の側は仕様どおりである）。
        ///
        /// **それはテストの前提が整っていないだけ**なので、ここで整える。
        /// **`store/` の DBMS や IIS Express と同じ扱い**である。
        ///
        /// **測りたいのは ID 連携の一巡であって、「許可」が押せることではない。**
        /// そのため、**ここでの成否は判定に出さない**（整えられなければ、
        /// 呼び出し側が「code が返らない」として落ちる）。
        ///
        /// **`prompt=none` を外して 1 回だけ叩く。**
        /// 同意画面（`submit.Grant` を持つ）が返ってきたときだけ押す。
        /// **記録が在れば同意画面は出ない**ので、何もせずに戻る。
        /// **上流が未サインインならログイン画面が返る**ので、これも押さない（`RT-140.6`）。
        /// </remarks>
        public static async Task<bool> EnsureUpstreamConsentAsync(
            IdPClient client, string authorizeUrl)
        {
            // **`prompt=none` だけを落とす。** 他のパラメタ（PKCE・state・nonce）は触らない。
            string url = authorizeUrl
                .Replace("&prompt=none", "")
                .Replace("?prompt=none&", "?");

            HttpResponseMessage res = await client.GetAsync(url);

            // リダイレクト（＝ 認可応答かエラー応答）なら、同意画面ではない。
            if (res.Headers.Location != null)
            {
                return false;
            }

            string html = await res.Content.ReadAsStringAsync();

            // **同意画面の目印は `submit.Grant`**（`Responses.NeedsConsent` と同じ見方）。
            if (string.IsNullOrEmpty(html) || !html.Contains("submit.Grant"))
            {
                return false;
            }

            Match m = IdFederation.AntiforgeryRegex.Match(html);

            if (!m.Success)
            {
                return false;
            }

            // **フォームは action を持たない**ので、認可要求と同じ URL へ POST される。
            HttpResponseMessage granted = await client.PostFormAsync(
                url,
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", m.Groups["value"].Value },
                    { "submit.Grant", "Grant" }
                });

            return granted.IsSuccessStatusCode
                || granted.StatusCode == HttpStatusCode.Found
                || granted.StatusCode == HttpStatusCode.Redirect;
        }

        /// <summary>下流の「ID連携でサインイン」を押して、最後まで流す</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <param name="downstreamUserName">下流の画面に入れる利用者名</param>
        /// <returns>FederationResult</returns>
        public static async Task<FederationResult> FederateAsync(
            IdPClient client, string downstreamUserName)
        {
            FederationResult result = new FederationResult();

            // (1) 下流のログイン画面
            HttpResponseMessage login = await client.GetAsync("/Account/Login");
            string loginHtml = await login.Content.ReadAsStringAsync();

            Match m = IdFederation.AntiforgeryRegex.Match(loginHtml);

            Assert.True(m.Success, "前提: 下流のログイン画面から AntiForgery トークンを取れること");

            // (2) 「ID連携でサインイン」を押す（上流の /authorize へリダイレクトされる）
            HttpResponseMessage start = await client.PostFormAsync(
                "/Account/Login",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", m.Groups["value"].Value },
                    // **下流の画面なので、下流の利用者名を入れる**（#260）。
                    { "Email", downstreamUserName },
                    { "Password", "" },
                    { "RememberMe", "false" },
                    { "submitButtonName", "id_federation_signin" }
                });

            if (start.Headers.Location == null)
            {
                return result;
            }

            result.AuthorizeUrl = start.Headers.Location.ToString();

            // (3) 上流の /authorize（prompt=none）
            result.AuthorizeResponse = await client.GetAsync(result.AuthorizeUrl);

            string authzHtml = await result.AuthorizeResponse.Content.ReadAsStringAsync();
            result.Hidden = Html.HiddenInputs(authzHtml);

            if (!result.Authorized)
            {
                // **同意の記録が無いだけなら、整えてもう一度だけ叩く**（#280）。
                //   **上流を作り直すと記録が消える**ので、ここが無いと
                //   **作り直した直後の通しで必ず落ちる**（実測 : 6 件）。
                if (await IdFederation.EnsureUpstreamConsentAsync(client, result.AuthorizeUrl))
                {
                    result.AuthorizeResponse = await client.GetAsync(result.AuthorizeUrl);

                    authzHtml = await result.AuthorizeResponse.Content.ReadAsStringAsync();
                    result.Hidden = Html.HiddenInputs(authzHtml);
                }
            }

            if (!result.Authorized)
            {
                return result;
            }

            // (4) 自動送信フォームを、下流の Redirect エンドポイントへ POST する
            string action = Html.FormAttribute(authzHtml, "action");

            Dictionary<string, string> form = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> item in result.Hidden)
            {
                form[item.Key] = item.Value;
            }

            result.Callback = await client.PostFormAsync(action, form);

            return result;
        }

        /// <summary>下流にサインインできているか</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>サインインしていたら true</returns>
        /// <remarks>
        /// **保護された画面が開くかどうかで見る。**
        /// 未サインインなら、Cookie 認証がログイン画面へリダイレクトする。
        /// </remarks>
        public static async Task<bool> IsSignedInAsync(IdPClient client)
        {
            HttpResponseMessage res = await client.GetAsync("/Manage/Index");

            return res.StatusCode == HttpStatusCode.OK;
        }
    }

    /// <summary>ID 連携の結果</summary>
    public sealed class FederationResult
    {
        /// <summary>下流が上流へ送った認可要求の URL</summary>
        public string AuthorizeUrl { get; set; }

        /// <summary>上流の認可応答（form_post の自動送信フォーム）</summary>
        public HttpResponseMessage AuthorizeResponse { get; set; }

        /// <summary>自動送信フォームの hidden</summary>
        public Dictionary<string, string> Hidden { get; set; }

        /// <summary>下流の Redirect エンドポイントの応答</summary>
        public HttpResponseMessage Callback { get; set; }

        /// <summary>上流が認可応答を返したか（form_post になったか）</summary>
        public bool Authorized
        {
            get
            {
                return this.Hidden != null && this.Hidden.ContainsKey("code");
            }
        }
    }
}
