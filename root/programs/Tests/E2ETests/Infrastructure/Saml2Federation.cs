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
//* クラス名        ：Saml2Federation
//* クラス日本語名  ：SAML2 の ID 連携（下流を駆動する）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/11  玄人 幸道         新規（#286 の段階 3）
//*  2026/10/13  玄人 幸道         SSO へ行く部分を FollowSsoAsync に切り出した（#293 の段階 4）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// SAML2 の ID 連携（上流の IdP へ委譲するサインイン）の手順。
    /// </summary>
    /// <remarks>
    /// **「下流」を駆動する**。上流は URL でしか扱わない（OIDC 側の `IdFederation` と同じ流儀）。
    ///
    /// | | OIDC（`IdFederation`） | SAML2（ここ） |
    /// |---|---|---|
    /// | 押すボタン | `id_federation_signin` | **`id_federation_saml2_signin`** |
    /// | 上流の口 | `/authorize` | **`/saml2request`**（`IdFederationSaml2RequestEndpoint`） |
    /// | 戻り | `code` を `form_post` | **`SAMLResponse`**（Redirect Binding） |
    /// | 同意 | **要る**（記録が無ければ同意画面。#280） | **要らない**（SAML の口は同意を通らない） |
    ///
    /// **上流は、下流の構成の `IdFederationSaml2RequestEndpoint` から引く。**
    /// **テストに URL を書かない**（構成がそのまま向き先である）。
    /// </remarks>
    public static class Saml2Federation
    {
        /// <summary>ID 連携専用の ACS の口（アクション名）</summary>
        /// <remarks>
        /// **URL ではなくパスで持つ。**
        /// **配信の形が配備で違う**（E2E は root、手動確認（VS）は `/MultiPurposeAuthSite` 配下）。
        /// </remarks>
        public const string AcsActionPath = "/Account/IDFederationAssertionConsumerService";

        /// <summary>上流の URL（スキーム＋ホスト＋ポート）</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>上流の URL。分からなければ null</returns>
        public static string UpstreamOrigin(IdPClient client)
        {
            string endpoint = client.Config.Get("IdFederationSaml2RequestEndpoint");

            if (string.IsNullOrEmpty(endpoint))
            {
                return null;
            }

            return new System.Uri(endpoint).GetLeftPart(System.UriPartial.Authority);
        }

        /// <summary>SAML2 の ID 連携が使えなければ Skip する</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>上流の URL</returns>
        /// <remarks>
        /// **設定が無い配備では、導線そのものが出ない**（`Config.CanIdFederationBySaml2`）。
        /// **上流が建っていないときと同じ扱い**で Skip する。
        /// </remarks>
        public static async Task<string> SkipIfNotAvailableAsync(IdPClient client)
        {
            Xunit.Skip.If(string.IsNullOrEmpty(client.Config.Get("IdFederationSaml2RequestEndpoint")),
                "IdFederationSaml2RequestEndpoint が構成ファイルにありません（#286 の段階 1）。");

            Xunit.Skip.If(string.IsNullOrEmpty(client.Config.Get("IdFederationSaml2CerFilePath")),
                "IdFederationSaml2CerFilePath が構成ファイルにありません（上流の署名証明書）。");

            // **上流が建っているか**は、OIDC 側と同じ見方でよい（同じサイトである）。
            return await IdFederation.SkipIfUpstreamIsDownAsync(client);
        }

        /// <summary>下流で「SAML2 の ID 連携」を押し、一巡させる</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **ブラウザがすることを、そのまま行う。**
        ///
        /// 1. 下流のサインイン画面を開く（AntiForgery と導線の有無を見る）
        /// 2. **`id_federation_saml2_signin` を押す** → 上流の SSO へリダイレクト
        /// 3. 上流が `SAMLResponse` を返す（**Redirect Binding なので、クエリに載って戻る**）
        /// 4. **下流の ACS へ、その URL をそのまま叩く**（ブラウザのリダイレクトと同じ）
        ///
        /// **`IdPClient` は `CookieContainer` を 1 つ持つ**ので、
        /// **上流・下流の Cookie を同時に持つ**（ブラウザと同じ状態）。
        /// </remarks>
        public static async Task<Saml2FederationResult> FederateAsync(IdPClient client)
        {
            Saml2FederationResult result = await Saml2Federation.StartAsync(client);

            if (string.IsNullOrEmpty(result.SsoUrl))
            {
                return result;
            }

            return await Saml2Federation.FollowSsoAsync(client, result.SsoUrl, result);
        }

        /// <summary>下流で「SAML2 の ID 連携」を押し、上流へ行く手前で止める</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>結果（`SsoUrl` まで）</returns>
        /// <remarks>
        /// **`FederateAsync` の (1) と (2) である。**
        /// **要求を細工してから投げる側から呼べるように、切り出してある**（#293 の段階 4）。
        /// </remarks>
        public static async Task<Saml2FederationResult> StartAsync(IdPClient client)
        {
            Saml2FederationResult result = new Saml2FederationResult();

            // (1) 下流のサインイン画面
            HttpResponseMessage login = await client.GetAsync("/Account/Login");
            string loginHtml = await login.Content.ReadAsStringAsync();

            result.LoginHtml = loginHtml;
            result.HasSaml2Button = loginHtml.Contains("id_federation_saml2_signin");
            result.HasOidcButton = loginHtml.Contains("\"id_federation_signin\"");

            string token = Html.Antiforgery(loginHtml);

            if (string.IsNullOrEmpty(token))
            {
                return result;
            }

            // (2) 「SAML2 の ID 連携」を押す
            HttpResponseMessage start = await client.PostFormAsync(
                "/Account/Login",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", token },
                    // **画面の入力値は使われない**（SAML に login_hint 相当が無い。#286 の決め事）。
                    { "Email", "" },
                    { "Password", "" },
                    { "RememberMe", "false" },
                    { "submitButtonName", "id_federation_saml2_signin" }
                });

            if (start.Headers.Location == null)
            {
                return result;
            }

            result.SsoUrl = start.Headers.Location.ToString();

            return result;
        }

        /// <summary>上流の SSO へ行き、戻ってきた応答を下流の ACS に渡す</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <param name="ssoUrl">上流の SSO の URL（`SAMLRequest` を含む）</param>
        /// <param name="result">詰める入れ物（null なら作る）</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **`FederateAsync` の (3) と (4) である。**
        /// **要求を細工して投げる側から呼べるように、切り出してある**（#293 の段階 4）。
        /// </remarks>
        public static async Task<Saml2FederationResult> FollowSsoAsync(
            IdPClient client, string ssoUrl, Saml2FederationResult result = null)
        {
            result = result ?? new Saml2FederationResult();
            result.SsoUrl = ssoUrl;

            //  (3) 上流の SSO（**ブラウザが行く先**）。
            //
            //    **上流の応答は 2 通りある。**
            //
            //    | | |
            //    |---|---|
            //    | **セッションが在る** | **下流の ACS へリダイレクト**（`SAMLResponse` をクエリに載せて） |
            //    | **セッションが無い** | **上流が自分のサインイン画面へリダイレクト**（`IsPassive` を送っていないため） |
            //
            //    **宛先で見分ける。** **リダイレクトしたこと自体では分からない。**
            //  **構成ファイルの `IdFederationSaml2ResponseEndpoint` とは比べない。**
            //    **あの値は手動確認（VS）用**で、`/MultiPurposeAuthSite` 付きである。
            //    **E2E の下流は root で配信する**ので、`test.ps1` が環境変数で上書きしている
            //    （**サイトはその値、テストが読む構成ファイルは別の値**）。
            //    **だから口の名前（パス）で見分ける。** 上流の画面の URL には出てこない。
            string url = result.SsoUrl;

            for (int i = 0; i < 5; i++)
            {
                HttpResponseMessage sso = await client.GetAsync(url);

                result.SsoStatusCode = sso.StatusCode;

                if (sso.Headers.Location == null)
                {
                    // **画面が返っている**（上流のサインイン画面など）。
                    result.SsoBody = await sso.Content.ReadAsStringAsync();
                    result.LandedOn = url;
                    return result;
                }

                string next = sso.Headers.Location.IsAbsoluteUri
                    ? sso.Headers.Location.ToString()
                    : new System.Uri(new System.Uri(url), sso.Headers.Location).ToString();

                if (0 <= next.IndexOf(Saml2Federation.AcsActionPath,
                        System.StringComparison.OrdinalIgnoreCase))
                {
                    // **下流の ACS を指した**（アサーションが返ってきた）。
                    result.AcsUrl = next;
                    break;
                }

                // **上流の中での移動**（サインイン画面へ、など）。追って、着いた先を見る。
                url = next;
            }

            if (result.AcsUrl == null)
            {
                result.LandedOn = url;
                return result;
            }

            // (4) 下流の ACS（**上流が指した先をそのまま叩く**）
            HttpResponseMessage acs = await client.GetAsync(result.AcsUrl);

            result.AcsStatusCode = acs.StatusCode;

            if (!result.Authorized)
            {
                result.AcsBody = await acs.Content.ReadAsStringAsync();
            }

            return result;
        }

        /// <summary>下流にサインインできているか</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>サインインしていたら true</returns>
        /// <remarks>**保護された画面が開くかどうかで見る**（OIDC 側と同じ）。</remarks>
        public static async Task<bool> IsSignedInAsync(IdPClient client)
        {
            HttpResponseMessage res = await client.GetAsync("/Manage/Index");

            return res.StatusCode == HttpStatusCode.OK;
        }

        /// <summary>下流でサインインしている利用者のメアド（画面から読む）</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>メアド（読めなければ空）</returns>
        /// <remarks>
        /// **`/Manage/Index` は、サインインしている利用者のメアドを出す。**
        /// **連携キーで同じ利用者に結び付いたか**を、これで見る。
        /// </remarks>
        public static async Task<string> SignedInEmailAsync(IdPClient client)
        {
            HttpResponseMessage res = await client.GetAsync("/Manage/Index");

            if (res.StatusCode != HttpStatusCode.OK)
            {
                return "";
            }

            string html = await res.Content.ReadAsStringAsync();

            System.Text.RegularExpressions.Match m =
                System.Text.RegularExpressions.Regex.Match(
                    html, @"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+");

            return m.Success ? m.Value : "";
        }
    }

    /// <summary>SAML2 の ID 連携の結果</summary>
    public sealed class Saml2FederationResult
    {
        /// <summary>下流のサインイン画面の HTML</summary>
        public string LoginHtml { get; set; }

        /// <summary>SAML2 の導線が出ていたか</summary>
        public bool HasSaml2Button { get; set; }

        /// <summary>OIDC の導線が出ていたか</summary>
        public bool HasOidcButton { get; set; }

        /// <summary>上流の SSO の URL（`SAMLRequest` を含む）</summary>
        public string SsoUrl { get; set; }

        /// <summary>上流の SSO の応答</summary>
        public HttpStatusCode SsoStatusCode { get; set; }

        /// <summary>上流が画面を返したときの HTML（サインインしていない場合）</summary>
        public string SsoBody { get; set; }

        /// <summary>ACS へ行かなかったときに、最後に着いた URL</summary>
        public string LandedOn { get; set; }

        /// <summary>上流が指した下流の ACS の URL（`SAMLResponse` を含む）</summary>
        public string AcsUrl { get; set; }

        /// <summary>下流の ACS の応答</summary>
        public HttpStatusCode AcsStatusCode { get; set; }

        /// <summary>ACS がサインインさせなかったときの HTML</summary>
        public string AcsBody { get; set; }

        /// <summary>上流へ送った `AuthnRequest`（XML。読めなければ null）</summary>
        public string AuthnRequestXml
        {
            get { return Saml2.FromRedirectQuery(this.SsoUrl, "SAMLRequest"); }
        }

        /// <summary>上流から返った `SAMLResponse`（XML。読めなければ null）</summary>
        public string ResponseXml
        {
            get { return Saml2.FromRedirectQuery(this.AcsUrl); }
        }

        /// <summary>アサーションを受け取り、サインインまで進んだか</summary>
        /// <remarks>
        /// **ACS はサインインさせたらリダイレクトする**（`RedirectToLocal`）。
        /// **受け付けなかったときは、エラー画面（HTTP 200）を返す。**
        /// </remarks>
        public bool Authorized
        {
            get
            {
                return this.AcsStatusCode == HttpStatusCode.Found
                    || this.AcsStatusCode == HttpStatusCode.Redirect
                    || this.AcsStatusCode == HttpStatusCode.SeeOther;
            }
        }
    }
}
