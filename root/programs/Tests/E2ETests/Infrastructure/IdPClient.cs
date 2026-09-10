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
//* クラス名        ：IdPClient
//* クラス日本語名  ：IdPをHTTPで駆動するテスト クライアント
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// IdPをHTTPで駆動する。
    ///
    /// 実装側のクラス（CmnEndpoints / Helper など）を参照しない。
    /// テストがブラックボックスであることを保つため、リクエストの組み立ても
    /// 応答の解析も、このクラスが独立して行う。
    ///
    /// ※ トークン・client_secret・パスワードを標準出力へ出さないこと。
    /// </summary>
    public sealed class IdPClient : IDisposable
    {
        /// <summary>__RequestVerificationToken の抽出</summary>
        private static readonly Regex AntiforgeryRegex = new Regex(
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private readonly HttpClientHandler _handler;
        private readonly HttpClient _http;

        /// <summary>テスト対象</summary>
        public TargetInfo Target { get; }

        /// <summary>構成ファイル</summary>
        public AppConfig Config
        {
            get { return this.Target.Config; }
        }

        /// <summary>サインイン済みか</summary>
        public bool IsSignedIn { get; private set; }

        /// <summary>コンストラクタ</summary>
        /// <param name="target">テスト対象</param>
        public IdPClient(TargetInfo target)
        {
            this.Target = target;

            this._handler = new HttpClientHandler();
            this._handler.CookieContainer = new CookieContainer();
            this._handler.UseCookies = true;

            // 認可応答のLocationを観測したいので、自動追跡しない。
            this._handler.AllowAutoRedirect = false;

            // 開発用の自己署名証明書を許容する。
            this._handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            this._http = new HttpClient(this._handler);
            this._http.Timeout = TimeSpan.FromSeconds(60);
        }

        /// <summary>Dispose</summary>
        public void Dispose()
        {
            this._http.Dispose();
            this._handler.Dispose();
        }

        #region 素のHTTP

        /// <summary>GET</summary>
        /// <param name="pathOrUrl">パス（/始まり）または絶対URL</param>
        /// <returns>応答</returns>
        public Task<HttpResponseMessage> GetAsync(string pathOrUrl)
        {
            return this._http.GetAsync(this.Absolute(pathOrUrl));
        }

        /// <summary>POST（application/x-www-form-urlencoded）</summary>
        /// <param name="pathOrUrl">パス（/始まり）または絶対URL</param>
        /// <param name="form">フォーム</param>
        /// <returns>応答</returns>
        public Task<HttpResponseMessage> PostFormAsync(
            string pathOrUrl, IDictionary<string, string> form)
        {
            // 値が null の項目は送らない（「送らない」と「空で送る」を区別するため）。
            List<KeyValuePair<string, string>> items = new List<KeyValuePair<string, string>>();

            foreach (KeyValuePair<string, string> item in form)
            {
                if (item.Value != null)
                {
                    items.Add(item);
                }
            }

            return this._http.PostAsync(this.Absolute(pathOrUrl), new FormUrlEncodedContent(items));
        }

        /// <summary>相対パスを絶対URLにする</summary>
        /// <param name="pathOrUrl">パスまたはURL</param>
        /// <returns>絶対URL</returns>
        private string Absolute(string pathOrUrl)
        {
            if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return pathOrUrl;
            }

            return this.Target.Url(pathOrUrl);
        }

        /// <summary>
        /// Discovery文書が返すURLを、テスト対象が実際に待ち受けているURLに読み替える。
        ///
        /// issuer や各エンドポイントは OAuth2AuthorizationServerEndpointsRootURI（構成ファイル）
        /// から組み立てられる。開発環境では、そこに書かれたURLと実際の待ち受けURLが
        /// 一致しないことがある（例: 構成は https://localhost:44300/MultiPurposeAuthSite、
        /// 実際は dotnet run の http://localhost:5099）。
        ///
        /// テストは「実際に動いているサイト」を叩きたいので、ここで前方一致の置換をする。
        /// </summary>
        /// <param name="url">Discovery文書が返したURL</param>
        /// <returns>テスト対象のURL</returns>
        public string ToLocalUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return url;
            }

            // サーバ側とクライアント側でルートURIが分かれている。
            string[] keys = new string[]
            {
                "OAuth2AuthorizationServerEndpointsRootURI",
                "OAuth2ClientEndpointsRootURI"
            };

            foreach (string key in keys)
            {
                string root = this.Config.Get(key);

                if (string.IsNullOrEmpty(root))
                {
                    continue;
                }

                root = root.TrimEnd('/');

                if (url.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    return this.Target.BaseUrl + url.Substring(root.Length);
                }
            }

            return url;
        }

        #endregion

        #region サインイン

        /// <summary>
        /// テスト ユーザでサインインする。
        /// UserStoreType=mem のとき、テスト ユーザは初回アクセスで作成される。
        /// </summary>
        /// <returns>Task</returns>
        public async Task SignInAsync()
        {
            if (this.IsSignedIn)
            {
                return;
            }

            HttpResponseMessage get = await this.GetAsync("/Account/Login");
            string html = await get.Content.ReadAsStringAsync();

            Match m = AntiforgeryRegex.Match(html);
            if (!m.Success)
            {
                throw new InvalidOperationException(
                    "ログイン画面から __RequestVerificationToken を取得できませんでした（HTTP "
                    + (int)get.StatusCode + "）。");
            }

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", m.Groups["value"].Value },
                { "Email", TestEnv.TestUserName },
                { "Password", this.Config.Get("TestUserPWD") },
                { "RememberMe", "false" },
                { "submitButtonName", "normal_signin" }
            };

            HttpResponseMessage post = await this.PostFormAsync("/Account/Login", form);

            // 成功時はリダイレクト。失敗時はログイン画面を再表示（HTTP 200）。
            if (post.StatusCode != HttpStatusCode.Found
                && post.StatusCode != HttpStatusCode.Redirect
                && post.StatusCode != HttpStatusCode.SeeOther)
            {
                throw new InvalidOperationException(
                    "サインインに失敗しました（HTTP " + (int)post.StatusCode
                    + "）。TestUserPWD と testUserName を確認してください。");
            }

            this.IsSignedIn = true;
        }

        #endregion

        #region 認可エンドポイント

        /// <summary>
        /// 認可リクエストを送る（リダイレクトは追跡しない）。
        /// </summary>
        /// <param name="parameters">クエリ パラメタ（値が null の項目は送らない）</param>
        /// <param name="path">エンドポイント（既定は /authorize）</param>
        /// <returns>AuthZResponse</returns>
        public async Task<AuthZResponse> AuthorizeAsync(
            IDictionary<string, string> parameters, string path = "/authorize")
        {
            HttpResponseMessage res = await this.GetAsync(path + "?" + BuildQuery(parameters));
            return await ToAuthZResponseAsync(res);
        }

        /// <summary>HttpResponseMessage を AuthZResponse に変換する</summary>
        /// <param name="res">応答</param>
        /// <returns>AuthZResponse</returns>
        public static async Task<AuthZResponse> ToAuthZResponseAsync(HttpResponseMessage res)
        {
            AuthZResponse result = new AuthZResponse();
            result.StatusCode = res.StatusCode;
            result.Parameters = new Dictionary<string, string>(StringComparer.Ordinal);
            result.RequestUrl = (res.RequestMessage == null || res.RequestMessage.RequestUri == null)
                ? null : res.RequestMessage.RequestUri.OriginalString;

            string location = (res.Headers.Location == null)
                ? null : res.Headers.Location.OriginalString;

            result.Location = location;

            if (string.IsNullOrEmpty(location))
            {
                result.Where = ParameterLocation.None;
                result.Body = await res.Content.ReadAsStringAsync();
                return result;
            }

            int hash = location.IndexOf('#');
            int question = location.IndexOf('?');

            // フラグメントが有れば、そちらを優先して見る（Implicit / Hybrid）。
            if (hash >= 0 && hash + 1 < location.Length)
            {
                result.Where = ParameterLocation.Fragment;
                ParseInto(location.Substring(hash + 1), result.Parameters);
                result.RedirectTo = location.Substring(0, (question >= 0 && question < hash) ? question : hash);
            }
            else if (question >= 0)
            {
                result.Where = ParameterLocation.Query;
                int end = (hash >= 0) ? hash : location.Length;
                ParseInto(location.Substring(question + 1, end - question - 1), result.Parameters);
                result.RedirectTo = location.Substring(0, question);
            }
            else
            {
                result.Where = ParameterLocation.None;
                result.RedirectTo = location;
            }

            return result;
        }

        /// <summary>
        /// 同意画面（OAuth2Authorize）で「許可」を押す。
        ///
        /// prompt=none を付けない認可リクエスト（Request Object 経由など）は、
        /// 一度この画面で止まる。フォームは action を持たず、
        /// 認可リクエストと同じURL（クエリ文字列込み）へPOSTされる。
        /// </summary>
        /// <param name="authz">同意画面が返ってきた応答</param>
        /// <returns>AuthZResponse</returns>
        public async Task<AuthZResponse> GrantConsentAsync(AuthZResponse authz)
        {
            if (!authz.NeedsConsent)
            {
                throw new InvalidOperationException(
                    "同意画面ではありません: " + authz.ToString());
            }

            Match m = AntiforgeryRegex.Match(authz.Body);

            if (!m.Success)
            {
                throw new InvalidOperationException(
                    "同意画面から __RequestVerificationToken を取得できませんでした。");
            }

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", m.Groups["value"].Value },
                { "submit.Grant", "Grant" }
            };

            HttpResponseMessage res = await this.PostFormAsync(authz.RequestUrl, form);
            return await ToAuthZResponseAsync(res);
        }

        /// <summary>
        /// 認可リクエストを送り、同意画面が出たら「許可」まで進める。
        /// </summary>
        /// <param name="url">認可リクエストのURL</param>
        /// <returns>AuthZResponse</returns>
        public async Task<AuthZResponse> AuthorizeAndGrantAsync(string url)
        {
            HttpResponseMessage res = await this.GetAsync(url);
            AuthZResponse authz = await ToAuthZResponseAsync(res);

            if (authz.NeedsConsent)
            {
                authz = await this.GrantConsentAsync(authz);
            }

            return authz;
        }

        #endregion

        #region トークン エンドポイントなど

        /// <summary>トークン エンドポイントを呼ぶ</summary>
        /// <param name="form">フォーム（値が null の項目は送らない）</param>
        /// <returns>JsonResponse</returns>
        public Task<JsonResponse> TokenAsync(IDictionary<string, string> form)
        {
            return this.PostJsonAsync("/token", form);
        }

        /// <summary>UserInfoエンドポイントを呼ぶ</summary>
        /// <param name="accessToken">アクセス トークン</param>
        /// <returns>JsonResponse</returns>
        public async Task<JsonResponse> UserInfoAsync(string accessToken)
        {
            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, this.Absolute("/userinfo"));
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + accessToken);

            HttpResponseMessage res = await this._http.SendAsync(req);
            return await ToJsonResponseAsync(res);
        }

        /// <summary>Introspectionエンドポイントを呼ぶ</summary>
        /// <param name="form">フォーム</param>
        /// <returns>JsonResponse</returns>
        public Task<JsonResponse> IntrospectAsync(IDictionary<string, string> form)
        {
            return this.PostJsonAsync("/introspect", form);
        }

        /// <summary>Revocationエンドポイントを呼ぶ</summary>
        /// <param name="form">フォーム</param>
        /// <returns>JsonResponse</returns>
        public Task<JsonResponse> RevokeAsync(IDictionary<string, string> form)
        {
            return this.PostJsonAsync("/revoke", form);
        }

        /// <summary>
        /// 本文をそのままPOSTする（PARエンドポイントは text/plain で JWS を受ける）。
        /// </summary>
        /// <param name="pathOrUrl">パスまたはURL</param>
        /// <param name="body">本文</param>
        /// <returns>JsonResponse</returns>
        public async Task<JsonResponse> PostTextAsync(string pathOrUrl, string body)
        {
            StringContent content = new StringContent(body, Encoding.UTF8, "text/plain");
            HttpResponseMessage res = await this._http.PostAsync(this.Absolute(pathOrUrl), content);

            return await ToJsonResponseAsync(res);
        }

        /// <summary>JSONを返すエンドポイントをGETする</summary>
        /// <param name="pathOrUrl">パスまたはURL</param>
        /// <returns>JsonResponse</returns>
        public async Task<JsonResponse> GetJsonAsync(string pathOrUrl)
        {
            HttpResponseMessage res = await this.GetAsync(pathOrUrl);
            return await ToJsonResponseAsync(res);
        }

        /// <summary>JSONを返すエンドポイントをPOSTする</summary>
        /// <param name="pathOrUrl">パスまたはURL</param>
        /// <param name="form">フォーム</param>
        /// <returns>JsonResponse</returns>
        public async Task<JsonResponse> PostJsonAsync(
            string pathOrUrl, IDictionary<string, string> form)
        {
            HttpResponseMessage res = await this.PostFormAsync(pathOrUrl, form);
            return await ToJsonResponseAsync(res);
        }

        /// <summary>HttpResponseMessage を JsonResponse に変換する</summary>
        /// <param name="res">応答</param>
        /// <returns>JsonResponse</returns>
        public static async Task<JsonResponse> ToJsonResponseAsync(HttpResponseMessage res)
        {
            JsonResponse result = new JsonResponse();
            result.StatusCode = res.StatusCode;
            result.ContentType = (res.Content.Headers.ContentType == null)
                ? null : res.Content.Headers.ContentType.MediaType;
            result.Body = await res.Content.ReadAsStringAsync();

            // 応答ヘッダを拾う。Cache-Control のように、
            // 本文ではなくヘッダで確かめる項目がある（RFC 6749 §5.1）。
            result.Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, IEnumerable<string>> h in res.Headers)
            {
                result.Headers[h.Key] = string.Join(", ", h.Value);
            }

            foreach (KeyValuePair<string, IEnumerable<string>> h in res.Content.Headers)
            {
                result.Headers[h.Key] = string.Join(", ", h.Value);
            }

            try
            {
                using (JsonDocument doc = JsonDocument.Parse(result.Body))
                {
                    result.Json = doc.RootElement.Clone();
                    result.IsJson = true;
                }
            }
            catch (JsonException)
            {
                result.IsJson = false;
            }

            return result;
        }

        #endregion

        #region 自己テスト（/Home/Saml2OAuth2Starters）

        /// <summary>
        /// アプリに同梱の自己テスト（OAuth2Starters）を起動する。
        ///
        /// 24 通りのフローが submit.&lt;名前&gt; 1 つで起動できるので、
        /// FAPI2 の Request Object のように組み立てが複雑なフローは、これで駆動する。
        /// </summary>
        /// <param name="submitButton">submit. を除いたボタン名（AuthorizationCodeFAPI2 など）</param>
        /// <param name="clientType">normal / fapi1 / fapi2 / device / fapi_ciba（空はログイン ユーザ）</param>
        /// <param name="clarifyRedirectUri">認可リクエストに redirect_uri を明示するか</param>
        /// <param name="responseMode">response_mode（既定は空）</param>
        /// <returns>応答（リダイレクトは追跡しない）</returns>
        public async Task<HttpResponseMessage> StartSelfTestAsync(
            string submitButton, string clientType = "normal",
            bool clarifyRedirectUri = true, string responseMode = "")
        {
            HttpResponseMessage get = await this.GetAsync("/Home/Saml2OAuth2Starters");
            string html = await get.Content.ReadAsStringAsync();

            Match m = AntiforgeryRegex.Match(html);

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "ClientType", clientType },
                { "ClarifyRedirectUri", clarifyRedirectUri ? "true" : "false" },
                { "ResponseMode", responseMode },
                { "submit." + submitButton, submitButton }
            };

            if (m.Success)
            {
                form.Add("__RequestVerificationToken", m.Groups["value"].Value);
            }

            return await this.PostFormAsync("/Home/Saml2OAuth2Starters", form);
        }

        #endregion

        #region クエリ文字列

        /// <summary>
        /// クエリ文字列を組み立てる。
        /// 値が null の項目は出力しない（空文字列は "key=" として出力する）。
        /// </summary>
        /// <param name="parameters">パラメタ</param>
        /// <returns>クエリ文字列</returns>
        public static string BuildQuery(IDictionary<string, string> parameters)
        {
            StringBuilder sb = new StringBuilder();

            foreach (KeyValuePair<string, string> p in parameters)
            {
                if (p.Value == null)
                {
                    continue;
                }

                if (sb.Length > 0)
                {
                    sb.Append('&');
                }

                sb.Append(Uri.EscapeDataString(p.Key));
                sb.Append('=');
                sb.Append(Uri.EscapeDataString(p.Value));
            }

            return sb.ToString();
        }

        /// <summary>クエリ文字列を辞書に取り込む</summary>
        /// <param name="query">? や # を除いたクエリ文字列</param>
        /// <param name="into">格納先</param>
        public static void ParseInto(string query, IDictionary<string, string> into)
        {
            foreach (string pair in query.Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }

                int eq = pair.IndexOf('=');

                if (eq < 0)
                {
                    into[Uri.UnescapeDataString(pair)] = "";
                }
                else
                {
                    into[Uri.UnescapeDataString(pair.Substring(0, eq))] =
                        Uri.UnescapeDataString(pair.Substring(eq + 1).Replace("+", "%20"));
                }
            }
        }

        #endregion
    }
}
