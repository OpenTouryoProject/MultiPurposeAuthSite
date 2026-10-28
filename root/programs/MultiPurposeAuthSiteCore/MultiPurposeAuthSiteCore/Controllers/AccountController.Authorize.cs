//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の 認可エンドポイント
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//*  2026/10/25  玄人 幸道         auth で同意画面を飛ばすのを、登録に明記したクライアントだけにした（#294）
//**********************************************************************************

/*
 * OAuth 2.0 / OIDC の認可エンドポイント
 * （要求の検証、max_age・prompt・同意、認可応答の返し方（Response Mode / JARM））と、
 * Device Authorization Grant の利用者コードの確認画面を担うAccountControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の 認可エンドポイント**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region Authorize（認可エンドポイント）

        #region max_age & auth_time

        // **max_age の判定は CommonLibrary へ移した**（#247。`CmnEndpoints.CheckAuthTime`）。
        // bool では「再認証」「login_required」「invalid_request」を区別できなかった。

        /// <summary>auth_timeを追加</summary>
        /// <param name="max_age">string</param>
        /// <param name="claims">JObject（Request Object の claims（無ければ null））</param>
        /// <param name="identity">ClaimsIdentity（認証Cookieから取得）</param>
        /// <remarks>
        /// max_age か claims で求められたときだけ、auth_time のクレームを足す。
        /// 最終的に、access_token と id_token の payload に出る。
        /// </remarks>
        private void AddAuthTimeClaim(string max_age, JObject claims, ClaimsIdentity identity)
        {
            // QueryString、Cookieなどに関連するのでController側で追加。
            // **auth_time を載せるのは、要求されたときだけ**（OIDC Core 2）。
            // - max_age が指定された（RP が「いつ認証したか」を確かめる）
            // - claims パラメタで id_token の auth_time を求められた（OIDC Core 5.5）
            if (!string.IsNullOrEmpty(max_age) || (claims != null
                && claims.ContainsKey(OAuth2AndOIDCConst.claims_id_token)
                && ((JObject)claims[OAuth2AndOIDCConst.claims_id_token]).ContainsKey(OAuth2AndOIDCConst.auth_time)))
            {
                // **前回の認証時刻は Cookie から読む**
                // サインイン時（InitSessionAfterlogin）と、ManageController でパスワードを確かめた時・サインインし直した時に、
                // W3C 形式の UTC で書いてある。
                IRequestCookieCollection requestCookies = MyHttpContext.Current.Request.Cookies;
                string auth_time = requestCookies.Get(Config.AuthTimeCookieName);

                // 「次回から自動的にサインイン」にチェックを入れてサインインし、ブラウザを閉じてから開き直した場合。
                // 認証 Cookie は残っているが、認証時刻 Cookie は消えている（そういう経路がある）。
                if (string.IsNullOrEmpty(auth_time))
                {
                    // AuthTimeCookie が無ければ、最小値で埋める（認証時刻が分からない）。
                    auth_time = DateTimeOffset.MinValue.ToString();
                }

                // **クレームとして持たせる**（値は W3C 形式）。
                // CmnAccessToken がこのクレームを拾い、access_token と id_token の auth_time にする。
                identity.AddClaim(new Claim(
                    OAuth2AndOIDCConst.UrnAuthTimeClaim,
                    FormatConverter.ToW3cTimestamp(DateTime.Parse(auth_time))));
            }
        }

        #endregion

        #region sid（OpSession）

        /// <summary>OpSessionの識別子を Cookie から読む</summary>
        /// <returns>OpSessionの識別子（Cookie が無ければ空）</returns>
        private string GetOpSession()
        {
            return MyHttpContext.Current.Request.Cookies.Get(Config.OpSessionCookieName) ?? "";
        }

        /// <summary>OpSessionの識別子をCookieに書く</summary>
        /// <param name="sessionId">Sessionの識別子</param>
        /// <remarks>**期限を付けない**（Session Cookie）。**ブラウザを閉じれば終わる。**</remarks>
        private void SetOpSessionCookie(string sessionId)
        {
            MyHttpContext.Current.Response.Cookies.Set(
                Config.OpSessionCookieName, sessionId, this._cookieOptions);
        }

        /// <summary>
        /// OpSessionの識別子が無ければ、作って送り返す。
        /// </summary>
        /// <returns>
        /// ある場合 null（呼び出し元は継続）。
        /// ない場合、作成してRedirectResult。同時に来た要求で識別子がずれるのを防ぐ。
        /// </returns>
        /// <remarks>
        /// **Cookie が無いまま認可要求が同時に来ると、別々の識別子ができ、片方が台帳に残る。**
        /// **先に Cookie を置いて送り返せば、同じ識別子で戻ってくる。**
        /// </remarks>
        private ActionResult EnsureOpSession()
        {
            // OpSessionがある場合は、何もしない。
            if (!string.IsNullOrEmpty(this.GetOpSession()))
            {
                return null;
            }

            // 既に 1 回送り返している場合も、何もしない。
            // 1.送り返したのに、ブラウザが Cookie を戻さない（本来の想定）
            // 2.最初から URL に印が付いている（送り返していないのに）
            if (!string.IsNullOrEmpty(HttpUtility.ParseQueryString(
                Request.QueryString.Value)[Const.OpSessionRetry]))
            {
                // 続けても失うのは「ログアウト補助」だけで、認証の安全性は下がらない。
                return null;
            }

            // OpSessionの識別子を作って
            this.SetOpSessionCookie(Guid.NewGuid().ToString("N"));

            // 印を付けて、元の URL へ送り返す（ブラウザは Cookie を受け取ってから戻ってくる）
            string url = UriHelper.GetEncodedUrl(Request);
            return new RedirectResult(url + (url.Contains("?") ? "&" : "?") + Const.OpSessionRetry + "=1");
        }

        /// <summary>OpSessionを終わらせる</summary>
        /// <returns>
        /// **ブラウザ経由で伝える先**（`iframe` に入れる URL）。
        /// **1 件も無ければ空** — **そのときは画面を挟まない。**
        /// </returns>
        /// <remarks>
        /// **サインアウトの前に呼ぶ。** **伝えて、台帳を消し、Cookie を落とす**。
        /// **伝えるのが先である** — **台帳を消すと、誰に伝えるかが分からなくなる。**
        ///
        /// | 伝え方 | ここで何をするか |
        /// |---|---|
        /// | **Back-Channel** | **サーバから POST する**（背景。**待たない**） |
        /// | **Front-Channel** | **URL を作って返すだけ。** **開くのはブラウザ**（`iframe`） |
        ///
        /// **呼ばれるのはサインアウトの 5 か所**
        /// （`/Account/Logout` / `/end_session` / `prompt=login` の再認証 / `max_age` の再認証 / 別のアカウントでログイン）。
        /// **どれも「OpSessionが終わる」場面**なので、**同じ扱いでよい。**
        /// </remarks>
        private List<string> ClearOpSession()
        {
            string sessionId = this.GetOpSession();
            List<string> iframeUrls = new List<string>();

            if (!string.IsNullOrEmpty(sessionId))
            {
                // **先に伝える**（#310）。
                // BackChannelLogout
                Sts.BackChannelLogout.NotifyBySession(sessionId);
                // FrontChannelLogout
                iframeUrls = Sts.FrontChannelLogout.GetIframeUrls(sessionId);

                // 台帳を消す
                Sts.SessionClientProvider.DeleteBySession(sessionId);
            }

            // OpSession の Cookie を落とす
            MyHttpContext.Current.Response.Cookies.Delete(Config.OpSessionCookieName);

            return iframeUrls;
        }

        /// <summary>sidを追加</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="identity">ClaimsIdentity（認証Cookieから取得）</param>
        /// <remarks>
        /// **Cookie に関わるので Controller 側で追加**（`AddAuthTimeClaim` と同じ理由）。
        /// **値を決めるのは CommonLibrary**（`SessionClientProvider`） —
        /// **クライアント毎に別の sid** を、台帳から引く（無ければ作る）。
        ///
        /// **呼ぶのは「code / token を実際に作る直前」である**。
        /// **同意画面を出しただけの相手・拒否された相手を、台帳に残さないため**である
        /// （**残すと、トークンを一度も受けていない RP へログアウトを伝え、
        /// その RP に「この利用者が来た」ことを教えてしまう**）。
        ///
        /// **Cookie は `EnsureOpSession` が用意する**（**認可の口の入口で呼ぶ**）。
        /// **それでも無ければ、ここで作る** — **同意応答（POST）は送り返せない**ため。
        /// **「次回から自動的にサインイン」で認証 Cookie だけが残っている**ことも在り、
        /// **そのときもセッションとして扱う。**
        ///
        /// **台帳に入れられない経路では、クレームを付けない**（**嘘の値を出さない**）。
        /// </remarks>
        private void AddSidClaim(string client_id, ClaimsIdentity identity)
        {
            // OpSessionからIDを取得
            string sessionId = this.GetOpSession();

            // OpSessionIDが無ければ、作ってCookieに置く。
            if (string.IsNullOrEmpty(sessionId))
            {
                sessionId = Guid.NewGuid().ToString("N");
                this.SetOpSessionCookie(sessionId);
            }

            // **クライアント毎に別の sid** を、台帳から引く（無ければ作る）。
            string sid = Sts.SessionClientProvider.GetOrCreateSid(
                sessionId, client_id, identity.Name);

            // **sid をクレームとして持たせる**。
            if (!string.IsNullOrEmpty(sid))
            {
                identity.AddClaim(new Claim(Const.UrnSidClaim, sid));
            }
        }

        /// <summary>Front-Channel Logout の画面を返す（#310）</summary>
        /// <param name="iframeUrls">`iframe` に入れる URL</param>
        /// <param name="continueUrl">`iframe` を並べた画面（親）が、その後に進む先（`iframe` の中は進まない）</param>
        /// <returns>画面（**伝える先が 1 件も無ければ null**）</returns>
        /// <remarks>
        /// **1 件も無ければ null を返す** — **呼び出し側がリダイレクトで終える。**
        /// **登録している RP が無い配備では、画面が増えない**（**応答も変わらない**）。
        ///
        /// **進む先は、呼び出し側が決める。**
        ///
        /// | 呼び出し元 | 場面 | 進む先 |
        /// |---|---|---|
        /// | `EndSession`（`/end_session`） | RP-Initiated Logout | **`post_logout_redirect_uri`**（登録と一致したもの。無ければ Home） |
        /// | `Logout`（`/Account/Logout`） | OP の画面でのサインアウト | Home |
        /// | `OAuth2Authorize` | 認可の途中のサインアウト（`max_age` 超過・`prompt=login`・別アカウント） | **同じ認可要求の URL**（サインインし直して、**認可を続ける**） |
        ///
        /// **外から渡された URL は、ここへ来ない（オープン リダイレクタにしない）。**
        /// **`post_logout_redirect_uri` は登録と完全一致を確かめた後の値**で、**他は自分の URL** である。
        /// </remarks>
        private ActionResult FrontChannelLogoutView(List<string> iframeUrls, string continueUrl)
        {
            if (iframeUrls == null || iframeUrls.Count == 0)
            {
                return null;
            }

            // iframe で、各 RP の frontchannel_logout_uri を開く（iss と sid を付けて）。
            // ブラウザが RP の Cookie を付けて送るので、RP は自分のセッションを閉じられる。
            ViewBag.IframeUrls = iframeUrls;

            // iframe を並べた画面（親）が、その後に進む先（進む先は呼び出し側が決める。remarks の表）
            ViewBag.ContinueUrl = continueUrl;

            return View("FrontChannelLogout");
        }

        #endregion

        #region エンドポイント自体
        /// <summary>認可エンドポイント</summary>
        /// <param name="client_id">string（必須）</param>
        /// <param name="redirect_uri">string（任意）</param>
        /// <param name="response_type">string（必須）</param>
        /// <param name="response_mode">string（任意）</param>
        /// <param name="scope">string（任意）</param>
        /// <param name="state">string（推奨）</param>
        /// <param name="nonce">string（OIDC 推奨）</param>
        /// <param name="max_age">string（OIDC 任意）</param>
        /// <param name="prompt">string（OIDC 任意）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        /// <remarks>
        /// **[AllowAnonymous] にしてある**（#254）。
        /// **`prompt=none` のときは UI を出さず、`login_required` を RP へ返す**必要があり
        /// （OIDC Core 3.1.2.1 / 3.1.2.6）、**[Authorize] のままでは、
        /// Cookie 認証がこのコードに入る前にサインイン画面へ飛ばしてしまう。**
        ///
        /// **未認証のときの扱いは、このメソッドの中で決める。**
        /// `prompt=none` でなければ `ChallengeResult` を返す（[Authorize] と同じ動き）。
        ///
        /// **判定は `redirect_uri` の照合（ValidateAuthZReqParam）より後で行う。**
        /// **照合前に RP へ返すと、オープン リダイレクトになる。**
        /// </remarks>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce, string max_age, string prompt) // OpenID Connect
        // Request.QueryStringで直接参照
        // - string code_challenge, string code_challenge_method) // OAuth PKCE
        // - string request_uri // FAPI2 : RequestObject
        {
            string valid_redirect_uri = ""; 
            string err = "";
            string errDescription = "";

            JObject claims = null;

            // code_challenge（PKCE必須かの確認に使う）と request_uri は、クエリ文字列から読む。
            // request_uri で Request Object が引ければ、各パラメタ（code_challenge を含む）をその値で上書きする
            // （無ければクエリ文字列のまま）。
            
            // **クエリ文字列は、デコードされた値で読む**（パーセント エンコードされた request_uri（urn:... のコロン）を取りこぼさないため）。
            
            string code_challenge = Request.Query[OAuth2AndOIDCConst.code_challenge];
            string request_uri = Request.Query[OAuth2AndOIDCConst.request_uri];
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                // 存在しないrequest_uriではnullになる（#185）。
                // その場合は上書きせず、後続のValidateAuthZReqParamでエラーにする。
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                if (requestObjectPayload != null)
                {
                    client_id = (string)requestObjectPayload[OAuth2AndOIDCConst.client_id];
                    redirect_uri = (string)requestObjectPayload[OAuth2AndOIDCConst.redirect_uri];
                    response_type = (string)requestObjectPayload[OAuth2AndOIDCConst.response_type];
                    response_mode = (string)requestObjectPayload[OAuth2AndOIDCConst.response_mode];
                    scope = (string)requestObjectPayload[OAuth2AndOIDCConst.scope];
                    state = (string)requestObjectPayload[OAuth2AndOIDCConst.state];
                    nonce = (string)requestObjectPayload[OAuth2AndOIDCConst.nonce];
                    max_age = (string)requestObjectPayload[OAuth2AndOIDCConst.max_age];
                    prompt = (string)requestObjectPayload[OAuth2AndOIDCConst.prompt];
                    claims = (JObject)requestObjectPayload[OAuth2AndOIDCConst.claims];
                    code_challenge = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge];
                }
            }

            // **要求の検証を先に行う**（#247）。`redirect_uri` を照合できていないと、エラーを RP へ返せない。
            if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription, code_challenge, prompt))
            {
                // **max_age と auth_time の照合**（判定は CommonLibrary）。
                OAuth2AndOIDCEnum.AuthTimeCheck authTimeCheck = Token.CmnEndpoints.CheckAuthTime(
                    max_age,
                    MyHttpContext.Current.Request.Cookies.Get(Config.AuthTimeCookieName),
                    MyHttpContext.Current.Request.Cookies.Get(Config.ReAuthenticatedAtCookieName));

                if (authTimeCheck == OAuth2AndOIDCEnum.AuthTimeCheck.InvalidMaxAge)
                {
                    // **0 以上の整数でない**（RFC 6749 4.1.2.1 : invalid_request）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "max_age must be a non-negative integer.";
                }
                else if (!this.User.Identity.IsAuthenticated)
                {
                    // **そもそもサインインしていない**（OIDC Core 3.1.2.6 : login_required）。
                    if (OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptNone))
                    {
                        // **prompt=none では UI を出せない**
                        err = OAuth2AndOIDCConst.login_required;
                        errDescription = "The end-user is not authenticated, but prompt=none was specified.";
                    }
                    else
                    {
                        // **サインイン画面へ送る**。
                        //   ChallengeResult は 401 を返し、Cookie 認証が LoginPath へのリダイレクトに変える。
                        return new ChallengeResult();
                    }
                }
                else if (authTimeCheck == OAuth2AndOIDCEnum.AuthTimeCheck.NeedsReAuthentication)
                {
                    // **再認証する**（OIDC Core 3.1.2.1）。
                    if (OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptNone))
                    {
                        // **prompt=none では UI を出せない**
                        err = OAuth2AndOIDCConst.login_required;
                        errDescription = "Re-authentication is required, but prompt=none was specified.";
                    }
                    else
                    {
                        // 印を残してサインアウトし、同じ URL に戻す（この後は認証が要るのでサインイン画面になる）。
                        // **印は繰り返しを防ぐため**（max_age=0 でも、再認証の直後なら続ける）。
                        MyHttpContext.Current.Response.Cookies.Set(Config.ReAuthenticatedAtCookieName,
                            FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);

                        // OpSessionを終わらせる（入り直すと新しい sid になる）
                        List<string> iframeUrlsForMaxAge = this.ClearOpSession();

                        // **SignInManager でサインアウトする。**
                        // `HttpContext.SignOutAsync()` では、Cookie（Identity.Application）が消えず、
                        // 次の要求でも認証済みのままだった（実測）。既存の Logout も SignInManager を使っている。
                        await this.SignInManager.SignOutAsync();

                        // **ブラウザ経由で伝えてから、同じ URL へ進む**（#310）。
                        ActionResult frontChannelForMaxAge = this.FrontChannelLogoutView(
                            iframeUrlsForMaxAge, UriHelper.GetEncodedUrl(Request));
                        if (frontChannelForMaxAge != null) { return frontChannelForMaxAge; }
                        else { return new RedirectResult(UriHelper.GetEncodedUrl(Request)); }
                    }
                }
                else if (OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptLogin)
                    && string.IsNullOrEmpty(MyHttpContext.Current.Request.Cookies.Get(Config.ReAuthenticatedAtCookieName)))
                {
                    // **prompt=login は、再認証を求める**（OIDC Core §3.1.2.1。#272）。
                    // **印が無いときだけ再認証する**（印は繰り返しを防ぐため）。
                    //   戻ってきた要求にも prompt=login が付いているので、印が無いと永久に送り返す。
                    //   印は、認可を続ける所（else）で消す。次の新しい要求の prompt=login は、また再認証になる。
                    MyHttpContext.Current.Response.Cookies.Set(Config.ReAuthenticatedAtCookieName,
                        FormatConverter.ToW3cTimestamp(DateTime.UtcNow), this._cookieOptions);

                    // **OpSessionを終わらせる**（入り直すと新しい sid になる）
                    List<string> iframeUrlsForPromptLogin = this.ClearOpSession();
                    await this.SignInManager.SignOutAsync();

                    // **ブラウザ経由で伝えてから、同じ URL へ進む**（#310）。
                    ActionResult frontChannelForPromptLogin = this.FrontChannelLogoutView(
                        iframeUrlsForPromptLogin, UriHelper.GetEncodedUrl(Request));
                    if (frontChannelForPromptLogin != null) { return frontChannelForPromptLogin; }
                    else { return new RedirectResult(UriHelper.GetEncodedUrl(Request)); }
                }
                else
                {
                    // **OpSessionの識別子を用意する**（#310）。
                    //   **無ければ Cookie を置いて、同じ URL へ送り返す**（同時に来た要求を 1 つの識別子に揃えるため）。
                    ActionResult ensured = this.EnsureOpSession();
                    if (ensured != null) return ensured;

                    // Cookie認証チケットからClaimsPrincipalを取得しておく。
                    AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
                    ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

                    // ClaimsIdentityを生成
                    ClaimsIdentity identity = new ClaimsIdentity(
                        principal.Claims, OAuth2AndOIDCConst.Bearer,
                        ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                    // **再認証の印を消す** 一度きりの印なので、ここまで来たら落とす。
                    MyHttpContext.Current.Response.Cookies.Delete(Config.ReAuthenticatedAtCookieName);

                    // auth_timeを追加
                    this.AddAuthTimeClaim(max_age, claims, identity);

                    // scopeパラメタ
                    string[] scopes = (scope ?? "").Split(' ');

                    if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                    {
                        // OAuth2/OIDC Authorization Code
                        ViewBag.Name = principal.Identity.Name;
                        ViewBag.Scopes = scopes;

                        // **認可画面で「何を確かめるのか」を出すための値**（#246 の項目 3）。
                        //   画面側は、自己テストを閉じている配置では出さない（項目 4 の線引き）。
                        ViewBag.ClientId = client_id;
                        ViewBag.ResponseType = response_type;
                        ViewBag.ResponseMode = response_mode;
                        ViewBag.ValidRedirectUri = valid_redirect_uri;
                        ViewBag.Prompt = prompt;
                        ViewBag.MaxAge = max_age;
                        ViewBag.RequestUri = request_uri;
                        ViewBag.HasState = !string.IsNullOrEmpty(state);
                        ViewBag.HasNonce = !string.IsNullOrEmpty(nonce);
                        ViewBag.HasClaims = (claims != null);

                        // 認証の場合、余計なscopeをfilterする。
                        //   **`auth` は、登録に明記したクライアントの要求だけを数える**（#294）。
                        //   Keycloak の Consent Required のオフや、Auth0 の first-party の同意を飛ばすと同じ考え方。
                        //   **要求に付けただけでは、同意画面を飛ばせない**（飛ばすかは、登録を管理する人が決める）。
                        //   **scope は case-sensitive**（RFC 6749 §3.3）なので、小文字化しない。
                        bool isAuth = Sts.Helper.FilterSupportedScopes(scopes, client_id)
                            .Contains(OAuth2AndOIDCConst.Scope_Auth);

                        if (string.IsNullOrWhiteSpace(prompt)) prompt = "";

                        #region 同意の判定
                        //   | 状況 | ここでの扱い |
                        //   |---|---|
                        //   | scope に `auth`（独自の認証用。**登録に明記したクライアントだけ**） | **飛ばす**（同意を求める対象でない） |
                        //   | 要求 scope が記録の部分集合 | **飛ばす** |
                        //   | `prompt=consent` | **記録が在っても出す**（§3.1.2.1） |
                        //   | `prompt=select_account` | **出す**（画面に「別のアカウントでログイン」が在る） |
                        //   | 記録が無い ＋ `prompt=none` | **`consent_required`**（§3.1.2.6。UI を出せない） |
                        //   | 記録が無い | 同意画面を出す |

                        string userId = this.UserManager.GetUserId(this.User);

                        // この要求の scope を、前に同意しているか
                        bool hasConsent = Sts.ConsentProvider.HasConsent(userId, client_id, scopes);
                        // RP が同意画面（consent）か、同意画面でのアカウントの選択（select_account）を求めている。
                        bool asksConsent = OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptConsent)
                                           || OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptSelectAccount);

                        #endregion

                        if (isAuth                              // 認可画面スキップの独自仕様
                            || (hasConsent && !asksConsent))    // または、同意済みで、取り直しを求められていない
                        {
                            // 認可画面をスキップ

                            // ★ 必要に応じてスコープのフィルタ
                            if (isAuth)
                            {
                                scopes = Sts.Helper.FilterClaimAtAuth(scopes).ToArray();
                            }

                            // **sid を足す**（#310。**発行の直前で台帳に書く**）
                            this.AddSidClaim(client_id, identity);

                            // ★ Codeの生成
                            string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                                client_id, state, scopes, claims, nonce);

                            // RedirectエンドポイントへCodeをRedirect
                            ActionResult actionResult = this.RedirectCode(
                                client_id, response_mode, valid_redirect_uri, code, state);
                            if (actionResult != null) return actionResult;
                        }
                        else if (OAuth2AndOIDCSpec.HasPrompt(
                            prompt, OAuth2AndOIDCConst.PromptNone))
                        {
                            // 同意画面を出す必要があるが、prompt=none（UI を出せない）。

                            // **UI を出せないので、エラーを RP へ返す**
                            //   （OIDC Core §3.1.2.6 : consent_required。#272）。
                            //   **ここで同意を飛ばすと、セッションが生きていれば
                            //   どのクライアントも無音で認可を取れる**（C-3）。
                            err = OAuth2AndOIDCConst.consent_required;
                            errDescription = "Consent is required, but prompt=none was specified.";
                        }
                        else
                        {
                            // 認可画面を表示
                            return View();
                        }
                    }
                    else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType)
                    {
                        // OAuth2/OIDC Implicit

                        // **sid を足す**（#310。**発行の直前で台帳に書く**）
                        this.AddSidClaim(client_id, identity);

                        // ★ Tokenの生成
                        Token.CmnEndpoints.CreateAuthZRes4ImplicitFlow(
                            identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                            response_type, client_id, state, scopes, claims, nonce,
                            out string access_token, out string id_token);

                        // RedirectエンドポイントへTokenをRedirect
                        ActionResult actionResult = this.RedirectToken(
                            client_id, response_mode, response_type, valid_redirect_uri,
                            access_token, id_token, state);
                        if (actionResult != null) return actionResult;
                    }
                    else if (response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                        || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                    {
                        // OIDC Hybrid Flow

                        // **sid を足す**（#310。**発行の直前で台帳に書く**）
                        this.AddSidClaim(client_id, identity);

                        // ★ Tokenの生成
                        string code = Token.CmnEndpoints.CreateAuthNRes4HybridFlow(
                            identity,
                            HttpUtility.ParseQueryString(Request.QueryString.Value),
                            client_id, state, scopes, claims, nonce,
                            out string access_token, out string id_token);

                        // RedirectエンドポイントへRedirect
                        ActionResult actionResult = this.RedirectCodeToken(
                            client_id, response_mode, response_type, valid_redirect_uri,
                            code, access_token, id_token, state);
                        if (actionResult != null) return actionResult;
                    }
                    else
                    {
                        // 不正なresponse_type
                    }
                }
            }
            else
            {
                // 不正なRequest
            }

            // ここまで来たらエラー。
            //   **障害対応のため、記録する**（#294）。**redirect_uri へ返したか、エラー画面か**も出す。
            Logging.MyOperationTrace(string.Format(Resources.Diagnostics.LogAuthorizeError,
                LogSanitizer.Sanitize(client_id), LogSanitizer.Sanitize(err),
                LogSanitizer.Sanitize(errDescription, Const.LogDetailMaxLength),
                string.IsNullOrEmpty(valid_redirect_uri)
                    ? Resources.Diagnostics.LogAuthorizeErrorToErrorPage : Resources.Diagnostics.LogAuthorizeErrorToRedirectUri));

            if (!string.IsNullOrEmpty(valid_redirect_uri))
            {
                // エラーのRedirect（valid_redirect_uriを使用する）
                // RFC 6749 4.1.2.1 : error / error_description、stateは要求にあれば返す（#187）
                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(valid_redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, err },
                        { OAuth2AndOIDCConst.error_description, errDescription },
                        { OAuth2AndOIDCConst.state, state }
                    }, false, CmnServerParams.IssuerId));
            }
            else
            {
                // エラー画面
                ViewData["Err"] = err;
                ViewData["ErrDescription"] = errDescription;
                return View("Error");
            }
        }

        /// <summary>
        /// 認可エンドポイント
        /// Authorization Codeグラント種別の権限付与画面の結果を受け取り、
        /// 仲介コードを発行してRedirectエンドポイントへRedirect。
        /// ※ パラメタは、認可レスポンスのURL中に残っているものを使用。
        /// </summary>
        /// <param name="client_id">string（必須）</param>
        /// <param name="redirect_uri">string（任意）</param>
        /// <param name="response_type">string（必須）</param>
        /// <param name="response_mode">string（任意）</param>
        /// <param name="scope">string（任意）</param>
        /// <param name="state">string（推奨）</param>
        /// <param name="nonce">string（OIDC 推奨）</param>
        /// <param name="max_age">string（OIDC 任意）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-req"/>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> OAuth2Authorize(
            string client_id, string redirect_uri,
            string response_type, string response_mode,
            string scope, string state,
            string nonce, string max_age) // OpenID Connect
        // Request.QueryStringで直接参照
        // - string code_challenge, string code_challenge_method) // OAuth PKCE
        // - string request_uri // FAPI2 : RequestObject
        {
            string prompt = ""; // ダミー
            JObject claims = null;

            // code_challenge（PKCE必須かの確認に使う）と request_uri は、クエリ文字列から読む。
            // request_uri で Request Object が引ければ、各パラメタ（code_challenge を含む）をその値で上書きする
            // （無ければクエリ文字列のまま）。

            // **クエリ文字列は、デコードされた値で読む**（パーセント エンコードされた request_uri（urn:... のコロン）を取りこぼさないため）。

            string code_challenge = Request.Query[OAuth2AndOIDCConst.code_challenge];
            string request_uri = Request.Query[OAuth2AndOIDCConst.request_uri];
            if (!string.IsNullOrEmpty(request_uri))
            {
                string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                // 存在しないrequest_uriではnullになる（#185）。
                // その場合は上書きせず、後続のValidateAuthZReqParamでエラーにする。
                JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

                if (requestObjectPayload != null)
                {
                    client_id = (string)requestObjectPayload[OAuth2AndOIDCConst.client_id];
                    redirect_uri = (string)requestObjectPayload[OAuth2AndOIDCConst.redirect_uri];
                    response_type = (string)requestObjectPayload[OAuth2AndOIDCConst.response_type];
                    response_mode = (string)requestObjectPayload[OAuth2AndOIDCConst.response_mode];
                    scope = (string)requestObjectPayload[OAuth2AndOIDCConst.scope];
                    state = (string)requestObjectPayload[OAuth2AndOIDCConst.state];
                    nonce = (string)requestObjectPayload[OAuth2AndOIDCConst.nonce];
                    max_age = (string)requestObjectPayload[OAuth2AndOIDCConst.max_age];
                    prompt = (string)requestObjectPayload[OAuth2AndOIDCConst.prompt];
                    claims = (JObject)requestObjectPayload[OAuth2AndOIDCConst.claims];
                    code_challenge = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge];
                }
            }

            if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out string valid_redirect_uri, out string err, out string errDescription,
                code_challenge, prompt))
            {
                // Cookie認証チケットからClaimsPrincipalを取得しておく。
                AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
                ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

                // ClaimsIdentityを生成
                ClaimsIdentity identity = new ClaimsIdentity(
                    principal.Claims, OAuth2AndOIDCConst.Bearer,
                    ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // auth_timeを追加
                this.AddAuthTimeClaim(max_age, claims, identity);

                // 次に、アクセス要求を保存して、仲介コードを発行する。

                // scopeパラメタ
                string[] scopes = (scope ?? "").Split(' ');

                if (!string.IsNullOrEmpty(MyHttpContext.Current.Request.Form["submit.Login"]))
                {
                    // 別のアカウントでログイン（サインアウトしてリダイレクト）

                    // OpSessionを終わらせる（入り直すと新しい sid になる）
                    List<string> iframeUrlsForSwitch = this.ClearOpSession();

                    // **SignInManager でサインアウトする。**
                    // `HttpContext.SignOutAsync()` では、Cookie（Identity.Application）が消えず、
                    // 次の要求でも認証済みのままだった（実測）。既存の Logout も SignInManager を使っている。
                    await this.SignInManager.SignOutAsync();

                    //  **ブラウザ経由で伝えてから、同じ URL へ進む**（#310）。
                    ActionResult frontChannelForSwitch = this.FrontChannelLogoutView(
                        iframeUrlsForSwitch, UriHelper.GetEncodedUrl(Request));
                    if (frontChannelForSwitch != null) return frontChannelForSwitch;

                    return new RedirectResult(UriHelper.GetEncodedUrl(Request));
                }
                else if (!string.IsNullOrEmpty(MyHttpContext.Current.Request.Form["submit.Deny"]))
                {
                    // **拒否した**（E-6 / #272）。
                    //   **RFC 6749 §4.1.2.1 : access_denied を redirect_uri へ返す。**
                    //   **記録は残さない**（「拒否した」を覚えて、
                    //   次回以降自動で断ることはしない。利用者が気を変えられなくなる）。
                    err = OAuth2AndOIDCConst.access_denied;
                    errDescription = "The resource owner denied the request.";
                }
                else if (!string.IsNullOrEmpty(MyHttpContext.Current.Request.Form["submit.Grant"]))
                {
                    // OAuth2/OIDC Authorization Code

                    // **sid を足す**（#310。**発行の直前で台帳に書く**）
                    this.AddSidClaim(client_id, identity);

                    // **同意を記録する**（#272 / D-6）。
                    //   **これが次回以降の `prompt=none` の判定の土台になる。**
                    //   **scope は足し込む**（増えた scope で同意し直しても、以前の分を失わない）。
                    Sts.ConsentProvider.Grant(
                        this.UserManager.GetUserId(this.User), client_id, scopes);

                    // ★ Codeの生成
                    string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                        identity, HttpUtility.ParseQueryString(Request.QueryString.Value),
                        client_id, state, scopes, claims, nonce);

                    // RedirectエンドポイントへCodeをRedirect
                    ActionResult actionResult = this.RedirectCode(
                        client_id, response_mode, valid_redirect_uri, code, state);
                    if (actionResult != null) return actionResult;
                }
                else
                {
                    // 不正な操作
                }
            }
            else
            {
                // 不正なRequest
            }

            if (string.IsNullOrEmpty(err))
            {
                // 再表示
                return View();
            }
            else if (!string.IsNullOrEmpty(valid_redirect_uri))
            {
                // エラーのRedirect（valid_redirect_uriを使用する）
                // RFC 6749 4.1.2.1 : error / error_description、stateは要求にあれば返す（#187）
                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(valid_redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, err },
                        { OAuth2AndOIDCConst.error_description, errDescription },
                        { OAuth2AndOIDCConst.state, state }
                    }, false, CmnServerParams.IssuerId));
            }
            else
            {
                // エラー画面
                ViewData["Err"] = err;
                ViewData["ErrDescription"] = errDescription;
                return View("Error");
            }
        }
        #endregion

        #region Redirect処理 (Response Mode & JARM)
        /// <summary>
        /// RedirectエンドポイントへCodeをRedirect
        /// </summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectCode(
            string client_id, string response_mode,
            string redirect_uri, string code, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            if (string.IsNullOrEmpty(response_mode) // 既定はqueryの意
                || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit())
            {
                // query
                return new RedirectResult(
                    OAuth2AndOIDCSpec.BuildRedirectUrl(
                        redirect_uri,
                        new Dictionary<string, string>()
                        {
                            { OAuth2AndOIDCConst.code, code },
                            { OAuth2AndOIDCConst.state, state }
                        },
                        false, CmnServerParams.IssuerId));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.jwt.ToStringByEmit()
                || response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit())
            {
                // jwt or query.jwt
                response = Token.CmnResponseObject.Create(
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.code , code },
                        { OAuth2AndOIDCConst.state,  state }
                    }, client_id, expiresUtc);

                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>() { { "response", response } },
                    false, CmnServerParams.IssuerId));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
            {
                // fragment
                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.code, code },
                        { OAuth2AndOIDCConst.state, state }
                    }, true, CmnServerParams.IssuerId));
            }
            else if (response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
            {
                // fragment.jwt
                response = Token.CmnResponseObject.Create(
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.code , code },
                        { OAuth2AndOIDCConst.state,  state }
                    }, client_id, expiresUtc);

                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>() { { "response", response } },
                    true, CmnServerParams.IssuerId));
            }
            else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
            {
                // form_post
                ViewData["Action"] = redirect_uri;
                ViewData["Code"] = code;
                ViewData["State"] = state;
                return View("FormPost");
            }
            else if (response_mode.ToLower().Replace('.', '_')
                == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
            {
                // form_post.jwt
                response = Token.CmnResponseObject.Create(
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.code , code },
                        { OAuth2AndOIDCConst.state,  state }
                    }, client_id, expiresUtc);

                ViewData["Action"] = redirect_uri;
                ViewData["Response"] = response;
                return View("FormPost");
            }
            else
            {
                // 不正な操作
                return null;
            }
        }

        /// <summary>
        /// RedirectエンドポイントへTokenをRedirect
        /// </summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="response_type">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="access_token">string</param>
        /// <param name="id_token">string</param>
        /// <param name="state">string</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectToken(
            string client_id, string response_mode, string response_type, string redirect_uri,
            string access_token, string id_token, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            // 補足
            // stateは、クライアントが指定した場合、基本的に必要になる。
            // access_tokenを返す場合、token_type, expires_inが必要になる。
            switch (response_type)
            {
                case OAuth2AndOIDCConst.ImplicitResponseType: // Token要求
                    if (string.IsNullOrEmpty(access_token))
                    {
                        // Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, null, null);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = Const.TokenTypeBearer;
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, null, null);

                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcImplicit1_ResponseType: // ID Token要求
                    if (string.IsNullOrEmpty(id_token))
                    {
                        // ID Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // ID Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.state,  state }
                                }, null, null);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["IDToken"] = id_token;
                            ViewData["State"] = state;
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.state,  state }
                                }, null, null);

                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcImplicit2_ResponseType: // ID Token & Token要求
                    if (string.IsNullOrEmpty(id_token) || string.IsNullOrEmpty(access_token))
                    {
                        // ID Token & Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // ID Token & Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, null, null);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["IDToken"] = id_token;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = Const.TokenTypeBearer;
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, null, null);

                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                default:
                    // queryはNG
                    return null;
            }
        }

        /// <summary>RedirectエンドポイントへCode & TokenをRedirect</summary>
        /// <param name="client_id">string</param>
        /// <param name="response_mode">string</param>
        /// <param name="response_type">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code">string</param>
        /// <param name="access_token">string</param>
        /// <param name="id_token">string</param>
        /// <param name="state">string</param>
        /// <returns></returns>
        private ActionResult RedirectCodeToken(
            string client_id, string response_mode, string response_type, string redirect_uri,
            string code, string access_token, string id_token, string state)
        {
            string response = ""; // JARM
            DateTimeOffset expiresUtc = this.CreateJarmExp();

            // 補足
            // stateは、クライアントが指定した場合、基本的に必要になる。
            // access_tokenを返す場合、token_type, expires_inが必要になる。
            switch (response_type)
            {
                case OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType: // Code & Token要求
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(access_token))
                    {
                        // Code & Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // Code & Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code , code },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, client_id, expiresUtc);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = Const.TokenTypeBearer;
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code , code },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, client_id, expiresUtc);

                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }

                    return null;

                case OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType: // Code & ID Token要求
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(id_token))
                    {
                        // Code & ID Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // Code & ID Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code , code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state }
                            }, client_id, expiresUtc);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["IDToken"] = id_token;
                            ViewData["State"] = state;
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(new Dictionary<string, string>()
                            {
                                { OAuth2AndOIDCConst.code,  code },
                                { OAuth2AndOIDCConst.IDToken , id_token },
                                { OAuth2AndOIDCConst.state,  state },
                            }, client_id, expiresUtc);
                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                case OAuth2AndOIDCConst.OidcHybrid3_ResponseType: // Code & ID Token & Token要求
                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(access_token) || string.IsNullOrEmpty(id_token))
                    {
                        // Code & ID Token & Tokenを発行できなかった
                        return CreateErrorResponseForToken(response_mode, redirect_uri, state);
                    }
                    else
                    {
                        // Code & ID Token & Tokenあり
                        if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                            || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
                        {
                            // fragment
                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code, code },
                                    { OAuth2AndOIDCConst.AccessToken, access_token },
                                    { OAuth2AndOIDCConst.IDToken, id_token },
                                    { OAuth2AndOIDCConst.state, state },
                                    { OAuth2AndOIDCConst.token_type, Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                        {
                            // fragment.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code , code },
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, client_id, expiresUtc);

                            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                                redirect_uri,
                                new Dictionary<string, string>() { { "response", response } },
                                true, CmnServerParams.IssuerId));
                        }
                        else if (response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
                        {
                            // form_post
                            ViewData["Action"] = redirect_uri;
                            ViewData["Code"] = code;
                            ViewData["IDToken"] = id_token;
                            ViewData["AccessToken"] = access_token;
                            ViewData["State"] = state;
                            ViewData["TokenType"] = Const.TokenTypeBearer;
                            ViewData["ExpiresIn"] = ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString();
                            return View("FormPost");
                        }
                        else if (response_mode.ToLower().Replace('.', '_')
                            == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                        {
                            // form_post.jwt
                            response = Token.CmnResponseObject.Create(
                                new Dictionary<string, string>()
                                {
                                    { OAuth2AndOIDCConst.code , code },
                                    { OAuth2AndOIDCConst.IDToken , id_token },
                                    { OAuth2AndOIDCConst.AccessToken , access_token },
                                    { OAuth2AndOIDCConst.state,  state },
                                    { OAuth2AndOIDCConst.token_type , Const.TokenTypeBearer },
                                    { OAuth2AndOIDCConst.expires_in , ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString() }
                                }, client_id, expiresUtc);

                            ViewData["Action"] = redirect_uri;
                            ViewData["Response"] = response;
                            return View("FormPost");
                        }
                    }
                    return null;

                default:
                    // queryはNG
                    return null;
            }
        }

        /// <summary>CreateJarmExp</summary>
        /// <returns>DateTimeOffset</returns>
        private DateTimeOffset CreateJarmExp()
        {
            return DateTimeOffset.Now.AddMinutes(10);
        }

        /// <summary>CreateErrorResponseForToken</summary>
        /// <param name="response_mode">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="state">string</param>
        private ActionResult CreateErrorResponseForToken(
            string response_mode, string redirect_uri, string state)
        {
            string response = "";

            if (string.IsNullOrEmpty(response_mode) // 既定はfragmentの意
                || response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit())
            {
                // fragment
                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied },
                        { OAuth2AndOIDCConst.state, state }
                    }, true, CmnServerParams.IssuerId));
            }
            else if(response_mode.ToLower().Replace('.', '_') == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
            {
                // fragment.jwt
                response = Token.CmnResponseObject.Create(
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error , OAuth2AndOIDCConst.access_denied },
                        { OAuth2AndOIDCConst.state,  state }
                    }, null, null);

                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>() { { "response", response } },
                    true, CmnServerParams.IssuerId));
            }
            else if(response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit())
            {
                // form_post
                ViewData["Action"] = redirect_uri;
                ViewData["Error"] = OAuth2AndOIDCConst.access_denied;
                ViewData["State"] = state;
                return View("FormPost");
            }
            else if(response_mode.ToLower() == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
            {
                // form_post.jwt
                response = Token.CmnResponseObject.Create(
                    new Dictionary<string, string>()
                    {
                        { OAuth2AndOIDCConst.error , OAuth2AndOIDCConst.access_denied },
                        { OAuth2AndOIDCConst.state,  state }
                    }, null, null);

                ViewData["Action"] = redirect_uri;
                ViewData["Response"] = response;
                return View("FormPost");
            }

            // queryはNG
            return null;
        }

        #endregion

        #endregion

        #region Device AuthZ
        /// <summary>
        /// DeviceAuthZVerify画面（初期表示）
        /// GET: /device_verify
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult DeviceAuthZVerify()
        {
            ViewBag.ReceiveResult = false;
            ViewBag.UserCode = UriOperator.GetParameterFromQueryString(
                OAuth2AndOIDCConst.user_code, Request.GetEncodedUrl());

            return View("DeviceAuthZVerify");
        }

        /// <summary>
        /// DeviceAuthZVerify画面
        /// POST: /device_verify
        /// </summary>
        /// <param name="formData">IFormCollection</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        public ActionResult DeviceAuthZVerify(IFormCollection formData)
        {
            ViewBag.ReceiveResult = false;

            if (formData != null)
            {
                string userCode = formData[OAuth2AndOIDCConst.user_code];
                string failureKey = Sts.AuthFailureProvider.DeviceVerifyKey(User.Identity.Name);

                //  **続けて間違えている利用者は、断る**（#305。RFC 8628 §5.2）。
                //    **間違えた `user_code` では、どの要求を狙ったか分からない**ので、
                //    **投入した人で数える。**
                //    **断っている間は、正しい `user_code` でも通さない。**
                if (Sts.AuthFailureProvider.IsLockedOut(failureKey))
                {
                    ViewBag.ReceiveResult = false;
                }
                else
                {
                    ViewBag.ReceiveResult = Sts.DeviceAuthZProvider.ReceiveResult(userCode, User.Identity.Name, formData.ContainsKey("allow"));

                    if (ViewBag.ReceiveResult)
                    {
                        Sts.AuthFailureProvider.Clear(failureKey);
                    }
                    else
                    {
                        Sts.AuthFailureProvider.Record(failureKey);
                    }
                }
            }
            
            return View("DeviceAuthZVerify");
        }
        #endregion
    }
}
