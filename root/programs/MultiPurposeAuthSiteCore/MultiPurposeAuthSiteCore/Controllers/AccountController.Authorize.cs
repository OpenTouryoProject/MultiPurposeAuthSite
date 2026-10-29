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
//*  2026/10/28  玄人 幸道         /device_verify の CSRF、Implicit・Hybrid の同意、auth_time・再認証の印の改ざん、
//*                                JARM の aud・exp、response_mode の扱い、Request Object の client_id を直した。
//*                                応答の組み立てを 1 か所にまとめ、本文を両版で同じにした（#294）
//*  2026/10/29  玄人 幸道         OpSession と /device_verify の初期表示も、補助を使って両版で同じ本文にした（#294）
//*  2026/10/30  玄人 幸道         auth_time を書く所の注を直した（管理画面の再サインインでは書かない。#294）
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
using System.Collections.Specialized;
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
        #region Authorize

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
                // **前回の認証時刻は Cookie から読む**（**改ざんできない形で包んである**。#294。`Sts.AuthTimeCookie`）。
                // サインイン時（InitSessionAfterlogin）と、ManageController で資格情報を確かめた時（パスワードの再確認・変更、外部ログインの結び付け）に書く。
                // **サインインし直しただけでは書かない**（#294。資格情報を確かめていないので、認証したことにはならない）。
                // **以前は平文の Cookie で、ブラウザ側で書き換えると、偽の auth_time を RP に保証していた。**
                string auth_time = this.ReadAuthTime();

                // 「次回から自動的にサインイン」にチェックを入れてサインインし、ブラウザを閉じてから開き直した場合。
                // 認証 Cookie は残っているが、認証時刻 Cookie は消えている（そういう経路がある）。
                // **書き換えられた・壊れた Cookie も、無いものとして扱う**（以前は DateTime.Parse で 500 になった）。
                if (string.IsNullOrEmpty(auth_time))
                {
                    // AuthTimeCookie が無ければ、最小値で埋める（認証時刻が分からない）。
                    auth_time = FormatConverter.ToW3cTimestamp(DateTime.MinValue);
                }

                // **クレームとして持たせる**（値は W3C 形式）。
                // CmnAccessToken がこのクレームを拾い、access_token と id_token の auth_time にする。
                identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnAuthTimeClaim, auth_time));
            }
        }

        #endregion

        #region sid（OpSession）

        /// <summary>OpSessionの識別子を Cookie から読む</summary>
        /// <returns>OpSessionの識別子（Cookie が無ければ空）</returns>
        private string GetOpSession()
        {
            return this.ReadCookie(Config.OpSessionCookieName) ?? "";
        }

        /// <summary>OpSessionの識別子をCookieに書く</summary>
        /// <param name="sessionId">Sessionの識別子</param>
        /// <remarks>**期限を付けない**（Session Cookie）。**ブラウザを閉じれば終わる。**</remarks>
        private void SetOpSessionCookie(string sessionId)
        {
            this.SetCookie(Config.OpSessionCookieName, sessionId);
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
            if (!string.IsNullOrEmpty(this.AuthZRequestQuery()[Const.OpSessionRetry]))
            {
                // 続けても失うのは「ログアウト補助」だけで、認証の安全性は下がらない。
                return null;
            }

            // OpSessionの識別子を作って
            this.SetOpSessionCookie(Guid.NewGuid().ToString("N"));

            // 印を付けて、元の URL へ送り返す（ブラウザは Cookie を受け取ってから戻ってくる）
            string url = this.CurrentRequestUrl();
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
            this.DeleteCookie(Config.OpSessionCookieName);

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
        /// `prompt=none` でなければサインイン画面へ送る（[Authorize] と同じ動き）。
        ///
        /// **判定は `redirect_uri` の照合（ValidateAuthZReqParam）より後で行う。**
        /// **照合前に RP へ返すと、オープン リダイレクトになる。**
        ///
        /// **同意の判定は、code・Implicit・Hybrid の 3 つで共通**（#294）。
        /// 以前は code の分岐の中にしか無く、**Implicit と Hybrid は同意を確かめずにトークンを発行していた**
        /// （#272 の「同意していなければ `prompt=none` は `consent_required`」も効いていなかった）。
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
            NameValueCollection query = this.AuthZRequestQuery();
            string code_challenge = query[OAuth2AndOIDCConst.code_challenge];
            string request_uri = query[OAuth2AndOIDCConst.request_uri];

            // request_uri で Request Object が引ければ、各パラメタ（code_challenge を含む）をその値で上書きする。
            if (!this.OverwriteByRequestObject(request_uri,
                ref client_id, ref redirect_uri, ref response_type, ref response_mode,
                ref scope, ref state, ref nonce, ref max_age, ref prompt, ref claims, ref code_challenge))
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "The client_id does not match the request object.";
            }
            // **要求の検証を先に行う**（#247）。`redirect_uri` を照合できていないと、エラーを RP へ返せない。
            else if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription, code_challenge, prompt))
            {
                // **max_age と auth_time の照合**（判定は CommonLibrary）。
                //   **どちらの Cookie も、改ざんできない形で読む**（#294。`Sts.AuthTimeCookie`）。
                OAuth2AndOIDCEnum.AuthTimeCheck authTimeCheck = Token.CmnEndpoints.CheckAuthTime(
                    max_age, this.ReadAuthTime(), this.ReadReAuthenticatedAt());

                if (!this.IsSupportedResponseMode(response_type, response_mode))
                {
                    // **この response_type で使えない response_mode**（#294）。
                    //   以前は発行した後で応答を作れず、**error が空のまま** RP へ返っていた。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The response_mode is not supported for the response_type.";
                }
                else if (authTimeCheck == OAuth2AndOIDCEnum.AuthTimeCheck.InvalidMaxAge)
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
                        return this.ChallengeSignIn();
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
                        // **印を残してサインアウトし、同じ URL に戻す**（この後は認証が要るのでサインイン画面になる）。
                        //   **印は繰り返しを防ぐため**（max_age=0 でも、再認証の直後なら続ける）。
                        return await this.SignOutForReAuthenticationAsync();
                    }
                }
                else if (OAuth2AndOIDCSpec.HasPrompt(prompt, OAuth2AndOIDCConst.PromptLogin)
                    && string.IsNullOrEmpty(this.ReadReAuthenticatedAt()))
                {
                    // **prompt=login は、再認証を求める**（OIDC Core §3.1.2.1。#272）。
                    //   **この要求の印が無いときだけ再認証する**（印は繰り返しを防ぐため）。
                    //   戻ってきた要求にも prompt=login が付いているので、印が無いと永久に送り返す。
                    //   **印は、この要求に結び付けてある**（#294。別の RP の prompt=login には効かない）。
                    return await this.SignOutForReAuthenticationAsync();
                }
                else
                {
                    // **OpSessionの識別子を用意する**（#310）。
                    //   **無ければ Cookie を置いて、同じ URL へ送り返す**（同時に来た要求を 1 つの識別子に揃えるため）。
                    ActionResult ensured = this.EnsureOpSession();
                    if (ensured != null) return ensured;

                    // Cookie認証チケットからClaimsIdentityを作る。
                    ClaimsIdentity identity = await this.CreateIdentityFromTicketAsync();

                    // **再認証の印を消す** 一度きりの印なので、ここまで来たら落とす。
                    this.DeleteCookie(Config.ReAuthenticatedAtCookieName);

                    // auth_timeを追加
                    this.AddAuthTimeClaim(max_age, claims, identity);

                    // scopeパラメタ
                    string[] scopes = (scope ?? "").Split(' ');

                    // **認可画面で「何を確かめるのか」を出すための値**（#246 の項目 3）。
                    //   画面側は、自己テストを閉じている配置では出さない（項目 4 の線引き）。
                    ViewBag.Name = identity.Name;
                    ViewBag.Scopes = scopes;
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

                    #region 同意の判定（code・Implicit・Hybrid で共通。#294）
                    //   | 状況 | ここでの扱い |
                    //   |---|---|
                    //   | scope に `auth`（独自の認証用。**登録に明記したクライアントだけ**） | **飛ばす**（同意を求める対象でない） |
                    //   | 要求 scope が記録の部分集合 | **飛ばす** |
                    //   | `prompt=consent` | **記録が在っても出す**（§3.1.2.1） |
                    //   | `prompt=select_account` | **出す**（画面に「別のアカウントでログイン」が在る） |
                    //   | 記録が無い ＋ `prompt=none` | **`consent_required`**（§3.1.2.6。UI を出せない） |
                    //   | 記録が無い | 同意画面を出す（**許可の POST が、response_type に応じて発行する**） |

                    // この要求の scope を、前に同意しているか
                    bool hasConsent = Sts.ConsentProvider.HasConsent(this.CurrentUserId(), client_id, scopes);
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

                        // ★ code / token の生成と、Redirectエンドポイントへの応答
                        ActionResult issued = this.IssueAuthorizationResponse(
                            identity, client_id, response_type, response_mode, valid_redirect_uri,
                            state, scopes, claims, nonce);
                        if (issued != null) return issued;

                        // 不正なresponse_type
                        err = OAuth2AndOIDCConst.unsupported_response_type;
                        errDescription = "The response_type is not supported.";
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
            }
            else
            {
                // 不正なRequest
            }

            // ここまで来たらエラー。
            return this.AuthorizeErrorResponse(
                client_id, response_type, response_mode, valid_redirect_uri, err, errDescription, state);
        }

        /// <summary>
        /// 認可エンドポイント
        /// 権限付与画面（同意画面）の結果を受け取り、
        /// response_type に応じて code / token を発行してRedirectエンドポイントへRedirect。
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
            string valid_redirect_uri = "";
            string err = "";
            string errDescription = "";

            string prompt = ""; // ダミー
            JObject claims = null;

            // code_challenge（PKCE必須かの確認に使う）と request_uri は、クエリ文字列から読む。
            NameValueCollection query = this.AuthZRequestQuery();
            string code_challenge = query[OAuth2AndOIDCConst.code_challenge];
            string request_uri = query[OAuth2AndOIDCConst.request_uri];

            // request_uri で Request Object が引ければ、各パラメタ（code_challenge を含む）をその値で上書きする。
            if (!this.OverwriteByRequestObject(request_uri,
                ref client_id, ref redirect_uri, ref response_type, ref response_mode,
                ref scope, ref state, ref nonce, ref max_age, ref prompt, ref claims, ref code_challenge))
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "The client_id does not match the request object.";
            }
            else if (Token.CmnEndpoints.ValidateAuthZReqParam(
                client_id, redirect_uri, ref response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription,
                code_challenge, prompt))
            {
                if (!this.IsSupportedResponseMode(response_type, response_mode))
                {
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The response_mode is not supported for the response_type.";
                }
                else if (!string.IsNullOrEmpty(this.FormValue("submit.Login")))
                {
                    // 別のアカウントでログイン（サインアウトしてリダイレクト）

                    // OpSessionを終わらせる（入り直すと新しい sid になる）
                    List<string> iframeUrlsForSwitch = this.ClearOpSession();
                    await this.SignOutApplicationCookieAsync();

                    //  **ブラウザ経由で伝えてから、同じ URL へ進む**（#310）。
                    ActionResult frontChannelForSwitch = this.FrontChannelLogoutView(
                        iframeUrlsForSwitch, this.CurrentRequestUrl());
                    if (frontChannelForSwitch != null) return frontChannelForSwitch;

                    return new RedirectResult(this.CurrentRequestUrl());
                }
                else if (!string.IsNullOrEmpty(this.FormValue("submit.Deny")))
                {
                    // **拒否した**（E-6 / #272）。
                    //   **RFC 6749 §4.1.2.1 : access_denied を redirect_uri へ返す。**
                    //   **記録は残さない**（「拒否した」を覚えて、
                    //   次回以降自動で断ることはしない。利用者が気を変えられなくなる）。
                    err = OAuth2AndOIDCConst.access_denied;
                    errDescription = "The resource owner denied the request.";
                }
                else if (!string.IsNullOrEmpty(this.FormValue("submit.Grant")))
                {
                    // Cookie認証チケットからClaimsIdentityを作る。
                    ClaimsIdentity identity = await this.CreateIdentityFromTicketAsync();

                    // auth_timeを追加
                    this.AddAuthTimeClaim(max_age, claims, identity);

                    // scopeパラメタ
                    string[] scopes = (scope ?? "").Split(' ');

                    // **同意を記録する**（#272 / D-6）。
                    //   **これが次回以降の `prompt=none` の判定の土台になる。**
                    //   **scope は足し込む**（増えた scope で同意し直しても、以前の分を失わない）。
                    Sts.ConsentProvider.Grant(this.CurrentUserId(), client_id, scopes);

                    // ★ code / token の生成と、Redirectエンドポイントへの応答
                    //   **response_type に応じて発行する**（#294。以前は code しか返さなかった）。
                    ActionResult issued = this.IssueAuthorizationResponse(
                        identity, client_id, response_type, response_mode, valid_redirect_uri,
                        state, scopes, claims, nonce);
                    if (issued != null) return issued;

                    // 不正なresponse_type
                    err = OAuth2AndOIDCConst.unsupported_response_type;
                    errDescription = "The response_type is not supported.";
                }
                else
                {
                    // **不正な操作**（同意画面のボタンが送られていない。#294）。
                    //   以前は画面を出し直していたが、**画面の値（ViewBag）を組まずに返していた。**
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "No action was selected on the consent screen.";
                }
            }
            else
            {
                // 不正なRequest
            }

            // ここまで来たらエラー。
            return this.AuthorizeErrorResponse(
                client_id, response_type, response_mode, valid_redirect_uri, err, errDescription, state);
        }

        #endregion

        #region 要求の読み込み・発行・エラー

        /// <summary>request_uri（PAR / JAR）の Request Object で、要求のパラメタを上書きする</summary>
        /// <param name="request_uri">request_uri（無ければ何もしない）</param>
        /// <param name="client_id">client_id</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="response_type">response_type</param>
        /// <param name="response_mode">response_mode</param>
        /// <param name="scope">scope</param>
        /// <param name="state">state</param>
        /// <param name="nonce">nonce</param>
        /// <param name="max_age">max_age</param>
        /// <param name="prompt">prompt</param>
        /// <param name="claims">claims</param>
        /// <param name="code_challenge">code_challenge</param>
        /// <returns>**クエリの client_id と、Request Object の client_id が食い違えば false**</returns>
        /// <remarks>
        /// **GET と POST に同じ 20 行があったので、1 つにした**（#294）。
        ///
        /// **クエリに client_id が在れば、Request Object の値と一致することを確かめる**
        /// （RFC 9126 §4 / RFC 9101 §5。#294）。以前は確かめずに上書きしていた。
        ///
        /// **存在しない request_uri では、Request Object が null になる**（#185）。
        /// その場合は上書きせず、後続の ValidateAuthZReqParam でエラーにする。
        /// </remarks>
        private bool OverwriteByRequestObject(string request_uri,
            ref string client_id, ref string redirect_uri, ref string response_type, ref string response_mode,
            ref string scope, ref string state, ref string nonce, ref string max_age, ref string prompt,
            ref JObject claims, ref string code_challenge)
        {
            if (string.IsNullOrEmpty(request_uri))
            {
                return true;
            }

            string requestObjectPayloadString = Sts.RequestObjectProvider.Get(
                request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

            JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

            if (requestObjectPayload == null)
            {
                return true;
            }

            string requestObjectClientId = (string)requestObjectPayload[OAuth2AndOIDCConst.client_id];

            if (!string.IsNullOrEmpty(client_id) && client_id != requestObjectClientId)
            {
                return false;
            }

            client_id = requestObjectClientId;
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

            return true;
        }

        /// <summary>code / token を発行し、Redirectエンドポイントへの応答を返す</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <param name="response_mode">response_mode</param>
        /// <param name="redirect_uri">照合済みの redirect_uri</param>
        /// <param name="state">state</param>
        /// <param name="scopes">scopes</param>
        /// <param name="claims">claims</param>
        /// <param name="nonce">nonce</param>
        /// <returns>応答（**知らない response_type なら null**）</returns>
        /// <remarks>
        /// **同意を飛ばせる場合（GET）と、同意画面で許可された場合（POST）で共用する**（#294）。
        /// </remarks>
        private ActionResult IssueAuthorizationResponse(
            ClaimsIdentity identity, string client_id, string response_type, string response_mode,
            string redirect_uri, string state, string[] scopes, JObject claims, string nonce)
        {
            string rt = (response_type ?? "").ToLower();

            bool isCode = rt == OAuth2AndOIDCConst.AuthorizationCodeResponseType;
            bool isImplicit = rt == OAuth2AndOIDCConst.ImplicitResponseType
                || rt == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                || rt == OAuth2AndOIDCConst.OidcImplicit2_ResponseType;
            bool isHybrid = rt == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                || rt == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                || rt == OAuth2AndOIDCConst.OidcHybrid3_ResponseType;

            if (!isCode && !isImplicit && !isHybrid)
            {
                return null;
            }

            // **sid を足す**（#310。**発行の直前で台帳に書く**）
            this.AddSidClaim(client_id, identity);

            NameValueCollection query = this.AuthZRequestQuery();
            string code = null;
            string access_token = null;
            string id_token = null;

            if (isCode)
            {
                // ★ Codeの生成（OAuth2/OIDC Authorization Code）
                code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                    identity, query, client_id, state, scopes, claims, nonce);
            }
            else if (isImplicit)
            {
                // ★ Tokenの生成（OAuth2/OIDC Implicit）
                Token.CmnEndpoints.CreateAuthZRes4ImplicitFlow(
                    identity, query, response_type, client_id, state, scopes, claims, nonce,
                    out access_token, out id_token);
            }
            else
            {
                // ★ Code & Tokenの生成（OIDC Hybrid Flow）
                code = Token.CmnEndpoints.CreateAuthNRes4HybridFlow(
                    identity, query, client_id, state, scopes, claims, nonce,
                    out access_token, out id_token);
            }

            return this.RedirectAuthorizationResponse(
                client_id, rt, response_mode, redirect_uri, code, access_token, id_token, state);
        }

        /// <summary>エラーを返す（照合済みの redirect_uri が在れば RP へ、無ければエラー画面）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <param name="response_mode">response_mode</param>
        /// <param name="valid_redirect_uri">照合済みの redirect_uri（無ければ空）</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <param name="state">state</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **GET と POST で共用する**（#294。**POST のエラーも記録する**ようにした）。
        /// **応答の形は、成功と同じく response_mode に従う**（Implicit / Hybrid は fragment、JARM なら JWT）。
        /// **response_mode が使えなければ、その response_type の既定の形で返す。**
        /// </remarks>
        private ActionResult AuthorizeErrorResponse(
            string client_id, string response_type, string response_mode,
            string valid_redirect_uri, string err, string errDescription, string state)
        {
            if (string.IsNullOrEmpty(err))
            {
                // **error を空のまま返さない**（#294）。
                err = OAuth2AndOIDCConst.server_error;
                errDescription = "The authorization request could not be processed.";
            }

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
                Dictionary<string, string> parameters = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.error, err },
                    { OAuth2AndOIDCConst.error_description, errDescription },
                    { OAuth2AndOIDCConst.state, state }
                };

                bool allowsQuery = AccountController.AllowsQueryResponseMode(response_type);

                return this.CreateAuthorizationResponse(client_id, response_mode, allowsQuery, valid_redirect_uri, parameters)
                    ?? this.CreateAuthorizationResponse(client_id, null, allowsQuery, valid_redirect_uri, parameters);
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
        /// Redirectエンドポイントへ、発行した code / token を返す
        /// </summary>
        /// <param name="client_id">client_id（JARM の aud）</param>
        /// <param name="response_type">response_type（小文字）</param>
        /// <param name="response_mode">response_mode</param>
        /// <param name="redirect_uri">照合済みの redirect_uri</param>
        /// <param name="code">code（無ければ null）</param>
        /// <param name="access_token">access_token（無ければ null）</param>
        /// <param name="id_token">id_token（無ければ null）</param>
        /// <param name="state">state</param>
        /// <returns>ActionResult（response_mode が使えなければ null）</returns>
        /// <remarks>
        /// **以前は response_type × response_mode の組み合わせを、3 つのメソッドで 1 つずつ書いていた**（約 600 行）。
        /// **その中で、`form_post.jwt` の比較の一部が `.` を `_` に直しておらず一致しない、**
        /// **Implicit の JARM が aud / exp / iss を入れない**、という食い違いが出ていた（#294）。
        /// **応答の形は `CreateAuthorizationResponse` の 1 か所で決める。**
        ///
        /// **発行できなかった場合は `server_error`**（#294。以前は理由に関係なく `access_denied`）。
        /// </remarks>
        private ActionResult RedirectAuthorizationResponse(
            string client_id, string response_type, string response_mode, string redirect_uri,
            string code, string access_token, string id_token, string state)
        {
            HashSet<string> parts = new HashSet<string>((response_type ?? "").Split(' '));

            bool wantsCode = parts.Contains(OAuth2AndOIDCConst.code);
            bool wantsIdToken = parts.Contains(OAuth2AndOIDCConst.IDToken);
            bool wantsToken = parts.Contains(OAuth2AndOIDCConst.ImplicitResponseType);

            Dictionary<string, string> parameters = new Dictionary<string, string>();

            if ((wantsCode && string.IsNullOrEmpty(code))
                || (wantsIdToken && string.IsNullOrEmpty(id_token))
                || (wantsToken && string.IsNullOrEmpty(access_token)))
            {
                // 発行できなかった
                parameters.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.server_error);
                parameters.Add(OAuth2AndOIDCConst.error_description, "The authorization response could not be issued.");
            }
            else
            {
                // 補足
                // access_tokenを返す場合、token_type, expires_inが必要になる。
                if (wantsCode) parameters.Add(OAuth2AndOIDCConst.code, code);
                if (wantsIdToken) parameters.Add(OAuth2AndOIDCConst.IDToken, id_token);

                if (wantsToken)
                {
                    parameters.Add(OAuth2AndOIDCConst.AccessToken, access_token);
                    parameters.Add(OAuth2AndOIDCConst.token_type, Const.TokenTypeBearer);
                    parameters.Add(OAuth2AndOIDCConst.expires_in,
                        ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString());
                }
            }

            // stateは、クライアントが指定した場合、基本的に必要になる。
            parameters.Add(OAuth2AndOIDCConst.state, state);

            return this.CreateAuthorizationResponse(client_id, response_mode,
                AccountController.AllowsQueryResponseMode(response_type), redirect_uri, parameters);
        }

        /// <summary>認可応答を、response_mode に従って返す（#294）</summary>
        /// <param name="client_id">client_id（JARM の aud）</param>
        /// <param name="response_mode">response_mode（空なら既定）</param>
        /// <param name="allowsQuery">query を使えるか（code だけ）</param>
        /// <param name="redirect_uri">照合済みの redirect_uri</param>
        /// <param name="parameters">応答のパラメタ</param>
        /// <returns>ActionResult（response_mode が使えなければ null）</returns>
        /// <remarks>
        /// | response_mode | 返し方 |
        /// |---|---|
        /// | 空 | **code は query、それ以外は fragment** |
        /// | `query` / `fragment` / `form_post` | そのまま（**トークンを含む応答に query は使わない**。OAuth 2.0 Multiple Response Types §5） |
        /// | `jwt` | **JARM の既定**（code は `query.jwt`、それ以外は `fragment.jwt`。JARM §2.3.4） |
        /// | `*.jwt` | **パラメタを署名した JWT（`response`）にして返す**（**`iss` / `aud` / `exp` を入れる**。JARM §2.1） |
        ///
        /// **`iss`（RFC 9207）は、query / fragment では BuildRedirectUrl が、form_post では画面が付ける**（JARM のときは JWT の中）。
        /// </remarks>
        private ActionResult CreateAuthorizationResponse(
            string client_id, string response_mode, bool allowsQuery,
            string redirect_uri, Dictionary<string, string> parameters)
        {
            string baseMode;
            bool isJwt;

            if (!AccountController.TryResolveResponseMode(response_mode, allowsQuery, out baseMode, out isJwt))
            {
                return null;
            }

            bool isFragment = baseMode == OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit();
            bool isFormPost = baseMode == OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit();

            if (isJwt)
            {
                // JARM
                string response = Token.CmnResponseObject.Create(parameters, client_id, this.CreateJarmExp());

                if (isFormPost)
                {
                    ViewData["Action"] = redirect_uri;
                    ViewData["Response"] = response;
                    return View("FormPost");
                }

                return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                    redirect_uri,
                    new Dictionary<string, string>() { { "response", response } },
                    isFragment, CmnServerParams.IssuerId));
            }

            if (isFormPost)
            {
                // form_post
                ViewData["Action"] = redirect_uri;

                foreach (KeyValuePair<string, string> p in parameters)
                {
                    ViewData[AccountController.FormPostKey(p.Key)] = p.Value;
                }

                return View("FormPost");
            }

            // query or fragment
            return new RedirectResult(OAuth2AndOIDCSpec.BuildRedirectUrl(
                redirect_uri, parameters, isFragment, CmnServerParams.IssuerId));
        }

        /// <summary>この response_type で、response_mode を使えるか</summary>
        /// <param name="response_type">response_type</param>
        /// <param name="response_mode">response_mode</param>
        /// <returns>使えるなら true</returns>
        private bool IsSupportedResponseMode(string response_type, string response_mode)
        {
            string baseMode;
            bool isJwt;

            return AccountController.TryResolveResponseMode(
                response_mode, AccountController.AllowsQueryResponseMode(response_type), out baseMode, out isJwt);
        }

        /// <summary>query を使える response_type か（code だけ）</summary>
        /// <param name="response_type">response_type</param>
        /// <returns>使えるなら true</returns>
        private static bool AllowsQueryResponseMode(string response_type)
        {
            return string.IsNullOrEmpty(response_type)
                || response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType;
        }

        /// <summary>response_mode を、返し方（query / fragment / form_post）と JARM かに分ける</summary>
        /// <param name="response_mode">response_mode（空なら既定）</param>
        /// <param name="allowsQuery">query を使えるか</param>
        /// <param name="baseMode">返し方</param>
        /// <param name="isJwt">JARM か</param>
        /// <returns>使えるなら true</returns>
        /// <remarks>**`.` と `_` は同じに扱う**（`form_post.jwt` と `form_post_jwt`。以前は比較の一部で直していなかった）。</remarks>
        private static bool TryResolveResponseMode(
            string response_mode, bool allowsQuery, out string baseMode, out bool isJwt)
        {
            string query = OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit();
            string fragment = OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit();
            string formPost = OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit();

            string mode = (response_mode ?? "").ToLower().Replace('.', '_');

            baseMode = null;
            isJwt = false;

            if (mode == "")
            {
                baseMode = allowsQuery ? query : fragment;
            }
            else if (mode == query || mode == fragment || mode == formPost)
            {
                baseMode = mode;
            }
            else if (mode == OAuth2AndOIDCEnum.ResponseMode.jwt.ToStringByEmit())
            {
                baseMode = allowsQuery ? query : fragment;
                isJwt = true;
            }
            else if (mode == OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit())
            {
                baseMode = query;
                isJwt = true;
            }
            else if (mode == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
            {
                baseMode = fragment;
                isJwt = true;
            }
            else if (mode == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
            {
                baseMode = formPost;
                isJwt = true;
            }
            else
            {
                // 知らない response_mode
                return false;
            }

            // **トークンを含む応答に query は使わない**
            return baseMode != query || allowsQuery;
        }

        /// <summary>form_post の画面（FormPost.cshtml）の ViewData のキー</summary>
        /// <param name="parameter">応答のパラメタ名</param>
        /// <returns>ViewData のキー</returns>
        private static string FormPostKey(string parameter)
        {
            switch (parameter)
            {
                case OAuth2AndOIDCConst.code: return "Code";
                case OAuth2AndOIDCConst.IDToken: return "IdToken";
                case OAuth2AndOIDCConst.AccessToken: return "AccessToken";
                case OAuth2AndOIDCConst.token_type: return "TokenType";
                case OAuth2AndOIDCConst.expires_in: return "ExpiresIn";
                case OAuth2AndOIDCConst.state: return "State";
                case OAuth2AndOIDCConst.error: return "Error";
                case OAuth2AndOIDCConst.error_description: return "ErrorDescription";
                default: return parameter;
            }
        }

        /// <summary>CreateJarmExp</summary>
        /// <returns>DateTimeOffset</returns>
        private DateTimeOffset CreateJarmExp()
        {
            return DateTimeOffset.Now.AddMinutes(10);
        }

        #endregion

        #region auth_time と再認証の印（#294）

        /// <summary>auth_time を読む（改ざんされていなければ。W3C 形式）</summary>
        /// <returns>W3C 形式の時刻（無い・開けなければ null）</returns>
        private string ReadAuthTime()
        {
            return Sts.AuthTimeCookie.UnprotectAuthTime(this.ReadCookie(Config.AuthTimeCookieName));
        }

        /// <summary>この要求の、再認証の印を読む</summary>
        /// <returns>W3C 形式の時刻（無い・開けない・別の要求の印なら null）</returns>
        private string ReadReAuthenticatedAt()
        {
            return Sts.AuthTimeCookie.UnprotectReAuthenticatedAt(
                this.ReadCookie(Config.ReAuthenticatedAtCookieName), this.ReAuthRequestKey());
        }

        /// <summary>この要求の指紋（再認証の印を、この要求に結び付ける）</summary>
        /// <returns>指紋</returns>
        private string ReAuthRequestKey()
        {
            NameValueCollection query = this.AuthZRequestQuery();
            List<KeyValuePair<string, string>> pairs = new List<KeyValuePair<string, string>>();

            foreach (string key in query.AllKeys)
            {
                if (key == null) continue;

                foreach (string value in query.GetValues(key) ?? new string[0])
                {
                    pairs.Add(new KeyValuePair<string, string>(key, value));
                }
            }

            return Sts.AuthTimeCookie.RequestKey(pairs, Const.OpSessionRetry);
        }

        /// <summary>再認証の印を残してサインアウトし、同じ URL に戻す（max_age 超過・prompt=login）</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> SignOutForReAuthenticationAsync()
        {
            //  **印は、この要求に結び付けて、改ざんできない形で残す**（#294）。
            this.SetCookie(Config.ReAuthenticatedAtCookieName,
                Sts.AuthTimeCookie.ProtectReAuthenticatedAt(DateTime.UtcNow, this.ReAuthRequestKey()));

            // **OpSessionを終わらせる**（入り直すと新しい sid になる）
            List<string> iframeUrls = this.ClearOpSession();

            await this.SignOutApplicationCookieAsync();

            // **ブラウザ経由で伝えてから、同じ URL へ進む**（#310）。
            ActionResult frontChannel = this.FrontChannelLogoutView(iframeUrls, this.CurrentRequestUrl());
            if (frontChannel != null) { return frontChannel; }

            return new RedirectResult(this.CurrentRequestUrl());
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
                OAuth2AndOIDCConst.user_code, this.CurrentRequestUrl());

            return View("DeviceAuthZVerify");
        }

        /// <summary>
        /// DeviceAuthZVerify画面
        /// POST: /device_verify
        /// </summary>
        /// <param name="formData">IFormCollection</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **AntiForgery トークンを検証する**（#294）。
        /// 以前は画面にトークンを埋めていたが、検証していなかった（認証 Cookie は `SameSite=None`）。
        /// </remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
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

        #region 版の違いを吸収する補助（net10.0 版。#294）

        //  **認可エンドポイントの本文は、両版で同じにしてある。**
        //    **版で違うのは、この補助だけ**（Cookie・クエリ・フォーム・サインアウト・認証チケット）。

        /// <summary>認可要求のクエリ（デコードした値）</summary>
        /// <returns>NameValueCollection</returns>
        /// <remarks>**デコードされた値で読む**（パーセント エンコードされた request_uri（urn:... のコロン）を取りこぼさないため）。</remarks>
        private NameValueCollection AuthZRequestQuery()
        {
            return HttpUtility.ParseQueryString(Request.QueryString.Value ?? "");
        }

        /// <summary>いまの要求の URL</summary>
        /// <returns>URL</returns>
        private string CurrentRequestUrl()
        {
            return UriHelper.GetEncodedUrl(Request);
        }

        /// <summary>フォームの値（POST のときだけ使う）</summary>
        /// <param name="name">名前</param>
        /// <returns>値</returns>
        private string FormValue(string name)
        {
            return MyHttpContext.Current.Request.Form[name];
        }

        /// <summary>Cookie を読む</summary>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ null）</returns>
        private string ReadCookie(string name)
        {
            return MyHttpContext.Current.Request.Cookies[name];
        }

        /// <summary>Cookie を書く</summary>
        /// <param name="name">名前</param>
        /// <param name="value">値</param>
        private void SetCookie(string name, string value)
        {
            MyHttpContext.Current.Response.Cookies.Set(name, value, this._cookieOptions);
        }

        /// <summary>Cookie を消す</summary>
        /// <param name="name">名前</param>
        private void DeleteCookie(string name)
        {
            MyHttpContext.Current.Response.Cookies.Delete(name);
        }

        /// <summary>認証 Cookie を消す（サインアウト）</summary>
        /// <returns>Task</returns>
        private async Task SignOutApplicationCookieAsync()
        {
            // **SignInManager でサインアウトする。**
            // `HttpContext.SignOutAsync()` では、Cookie（Identity.Application）が消えず、
            // 次の要求でも認証済みのままだった（実測）。既存の Logout も SignInManager を使っている。
            await this.SignInManager.SignOutAsync();
        }

        /// <summary>Cookie認証チケットから、発行に使う ClaimsIdentity を作る</summary>
        /// <returns>ClaimsIdentity</returns>
        private async Task<ClaimsIdentity> CreateIdentityFromTicketAsync()
        {
            AuthenticateResult ticket = await HttpContext.AuthenticateAsync();
            ClaimsPrincipal principal = (ticket != null) ? ticket.Principal : null;

            return new ClaimsIdentity(
                principal.Claims, OAuth2AndOIDCConst.Bearer,
                ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
        }

        /// <summary>サインインしている利用者の id</summary>
        /// <returns>id</returns>
        private string CurrentUserId()
        {
            return this.UserManager.GetUserId(this.User);
        }

        /// <summary>サインイン画面へ送る</summary>
        /// <returns>ActionResult</returns>
        private ActionResult ChallengeSignIn()
        {
            // ChallengeResult は 401 を返し、Cookie 認証が LoginPath へのリダイレクトに変える。
            return new ChallengeResult();
        }

        #endregion
    }
}
