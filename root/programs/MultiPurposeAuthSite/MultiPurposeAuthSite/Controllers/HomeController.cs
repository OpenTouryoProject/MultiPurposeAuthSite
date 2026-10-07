//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController
//*
//* 作成日時        ：－
//* 作成者          ：生技
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/02/08  西野 大介         OAuth2Starters改造
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PKCE for SPA対応実施
//*  2020/03/04  西野 大介         FAPI CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/11/12  西野 大介         redirect_uri、ROへの対策漏れ。
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/08  玄人 幸道         OIDCでもredirect_uriをcodeに紐付ける（#186）
//*  2026/09/17  玄人 幸道         IsLockedDownRedirectEndpoint を IsLockedDownTestEndpoints に改名（#219）
//*  2026/09/18  玄人 幸道         require_pkce のクライアントを試す口を追加（#221）
//*  2026/09/25  玄人 幸道         CIBA の認証要求の aud を Issuer Identifier にした（#234 の段階 1）
//*  2026/09/25  玄人 幸道         CIBA の認証要求を request で直接送り、クライアント認証を添える（#234 の段階 3）
//*  2026/09/25  玄人 幸道         CIBA の自己テストの結果文字列を net10.0 版に揃えた
//*  2026/09/27  玄人 幸道         自己テストに RP-Initiated Logout の口を追加（#232）
//*  2026/09/28  玄人 幸道         自己テストに PAR（/par）経路を追加（#246）
//*  2026/09/28  玄人 幸道         組み立てを SelfTestClient へ寄せた（#246）
//*  2026/09/28  玄人 幸道         CIBA の結果を画面に出し、interval に従わせた（#246 の 3-a / 3-b）
//*  2026/09/28  玄人 幸道         Device AuthZ の結果も画面に出し、interval に従わせた（#246 の 3-a / 3-b）
//*  2026/09/28  玄人 幸道         Device AuthZ の verification_uri のリンクが二重になっていたのを修正（#246）
//*  2026/09/28  玄人 幸道         SAML2 の Post & Redirect Binding を追加（#246 の項目 2）
//*  2026/09/29  玄人 幸道         OIDC ボタンの prompt=none を、画面の選択で上書きできるようにした（#247）
//*  2026/09/29  玄人 幸道         FAPI1 PKCE のボタンが S256 の値を plain と宣言していた（#245）
//*  2026/10/01  玄人 幸道         自己テストの宛先を、メアドではなく利用者名にした（#151 の段階 3）
//*  2026/10/06  玄人 幸道         OIDCボタンの固定のprompt=noneを外した（#272 の段階 2）
//*  2026/10/07  玄人 幸道         WebAuthnStarters を削除（#137）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    [Authorize]
    public class HomeController : MyBaseMVController
    {
        #region constructor

        /// <summary>constructor</summary>
        public HomeController() { }

        #endregion

        #region property

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private ApplicationSignInManager SignInManager
        {
            get
            {
                return HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
        }

        /// <summary>AuthenticationManager</summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        #endregion

        #endregion

        #region Test MVC

        #region Action Method

        /// <summary>
        /// GET: Home
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// GET: Home/Scroll
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Scroll()
        {
            return View();
        }

        #endregion

        #endregion

        #region Test STS

        #region Params

        /// <summary>Issuer</summary>
        private string Issuer = "";

        /// <summary>RedirectUri</summary>
        private string RedirectUri = "";

        /// <summary>ClarifyRedirectUri</summary>
        private bool ClarifyRedirectUri = false;

        #region Saml2

        /// <summary>認可エンドポイント</summary>
        private string Saml2RequestEndpoint = "";
                
        #endregion

        #region OAuth2
        /// <summary>認可エンドポイント</summary>
        private string OAuth2AuthorizeEndpoint = "";

        /// <summary>ResponseMode</summary>
        private string ResponseMode = ""; 

        /// <summary>prompt（画面で選ぶ。#246 の項目 3）</summary>
        private string Prompt = "";

        /// <summary>max_age（画面で選ぶ。#246 の項目 3）</summary>
        private string MaxAge = "";

        /// <summary>ClientName</summary>
        private string ClientName = "";

        /// <summary>ClientId</summary>
        private string ClientId = "";

        /// <summary>state (nonce)</summary>
        private string State = "";

        /// <summary>nonce</summary>
        private string Nonce = "";

        /// <summary>code_verifier</summary>
        private string CodeVerifier = "";

        /// <summary>code_verifier</summary>
        private string CodeChallenge = "";
        #endregion

        #endregion

        #region Common

        #region InitParams

        #region InitSaml2Params

        /// <summary>テスト用にパラメタを初期化</summary>
        private void InitSaml2Params()
        {
            this.Saml2RequestEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            // Issuer (RootURI + ClientId) 
            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            this.Issuer = "http://" + ClientId;

            if (this.ClarifyRedirectUri)
            {
                this.RedirectUri = Helper.GetInstance().GetAssertionConsumerServiceURL(this.ClientId);
            }

            // RelayStateに入れる（本来の用途と異なるが）。
            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
        }

        /// <summary>テスト用にパラメタを保存</summary>
        private void SaveSaml2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            // client_id → Issuer
            Session[Const.TestClientId] = this.ClientId;
            Response.Cookies[Const.TestClientId].Value = this.ClientId;

            // redirect_uri → AssertionConsumerService
            Session[Const.TestRedirectUri] = this.RedirectUri;
            Response.Cookies[Const.TestRedirectUri].Value = this.RedirectUri;

            // state → RelayState
            Session[Const.TestState] = this.State;
            Response.Cookies[Const.TestState].Value = this.State;
        }

        #endregion

        #region InitOAuth2Params

        /// <summary>テスト用にパラメタを初期化</summary>
        private void InitOAuth2Params()
        {
            this.OAuth2AuthorizeEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI
            + Config.OAuth2AuthorizeEndpoint;

            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            // ココでは、まだ、response_typeが明確にならないので取得できない。
            //this.RedirectUri = Helper.GetInstance().GetClientsRedirectUri(this.ClientName, response_type);

            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。

            this.CodeVerifier = "";
            this.CodeChallenge = "";
        }

        /// <summary>テスト用にパラメタを保存</summary>
        private void SaveOAuth2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            // client_id
            Session[Const.TestClientId] = this.ClientId;
            Response.Cookies[Const.TestClientId].Value = this.ClientId;

            // state
            Session[Const.TestState] = this.State;
            Response.Cookies[Const.TestState].Value = this.State;

            // redirect_uri
            // OIDCでもTokenリクエストにredirect_uriを指定する（OIDC Core 3.1.3.1）（#186）。
            Session[Const.TestRedirectUri] = this.RedirectUri;
            Response.Cookies[Const.TestRedirectUri].Value = this.RedirectUri;

            // nonce
            Session[Const.TestNonce] = this.Nonce;
            Response.Cookies[Const.TestNonce].Value = this.Nonce;

            // code_verifier
            Session[Const.TestCodeVerifier] = this.CodeVerifier;
            Response.Cookies[Const.TestCodeVerifier].Value = this.CodeVerifier;
        }

        #endregion

        #endregion

        #region Assemble

        #region AssembleSaml2
        #endregion

        #region AssembleOAuth2

        #region OAuth2/OIDC
        /// <summary>OAuth2スターターに追加のパラメタを組み込む</summary>
        /// <param name="redirect">string</param>
        /// <param name="response_type">string</param>
        /// <returns>OAuth2スターター</returns>
        private string AndAddAdditionalParamToOAuth2Starter(string redirect, string response_type)
        {
            // RedirectUriの追加
            if (this.ClarifyRedirectUri)
            {
                string temp = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
                this.RedirectUri = CmnEndpoints.GetRedirectUriFromConstr(temp);
                redirect += "&" + OAuth2AndOIDCConst.redirect_uri + "=" + this.RedirectUri;
            }

            // ResponseModeの指定
            if (!string.IsNullOrEmpty(this.ResponseMode))
            {
                redirect += "&" + OAuth2AndOIDCConst.response_mode + "=" + this.ResponseMode;
            }

            // **prompt と max_age の指定**（#246 の項目 3）。
            //   認可画面（同意）の出方を、画面から試せるようにするためにある。
            //   **ここは認可エンドポイントへ行く全てのスターターが通る**ので、1 か所で足りる。
            if (!string.IsNullOrEmpty(this.Prompt))
            {
                redirect += "&" + OAuth2AndOIDCConst.prompt + "=" + this.Prompt;
            }

            if (!string.IsNullOrEmpty(this.MaxAge))
            {
                redirect += "&" + OAuth2AndOIDCConst.max_age + "=" + this.MaxAge;
            }

            return redirect;
        }

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        private string AssembleOAuth2Starter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.StandardScopes, this.State);

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOIDCスターター</returns>
        private string AssembleOidcStarter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes, this.State)
                    + "&nonce=" + this.Nonce
                    // **画面で max_age を選んでいれば、そちらを使う**（#246 の項目 3）。
                    //   選んでいなければ、従来どおり 600 秒を付ける。
                    + (string.IsNullOrEmpty(this.MaxAge) ? "&max_age=600" : "");

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }
        #endregion

        #region FAPI
        /// <summary>FAPI1スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1Starter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.StandardScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State);
            // テストコードで、clientを識別するために、Stateに細工する。

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>FAPI1 + OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1_OIDCStarter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State)
                    + "&nonce=" + this.Nonce;
            // テストコードで、clientを識別するために、Stateに細工する。

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>FAPI2CCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI2CCスターター</returns>
        /// <remarks>
        /// **組み立ては SelfTestClient に寄せた**（#246。両アプリに同文で二重に在ったため）。
        /// ここは「どのパターンを試すか」だけを決める。
        ///
        /// 預け先は **`/ros`**（独自。RFC 9101 §5.2.1 の任意機能として維持）。
        /// **クライアント認証は無い**（Request Object の署名だけを見る口）。
        /// PAR（RFC 9126）に預ける形は AssembleFAPI2ParStarterAsync。
        /// </remarks>
        private async Task<string> AssembleFAPI2CCStarterAsync(string response_type)
        {
            if (this.ClarifyRedirectUri)
            {
                string temp = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
                this.RedirectUri = CmnEndpoints.GetRedirectUriFromConstr(temp);
            }

            // テストコードで、clientを識別するために、Stateに細工する。
            // TestCase（max_age, auth_time）: 無し, 不要、有り, 不要、無し, 必要
            SelfTestClient.PushResult ret = await SelfTestClient.RegisterRequestObjectAsync(
                this.ClientId, response_type, this.ResponseMode, this.RedirectUri,
                OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":" + this.State, this.Nonce,
                SelfTestClient.SampleClaims());

            if (string.IsNullOrEmpty(ret.RequestUri))
            {
                // 署名の検証ができなかった、または預けられなかった。
                return null;
            }

            // request_uriの認可リクエストを投げる。
            return this.OAuth2AuthorizeEndpoint + string.Format("?request_uri={0}", ret.RequestUri);
        }

        /// <summary>FAPI2CC ＋ PAR のスターターを組み立てて返す（#246）</summary>
        /// <param name="response_type">string</param>
        /// <returns>認可エンドポイントの URL（預けられなければ null）</returns>
        /// <remarks>
        /// **FAPI 2.0 の正規の形。** 認可リクエストを **PAR（RFC 9126）に預けてから**認可する。
        /// AssembleFAPI2CCStarterAsync との違いは、預け先と認証だけ。
        ///
        /// | | /ros（独自。RFC 9101 5.2.1 の任意機能として維持） | /par（RFC 9126） |
        /// |---|---|---|
        /// | 認証 | **無し**（Request Object の署名だけ） | **クライアント認証**（ここでは private_key_jwt） |
        /// | 本文 | 署名付き JWT を生で | フォーム（request に JAR を入れる） |
        /// | 応答 | iss / aud / request_uri / exp | **request_uri / expires_in** |
        ///
        /// **組み立てと預けは SelfTestClient**（Open棟梁 の
        /// `OAuth2AndOIDCClient.PushAuthorizationRequestAsync` を通る）。
        /// E2E は実装側のライブラリを使わないので、**相互接続性の確認はここにしか無い。**
        ///
        /// **預けた結果は画面に出す**（request_uri / expires_in）。目視で確かめるため。
        /// </remarks>
        private async Task<string> AssembleFAPI2ParStarterAsync(string response_type)
        {
            if (this.ClarifyRedirectUri)
            {
                string temp = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
                this.RedirectUri = CmnEndpoints.GetRedirectUriFromConstr(temp);
            }

            // テストコードで、clientを識別するために、Stateに細工する。
            SelfTestClient.PushResult ret = await SelfTestClient.PushAuthorizationRequestAsync(
                this.ClientId, response_type, this.ResponseMode, this.RedirectUri,
                OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":" + this.State, this.Nonce,
                SelfTestClient.SampleClaims());

            // 画面に出す（目視で確かめるもの）
            ViewBag.AuthRequestPushUri = ret.Endpoint;
            ViewBag.ClientId = this.ClientId;
            ViewBag.AuthMethod = OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit();
            ViewBag.RequestObject = ret.RequestObject;
            ViewBag.RequestObjectJson = ret.RequestObjectJson;
            ViewBag.Response = ret.Response;
            ViewBag.RequestUri = ret.RequestUri;
            ViewBag.ExpiresIn = ret.ExpiresIn;

            if (string.IsNullOrEmpty(ret.RequestUri))
            {
                // 預けられなかった（応答をそのまま画面で見せる）。
                return null;
            }

            // request_uri の認可リクエスト
            return this.OAuth2AuthorizeEndpoint + string.Format("?request_uri={0}", ret.RequestUri);
        }
        #endregion

        #region Back Channel

        #region Device AuthZ
        /// <summary>Device AuthZスターターを組み立てて返す</summary>
        /// <returns>組み立てたDevice AuthZスターター</returns>
        private async Task<ActionResult> AssembleDeviceAuthZStarterAsync()
        {
            // リクエスト
            string deviceAuthZAuthorizeEndpoint = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZAuthorizeEndpoint;
            string responseString = await Helper.GetInstance().DeviceAuthZRequestAsync(new Uri(deviceAuthZAuthorizeEndpoint), this.ClientId);

            // レスポンス
            JObject responseJObject = (JObject)JsonConvert.DeserializeObject(responseString);
            ViewBag.ClientId = this.ClientId;
            ViewBag.DeviceCode = (string)responseJObject[OAuth2AndOIDCConst.device_code];
            ViewBag.UserCode = (string)responseJObject[OAuth2AndOIDCConst.user_code];
            // **応答の verification_uri は絶対 URI である**（RFC 8628 3.2 : ユーザが別の端末で開く URL）。
            //   ここで RootURI を足していたため、URL が二重になり、
            //   **画面のリンクが 404 になっていた**（承認の画面に行けない）（#246）。
            ViewBag.VerificationUri = (string)responseJObject[OAuth2AndOIDCConst.verification_uri];
            ViewBag.VerificationUriComplete = (string)responseJObject[OAuth2AndOIDCConst.verification_uri_complete];

            // **interval と expires_in を画面に渡す**（#246 の 3-b）。
            //   RFC 8628 3.5 は、機器がこの間隔を空けて問い合わせることを求めている。
            //   ポーリングは次の POST で行うので、画面（hidden）で持ち回す。
            ViewBag.Interval = (string)responseJObject[OAuth2AndOIDCConst.PollingInterval];
            ViewBag.ExpiresIn = (string)responseJObject[OAuth2AndOIDCConst.expires_in];

            return View("DeviceAuthZResponse");
        }
        #endregion

        #region FAPI CIBA
        /// <summary>FAPI CIBA Profile を通し、結果の画面を返す</summary>
        /// <returns>ActionResult（CibaProfileResponse 画面）</returns>
        /// <remarks>
        /// **通しの本体は `SelfTestClient.RunCibaProfileAsync`**（#246 で両アプリから寄せた）。
        /// ここは client_id と login_hint を選び、結果を画面に渡すだけ。
        ///
        /// **以前は結果を URL（`?ret=OK_…`）で返していた**（#246 の 3-a）。
        /// `OK_` が接頭辞で、その後ろが判定という形だったため、
        /// **`?ret=OK_ABNORMAL_END` が成功なのか失敗なのか読めなかった。**
        /// </remarks>
        private async Task<ActionResult> AssembleFAPICibaProfileStarterAsync()
        {
            // **承認を待つ上限（秒）。**
            //   認証デバイスでの承認を待つが、待ち続けはしない（#246 の 3-b）。
            //   net48 の ASP.NET は要求を 110 秒（executionTimeout の既定）で打ち切るので、それより短くする。
            const int MaxWaitSeconds = 60;

            SelfTestClient.CibaResult result = await SelfTestClient.RunCibaProfileAsync(
                this.ClientId,      // FAPI2用か自前のクライアント
                "tanaka",           // プッシュ通知の対象となるアカウント（#151 の段階 3 で利用者名とメアドを分けた）
                MaxWaitSeconds);

            ViewBag.ClientId = this.ClientId;
            ViewBag.Verdict = result.Verdict;
            ViewBag.Reason = result.Reason;
            ViewBag.CibaAuthorizeEndpoint = result.Endpoint;
            ViewBag.RequestObject = result.RequestObject;
            ViewBag.RequestObjectJson = result.RequestObjectJson;
            ViewBag.AuthZResponse = result.AuthZResponse;
            ViewBag.AuthReqId = result.AuthReqId;
            ViewBag.Interval = result.Interval;
            ViewBag.ExpiresIn = result.ExpiresIn;
            ViewBag.PollIntervalSeconds = result.PollIntervalSeconds;
            ViewBag.PollCount = result.PollCount;
            ViewBag.WaitLimitSeconds = result.WaitLimitSeconds;
            ViewBag.TokenResponse = result.TokenResponse;
            ViewBag.UserInfoResponse = result.UserInfoResponse;

            return View("CibaProfileResponse");
        }
        #endregion

        #endregion

        #endregion

        #endregion

        #endregion

        #region Action Method

        #region Public

        #region Starters

        /// <summary>
        /// SAML2OAuth2Starters画面（初期表示）
        /// GET: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Saml2OAuth2Starters()
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return View("Index");
            }
            else
            {
                return View(new HomeSaml2OAuth2StartersViewModel()); 
            }
        }

        /// <summary>
        /// SAML2OAuth2Starters画面
        /// POST: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Saml2OAuth2Starters(HomeSaml2OAuth2StartersViewModel model)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return View("Index");
            }
            else
            {
                // AccountLoginViewModelの検証
                if (ModelState.IsValid)
                {
                    // RedirectUriの扱い
                    this.ClarifyRedirectUri = model.ClarifyRedirectUri;

                    #region Client選択
                    if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit())
                    {
                        // OAuth2.0 / OIDC用 Client
                        this.ClientName = "TestClient";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit())
                    {
                        // Financial-grade API - Part1用 Client
                        this.ClientName = "TestClient1";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
                    {
                        // Financial-grade API - Part2用 Client
                        this.ClientName = "TestClient2";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit())
                    {
                        // Device Authorization Grant用 Client
                        this.ClientName = "TestClient3";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit())
                    {
                        // Financial-grade API - CIBA用 Client
                        this.ClientName = "TestClient4";
                    }
                    else if (model.ClientType == HomeSaml2OAuth2StartersViewModel.RequirePkceClientType)
                    {
                        // **クライアント単位で PKCE を必須にした Client（#221）。**
                        //   登録（OAuth2ClientsInformation）で require_pkce = true。
                        //   これを選ぶと、**下のボタンはどれもこのクライアントで動く。**
                        //   PKCE を付けないフローは、認可エンドポイントで invalid_request になる。
                        this.ClientName = "TestClient6";
                    }
                    else
                    {
                        // ログイン・ユーザの Client
                        if (User.Identity.IsAuthenticated)
                        {
                            // ユーザの取得
                            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                            this.ClientName = user.UserName;
                        }
                    }
                    #endregion

                    #region ResponseMode選択
                    if(string.IsNullOrEmpty(model.ResponseMode))
                    {
                        this.ResponseMode = "";
                    }
                    else if (model.ResponseMode.ToLower().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = "query.jwt";
                    }
                    else if (model.ResponseMode.ToLower().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = "fragment.jwt";
                    }
                    else if (model.ResponseMode.ToLower().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = "form_post.jwt";
                    }
                    else
                    {
                        this.ResponseMode = model.ResponseMode;
                    }
                    #endregion

                    // **prompt と max_age は、そのまま渡す**（#246 の項目 3）。
                    //   値の妥当性はサーバ側が判断する（未対応の値を選んだときの振る舞いも見たいため）。
                    this.Prompt = model.Prompt ?? "";
                    this.MaxAge = model.MaxAge ?? "";

                    #region Starterの実行

                    // **ログアウトは、クライアントの選択に依らない**（#232）。
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.EndSession")))
                    {
                        return this.EndSession();
                    }

                    if (!string.IsNullOrEmpty(this.ClientName))
                    {
                        #region SAML2
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectRedirectBinding")))
                        {
                            return this.Saml2RedirectRedirectBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectPostBinding")))
                        {
                            return this.Saml2RedirectPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2PostPostBinding")))
                        {
                            return this.Saml2PostPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2PostRedirectBinding")))
                        {
                            // **4 つ目の組み合わせ**（#246 の項目 2）
                            return this.Saml2PostRedirectBinding();
                        }
                        #endregion

                        #region OAuth2

                        #region AuthorizationCode系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode")))
                        {
                            return this.AuthorizationCode();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_OIDC")))
                        {
                            return this.AuthorizationCode_OIDC();
                        }
                        #endregion

                        #region Implicit系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit")))
                        {
                            return this.Implicit();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC1")))
                        {
                            return this.Implicit_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC2")))
                        {
                            return this.Implicit_OIDC2();
                        }
                        #endregion

                        #region Hybrid系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC1")))
                        {
                            return this.Hybrid_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC2")))
                        {
                            return this.Hybrid_OIDC2();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC3")))
                        {
                            return this.Hybrid_OIDC3();
                        }
                        #endregion

                        #region PKCE系
                        if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_Plain"]))
                        {
                            return this.PKCE_Plain();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_S256"]))
                        {
                            return this.PKCE_S256();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_Plain_4SPA"]))
                        {
                            return this.PKCE_Plain(toSpa: true);
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_S256_4SPA"]))
                        {
                            return this.PKCE_S256(toSpa: true);
                        }
                        #endregion

                        #region F-API系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1")))
                        {
                            return this.AuthorizationCodeFAPI1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_OIDC")))
                        {
                            return this.AuthorizationCodeFAPI1_OIDC();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_PKCE")))
                        {
                            return this.AuthorizationCodeFAPI1_PKCE();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI2")))
                        {
                            return await this.AuthorizationCodeFAPI2Async();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI2_PAR")))
                        {
                            return await this.AuthorizationCodeFAPI2ParAsync();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.FAPI_CIBA_Profile")))
                        {
                            return await this.FAPICibaProfileAsync();
                        }
                        #endregion

                        #region Another系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.ResourceOwnerPasswordCredentialsFlow")))
                        {
                            return await this.ResourceOwnerPasswordCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.ClientCredentialsFlow")))
                        {
                            return await this.ClientCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.JWTBearerTokenFlow")))
                        {
                            return await this.JWTBearerTokenFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.DeviceAuthZGrant")))
                        {
                            return await this.DeviceAuthZAsync();
                        }
                        #endregion

                        #endregion
                    }
                    #endregion
                }

                // 再表示
                return View(model);
            }
        }

        #endregion

        #region Device AuthZ

        /// <summary>
        /// DeviceAuthZResponse画面（ポーリングして、結果の画面を返す）
        /// POST: /Home/DeviceAuthZResponse
        /// </summary>
        /// <param name="formData">FormCollection</param>
        /// <returns>ActionResult（DeviceAuthZPollingResult 画面）</returns>
        /// <remarks>
        /// **ポーリングの本体は `SelfTestClient.RunDeviceAuthZPollingAsync`**（#246 で両アプリから寄せた）。
        ///
        /// **以前は結果を URL（`?ret=OK_…`）で返していた**（#246 の 3-a。CIBA と同じ）。
        /// `OK_` が接頭辞で、その後ろが判定という形だったため、
        /// **`?ret=OK_ABNORMAL_END` が成功なのか失敗なのか読めなかった。**
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> DeviceAuthZResponse(FormCollection formData)
        {
            // **承認を待つ上限（秒）。**
            //   利用者が user_code を入れて許可するまで待つが、待ち続けはしない（#246 の 3-b）。
            //   net48 の ASP.NET は要求を 110 秒（executionTimeout の既定）で打ち切るので、それより短くする。
            const int MaxWaitSeconds = 60;

            string client_id = formData[OAuth2AndOIDCConst.client_id];
            string device_code = formData[OAuth2AndOIDCConst.device_code];
            string interval = formData[OAuth2AndOIDCConst.PollingInterval];

            SelfTestClient.DeviceAuthZResult result = await SelfTestClient.RunDeviceAuthZPollingAsync(
                client_id, device_code, interval, MaxWaitSeconds);

            ViewBag.ClientId = client_id;
            ViewBag.Verdict = result.Verdict;
            ViewBag.Reason = result.Reason;
            ViewBag.TokenEndpoint = result.TokenEndpoint;
            ViewBag.Interval = result.Interval;
            ViewBag.PollIntervalSeconds = result.PollIntervalSeconds;
            ViewBag.PollCount = result.PollCount;
            ViewBag.WaitLimitSeconds = result.WaitLimitSeconds;
            ViewBag.TokenResponse = result.TokenResponse;
            ViewBag.UserInfoResponse = result.UserInfoResponse;

            return View("DeviceAuthZPollingResult");
        }

        #endregion

        #endregion

        #region Private

        #region SAML2

        /// <summary>Test Saml2 Redirect & Redirect Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectRedirectBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpRedirect,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Redirect & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpPost,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Post & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2PostPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string samlRequest = SAML2Client.CreatePostRequest(
                SAML2Enum.ProtocolBinding.HttpPost,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Post
            ViewData["RelayState"] = this.State;
            ViewData["SAMLRequest"] = samlRequest;
            ViewData["Action"] = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            return View("PostBinding");
        }

        /// <summary>Test Saml2 Post & Redirect Binding</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **4 つ目の組み合わせ**（#246 の項目 2）。
        /// 要求を POST で送り、**応答は Redirect（GET）で受ける**。
        /// `ProtocolBinding` が応答の受け取り方を決めるので、`HttpRedirect` を渡す。
        /// </remarks>
        private ActionResult Saml2PostRedirectBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string samlRequest = SAML2Client.CreatePostRequest(
                SAML2Enum.ProtocolBinding.HttpRedirect,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Post
            ViewData["RelayState"] = this.State;
            ViewData["SAMLRequest"] = samlRequest;
            ViewData["Action"] = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            return View("PostBinding");
        }

        #endregion

        #region OAuth2

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Authorization Code Flow (OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_OIDC()
        {
            this.InitOAuth2Params();

            // Assemble
            // **prompt は固定しない**（#272 の段階 2）。
            //   以前は、画面で選んでいなければ **`prompt=none` を付けていた**
            //   （同意画面を飛ばして 1 回のクリックで通すため）。
            //   **同意を記録するようになったので、それでは回らない。**
            //   **記録が無い配備では、初回に必ず `consent_required` になる。**
            //   いまは**初回だけ同意画面を通る**（2 回目以降は記録が効いて飛ぶ）。
            //   **`prompt` を試したいときは、画面の選択で指定する**（#246 の項目 3）。
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region PKCE

        /// <summary>Test Authorization Code Flow (PKCE plain)</summary>
        /// <param name="toSpa">bool</param>
        /// <returns>ActionResult</returns>
        private ActionResult PKCE_Plain(bool toSpa = false)
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_plain;

            // Authorization Code Grant Flow with PKCE
            if (toSpa) redirect += "&response_mode=fragment";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (PKCE S256)</summary>
        /// <param name="toSpa">bool</param>
        /// <returns>ActionResult</returns>
        private ActionResult PKCE_S256(bool toSpa = false)
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256;

            // Authorization Code Grant Flow with PKCE
            if (toSpa) redirect += "&response_mode=fragment";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Implicit Flow

        #region OAuth2

        /// <summary>Test Implicit Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.ImplicitResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Implicit Flow 'id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC1()
        {
            this.InitOAuth2Params();

            // Assemble 'id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit1_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC2()
        {
            this.InitOAuth2Params();

            // Assemble 'id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit2_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Hybrid Flow

        #region OIDC

        /// <summary>Test Hybrid Flow 'code id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC1()
        {
            this.InitOAuth2Params();

            // Assemble 'code id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC2()
        {
            this.InitOAuth2Params();

            // Assemble 'code token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC3()
        {
            this.InitOAuth2Params();

            // Assemble 'code id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid3_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Financial-grade API

        #region FAPI1

        /// <summary>Test Authorization Code Flow (FAPI1)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleFAPI1Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (FAPI1, OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_OIDC()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (FAPI1 PC, PKCE)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_PKCE()
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);

            // Assemble
            // **S256 で計算した値なので、宣言も S256 にする**（#245 の段階 2）。
            //   plain と宣言していたため、トークン要求で challenge == verifier の比較になり、
            //   **このボタンは必ず失敗していた**（FAPI 1.0 Advanced も S256 を求める）。
            string redirect = this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256;

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region FAPI2

        /// <summary>Test Authorization Code Flow (FAPI2)</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> AuthorizationCodeFAPI2Async()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = await this.AssembleFAPI2CCStarterAsync(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (FAPI2 CC, PAR)（#246）</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **預けた結果を画面で見せてから、続けて認可へ進む。**
        /// 他のスターターのように直接リダイレクトしないのは、
        /// **request_uri と expires_in を目視で確かめる**ため（#246）。
        /// </remarks>
        private async Task<ActionResult> AuthorizationCodeFAPI2ParAsync()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = await this.AssembleFAPI2ParStarterAsync(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            ViewBag.AuthorizeUrl = redirect;

            return View("PushedAuthorizationResponse");
        }


        #endregion

        #region CIBA

        /// <summary>Test FAPI CIBA Profile</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> FAPICibaProfileAsync()
        {
            this.InitOAuth2Params();

            // Assemble（結果の画面まで組み立てる。#246 の 3-a）
            return await this.AssembleFAPICibaProfileStarterAsync();
        }

        #endregion

        #endregion

        #region Another Flow

        #region Resource Owner Password Credentials Flow

        /// <summary>ResourceOwnerPasswordCredentialsFlow</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> ResourceOwnerPasswordCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            string response = await Helper.GetInstance()
                .ResourceOwnerPasswordCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, Config.AdministratorUID, Config.AdministratorPWD, Const.StandardScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region Client Credentials Flow

        /// <summary>ClientCredentialsFlow</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> ClientCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            string response = await Helper.GetInstance()
                .ClientCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, Const.StandardScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>JWTBearerTokenFlow</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> JWTBearerTokenFlow()
        {
            // ClientNameから、client_id(iss)を取得。
            string iss = Helper.GetInstance().GetClientIdByName(this.ClientName);

            // **アサーションの組み立ては SelfTestClient**（#246。aud はトークン エンドポイント）。
            string response = await Helper.GetInstance().JwtBearerTokenFlowAsync(
                new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                SelfTestClient.CreateClientAssertion(
                    iss, Config.OAuth2AccessTokenExpireTimeSpanFromMinutes, Const.StandardScopes));

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region Device AuthZ

        /// <summary>Test Device AuthZ</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> DeviceAuthZAsync()
        {
            this.InitOAuth2Params();
            //this.SaveOAuth2Params();
            return await this.AssembleDeviceAuthZStarterAsync();
        }

        #endregion

        #region RP-Initiated Logout（#232）

        /// <summary>Test RP-Initiated Logout</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **この画面は id_token を持っていない**ので、`id_token_hint` を付けずに要求する。
        /// つまり **RP-Initiated Logout 1.0 §2 の「確認しなければならない」経路**を手で試すもの。
        ///
        /// **`id_token_hint` 付きの本筋**（確認なしでログアウトし、`post_logout_redirect_uri` へ戻る）は、
        /// 認可コード フローの結果画面（`Account/OAuth2AuthorizationCodeGrantClient`）のボタンで試す。
        /// 合否の自動判定は E2E（`RT-232`）が持つ。ここはブラウザの Cookie が絡むため、
        /// **サーバ側の自己テストでは「消えたか」を確かめられない。**
        /// </remarks>
        private ActionResult EndSession()
        {
            return Redirect(Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.OAuth2EndSessionEndpoint);
        }

        #endregion


        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}