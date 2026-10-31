//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストの FAPI（FAPI1・FAPI2・CIBA）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.TokenProviders;

using System.Web.Mvc;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストの FAPI（FAPI1・FAPI2・CIBA））</summary>
    public partial class HomeController
    {
        #region Assemble

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
                    this.ClientId, response_type, Const.SelfTestScopes,
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

        #region Action Method

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

        #endregion
    }
}