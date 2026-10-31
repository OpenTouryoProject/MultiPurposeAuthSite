//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストのその他のフロー（ROPC・Client Credentials・JWT Bearer・Device AuthZ・RP-Initiated Logout）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         DeviceAuthZResponse を IsLockedDownTestEndpoints で閉じ、AntiForgery を確かめる。ROPC はテスト利用者で。応答が JSON でなくても 500 にしない（#294）
//*  2026/10/31  玄人 幸道         Device AuthZ の開始も、応答が壊れていても 500 にしない（#294）
//*  2026/10/31  玄人 幸道         Device AuthZ の開始で、/device_authz が断った理由を画面に出す（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.Test;

using System;
using System.Globalization;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストのその他のフロー（ROPC・Client Credentials・JWT Bearer・Device AuthZ・RP-Initiated Logout））</summary>
    public partial class HomeController
    {
        #region Assemble

        #region Device AuthZ
        /// <summary>Device AuthZスターターを組み立てて返す</summary>
        /// <returns>組み立てたDevice AuthZスターター</returns>
        private async Task<ActionResult> AssembleDeviceAuthZStarterAsync()
        {
            // リクエスト
            string deviceAuthZAuthorizeEndpoint = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZAuthorizeEndpoint;
            string responseString = await Helper.GetInstance().DeviceAuthZRequestAsync(new Uri(deviceAuthZAuthorizeEndpoint), this.ClientId);

            // レスポンス
            //   **壊れていても 500 にしない**（#294。読めない項目は空で出す）。
            JObject parsed = HomeController.ReadJson(responseString);
            JObject responseJObject = parsed ?? new JObject();
            ViewBag.ClientId = this.ClientId;
            ViewBag.DeviceCode = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.device_code);
            ViewBag.UserCode = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.user_code);
            // **応答の verification_uri は絶対 URI である**（RFC 8628 3.2 : ユーザが別の端末で開く URL）。
            //   ここで RootURI を足していたため、URL が二重になり、
            //   **画面のリンクが 404 になっていた**（承認の画面に行けない）（#246）。
            ViewBag.VerificationUri = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.verification_uri);
            ViewBag.VerificationUriComplete = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.verification_uri_complete);

            // **interval と expires_in を画面に渡す**（#246 の 3-b）。
            //   RFC 8628 3.5 は、機器がこの間隔を空けて問い合わせることを求めている。
            //   ポーリングは次の POST で行うので、画面（hidden）で持ち回す。
            ViewBag.Interval = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.PollingInterval);
            ViewBag.ExpiresIn = HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.expires_in);

            // **断られたら、理由を出す**（#294。以前は項目が空になるだけだった）。
            //   例 : Device の許可を持たないクライアント、クライアント証明書を提示して公開クライアントが 401 になる配備（#226）。
            if (string.IsNullOrEmpty((string)ViewBag.DeviceCode))
            {
                ViewBag.Error = (parsed == null)
                    ? "The response is not a JSON object: " + (responseString ?? "")
                    : HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.error)
                        + " : " + HomeController.ReadString(responseJObject, OAuth2AndOIDCConst.error_description);
            }

            return View("DeviceAuthZResponse");
        }
        #endregion

        #endregion

        #region Action Method

        #region Device AuthZ

        /// <summary>
        /// DeviceAuthZResponse画面（ポーリングして、結果の画面を返す）
        /// POST: /Home/DeviceAuthZResponse
        /// </summary>
        /// <param name="formData">IFormCollection</param>
        /// <returns>ActionResult（DeviceAuthZPollingResult 画面）</returns>
        /// <remarks>
        /// **ポーリングの本体は `SelfTestClient.RunDeviceAuthZPollingAsync`**（#246 で両アプリから寄せた）。
        ///
        /// **以前は結果を URL（`?ret=OK_…`）で返していた**（#246 の 3-a。CIBA と同じ）。
        /// `OK_` が接頭辞で、その後ろが判定という形だったため、
        /// **`?ret=OK_ABNORMAL_END` が成功なのか失敗なのか読めなかった。**
        ///
        /// **`IsLockedDownTestEndpoints` で閉じる**（#294）。**以前は閉じておらず**、
        /// 本番で自己テストを閉じても、**この口だけは匿名で使えた**（サーバに自分の `/token` を問い合わせさせる）。
        /// **AntiForgery トークンも確かめる**（画面は出していたが、確かめていなかった）。
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeviceAuthZResponse(IFormCollection formData)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return View("Index");
            }

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

        #region Another Flow

        /// <summary>応答を JSON のオブジェクトとして読む（#294）</summary>
        /// <param name="response">応答</param>
        /// <returns>JObject（JSON のオブジェクトでなければ null）</returns>
        /// <remarks>
        /// **JSON でない応答でも 500 にしない**（以前は決め打ちで読み、例外になった）。
        /// **応答はそのまま画面に出す**ので、何が返ったかはそこで分かる。
        /// </remarks>
        private static JObject ReadJson(string response)
        {
            try
            {
                return JsonConvert.DeserializeObject(response ?? "") as JObject;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        /// <summary>JSON の値を文字列で読む（#294）</summary>
        /// <param name="json">JObject</param>
        /// <param name="name">名前</param>
        /// <returns>値（無い・値でなければ空）</returns>
        /// <remarks>
        /// **`(string)` の変換は、配列やオブジェクトだと `ArgumentException` を投げる**ので使わない。
        /// **数値も読む**（`interval` / `expires_in` は JSON の数値。C-55 のレビュー）。
        /// </remarks>
        private static string ReadString(JObject json, string name)
        {
            JValue value = (json == null) ? null : json[name] as JValue;

            return (value == null || value.Value == null)
                ? "" : Convert.ToString(value.Value, CultureInfo.InvariantCulture);
        }

        /// <summary>トークン応答から access_token を読む（#294）</summary>
        /// <param name="response">トークン応答</param>
        /// <returns>access_token（読めなければ空）</returns>
        private static string ReadAccessToken(string response)
        {
            return HomeController.ReadString(HomeController.ReadJson(response), OAuth2AndOIDCConst.AccessToken);
        }

        #region Resource Owner Password Credentials Flow

        /// <summary>Test Resource Owner Password Credentials Flow</summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **資源の持ち主は、テスト利用者（`tanaka`）**（#294）。
        /// **以前は管理者（`AdministratorUID` / `AdministratorPWD`）で取っていた**ので、
        /// 自己テストの口が開いている間は、**ログインしていない人にも管理者のトークンを画面で見せていた。**
        /// **`TestUserPWD` が無ければ、トークンを取らずに理由を出す**（テスト利用者が作られていないため）。
        /// </remarks>
        private async Task<ActionResult> ResourceOwnerPasswordCredentialsFlow()
        {
            if (string.IsNullOrEmpty(Config.TestUserPWD))
            {
                ViewBag.Response = "TestUserPWD is not configured. The self-test ROPC uses the test user.";
                ViewBag.AccessToken = "";
                return View("OAuth2ClientAuthenticationFlow");
            }

            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            string response = await Helper.GetInstance()
                .ResourceOwnerPasswordCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, "tanaka" + Config.TestUserSuffix, Config.TestUserPWD, Const.SelfTestScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = HomeController.ReadAccessToken(response);

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region Client Credentials Flow

        /// <summary>Test Client Credentials Flow</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> ClientCredentialsFlow()
        {
            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            string response = await Helper.GetInstance()
                .ClientCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, Const.SelfTestScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = HomeController.ReadAccessToken(response);

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>Test JWT Bearer Token Flow</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> JWTBearerTokenFlow()
        {
            // ClientNameから、client_id(iss)を取得。
            string iss = Helper.GetInstance().GetClientIdByName(this.ClientName);

            // **アサーションの組み立ては SelfTestClient**（#246。aud はトークン エンドポイント）。
            string response = await Helper.GetInstance().JwtBearerTokenFlowAsync(
                new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                SelfTestClient.CreateClientAssertion(
                    iss, Config.OAuth2AccessTokenExpireTimeSpanFromMinutes, Const.SelfTestScopes));

            ViewBag.Response = response;
            ViewBag.AccessToken = HomeController.ReadAccessToken(response);

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
    }
}