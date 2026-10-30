//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：OAuth2EndpointController
//* クラス日本語名  ：OAuth2EndpointController の プッシュ通知
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Util;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（プッシュ通知）</summary>
    public partial class OAuth2EndpointController
    {
        #region プッシュ通知

        /// <summary>
        /// ユーザ情報にデバイス・トークンを追加
        /// POST: /SetDeviceToken
        /// </summary>
        /// <param name="formData">
        /// - device_token
        /// </param>
        /// <returns>
        /// 成功は 200 と "OK"。失敗は本文 "NG" のまま、
        /// トークンの不備は 401（WWW-Authenticate: Bearer）、パラメタの不備は 400（#196）
        /// </returns>
        /// <remarks>
        /// 認証デバイス（authentication_device）が、サインインの後に呼ぶ（端末の登録）。
        /// </remarks>
        [HttpPost]
        [MpasBrowserApiCors]   // 同上
        public async Task<IHttpActionResult> SetDeviceToken(FormDataCollection formData)
        {
            string device_token = (formData == null) ? null : (string)formData[Const.ParamDeviceToken];

            if (string.IsNullOrEmpty(device_token))
            {
                // パラメタの不備（#196 : 400）
                return this.NGResult(400, "SetDeviceToken", null);
            }

            // クライアント認証（Bearer トークン）
            if (!AuthenticationHeader.GetAccessToken(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken, out string authScheme))
            {
                // トークンが無い（RFC 6750 3.1 : エラー コードを付けない）（#196 : 401）
                return this.NGResult(401, "SetDeviceToken", null);
            }

            // 証明書に紐づくトークンは、その証明書を提示した要求でしか使えない（RFC 8705 3）
            //  **`out` の変数は、条件の前で宣言する**（#311 の段階 4）。
            //    **`&&` で呼ばれないことが在る**ので、
            //    **条件の中で宣言すると「代入されていない」ことになる。**
            string dpopError = null;

            if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity)
                && Token.CmnAccessToken.VerifyCertificateBinding(identity, Request.GetClientCertificate())
                //  **DPoP に縛られたトークンは、その鍵の証明と一緒でしか使えない**
                //    （RFC 9449 §7.1。#311 の段階 2）。
                && this.VerifyDPoP(identity, bearerToken, authScheme == OAuth2AndOIDCConst.DPoP, out dpopError))
            {
                // ClientIdの取り出し
                Claim ClientId = identity.Claims.Where(
                    x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                ApplicationUser user =
                    //CmnUserStore.FindByName(identity.Name);
                    PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);

                if (user != null)
                {
                    // デバイストークンの保存
                    user.DeviceToken = device_token;
                    await UserManager.UpdateAsync(user);

                    return this.Ok("OK");
                }
            }

            // 無効なトークン、またはユーザの無いトークン（RFC 6750 3.1 : invalid_token）（#196 : 401）
            return this.NGResult(401, "SetDeviceToken",
                dpopError ?? OAuth2AndOIDCConst.invalid_token);
        }

        /// <summary>
        /// 2FAのプッシュ承認を受信
        /// POST: /2fa_result
        /// </summary>
        /// <param name="formData">code</param>
        /// <returns>
        /// 成功は 200 と "OK"。失敗は本文 "NG" のまま、
        /// トークンの不備は 401（WWW-Authenticate: Bearer）、コードの不備は 400（#216）
        /// </returns>
        /// <remarks>
        /// 認証デバイス（authentication_device）が、プッシュ通知で受け取った 2FA のコードを送り返す。
        /// **ブラウザの 2FA セッションは Cookie にあり、端末からは触れない**ので、
        /// ここでは「誰がどのコードを承認したか」を記録するだけ。
        /// サインインを完了させるのは、待っているブラウザ側（Account/TwoFactorPushStatus）。
        ///
        /// net10.0 版（#213）との違いは、コードを作ったプロバイダの名前だけ。
        /// net48 版は MobileApp のプロバイダを登録しているので、それで検証する。
        /// </remarks>
        [HttpPost]
        [MpasBrowserApiCors]   // 同上
        public async Task<IHttpActionResult> TwoFactorPushResult(FormDataCollection formData)
        {
            // クライアント認証（Bearer トークン）
            if (!AuthenticationHeader.GetAccessToken(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken, out string authScheme))
            {
                // トークンが無い（RFC 6750 3.1 : エラー コードを付けない）
                return this.NGResult(401, Const.EndpointTwoFactorResult, null);
            }

            ApplicationUser user = null;

            // 証明書に紐づくトークンは、その証明書を提示した要求でしか使えない（RFC 8705 3）
            //  **`out` の変数は、条件の前で宣言する**（#311 の段階 4）。
            //    **`&&` で呼ばれないことが在る**ので、
            //    **条件の中で宣言すると「代入されていない」ことになる。**
            string dpopError = null;

            if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity)
                && Token.CmnAccessToken.VerifyCertificateBinding(identity, Request.GetClientCertificate())
                //  **DPoP に縛られたトークンは、その鍵の証明と一緒でしか使えない**
                //    （RFC 9449 §7.1。#311 の段階 2）。
                && this.VerifyDPoP(identity, bearerToken, authScheme == OAuth2AndOIDCConst.DPoP, out dpopError))
            {
                // ClientIdの取り出し
                Claim ClientId = identity.Claims.Where(
                    x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                user = PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);
            }

            if (user == null)
            {
                // 無効なトークン、またはユーザの無いトークン（RFC 6750 3.1 : invalid_token）
                return this.NGResult(401, Const.EndpointTwoFactorResult,
                dpopError ?? OAuth2AndOIDCConst.invalid_token);
            }

            string code = (formData == null) ? null : (string)formData["code"];

            if (string.IsNullOrEmpty(code))
            {
                // パラメタの不備
                return this.NGResult(400, Const.EndpointTwoFactorResult, null);
            }

            // **保存する前に、そのコードがこの利用者のものかを確かめる。**
            //   他人のコードや、期限切れ・でたらめなコードを記録させないため。
            //   プロバイダは、送信時（MobileAppTokenProvider）と揃える。
            if (!await UserManager.VerifyTwoFactorTokenAsync(
                user.Id, MobileAppTokenProvider.ProviderName, code))
            {
                // 合わないコード（存在を推測させないよう、パラメタの不備と同じ応答にする）
                return this.NGResult(400, Const.EndpointTwoFactorResult, null);
            }

            // 承認を記録する（待っているブラウザが拾う）
            Sts.TwoFactorPushProvider.Create(user.Id, code);

            return this.Ok("OK");
        }

        #endregion
    }
}