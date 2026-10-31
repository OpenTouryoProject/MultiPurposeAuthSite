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
//* クラス日本語名  ：OAuth2EndpointのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2018/12/26  西野 大介         分割
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/08/01  西野 大介         client_secret_postのサポートを追加
//*  2019/12/25  西野 大介         PPID対応による見直し（SamlMetadata）
//*  2020/01/07  西野 大介         PPID対応実施（GetUserClaims）
//*  2020/02/27  西野 大介         FAPI CIBA対応実施（CibaAuthorize, CibaPushResult）
//*  2020/03/09  西野 大介         FormDataCollectionチェック処理の強化
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2020/12/18  西野 大介         Device AuthZ対応実施（DeviceAuthZAuthorize）
//*                                ・DeviceAuthZResponse画面 → HomeControllerに。
//*                                ・DeviceAuthZVerify画面 → AccountControllerに。
//*  2020/12/21  西野 大介         CIBAのTokenのsubを認可ユーザに変更
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/08  玄人 幸道         Device AuthZのクライアント認証を追加（#193）
//*  2026/09/08  玄人 幸道         revoke/introspectの所有者確認を追加（#194）
//*  2026/09/11  玄人 幸道         /revoke /introspect を RFC 7009 / 7662 に合わせて修正（#200）
//*  2026/09/11  玄人 幸道         /token のエラー応答を 400 / 401 で返す（#196）
//*  2026/09/11  玄人 幸道         /revoke のエラー応答を 400 / 401 で返す。/token と共用するエラー応答を共通の region へ（#196）
//*  2026/09/13  玄人 幸道         CIBAの返答に所有者確認を追加。メモリ ストアの取り違えも修正
//*  2026/09/16  玄人 幸道         /ciba_authz : 端末未登録・FCM送信失敗を JSON のエラー応答にする（#210）
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認（/2fa_result）を追加（#216）
//*  2026/09/17  玄人 幸道         トークン応答に Cache-Control: no-store / Pragma: no-cache を付ける（#218）
//*  2026/09/22  玄人 幸道         Device AuthZ グラントでも、登録種別を判定する（#224）
//*  2026/09/23  玄人 幸道         証明書に紐づくトークン（cnf）を、提示された証明書と照合する
//*  2026/09/24  玄人 幸道         /ros の応答に有効期限（exp）を入れ、CIBA では使い終わった Request Object を消す（#188）
//*  2026/09/24  玄人 幸道         PAR（RFC 9126）の /par を追加（#229）
//*  2026/09/24  玄人 幸道         /ciba_authz で request を直接受け取る（CIBA Core 7.1.1。#233）
//*  2026/09/25  玄人 幸道         /ciba_authz にクライアント認証を入れる（CIBA Core 7.1。#234 の段階 3）
//*  2026/09/25  玄人 幸道         profile / address のクレームを、設定の対応付けから返す（#230）
//*  2026/09/25  玄人 幸道         client_assertion を読む（グラント用の assertion とは別に持つ）（#238）
//*  2026/09/26  玄人 幸道         refresh_token / ROPC / client_credentials と /revoke・/introspect で非対称の認証を受ける（#239）
//*  2026/09/27  玄人 幸道         Basic の資格情報を復号して照合する（#237）
//*  2026/10/01  玄人 幸道         CIBA の認可コードに、sub ではなく利用者名を入れるようにした（#151 の段階 4）
//*  2026/10/04  玄人 幸道         CORSを口ごとの属性にし、資格情報付きを止めた
//*  2026/10/14  玄人 幸道         /samlmetadata の組み立てを CmnSamlMetadata へ寄せた（#292 の段階 3）
//*  2026/10/16  玄人 幸道         /jwkcerts を覚えて返す（Cache-Control / ETag / 304）（#303）
//*  2026/10/21  玄人 幸道         /token で DPoP の証明を受け取る（#311 の段階 1）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//*  2026/10/25  玄人 幸道         エラー応答（OAuth2Error / NGResult / /userinfo）を OPERATION に記録する（障害対応のため。#294）
//*  2026/10/29  玄人 幸道         CIBA を client_assertion（private_key_jwt）で通す（/ciba_authz の client_id・/token。#294）
//*  2026/10/30  玄人 幸道         partial に分割（Token / UserInfo / Revocation / DeviceAuthZ / Ciba / RequestObject / Metadata / Push。#294）
//*  2026/10/30  玄人 幸道         認証デバイス用の口を、認証デバイスのクライアントに発行したトークンに限る判定を追加（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Manager;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;

using System.Web;
using System.Web.Http;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;   // ETag / Cache-Control（#303）

using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointのApiController（ライブラリ）</summary>
    //  **CORS はクラスに付けない。** **口ごとに属性で選ぶ**（net10.0 版の #265 と揃える）。
    //    以前はここに次が付いていた。
    //      [EnableCors(origins: "*", headers: "*", methods: "*", SupportsCredentials = true)]
    //    **`origins: "*"` と `SupportsCredentials = true` を同時に指定すると、
    //    System.Web.Http.Cors は Allow-Origin に要求の Origin を反映し、
    //    Allow-Credentials: true を付ける。**
    //    **任意のオリジンから、利用者の Cookie を伴った要求が許されていた**（実測）。
    //  **付けていない口は CORS 無し**（ブラウザから叩く口ではない）。
    //    /revoke /introspect /device_authz /ciba_authz /par /ros
    [MyBaseAsyncApiController(httpAuthHeader: EnumHttpAuthHeader.None)] // 認証無し（自前）
    public partial class OAuth2EndpointController : ApiController
    {
        #region constructor

        /// <summary>constructor</summary>
        public OAuth2EndpointController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        #endregion

        #region キャッシュ制御

        /// <summary>
        /// トークンを含む応答が、キャッシュに残らないようにする（#218）
        /// </summary>
        /// <remarks>
        /// RFC 6749 5.1（成功）/ 5.2（エラー）は、
        /// **Cache-Control: no-store と Pragma: no-cache を MUST** としている。
        /// 中間のキャッシュやブラウザの履歴にトークンを残さないため。
        ///
        /// **アクションの入口で呼ぶ。** 成功・エラーのどちらの経路でも返すため。
        ///
        /// **System.Web の Response.Cache を使う。** ヘッダを直接書いても、
        /// ASP.NET のキャッシュ モジュールに上書きされることがあるため。
        /// SetCacheability(NoCache) が Pragma: no-cache も付ける。
        /// </remarks>
        private void SetNoStore()
        {
            HttpResponse response = HttpContext.Current.Response;

            response.Cache.SetCacheability(HttpCacheability.NoCache);
            response.Cache.SetNoStore();
        }

        #endregion

        #region 認証デバイスのトークン（#294）

        /// <summary>認証デバイスのクライアントに発行したトークンか（#294）</summary>
        /// <param name="audience">トークンの aud（`UrnAudienceClaim`。無ければ null）</param>
        /// <returns>認証デバイスのものなら true</returns>
        /// <remarks>
        /// **`/SetDeviceToken`・`/ciba_result`・`/2fa_result` は、このトークンだけを受ける**（`AuthenticationDeviceClientIds`）。
        /// **以前は発行先を見ておらず**、利用者が同意した**どの RP のトークンでも**、
        /// 端末の登録を差し替え、CIBA の要求を「許可」し、2FA のプッシュ承認を記録できた。
        /// **aud が無いトークンも断る**（自分が発行するトークンには必ず載る）。
        /// </remarks>
        private static bool IsAuthenticationDeviceToken(Claim audience)
        {
            return audience != null
                && Config.AuthenticationDeviceClientIds.Contains(audience.Value, StringComparer.Ordinal);
        }

        #endregion

        #region 共通のエラー応答

        /// <summary>エラー応答を記録する（障害対応のため。#294）</summary>
        /// <param name="status">HTTP ステータス</param>
        /// <param name="err">error / error_description（無ければ null）</param>
        private void TraceErrorResponse(int status, Dictionary<string, string> err)
        {
            Logging.MyOperationTraceForErrorResponse(
                HttpContext.Current.Request.Path, status, err, this.ClientIdForLog());
        }

        /// <summary>ログに出す client_id（Basic 認証 → フォームの順。分からなければ空）</summary>
        /// <returns>client_id</returns>
        private string ClientIdForLog()
        {
            try
            {
                HttpRequest request = HttpContext.Current.Request;
                string clientId = RateLimitProvider.ClientIdFromAuthorizationHeader(
                    request.Headers[Const.HeaderAuthorization]);

                if (string.IsNullOrEmpty(clientId))
                {
                    clientId = request.Form[OAuth2AndOIDCConst.client_id];
                }

                return clientId ?? "";
            }
            catch
            {
                //  **記録のために、応答を落とさない。**
                return "";
            }
        }

        /// <summary>
        /// クライアント認証を行うエンドポイント（/token・/revoke・/introspect・/device_authz・/ciba_authz）のエラー応答を作る（RFC 6749 5.2）
        /// </summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <param name="realm">WWW-Authenticate の realm（エンドポイントの名前。null なら WWW-Authenticate を付けない）</param>
        /// <returns>400、または 401（invalid_client）</returns>
        /// <remarks>
        /// 以前は Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// 本文（error / error_description の JSON）は変えない。
        /// /revoke のエラーも RFC 6749 5.2 に従う（RFC 7009 2.2.1）ので、/token の region から移して共用する（#196）。
        /// /introspect のクライアント認証の失敗も、RFC 6749 5.2 のとおり 401（RFC 7662 2.3）。
        /// /device_authz のクライアント認証は /token と同じ（RFC 8628 3.1）なので、エラーも同じく返す。
        /// /ciba_authz は HTTP 認証ではなく署名した要求でクライアントを識別するので、realm に null を渡す（CIBA Core 13）。
        /// </remarks>
        private IHttpActionResult OAuth2Error(Dictionary<string, string> err, string realm)
        {
            HttpStatusCode status = (HttpStatusCode)Token.CmnEndpoints.GetErrorStatusCode(err);
            HttpResponseMessage res = this.Request.CreateResponse(status, err);

            this.TraceErrorResponse((int)status, err);

            if (status == HttpStatusCode.Unauthorized && realm != null)
            {
                // クライアント認証の失敗。受け付ける認証方式を示す。
                // Authorization ヘッダで認証を試みたクライアントには必須（RFC 6749 5.2）。
                res.Headers.WwwAuthenticate.Add(
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "realm=\"" + realm + "\""));
            }

            //  **nonce が要るなら、新しい値を渡す**（RFC 9449 §8。#311 の段階 4）。
            //    **成功応答には付けない** — **窓（5〜10 分）が切れたら 1 往復増える。**
            if (err != null
                && err.TryGetValue(OAuth2AndOIDCConst.error, out string error)
                && error == OAuth2AndOIDCConst.use_dpop_nonce)
            {
                res.Headers.Add(OAuth2AndOIDCConst.HttpHeader_DPoPNonce,
                    Sts.CmnDPoP.CurrentNonce(Sts.CmnDPoP.PurposeAs));
            }

            return this.ResponseMessage(res);
        }

        /// <summary>
        /// 文字列（OK / NG）で答えるエンドポイント（/SetDeviceToken・/ciba_result）の失敗の応答を作る
        /// </summary>
        /// <param name="status">HTTP ステータス（400 / 401）</param>
        /// <param name="realm">WWW-Authenticate の realm（401 のとき）</param>
        /// <param name="error">WWW-Authenticate の error（トークンが無い場合は null）</param>
        /// <returns>本文が "NG" の応答</returns>
        /// <remarks>
        /// 認証デバイス（authentication_device）は、HTTP ステータスと本文の "OK" を見ている。
        /// 本文は従来の "NG" のまま、ステータスだけを 400 / 401 にする（#196）。
        /// 401 には、Bearer トークンが要ることを示す WWW-Authenticate を付ける（RFC 6750 3）。
        /// </remarks>
        private IHttpActionResult NGResult(int status, string realm, string error)
        {
            HttpResponseMessage res = this.Request.CreateResponse((HttpStatusCode)status, "NG");

            this.TraceErrorResponse(status,
                (error == null) ? null : new Dictionary<string, string>() { { OAuth2AndOIDCConst.error, error } });

            if (status == 401)
            {
                Dictionary<string, string> err = new Dictionary<string, string>();

                if (error != null)
                {
                    err.Add(OAuth2AndOIDCConst.error, error);
                }

                //  **`DPoP` スキームで来た要求には、`DPoP` で答える**（RFC 9449 §7.1。#311 の段階 4）。
                string scheme = AuthenticationHeader.GetChallengeScheme(HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization]);

                res.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue(
                    scheme, Token.CmnEndpoints.GetChallengeParameter(scheme, realm, err)));

                string nonce = Sts.CmnDPoP.NonceForChallenge(scheme == OAuth2AndOIDCConst.DPoP);

                if (nonce != null)
                {
                    res.Headers.Add(OAuth2AndOIDCConst.HttpHeader_DPoPNonce, nonce);
                }
            }

            return this.ResponseMessage(res);
        }

        #endregion
    }
}