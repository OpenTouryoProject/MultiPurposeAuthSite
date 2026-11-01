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
//*  2021/07/10  西野 大介         2FAにプッシュ通知を追加（AspNetCore.Identityのみ
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/08  玄人 幸道         Device AuthZのクライアント認証を追加（#193）
//*  2026/09/08  玄人 幸道         revoke/introspectの所有者確認を追加（#194）
//*  2026/09/11  玄人 幸道         /revoke /introspect を RFC 7009 / 7662 に合わせて修正（#200）
//*  2026/09/11  玄人 幸道         /token のエラー応答を 400 / 401 で返す（#196）
//*  2026/09/11  玄人 幸道         /revoke のエラー応答を 400 / 401 で返す。/token と共用するエラー応答を共通の region へ（#196）
//*  2026/09/13  玄人 幸道         CIBAの返答に所有者確認を追加。メモリ ストアの取り違えも修正
//*  2026/09/16  玄人 幸道         /ciba_authz : 端末未登録・FCM送信失敗を JSON のエラー応答にする（#210）
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認（/2fa_result）を追加（#213）
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
//*  2026/10/04  玄人 幸道         CORSを口ごとの属性にした（#265）
//*  2026/10/14  玄人 幸道         /samlmetadata の組み立てを CmnSamlMetadata へ寄せた（#292 の段階 3）
//*  2026/10/16  玄人 幸道         /jwkcerts を覚えて返す（Cache-Control / ETag / 304）（#303）
//*  2026/10/21  玄人 幸道         /token で DPoP の証明を受け取る（#311 の段階 1）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//*  2026/10/25  玄人 幸道         エラー応答（OAuth2Error / NGResult / /userinfo）を OPERATION に記録する（障害対応のため。#294）
//*  2026/10/29  玄人 幸道         CIBA を client_assertion（private_key_jwt）で通す（/ciba_authz の client_id・/token。#294）
//*  2026/10/30  玄人 幸道         partial に分割（Token / UserInfo / Revocation / DeviceAuthZ / Ciba / RequestObject / Metadata / Push。#294）
//*  2026/10/30  玄人 幸道         認証デバイス用の口を、認証デバイスのクライアントに発行したトークンに限る判定を追加（#294）
//**********************************************************************************

using MultiPurposeAuthSite;
using MultiPurposeAuthSite.Co;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointのApiController（ライブラリ）</summary>
    //  **CORS はクラスに付けない**（#265）。**口ごとに属性で選ぶ。**
    //    以前はここに [EnableCors]（ポリシー名なし）が付いており、
    //    Startup のインラインの全開ポリシーと合わせて、
    //    **/token /revoke /introspect まで任意オリジンから叩けた。**
    //  **付けていない口は CORS 無し**（ブラウザから叩く口ではない）。
    //    /revoke /introspect /device_authz /ciba_authz /par /ros
    //[ApiController]
    [MyBaseAsyncApiController(httpAuthHeader: EnumHttpAuthHeader.None)] // 認証無し（自前）
    public partial class OAuth2EndpointController : ControllerBase
    {
        #region DI(CA)対応
        #region members & constructor

        #region members

        #region OwinContext
        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        public OAuth2EndpointController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
        }
        #endregion

        #endregion

        #region property

        #region UserManager / RoleManager

        /// <summary>UserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>RoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        #endregion

        #endregion

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
        /// </remarks>
        private void SetNoStore()
        {
            IHeaderDictionary headers = MyHttpContext.Current.Response.Headers;

            headers[Const.HeaderCacheControl] = Const.CacheControlNoStore;
            headers[Const.HeaderPragma] = Const.PragmaNoCache;
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
                this.Request.Path.Value, status, err, this.ClientIdForLog());
        }

        /// <summary>ログに出す client_id（Basic 認証 → フォームの順。分からなければ空）</summary>
        /// <returns>client_id</returns>
        private string ClientIdForLog()
        {
            try
            {
                string clientId = RateLimitProvider.ClientIdFromAuthorizationHeader(
                    this.Request.Headers[Const.HeaderAuthorization]);

                //  **フォームは、口の処理で読み終えている**（ここで本文を読み直さない）。
                if (string.IsNullOrEmpty(clientId) && this.Request.HasFormContentType)
                {
                    clientId = this.Request.Form[OAuth2AndOIDCConst.client_id];
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
        private IActionResult OAuth2Error(Dictionary<string, string> err, string realm)
        {
            int status = Token.CmnEndpoints.GetErrorStatusCode(err);

            this.TraceErrorResponse(status, err);

            if (status == 401 && realm != null)
            {
                // クライアント認証の失敗。受け付ける認証方式を示す。
                // Authorization ヘッダで認証を試みたクライアントには必須（RFC 6749 5.2）。
                this.Response.Headers[Const.HeaderWwwAuthenticate] = "Basic realm=\"" + realm + "\"";
            }

            //  **nonce が要るなら、新しい値を渡す**（RFC 9449 §8。#311 の段階 4）。
            //    **成功応答には付けない** — **窓（5〜10 分）が切れたら 1 往復増える。**
            if (err != null
                && err.TryGetValue(OAuth2AndOIDCConst.error, out string error)
                && error == OAuth2AndOIDCConst.use_dpop_nonce)
            {
                this.Response.Headers[OAuth2AndOIDCConst.HttpHeader_DPoPNonce] =
                    Sts.CmnDPoP.CurrentNonce(Sts.CmnDPoP.PurposeAs);
            }

            return new ObjectResult(err) { StatusCode = status };
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
        private IActionResult NGResult(int status, string realm, string error)
        {
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
                string scheme = AuthenticationHeader.GetChallengeScheme(MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization]);

                this.Response.Headers[Const.HeaderWwwAuthenticate] =
                    scheme + " " + Token.CmnEndpoints.GetChallengeParameter(scheme, realm, err);

                string nonce = Sts.CmnDPoP.NonceForChallenge(scheme == OAuth2AndOIDCConst.DPoP);

                if (nonce != null)
                {
                    this.Response.Headers[OAuth2AndOIDCConst.HttpHeader_DPoPNonce] = nonce;
                }
            }

            return new ObjectResult("NG") { StatusCode = status };
        }

        #endregion
    }
}