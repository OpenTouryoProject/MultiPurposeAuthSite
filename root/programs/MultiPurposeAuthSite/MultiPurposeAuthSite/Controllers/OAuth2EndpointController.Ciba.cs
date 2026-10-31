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
//* クラス日本語名  ：OAuth2EndpointController の CIBA（/ciba_authz）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（OAuth2EndpointController.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         /ciba_result を認証デバイスのトークンに限る・expires_in / interval を数値で返す・requested_expiry を上限で頭打ちにする（#294）
//*  2026/10/30  玄人 幸道         CIBA のプッシュ送信で使われていない変数を外した（net10.0 版に揃えた。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Util;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointController（CIBA（/ciba_authz））</summary>
    public partial class OAuth2EndpointController
    {
        #region /ciba

        /// <summary>
        /// FAPI CIBAの認可リクエストを受信
        /// POST: /ciba_authz
        /// </summary>
        /// <param name="formData">
        /// request（CIBA Core 7.1.1）または request_uri（独自拡張。後方互換）
        /// </param>
        /// <returns>成功は 200、エラーは 400 / 401（CIBA Core 7.3 / 13）（#196）</returns>
        [HttpPost]
        public async Task<IHttpActionResult> CibaAuthorizeAsync(FormDataCollection formData)
        {
            // **資格情報・属性を返すので、キャッシュに残さない**（#218）。
            //   RFC は MUST としていないが、困る性質は /token と同じ。
            this.SetNoStore();

            string err = "";
            string errDescription = "";

            if (formData != null)
            {
                // **CIBA Core 7.1.1 : 署名した認証要求を request で直接受け取る（#233）。**
                //   request_uri（/ros に預ける形）は独自拡張で、CIBA Core には無い。
                //   後方互換のため当面残す（両方あれば request を優先する）。
                string request = formData[OAuth2AndOIDCConst.request];
                string request_uri = formData[OAuth2AndOIDCConst.request_uri];

                // **クライアント認証の資格情報を取り出す（CIBA Core 7.1 : MUST。#234 の段階 3）。**
                //   /par・/token と同じ取り出し方。
                // client_secret_basic
                if (!Token.CmnEndpoints.GetBasicCredentials(
                    HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                    out string client_id, out string client_secret))
                {
                    // client_secret_post
                    client_id = formData[OAuth2AndOIDCConst.client_id];
                    client_secret = formData[OAuth2AndOIDCConst.client_secret];
                }

                // private_key_jwt / mTLS
                string assertion = OAuth2AndOIDCSpec.GetClientAssertion(
                    formData[OAuth2AndOIDCConst.client_assertion],
                    formData[OAuth2AndOIDCConst.client_assertion_type],
                    formData[OAuth2AndOIDCConst.assertion]);
                X509Certificate2 x509 = Request.GetClientCertificate();

                string authReqId = "";

                if (!string.IsNullOrEmpty(request) || !string.IsNullOrEmpty(request_uri))
                {
                    // 受け取りと署名検証は、両アプリで同じ（CommonLibrary）。
                    bool received = Token.CmnEndpoints.ReceiveCibaRequest(
                        client_id, client_secret, assertion, x509,
                        request, request_uri, out JObject jsonObj, out err, out errDescription);

                    string scope = "";
                    string client_notification_token = "";
                    string binding_message = "";
                    string user_code = "";
                    string requested_expiry = "";
                    string login_hint = "";

                    if (!received)
                    {
                        // 受け取れなかった（err, errDescriptionは設定済み）。
                    }
                    // **client_id は、要求の iss（＝認証したクライアント。ReceiveCibaRequest が照合済み）から取る**（#294）。
                    //   **private_key_jwt ではフォームに client_id が無い**ので、以前は空のまま code を作り、500 になっていた。
                    else if (Token.CmnEndpoints.ValidateCibaAuthZReqParam(
                        jsonObj, out client_id, out scope,
                        out client_notification_token, out binding_message,
                        out user_code, out requested_expiry, out login_hint,
                        out err, out errDescription))
                    {
                        // 検証成功

                        // AccountControllerからの移行なので...。
                        string name = Helper.GetInstance().GetClientName(client_id);

                        // scopeパラメタ
                        string[] scopes = (scope ?? "").Split(' ');

                        // **login_hint から利用者を引く**（#151 の段階 4）。
                        //   **identity.Name は「利用者名」として扱われる**
                        //   （CmnAccessToken が、ここから改めて sub を作る）。
                        //   **sub を入れてはいけない**（利用者 ID や PPID なので、引けなくなる）。
                        //
                        //   **ここでは利用者の解決だけに使う**（戻り値の sub は使わない）。
                        ApplicationUser user = null;
                        PPIDExtension.GetSubForOIDC(client_id, login_hint, out user);

                        if (user != null)
                        {
                            // codeの生成
                            string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                new ClaimsIdentity(new GenericIdentity(user.UserName)),
                                new NameValueCollection(),
                                client_id, "", scopes, null, "");

                            // requested_expiry → UnixTime化
                            //   **`CibaExpireTimeSpanFromSeconds` を上限にする**（#294。値は `ValidateCibaAuthZReqParam` が検証済み）。
                            //   **以前は上限が無く**、読めない値は 0 になって、作った瞬間に期限が切れていた。
                            int _requested_expiry = Token.CmnEndpoints.CibaExpiresIn(requested_expiry);

                            long authReqExp = DateTimeOffset.Now.AddSeconds(_requested_expiry).ToUnixTimeSeconds();

                            // **承認する手段（認証デバイス）があるかを、送る前に確かめる（#210）。**
                            //   以前は空の宛先のまま送信し、処理されない例外で HTTP 500 になっていた。
                            //   ユーザは見つかっているので unknown_user_id ではなく access_denied を返す。
                            //   Create の前に確かめ、保留中のレコードを作らない。
                            if (!Sts.CibaProvider.DebugModeWithOutAD
                                && string.IsNullOrEmpty(user.DeviceToken))
                            {
                                err = OAuth2AndOIDCConst.access_denied;
                                errDescription = "The authentication device is not registered.";

                                return this.OAuth2Error(new Dictionary<string, string>()
                                {
                                    {OAuth2AndOIDCConst.error, err},
                                    {OAuth2AndOIDCConst.error_description, errDescription}
                                }, null);
                            }

                            // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
                            //   CIBA は認可エンドポイントを通らないので、ここで消す。
                            //   request で直接受け取ったときは預けたものが無いので、消す対象も無い（#233）。
                            if (!string.IsNullOrEmpty(request_uri))
                            {
                                Sts.RequestObjectProvider.Delete(
                                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
                            }

                            // CIBA情報をストア
                            // **誰宛ての要求かを記録する**（user は login_hint で解決した利用者）。
                            Sts.CibaProvider.Create(
                               client_notification_token,
                               authReqExp, code, binding_message, user.Id, out authReqId);

#pragma warning disable 162

                            // プッシュ通知を、userに送信
                            if (!Sts.CibaProvider.DebugModeWithOutAD)
                            {
                                // **送信の失敗を、処理されない例外にしない（#210）。**
                                //   以前はここで例外が外に出て、HTTP 500 と JSON でない本文（開発モードでは例外の平文）を返していた。
                                //   CIBA 情報は上の Create で保存済みなので、失敗しても期限切れまで残る。
                                try
                                {
                                    // - DeviceTokenを使用してプッシュ通知
                                    //   **戻り値は使わない**（net10.0 版と同じ。#294 で、使われていない変数を外した）。
                                    await FcmService.GetInstance().SendAsync(
                                        user.DeviceToken, "CIBA", "Allow / Deny",
                                        new Dictionary<string, string>()
                                        {
                                            { OAuth2AndOIDCConst.auth_req_id, authReqId},
                                            { OAuth2AndOIDCConst.binding_message, binding_message}
                                        });
                                }
                                catch (Exception ex)
                                {
                                    // **原因は、記録に残す。** 例外を受け止めると、
                                    //   これまで OnException が ACCESS ログに書いていた内容が失われるため。
                                    Logging.MyDebugLogForEx(ex);

                                    // 資格情報の誤り、宛先の拒否、通信障害など。
                                    // **ここで返す。** 後続は成功のレスポンス（200 と auth_req_id）で、
                                    // err を見ないため、設定するだけでは成功として返ってしまう。
                                    err = OAuth2AndOIDCConst.server_error;
                                    errDescription = "Failed to send the push notification.";

                                    return this.OAuth2Error(new Dictionary<string, string>()
                                    {
                                        {OAuth2AndOIDCConst.error, err},
                                        {OAuth2AndOIDCConst.error_description, errDescription}
                                    }, null);
                                }
                            }
                            else
                            {
                                // テストを通すため追加
                                Sts.CibaProvider.ReceiveResult(authReqId, user.Id, true);
                            }

#pragma warning restore 162

                            // ココまでの結果をレスポンス（CIBA Core 7.3 : 200）
                            //   **expires_in / interval は JSON の数値**（CIBA Core 7.3。#294。以前は文字列だった）。
                            return this.Ok(new Dictionary<string, object>()
                            {
                                {OAuth2AndOIDCConst.auth_req_id, authReqId},
                                {OAuth2AndOIDCConst.expires_in, _requested_expiry},
                                {OAuth2AndOIDCConst.PollingInterval, Config.CibaPollingIntervalSeconds}
                            });
                        }
                        else
                        {
                            // login_hint のユーザが見つからない（CIBA Core 13 : unknown_user_id）。
                            // 以前は err / errDescription が空のまま返っていた（#196）。
                            err = OAuth2AndOIDCConst.unknown_user_id;
                            errDescription = "The user identified by login_hint was not found.";
                        }
                        // 以降で、下記を束ねる。
                        // - プッシュ通知の応答結果
                        // - Tokenリクエスト（polling）
                    }
                    else
                    {
                        // 検証失敗
                        // err, errDescriptionは設定済み。
                    }
                }
                else
                {
                    // 不正なRequest
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "request or request_uri is required.";
                }
            }
            else
            {
                // FormDataCollection無し
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "Form data is null.";
            }

            // エラー（CIBA Core 13 : invalid_client は 401、それ以外は 400）（#196）
            // **クライアント認証を行うようになったので、401 には WWW-Authenticate を付ける**
            //   （Authorization ヘッダで認証を試みたクライアントには必須。RFC 6749 5.2。#234 の段階 3）。
            return this.OAuth2Error(new Dictionary<string, string>()
            {
                {OAuth2AndOIDCConst.error, err},
                {OAuth2AndOIDCConst.error_description, errDescription}
            }, Const.EndpointCibaAuthZ);
        }

        /// <summary>
        /// CIBAのプッッシュ結果を受信
        /// POST: /ciba_result
        /// </summary>
        /// <param name="formData">
        /// - auth_req_id
        /// - result
        /// </param>
        /// <returns>
        /// 成功は 200 と "OK"。失敗は本文 "NG" のまま、
        /// トークンの不備は 401（WWW-Authenticate: Bearer）、パラメタの不備は 400（#196）
        /// </returns>
        /// <remarks>
        /// 認証デバイス（authentication_device）が、プッシュ通知を受けて「許可 / 拒否」を押したときに呼ぶ。
        /// </remarks>
        [HttpPost]
        [MpasBrowserApiCors]   // 認証デバイスの web ビルド（PWA）が叩く
        public IHttpActionResult CibaPushResult(FormDataCollection formData)
        {
            // クライアント認証（Bearer トークン）
            if (!AuthenticationHeader.GetAccessToken(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken, out string authScheme))
            {
                // トークンが無い（RFC 6750 3.1 : エラー コードを付けない）（#196 : 401）
                return this.NGResult(401, Const.EndpointCibaResult, null);
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

                //  **認証デバイスのクライアントに発行したトークンだけを受ける**（#294。`IsAuthenticationDeviceToken`）。
                //    **以前は、どの RP のトークンでも、CIBA の要求を「許可」できた。**
                if (OAuth2EndpointController.IsAuthenticationDeviceToken(ClientId))
                {
                    user = PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);
                }
            }

            if (user == null)
            {
                // 無効なトークン、またはユーザの無いトークン（RFC 6750 3.1 : invalid_token）（#196 : 401）
                return this.NGResult(401, Const.EndpointCibaResult,
                dpopError ?? OAuth2AndOIDCConst.invalid_token);
            }

            // 変数
            string auth_req_id = (formData == null) ? null : (string)formData[OAuth2AndOIDCConst.auth_req_id];
            string temp = (formData == null) ? null : (string)formData["result"];

            if (!string.IsNullOrEmpty(auth_req_id)
                && bool.TryParse(temp, out bool result))
            {
                if (Sts.CibaProvider.ReceiveResult(auth_req_id, user.Id, result))
                {
                    return this.Ok("OK");
                }

                // **自分宛ての要求ではない（または、その要求が無い）。**
                //   区別して返すと、auth_req_id の存在を推測させるので、同じ応答にする。
                return this.NGResult(400, Const.EndpointCibaResult, null);
            }

            // パラメタの不備（#196 : 400）
            return this.NGResult(400, Const.EndpointCibaResult, null);
        }

        #endregion
    }
}