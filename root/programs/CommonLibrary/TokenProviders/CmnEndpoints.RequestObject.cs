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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の Request Object・PAR
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         文字列でない iss・壊れた鍵の登録で 500 にしない。using を整理した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（Request Object・PAR）</summary>
    public partial class CmnEndpoints
    {
        #region AuthZ(N)Endpoint

        #region JWT の読み取り（#241）

        /// <summary>公開鍵（JWK）を、登録する形（Base64URL）にする（#307 の段階 3）</summary>
        /// <param name="jwk">JWK（1 本。JWK Set ではない）</param>
        /// <returns>登録する値（Base64URL の JWK）</returns>
        /// <remarks>
        /// **`DecodeRegisteredJwk` の逆である。** **形の知識を 1 か所に置くため、ここに並べた。**
        /// **列が持つのは「JWK 1 本を Base64URL にしたもの」**で、**JWK Set ではない**
        /// （`jwk_rsa_publickey` / `jwk_ecdsa_publickey` の 2 列に分かれている）。
        /// **余白を入れない**（`Formatting.None`）。
        /// </remarks>
        public static string EncodeRegisteredJwk(JObject jwk)
        {
            if (jwk == null)
            {
                return "";
            }

            return CustomEncode.ToBase64UrlString(
                CustomEncode.StringToByte(
                    jwk.ToString(Formatting.None), CustomEncode.us_ascii));
        }

        /// <summary>登録された公開鍵（Base64URL の JWK）を復号する（無ければ空）</summary>
        /// <param name="base64UrlJwk">登録された値</param>
        /// <returns>JWK の JSON（無ければ空）</returns>
        /// <remarks>
        /// **未登録のクライアントでは空が返る**（#241）。
        /// 以前は空かどうかを確かめる前に復号しており、
        /// `FromBase64UrlString(null)` が NullReferenceException になって **HTTP 500** だった。
        /// </remarks>
        public static string DecodeRegisteredJwk(string base64UrlJwk)
        {
            if (string.IsNullOrEmpty(base64UrlJwk))
            {
                return "";
            }

            try
            {
                return CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(base64UrlJwk), CustomEncode.us_ascii);
            }
            catch
            {
                // 登録の値が壊れている（運用の誤り）。**要求の側の誤りと区別せず、認証失敗にする。**
                return "";
            }
        }

        /// <summary>JWT の payload から、文字列のクレームを取り出す（無い・文字列でなければ空）</summary>
        /// <param name="payload">payload（null 可）</param>
        /// <param name="name">クレーム名</param>
        /// <returns>値（無ければ空）</returns>
        /// <remarks>
        /// **`(string)payload[name]` は、値がオブジェクトや配列だと例外になる**（#294）。
        /// **外から来た JWT の `iss` などを読むときは、こちらを使う**（#241 と同じ方針）。
        /// </remarks>
        private static string StringClaimOf(JObject payload, string name)
        {
            JToken value = (payload == null) ? null : payload[name];

            return (value != null && value.Type == JTokenType.String) ? (string)value : "";
        }

        #endregion

        #region RegisterRequestObject

        /// <summary>
        /// Request Object を預かる（`/ros`）（#235）
        /// </summary>
        /// <param name="requestObject">本文に入っていた署名付き JWT</param>
        /// <param name="ret">応答（iss / aud / request_uri / exp）</param>
        /// <returns>預かれたか（false なら 400）</returns>
        /// <remarks>
        /// **両アプリの Controller に同じものが書かれていたので、ここへ移した（#235）。**
        /// **振る舞いは変えていない。** 署名だけを確かめ、**クライアント認証はしない**。
        ///
        /// **この口は RFC 9101（JAR）§5.2.1 が認めている任意機能**
        /// （「認可サーバが、Request Object を POST して request_uri を得る URL を提供してもよい」）。
        /// ただし RFC は中身を規定していないので、**相互運用できる口ではない。**
        /// 新しい RP は `/par`（RFC 9126。クライアント認証とパラメタの検証も行う。#229）を使う。
        ///
        /// CIBA と FAPI2 CC で、署名検証に使う鍵の種類が違う（ES256 / RS256）。
        /// **`client_notification_token` があるかどうかで見分ける**（従来どおり）。
        ///
        /// **応答を組み立てるのは Controller 側**（net48 は HttpResponseMessage、
        /// net10.0 は Created で包む）。ここは中身だけを返す。
        /// </remarks>
        public static bool RegisterRequestObject(string requestObject, out Dictionary<string, object> ret)
        {
            ret = null;

            if (string.IsNullOrEmpty(requestObject))
            {
                return false;
            }

            // 公開鍵取得にissが必要。
            // - issを取り出す。
            //   **JWT でない値を渡されても、例外にしない**（#241）。
            JObject payload = JwtReader.TryReadPayload(requestObject);

            if (payload == null)
            {
                return false;
            }

            string requestObjectString = payload.ToString(Formatting.None);
            // **文字列でない iss で例外にしない**（#294）。
            string iss = CmnEndpoints.StringClaimOf(payload, OAuth2AndOIDCConst.iss);
            string pubKey = "";
            bool result = false;

            if (string.IsNullOrEmpty(iss))
            {
                // iss が無ければ、公開鍵を引けない（#241）。
                return false;
            }

            if (payload.ContainsKey(OAuth2AndOIDCConst.client_notification_token))
            {
                // CIBA

                // - 公開鍵取得を取り出す。
                pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkECDsaPublickey(iss));

                // 署名検証
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.VerifyCiba(requestObject, out iss, pubKey);
            }
            else
            {
                // F-API2 CC

                // - 公開鍵取得を取り出す。
                pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkRsaPublickey(iss));

                // **登録 request_object_signing_alg で絞る**（#262）。
                //   **CIBA（上の分岐）は対象外**。あちらは ES256 固定で、仕様でも別の登録項目。
                if (!CmnEndpoints.AllowsVerifyingAlg(
                    Helper.GetInstance().GetRequestObjectSigningAlg(iss),
                    CmnEndpoints.RequestObjectSigningAlgs,
                    JwtReader.TryReadAlg(requestObject)))
                {
                    return false;
                }

                // 署名検証
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.Verify(requestObject, out iss, pubKey);
            }

            if (!result)
            {
                return false;
            }

            string urn = Guid.NewGuid().ToString("N");

            // RequestObjectの登録
            RequestObjectProvider.Create(urn, requestObjectString);

            // 従来と同じ並びで入れる（**JSON の項目の順序は、RP に対する取り決めではない**。
            //   差分を読みやすくするためだけ）。`exp` は**数値**で返す（文字列にしない）。
            ret = new Dictionary<string, object>()
            {
                { OAuth2AndOIDCConst.iss, CmnServerParams.IssuerId },
                { OAuth2AndOIDCConst.aud, iss },
                { OAuth2AndOIDCConst.request_uri, OAuth2AndOIDCConst.UrnRequestUriBase + urn },
                // **有効期限を返す**（#188。以前は空文字だった）。
                //   NumericDate（RFC 7519 2章）＝ 秒。**数値で返す**（文字列にしない）。
                { OAuth2AndOIDCConst.exp, DateTimeOffset.Now.Add(
                    Config.RequestObjectExpireTimeSpanFromSeconds).ToUnixTimeSeconds() },
            };

            return true;
        }

        #endregion

        #region PushedAuthorizationRequest（PAR）

        /// <summary>
        /// PAR（RFC 9126）: 認可要求を先に預かり、request_uri を払い出す（#229）
        /// </summary>
        /// <param name="client_id">client_id（フォーム）</param>
        /// <param name="client_secret">client_secret（フォーム。Basic 認証のときは呼び出し元が取り出す）</param>
        /// <param name="assertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="parameters">フォームのパラメタ（request を含むことがある）</param>
        /// <param name="ret">応答（request_uri / expires_in）</param>
        /// <param name="err">エラー</param>
        /// <returns>成否</returns>
        /// <remarks>
        /// **独自の /ros との違いは、クライアント認証と、要求の検証、応答の形。**
        ///
        /// | | /ros（独自。後方互換で残す） | ここ（RFC 9126） |
        /// |---|---|---|
        /// | 認証 | Request Object の署名だけ | **トークン エンドポイントと同じクライアント認証**（§2） |
        /// | 本文 | 署名付き JWT を生で | **フォーム**（request に JAR を入れてもよい） |
        /// | 応答 | iss / aud / request_uri / exp | **request_uri / expires_in**（§2.2） |
        ///
        /// 有効期限と使い切りは、#188 で入れた RequestObjectProvider の仕組みをそのまま使う。
        /// </remarks>
        public static bool PushedAuthorizationRequest(
            string client_id, string client_secret, string assertion, X509Certificate2 x509,
            NameValueCollection parameters,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            #region クライアント認証

            bool authned = false;

            if (!string.IsNullOrEmpty(assertion))
            {
                // private_key_jwt
                authned = CmnEndpoints.ClientAuthentication(
                    assertion, out client_id, ref x509, out ClientModePolicy.Proof _);
            }
            else
            {
                // client_secret（basic / post）または mTLS
                authned = CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509, out ClientModePolicy.Proof _);
            }

            if (!authned)
            {
                // RFC 9126 §2.3 : クライアント認証の失敗は invalid_client（401）
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                return false;
            }

            #endregion

            #region 預かる中身を決める（request（JAR）か、フォームのパラメタか）

            // **request_uri は受け付けない**（RFC 9126 §2.1）。
            if (!string.IsNullOrEmpty(parameters[OAuth2AndOIDCConst.request_uri]))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "request_uri is not allowed here.");
                return false;
            }

            JObject payload = null;
            string request = parameters["request"];

            if (!string.IsNullOrEmpty(request))
            {
                // **署名付き Request Object（JAR）。** /ros と同じ鍵で検証する。
                //   **登録の値が壊れていても例外にしない**（#294。`DecodeRegisteredJwk` は空を返す）。
                string pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkRsaPublickey(client_id));

                if (string.IsNullOrEmpty(pubKey))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "This client has no registered key for the request object.");
                    return false;
                }

                // **登録 request_object_signing_alg で絞る**（#262）。
                if (!CmnEndpoints.AllowsVerifyingAlg(
                    Helper.GetInstance().GetRequestObjectSigningAlg(client_id),
                    CmnEndpoints.RequestObjectSigningAlgs,
                    JwtReader.TryReadAlg(request)))
                {
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description,
                        "The request object is not signed with the registered request_object_signing_alg.");
                    return false;
                }

                if (!RequestObject.Verify(request, out string iss, pubKey))
                {
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The request object is not verified.");
                    return false;
                }

                if (iss != client_id)
                {
                    // **認証したクライアントと、要求の中の iss が食い違う。**
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The request object was not issued by this client.");
                    return false;
                }

                payload = (JObject)JsonConvert.DeserializeObject(
                    CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(request.Split('.')[1]), CustomEncode.us_ascii));
            }
            else
            {
                // **フォームのパラメタ。** 認可エンドポイントに送るはずの値を、そのまま預かる。
                payload = new JObject();

                foreach (string key in parameters.AllKeys)
                {
                    if (string.IsNullOrEmpty(key)) continue;

                    switch (key)
                    {
                        // クライアント認証の値は預からない（#238 で assertion も対象にした）
                        case OAuth2AndOIDCConst.client_secret:
                        case OAuth2AndOIDCConst.client_assertion:
                        case OAuth2AndOIDCConst.client_assertion_type:
                        case OAuth2AndOIDCConst.assertion:
                            break;

                        default:
                            payload[key] = parameters[key];
                            break;
                    }
                }

                // **認証したクライアントの client_id を使う**（フォームの値は上書きする）。
                payload[OAuth2AndOIDCConst.client_id] = client_id;
            }

            #endregion

            #region 認可エンドポイントと同じ検証（RFC 9126 §2.1）

            // **`response_type` は `ref` で渡す**（#267。正規化した値が返る）。
            //   **預けた Request Object は、/authorize でもう一度読む**ので、
            //   **ここで正規化した値を payload に書き戻しておく**（並びを揃える）。
            string parResponseType = (string)payload[OAuth2AndOIDCConst.response_type];

            if (!CmnEndpoints.ValidateAuthZReqParam(
                (string)payload[OAuth2AndOIDCConst.client_id],
                (string)payload[OAuth2AndOIDCConst.redirect_uri],
                ref parResponseType,
                (string)payload[OAuth2AndOIDCConst.scope] ?? "",
                (string)payload[OAuth2AndOIDCConst.nonce],
                out string _, out string error, out string errorDescription,
                (string)payload[OAuth2AndOIDCConst.code_challenge] ?? "",
                (string)payload[OAuth2AndOIDCConst.prompt] ?? ""))
            {
                err.Add(OAuth2AndOIDCConst.error, error);
                err.Add(OAuth2AndOIDCConst.error_description, errorDescription);
                return false;
            }

            payload[OAuth2AndOIDCConst.response_type] = parResponseType;

            #endregion

            #region 預かる

            string urn = Guid.NewGuid().ToString("N");

            RequestObjectProvider.Create(urn, payload.ToString(Formatting.None));

            ret = new Dictionary<string, string>()
            {
                { OAuth2AndOIDCConst.request_uri, OAuth2AndOIDCConst.UrnRequestUriBase + urn },
                { OAuth2AndOIDCConst.expires_in, ((int)Config.RequestObjectExpireTimeSpanFromSeconds.TotalSeconds).ToString() }
            };

            return true;

            #endregion
        }

        #endregion

        #endregion
    }
}