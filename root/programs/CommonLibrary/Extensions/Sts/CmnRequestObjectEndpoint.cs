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
//* クラス名        ：CmnRequestObjectEndpoint
//* クラス日本語名  ：CmnRequestObjectEndpoint（ライブラリ）の Request Object・PAR
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         文字列でない iss・壊れた鍵の登録で 500 にしない。using を整理した（#294）
//*  2026/10/29  玄人 幸道         PAR の Request Object の client_id を、認証したクライアントと照合する（C-41。#294）
//*  2026/10/29  玄人 幸道         /ros の Request Object の client_id を、署名したクライアントと照合する（F5。#294）
//*  2026/10/31  玄人 幸道         /par の claims を JSON のオブジェクトとして預ける。読めなければ invalid_request（#294）
//*  2026/10/31  玄人 幸道         /ros と PAR の Request Object も、claims がオブジェクトでなければ断る（#294）
//*  2026/11/01  玄人 幸道         TokenProviders/CmnEndpoints.RequestObject.cs（partial）から、Extensions/Sts の別のクラスとして移した（#321）
//*  2026/11/06  玄人 幸道         /ros と PAR の Request Object の aud を issuer と照合する。FAPI の登録は exp・nbf を必須にし、寿命を 60 分以内に限る（#336）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>CmnRequestObjectEndpoint（Request Object・PAR）</summary>
    /// <remarks>
    /// **以前は `TokenProviders/CmnEndpoints` の partial（`CmnEndpoints.RequestObject.cs`）だった**（#321 で移した）。
    /// **本体の部品は `CmnEndpoints.` を付けて呼ぶ**（クライアント認証・`CheckClientMode` など）。
    /// </remarks>
    public static class CmnRequestObjectEndpoint
    {
        #region AuthZ(N)Endpoint

        #region claims の形（#294）

        /// <summary>payload の claims が、無いか JSON のオブジェクトか（#294）</summary>
        /// <param name="payload">Request Object の payload</param>
        /// <returns>無いか、オブジェクトなら true</returns>
        /// <remarks>**OIDC Core 5.5 の claims は JSON のオブジェクト**である（文字列・配列・null は受けない）。</remarks>
        private static bool IsClaimsObjectOrAbsent(JObject payload)
        {
            JToken claims = (payload == null) ? null : payload[OAuth2AndOIDCConst.claims];

            return claims == null || claims.Type == JTokenType.Object;
        }

        #endregion

        #region FAPI の時刻のクレーム（#336）

        /// <summary>FAPI の Request Object の寿命の上限（秒）</summary>
        private const long FapiRequestObjectMaxLifetimeSeconds = 60 * 60;

        /// <summary>FAPI の登録なら、exp・nbf が在り、寿命が 60 分以内か（#336）</summary>
        /// <param name="client_id">Request Object を署名したクライアント</param>
        /// <param name="payload">Request Object の payload（署名は確かめた後であること）</param>
        /// <returns>FAPI の登録でないか、満たしていれば true</returns>
        /// <remarks>
        /// **FAPI 1.0 Advanced §5.2.2-13・17、FAPI 2.0 Message Signing §5.3.1-3・4。**
        ///
        /// | クレーム | 確かめること |
        /// |---|---|
        /// | `nbf` | 在り、60 分より前でない |
        /// | `exp` | 在り、`nbf` から 60 分以内 |
        ///
        /// **過ぎていないか**（`exp` が先、`nbf` が後でない）は、Open棟梁 の `RequestObject.Verify` が確かめている（OpenTouryo#653）。
        /// **ここで足すのは、在ることと、寿命の上限**である（Open棟梁 は、在れば確かめるだけ）。
        /// **FAPI でない登録には求めない**（RFC 9101 は `exp`・`nbf` を必須にしていない）。
        /// </remarks>
        private static bool VerifyFapiTimeClaims(string client_id, JObject payload)
        {
            string mode = Helper.GetInstance().GetClientMode(client_id);

            if (mode != OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit()
                && mode != OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
            {
                return true;
            }

            if (!CmnRequestObjectEndpoint.TryReadNumericDate(payload[OAuth2AndOIDCConst.exp], out double exp)
                || !CmnRequestObjectEndpoint.TryReadNumericDate(payload[OAuth2AndOIDCConst.nbf], out double nbf))
            {
                return false;
            }

            double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return nbf >= now - CmnRequestObjectEndpoint.FapiRequestObjectMaxLifetimeSeconds
                && exp - nbf <= CmnRequestObjectEndpoint.FapiRequestObjectMaxLifetimeSeconds;
        }

        /// <summary>NumericDate（JSON の数値）を読む（#336）</summary>
        /// <param name="token">クレームの値</param>
        /// <param name="value">秒</param>
        /// <returns>読めれば true</returns>
        /// <remarks>**数値だけを受ける**（RFC 7519 §2。文字列は受けない）。**外から来た値なので、例外にしない。**</remarks>
        private static bool TryReadNumericDate(JToken token, out double value)
        {
            value = 0;

            if (token == null || (token.Type != JTokenType.Integer && token.Type != JTokenType.Float))
            {
                return false;
            }

            try
            {
                value = token.Value<double>();
            }
            catch (Exception)
            {
                // 桁の大きすぎる整数など
                return false;
            }

            return !double.IsNaN(value) && !double.IsInfinity(value);
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
            string iss = JwtUtil.StringClaimOf(payload, OAuth2AndOIDCConst.iss);
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
                pubKey = JwtUtil.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkECDsaPublickey(iss));

                // 署名とクレームの検証
                //   **aud は issuer**（CIBA Core §7.1.1。#336）。必須のクレームと時刻は Open棟梁 が確かめる（OpenTouryo#653）。
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.VerifyCiba(requestObject, CmnServerParams.IssuerId, out iss, pubKey);
            }
            else
            {
                // F-API2 CC

                // - 公開鍵取得を取り出す。
                pubKey = JwtUtil.DecodeRegisteredJwk(
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

                // 署名とクレームの検証（#336）
                //   **aud は issuer だけ**（RFC 9101 §4、FAPI 1.0 Advanced §5.2.2-15、FAPI 2.0 Message Signing §5.3.1-2）。
                //   **以前は署名しか確かめず、期限の過ぎたもの・別の認可サーバ宛てのものも預かっていた。**
                //   必須のクレームと、在る時刻のクレームは Open棟梁 が確かめる（OpenTouryo#653）。
                //   **FAPI の登録は、exp・nbf を必須にし、寿命を 60 分以内に限る**（`VerifyFapiTimeClaims`）。
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.Verify(requestObject, CmnServerParams.IssuerId, out iss, pubKey)
                    && CmnRequestObjectEndpoint.VerifyFapiTimeClaims(iss, payload);
            }

            if (!result)
            {
                return false;
            }

            //  **中の client_id も、署名したクライアント（iss）であること**（RFC 9101 §6.3。F5。#294）。
            //    **以前は署名（iss）だけを確かめ、中の client_id は確かめていなかった**ので、
            //    **自分の鍵で署名した Request Object を、別のクライアントの名義で預けられた**
            //    （`/authorize` は、要求の client_id と Request Object の client_id だけを突き合わせる）。
            //    **PAR（C-41）と同じ扱い** — **無ければ iss で埋める。**
            //    **埋めるのは CIBA の要求だけになった**（#336）。RS256 の Request Object は、
            //    Open棟梁 の `RequestObject.Verify` が client_id を必須にした（OpenTouryo#653）ので、無ければ上で断られる。
            JToken roClientId = payload[OAuth2AndOIDCConst.client_id];

            if (roClientId == null)
            {
                payload[OAuth2AndOIDCConst.client_id] = iss;
                requestObjectString = payload.ToString(Formatting.None);
            }
            else if (roClientId.Type != JTokenType.String || (string)roClientId != iss)
            {
                return false;
            }

            //  **claims は JSON のオブジェクトであること**（OIDC Core 5.5。#294）。
            //    **PAR のフォームと同じ扱い**（以前は `/authorize` で読めずに 500、いまは黙って無視していた）。
            if (!CmnRequestObjectEndpoint.IsClaimsObjectOrAbsent(payload))
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
                string pubKey = JwtUtil.DecodeRegisteredJwk(
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

                //  **aud は issuer だけ**（RFC 9101 §4 / FAPI。#336。`RegisterRequestObject` と同じ）。
                if (!RequestObject.Verify(request, CmnServerParams.IssuerId, out string iss, pubKey))
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

                //  **中の client_id も、認証したクライアントであること**（RFC 9126 §3 / RFC 9101 §6.3。C-41。#294）。
                //    **以前は iss だけを照合し、検証と保存は中の client_id で行っていた**ので、
                //    **別のクライアントの名義で、預けた要求を作れた。**
                //    **無ければ、認証したクライアントで埋める**（フォームの経路と同じ）。
                //    **ただし今は、無いものは上の `RequestObject.Verify` で断られる**（client_id を必須にした。OpenTouryo#653。#336）。
                JToken roClientId = payload[OAuth2AndOIDCConst.client_id];

                if (roClientId == null)
                {
                    payload[OAuth2AndOIDCConst.client_id] = client_id;
                }
                else if (roClientId.Type != JTokenType.String || (string)roClientId != client_id)
                {
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The client_id in the request object does not match the authenticated client.");
                    return false;
                }

                //  **claims は JSON のオブジェクトであること**（OIDC Core 5.5。#294。フォームの経路と同じ）
                if (!CmnRequestObjectEndpoint.IsClaimsObjectOrAbsent(payload))
                {
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The claims in the request object must be a JSON object.");
                    return false;
                }

                //  **FAPI の登録は、exp・nbf を必須にし、寿命を 60 分以内に限る**（#336。`RegisterRequestObject` と同じ）。
                //    **フォームのパラメタ（下）には求めない**（FAPI 2.0 Security Profile は JAR を求めない。求めるのは Message Signing）。
                if (!CmnRequestObjectEndpoint.VerifyFapiTimeClaims(client_id, payload))
                {
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidRequestObject); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description,
                        "The request object of a FAPI client must have exp and nbf, and live no longer than 60 minutes.");
                    return false;
                }
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

                        case OAuth2AndOIDCConst.claims:
                            //  **claims は JSON のオブジェクトとして預ける**（OIDC Core 5.5。#294）。
                            //    **以前は文字列のまま預けていた**ので、**/authorize で `(JObject)` の変換に失敗して 500 になった。**
                            //    **Request Object（JAR）では、もともとオブジェクトで入る。**
                            JObject parClaims = null;
                            try
                            {
                                parClaims = JsonConvert.DeserializeObject(parameters[key] ?? "") as JObject;
                            }
                            catch (JsonException)
                            {
                                parClaims = null;
                            }

                            if (parClaims == null)
                            {
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                                err.Add(OAuth2AndOIDCConst.error_description, "The claims parameter must be a JSON object.");
                                return false;
                            }

                            payload[key] = parClaims;
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