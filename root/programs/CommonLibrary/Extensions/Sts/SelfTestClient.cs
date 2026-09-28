//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：SelfTestClient
//* クラス日本語名  ：自己テストのクライアント側の組み立て
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/28  玄人 幸道         新規（#246 : 両アプリに二重だった組み立てを寄せた）
//*  2026/09/28  玄人 幸道         CIBA の通しを寄せ、判定とポーリングを直した（#246 の 3-a / 3-b）
//*  2026/09/28  玄人 幸道         Device Authorization Grant のポーリングも寄せた（#246 の 3-a / 3-b）
//*  2026/09/28  玄人 幸道         SAML2 の応答（Assertion）を読む処理を寄せた（#246 の項目 3）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 自己テスト（この実装が兼ねているクライアント）の**組み立て**を受け持つ（#246）。
    /// </summary>
    /// <remarks>
    /// **なぜ Helper と分けるか。**
    /// `Helper` は「**WebAPI 呼び出し ＋ コンテナ化の URL 変換**」を受け持つ
    /// （全メソッドが `GetContainerizatedAuthZServerUri` を通す）。
    /// こちらは「**鍵を読み、JWT（Request Object / client_assertion）を作る**」側で、関心が別。
    ///
    /// **両アプリ（net48 / net10.0）の `HomeController` に、ほぼ同文で二重に在ったもの**を寄せた。
    /// 自己テストのパターンを増やすたびに二重が増える状態だったため（#246）。
    ///
    /// **HTTP はここでは行わず、`Helper` に委ねる。**
    /// 預ける系（`/ros` / `/par`）だけは「組み立て → 預ける → 応答を解く」までを 1 つにしている
    /// （呼び出し側が毎回同じ 3 手順を書いていたため）。
    ///
    /// **この実装自身のクライアントとしての振る舞いなので、IdP の処理からは呼ばない。**
    /// </remarks>
    public static class SelfTestClient
    {
        #region 鍵

        /// <summary>RSA の秘密鍵（クライアントのもの）を読む</summary>
        /// <returns>RSAParameters（秘密鍵を含む）</returns>
        private static RSAParameters RsaPrivateKey()
        {
            DigitalSignX509 dsX509 = new DigitalSignX509(
                CmnClientParams.RsaPfxFilePath,
                CmnClientParams.RsaPfxPassword,
                HashAlgorithmName.SHA256);

            return ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true);
        }

        /// <summary>ECDSA の公開鍵（クライアントのもの）を読む</summary>
        /// <returns>ECParameters（公開鍵のみ）</returns>
        private static ECParameters EcdsaPublicKey()
        {
            DigitalSignECDsaX509 dsX509 = new DigitalSignECDsaX509(
                CmnClientParams.EcdsaPfxFilePath,
                CmnClientParams.EcdsaPfxPassword,
                HashAlgorithmName.SHA256);

            return ((ECDsa)dsX509.AsymmetricAlgorithm).ExportParameters(false);
        }

        #endregion

        #region client_assertion

        /// <summary>client_assertion（private_key_jwt）を作る</summary>
        /// <param name="clientId">client_id（iss に入る）</param>
        /// <param name="lifetime">有効期間</param>
        /// <param name="scopes">scope（サーバは見ないが、従来と同じ値を入れる）</param>
        /// <returns>署名付き JWT</returns>
        /// <remarks>
        /// **`aud` はトークン エンドポイント**（RFC 7523 §3）。
        /// **サーバ側（`CmnEndpoints.ClientAuthentication`）がそこを見る**ので、外すと認証できない。
        /// </remarks>
        public static string CreateClientAssertion(string clientId, TimeSpan lifetime, string scopes)
        {
            return JwtAssertion.CreateByRsa(
                clientId,
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint,
                lifetime, scopes, SelfTestClient.RsaPrivateKey());
        }

        #endregion

        #region Request Object

        /// <summary>認可リクエストの Request Object（RS256）を作る</summary>
        /// <param name="clientId">client_id（iss に入る）</param>
        /// <param name="aud">aud（預け先のエンドポイント）</param>
        /// <param name="responseType">response_type</param>
        /// <param name="responseMode">response_mode</param>
        /// <param name="redirectUri">redirect_uri（明示しないときは空）</param>
        /// <param name="scopes">scope</param>
        /// <param name="state">state</param>
        /// <param name="nonce">nonce</param>
        /// <param name="claims">claims（null なら空で作る）</param>
        /// <returns>署名付き JWT（自己検証に失敗したら空）</returns>
        /// <remarks>
        /// **作った後に自分で検証する**（従来の「検証テスト」をここに入れた）。
        /// 失敗したら空を返すので、呼び出し側は預けずに済む。
        ///
        /// **`claims` に null を渡してはならない。** `RequestObject.Create` は
        /// null チェックをせずに参照する（`ClaimsInRO` 側は各引数の null を受ける）。
        /// このため、null のときは空の `ClaimsInRO` を渡す。
        /// </remarks>
        public static string CreateRequestObject(
            string clientId, string aud, string responseType, string responseMode,
            string redirectUri, string scopes, string state, string nonce, ClaimsInRO claims)
        {
            RSAParameters rsa = SelfTestClient.RsaPrivateKey();

            string requestObject = RequestObject.Create(
                clientId, aud, responseType, responseMode,
                redirectUri, scopes, state, nonce,
                "600", "", "",
                claims ?? new ClaimsInRO(null, null, null),
                rsa);

            // 検証テスト（作ったものを、自分の公開鍵で検証できるか）
            if (!RequestObject.Verify(requestObject, out string _, rsa))
            {
                return "";
            }

            return requestObject;
        }

        /// <summary>CIBA の認証要求（ES256）を作る</summary>
        /// <param name="clientId">client_id（iss に入る）</param>
        /// <param name="scopes">scope</param>
        /// <param name="loginHint">login_hint（プッシュ通知の宛先になる利用者）</param>
        /// <param name="clientNotificationToken">client_notification_token</param>
        /// <param name="bindingMessage">binding_message</param>
        /// <returns>署名付き JWT（自己検証に失敗したら空）</returns>
        /// <remarks>
        /// **`aud` は OP の Issuer Identifier**（CIBA Core §7.1.1。#234 の段階 1）。
        /// エンドポイントの URL ではない。
        /// </remarks>
        public static string CreateCibaRequestObject(
            string clientId, string scopes, string loginHint,
            string clientNotificationToken, string bindingMessage)
        {
            string requestObject = RequestObject.CreateCiba(
                clientId, Config.IssuerId,
                DateTimeOffset.Now.AddMinutes(10).ToUnixTimeSeconds().ToString(),
                DateTimeOffset.Now.ToUnixTimeSeconds().ToString(),
                scopes, clientNotificationToken, bindingMessage, "", "",
                loginHint,
                null, // request_context や intent などを格納した Dictionary（無し）
                CmnClientParams.EcdsaPfxFilePath, CmnClientParams.EcdsaPfxPassword);

            // 検証テスト
            if (!RequestObject.VerifyCiba(requestObject, out string _, SelfTestClient.EcdsaPublicKey()))
            {
                return "";
            }

            return requestObject;
        }

        /// <summary>client_notification_token を作る（CIBA）</summary>
        /// <returns>ランダムな文字列</returns>
        public static string CreateClientNotificationToken()
        {
            return CustomEncode.ToBase64UrlString(GetPassword.RandomByte(160));
        }

        /// <summary>自己テストが使う claims（従来と同じ内容）</summary>
        /// <returns>ClaimsInRO</returns>
        /// <remarks>
        /// **もとは HomeController に直接書かれていた**（#246 で寄せた）。
        /// `userinfo` に picture、`id_token` に hoge と acr（LoA1 / LoA2）を要求する。
        /// **何を要求したかを画面で見るためのもの**で、値そのものに意味は無い。
        /// </remarks>
        public static ClaimsInRO SampleClaims()
        {
            return new ClaimsInRO(
                // userinfo > claims
                new Dictionary<string, object>()
                {
                    { "picture", new { essential = true } }
                },
                // id_token > claims
                new Dictionary<string, object>()
                {
                    { "hoge", new { essential = true } }
                },
                // id_token > acr
                new
                {
                    essential = true,
                    values = new string[]
                    {
                        OAuth2AndOIDCConst.UrnLoA1,
                        OAuth2AndOIDCConst.UrnLoA2
                    }
                });
        }

        #endregion

        #region CIBA を通す

        /// <summary>CIBA の自己テストの結果</summary>
        /// <remarks>**画面で目視するためのもの。** 判定と、その理由と、途中の実値を持つ。</remarks>
        public class CibaResult
        {
            /// <summary>判定（NORMAL_END / ABNORMAL_END）</summary>
            public string Verdict { get; set; }

            /// <summary>その判定になった理由</summary>
            public string Reason { get; set; }

            /// <summary>認証要求の宛先（/ciba_authz）</summary>
            public string Endpoint { get; set; }

            /// <summary>送った認証要求（署名付き JWT）</summary>
            public string RequestObject { get; set; }

            /// <summary>認証要求の payload（JSON）</summary>
            public string RequestObjectJson { get; set; }

            /// <summary>/ciba_authz の応答（そのまま）</summary>
            public string AuthZResponse { get; set; }

            /// <summary>auth_req_id（取れなければ空）</summary>
            public string AuthReqId { get; set; }

            /// <summary>interval（秒。サーバが返した値）</summary>
            public string Interval { get; set; }

            /// <summary>expires_in（秒。サーバが返した値）</summary>
            public string ExpiresIn { get; set; }

            /// <summary>ポーリングの間隔（秒。最後に待った値。slow_down で増える）</summary>
            public int PollIntervalSeconds { get; set; }

            /// <summary>ポーリングした回数</summary>
            public int PollCount { get; set; }

            /// <summary>承認を待つ上限（秒）</summary>
            public int WaitLimitSeconds { get; set; }

            /// <summary>/token の最後の応答</summary>
            public string TokenResponse { get; set; }

            /// <summary>/userinfo の応答（トークンを取れたときだけ）</summary>
            public string UserInfoResponse { get; set; }
        }

        /// <summary>CIBA（FAPI-CIBA Profile）を最後まで通す</summary>
        /// <param name="clientId">client_id</param>
        /// <param name="loginHint">login_hint（プッシュ通知の宛先になる利用者）</param>
        /// <param name="maxWaitSeconds">承認を待つ上限（秒）</param>
        /// <returns>結果（画面で見せる）</returns>
        /// <remarks>
        /// **両アプリの HomeController に同文で在ったもの**を寄せた（#246）。
        ///
        /// **判定と、その理由を返す**（#246 の 3-a）。
        /// 以前は `?ret=OK_` ＋ 判定 という URL に移るだけで、
        /// **`OK_` が接頭辞だと読めず、`?ret=OK_ABNORMAL_END` の可否が分からなかった。**
        /// 失敗した理由（`/ciba_authz` の応答、ポーリングのエラー）も出ていなかった。
        ///
        /// **ポーリングは、サーバが返した `interval` に従い、上限で打ち切る**（同 3-b）。
        /// 以前は `Thread.Sleep(30)`（30 ミリ秒）で上限が無く、
        /// **承認されなければ要求の期限（既定 600 秒）まで `/token` を叩き続けていた**
        /// （画面のタブを閉じても止まらない。`authentication_device/CHEATSHEET.md` に記録があった）。
        ///
        /// **CIBA は認証デバイスの登録と承認が要る。**
        /// 端末が登録されていなければ `/ciba_authz` が受け付けないので、
        /// **そこで終わるのが正しい振る舞いである**（手順は `authentication_device/CHEATSHEET.md`）。
        /// </remarks>
        public static async Task<CibaResult> RunCibaProfileAsync(
            string clientId, string loginHint, int maxWaitSeconds)
        {
            CibaResult ret = new CibaResult()
            {
                Verdict = "ABNORMAL_END",
                Reason = "",
                Endpoint = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.CibaAuthorizeEndpoint,
                RequestObject = "",
                RequestObjectJson = "",
                AuthZResponse = "",
                AuthReqId = "",
                Interval = "",
                ExpiresIn = "",
                PollIntervalSeconds = 0,
                PollCount = 0,
                WaitLimitSeconds = maxWaitSeconds,
                TokenResponse = "",
                UserInfoResponse = ""
            };

            #region 認証要求を組み立てる（ES256。aud は Issuer Identifier）

            ret.RequestObject = SelfTestClient.CreateCibaRequestObject(
                clientId, "hoge " + OAuth2AndOIDCConst.Scope_Openid, loginHint,
                SelfTestClient.CreateClientNotificationToken(), GetPassword.Generate(4, 0));

            if (string.IsNullOrEmpty(ret.RequestObject))
            {
                ret.Reason = "認証要求（署名付き JWT）の自己検証に失敗した。送っていない。";
                return ret;
            }

            ret.RequestObjectJson = CustomEncode.ByteToString(
                CustomEncode.FromBase64UrlString(ret.RequestObject.Split('.')[1]), CustomEncode.us_ascii);

            #endregion

            #region 認証要求を送る（CIBA Core 7.1.1 : request で直接。7.1 : クライアント認証つき）

            ret.AuthZResponse = await Helper.GetInstance().CibaAuthZRequestAsync(
                new Uri(ret.Endpoint), ret.RequestObject,
                clientId, Helper.GetInstance().GetClientSecret(clientId));

            JObject authZ = SelfTestClient.TryReadJson(ret.AuthZResponse);

            if (authZ != null)
            {
                ret.AuthReqId = (string)authZ[OAuth2AndOIDCConst.auth_req_id] ?? "";
                ret.Interval = (string)authZ[OAuth2AndOIDCConst.PollingInterval] ?? "";
                ret.ExpiresIn = (string)authZ[OAuth2AndOIDCConst.expires_in] ?? "";
            }

            if (string.IsNullOrEmpty(ret.AuthReqId))
            {
                // **端末が登録されていなければ、ここで終わる。**
                ret.Reason = "認証要求が受け付けられなかった（auth_req_id が返らない） : "
                    + SelfTestClient.ErrorOf(authZ, "応答が JSON ではない");
                return ret;
            }

            #endregion

            #region ポーリングする（interval に従い、上限で打ち切る）

            // **間隔はサーバが返した interval に従う**（CIBA Core 11。返らなければ設定値）。
            int interval = Config.CibaPollingIntervalSeconds;

            int fromServer = 0;
            if (int.TryParse(ret.Interval, out fromServer) && 0 < fromServer)
            {
                interval = fromServer;
            }

            // **要求の期限より長くは待たない**（期限が切れた後を叩いても変わらない）。
            int expiresIn = 0;
            if (int.TryParse(ret.ExpiresIn, out expiresIn) && 0 < expiresIn && expiresIn < ret.WaitLimitSeconds)
            {
                ret.WaitLimitSeconds = expiresIn;
            }

            Uri tokenEndpointUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            string clientSecret = Helper.GetInstance().GetClientSecret(clientId);
            string authReqId = ret.AuthReqId;

            PollOutcome poll = await SelfTestClient.PollForTokenAsync(
                () => Helper.GetInstance().GetAccessTokenByCibaAsync(
                    tokenEndpointUri, clientId, clientSecret, authReqId),
                interval, ret.WaitLimitSeconds);

            #endregion

            ret.Verdict = poll.Verdict;
            ret.Reason = poll.Reason;
            ret.PollIntervalSeconds = poll.IntervalSeconds;
            ret.PollCount = poll.Count;
            ret.TokenResponse = poll.TokenResponse;
            ret.UserInfoResponse = poll.UserInfoResponse;

            return ret;
        }

        #endregion

        #region Device Authorization Grant の承認を待つ

        /// <summary>Device Authorization Grant のポーリングの結果</summary>
        /// <remarks>**画面で目視するためのもの。**</remarks>
        public class DeviceAuthZResult
        {
            /// <summary>判定（NORMAL_END / ABNORMAL_END）</summary>
            public string Verdict { get; set; }

            /// <summary>その判定になった理由</summary>
            public string Reason { get; set; }

            /// <summary>ポーリング先（トークン エンドポイント）</summary>
            public string TokenEndpoint { get; set; }

            /// <summary>interval（秒。/device_authz が返した値）</summary>
            public string Interval { get; set; }

            /// <summary>ポーリングの間隔（秒。最後に待った値。slow_down で増える）</summary>
            public int PollIntervalSeconds { get; set; }

            /// <summary>ポーリングした回数</summary>
            public int PollCount { get; set; }

            /// <summary>承認を待つ上限（秒）</summary>
            public int WaitLimitSeconds { get; set; }

            /// <summary>/token の最後の応答</summary>
            public string TokenResponse { get; set; }

            /// <summary>/userinfo の応答（トークンを取れたときだけ）</summary>
            public string UserInfoResponse { get; set; }
        }

        /// <summary>Device Authorization Grant の承認を待つ（RFC 8628 3.4）</summary>
        /// <param name="clientId">client_id</param>
        /// <param name="deviceCode">device_code</param>
        /// <param name="interval">/device_authz が返した interval（空なら設定値）</param>
        /// <param name="maxWaitSeconds">承認を待つ上限（秒）</param>
        /// <returns>結果（画面で見せる）</returns>
        /// <remarks>
        /// **両アプリの HomeController に同文で在ったもの**を寄せた（#246）。
        ///
        /// **CIBA と同じ理由で、判定と理由を返す**（#246 の 3-a）。
        /// 以前は `?ret=OK_` ＋ 判定 という URL に移るだけだった。
        ///
        /// **間隔は `/device_authz` が返した `interval` に従う**（RFC 8628 3.5。#246 の 3-b）。
        /// 以前は `ExponentialBackoff(10, 5)` で、**上限は回数だけ**だった。
        /// </remarks>
        public static async Task<DeviceAuthZResult> RunDeviceAuthZPollingAsync(
            string clientId, string deviceCode, string interval, int maxWaitSeconds)
        {
            DeviceAuthZResult ret = new DeviceAuthZResult()
            {
                Verdict = "ABNORMAL_END",
                Reason = "",
                TokenEndpoint = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint,
                Interval = interval ?? "",
                PollIntervalSeconds = 0,
                PollCount = 0,
                WaitLimitSeconds = maxWaitSeconds,
                TokenResponse = "",
                UserInfoResponse = ""
            };

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(deviceCode))
            {
                ret.Reason = "client_id か device_code が渡されていない。問い合わせていない。";
                return ret;
            }

            // **間隔はサーバが返した interval に従う**（返らなければ設定値）。
            int seconds = Config.DeviceAuthZPollingIntervalSeconds;

            int fromServer = 0;
            if (int.TryParse(ret.Interval, out fromServer) && 0 < fromServer)
            {
                seconds = fromServer;
            }

            Uri tokenEndpointUri = new Uri(ret.TokenEndpoint);

            PollOutcome poll = await SelfTestClient.PollForTokenAsync(
                () => Helper.GetInstance().GetAccessTokenByDeviceAuthZAsync(
                    tokenEndpointUri, clientId, deviceCode),
                seconds, ret.WaitLimitSeconds);

            ret.Verdict = poll.Verdict;
            ret.Reason = poll.Reason;
            ret.PollIntervalSeconds = poll.IntervalSeconds;
            ret.PollCount = poll.Count;
            ret.TokenResponse = poll.TokenResponse;
            ret.UserInfoResponse = poll.UserInfoResponse;

            return ret;
        }

        #endregion

        #region ポーリング（CIBA と Device Authorization Grant で共通）

        /// <summary>ポーリングの結果</summary>
        private class PollOutcome
        {
            /// <summary>判定（NORMAL_END / ABNORMAL_END）</summary>
            public string Verdict { get; set; }

            /// <summary>その判定になった理由</summary>
            public string Reason { get; set; }

            /// <summary>最後に待った間隔（秒）</summary>
            public int IntervalSeconds { get; set; }

            /// <summary>問い合わせた回数</summary>
            public int Count { get; set; }

            /// <summary>/token の最後の応答</summary>
            public string TokenResponse { get; set; }

            /// <summary>/userinfo の応答（トークンを取れたときだけ）</summary>
            public string UserInfoResponse { get; set; }
        }

        /// <summary>承認されるまでトークン エンドポイントに問い合わせる</summary>
        /// <param name="requestToken">トークン要求（1 回分）</param>
        /// <param name="intervalSeconds">間隔（秒）</param>
        /// <param name="waitLimitSeconds">承認を待つ上限（秒）</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **CIBA（CIBA Core 11）と Device Authorization Grant（RFC 8628 3.4 / 3.5）は、
        /// 同じ形のポーリングである**（`authorization_pending` なら続け、`slow_down` なら
        /// 間隔を 5 秒増やし、それ以外なら終わる。エラー コードの文字列も同じ）。
        /// **二重に書かないよう、ここに 1 つだけ置く**（#246 の 3-b）。
        ///
        /// **上限で打ち切る。** 承認されないと画面が返らないままになるため。
        /// </remarks>
        private static async Task<PollOutcome> PollForTokenAsync(
            Func<Task<string>> requestToken, int intervalSeconds, int waitLimitSeconds)
        {
            PollOutcome ret = new PollOutcome()
            {
                Verdict = "ABNORMAL_END",
                Reason = "",
                IntervalSeconds = intervalSeconds,
                Count = 0,
                TokenResponse = "",
                UserInfoResponse = ""
            };

            DateTime deadline = DateTime.Now.AddSeconds(waitLimitSeconds);

            while (true)
            {
                ret.Count++;

                ret.TokenResponse = await requestToken();

                JObject token = SelfTestClient.TryReadJson(ret.TokenResponse);
                string error = (token == null) ? "" : ((string)token[OAuth2AndOIDCConst.error] ?? "");

                if (token != null && string.IsNullOrEmpty(error))
                {
                    // 正常系（トークンを取れた）
                    ret.UserInfoResponse = await Helper.GetInstance().GetUserInfoAsync(
                        (string)token[OAuth2AndOIDCConst.AccessToken]);

                    ret.Verdict = "NORMAL_END";
                    ret.Reason = "トークンを取得し、/userinfo まで通った。";
                    return ret;
                }

                if (error == OAuth2AndOIDCEnum.CibaState.slow_down.ToStringByEmit())
                {
                    // **slow_down は「続けてよいが、間隔を 5 秒増やせ」。**
                    //   このサーバは返さない（返す経路が保留になっている）が、
                    //   **クライアントとしては従うのが正しい**ので、ここで足す。
                    ret.IntervalSeconds += 5;
                }
                else if (error != OAuth2AndOIDCEnum.CibaState.authorization_pending.ToStringByEmit())
                {
                    // **authorization_pending 以外は、待っても変わらない**（拒否・期限切れなど）。
                    ret.Reason = "ポーリングが終了した : "
                        + SelfTestClient.ErrorOf(token, "応答が JSON ではない");
                    return ret;
                }

                if (deadline <= DateTime.Now)
                {
                    ret.Reason = "承認を待つ上限（" + waitLimitSeconds.ToString()
                        + " 秒）に達した。承認されなかった（authorization_pending のまま）。";
                    return ret;
                }

                await Task.Delay(TimeSpan.FromSeconds(ret.IntervalSeconds));
            }
        }

        #endregion

        #region SAML2 の応答（Assertion）を読む

        /// <summary>SAML2 の応答を検証した結果</summary>
        /// <remarks>
        /// **画面で目視するためのもの**（#246 の項目 3）。
        /// **アサーションの XML と、検証の結果と、読み取った属性**を持つ。
        /// </remarks>
        public class Saml2Result
        {
            /// <summary>判定（NORMAL_END / ABNORMAL_END）</summary>
            public string Verdict { get; set; }

            /// <summary>その判定になった理由</summary>
            public string Reason { get; set; }

            /// <summary>バインディング（どう受け取ったか）</summary>
            public string Binding { get; set; }

            /// <summary>SigAlg（Redirect Binding のときだけ付く）</summary>
            public string SigAlg { get; set; }

            /// <summary>RelayState</summary>
            public string RelayState { get; set; }

            /// <summary>RelayState が、送った state と一致したか（送っていなければ null）</summary>
            public bool? RelayStateMatched { get; set; }

            /// <summary>署名を検証できたか</summary>
            public bool SignatureVerified { get; set; }

            /// <summary>Issuer が、この IdP（設定の IssuerId）と一致したか</summary>
            public bool IssuerMatched { get; set; }

            /// <summary>NameID（誰として認証されたか）</summary>
            public string NameId { get; set; }

            /// <summary>Issuer</summary>
            public string Issuer { get; set; }

            /// <summary>Audience</summary>
            public string Audience { get; set; }

            /// <summary>InResponseTo（要求の ID）</summary>
            public string InResponseTo { get; set; }

            /// <summary>Recipient（SubjectConfirmationData）</summary>
            public string Recipient { get; set; }

            /// <summary>NotOnOrAfter（これを過ぎたら使えない）</summary>
            public string NotOnOrAfter { get; set; }

            /// <summary>StatusCode</summary>
            public string StatusCode { get; set; }

            /// <summary>NameIDFormat</summary>
            public string NameIdFormat { get; set; }

            /// <summary>AuthnContextClassRef（どう認証したか）</summary>
            public string AuthnContextClassRef { get; set; }

            /// <summary>応答の XML（字下げして出す。空なら読めなかった）</summary>
            public string ResponseXml { get; set; }
        }

        /// <summary>SAML2 の応答（SAMLResponse）を検証し、目視できる形にする</summary>
        /// <param name="samlResponse">SAMLResponse（受け取ったまま）</param>
        /// <param name="queryString">クエリ文字列（Redirect Binding のときだけ。署名の対象）</param>
        /// <param name="sigAlg">SigAlg（同上）</param>
        /// <param name="relayState">RelayState</param>
        /// <param name="expectedRelayState">送った state（照合する。無ければ空）</param>
        /// <param name="isGet">GET（Redirect Binding）で受け取ったか</param>
        /// <returns>結果（画面で見せる）</returns>
        /// <remarks>
        /// **両アプリの `AccountController.AssertionConsumerService` に同文で在ったもの**を寄せた（#246）。
        ///
        /// **アサーションを画面に出すためにある。**
        /// 以前は検証の結果を `?ret=認証完了（nameId=…）` / `?ret=認証失敗` という URL に載せるだけで、
        /// **署名を検証できたのか、Issuer が違ったのか、そもそも応答が読めなかったのかが分からなかった。**
        /// 読み取った属性（`Audience`・`NotOnOrAfter`・`AuthnContextClassRef` など）も、
        /// **XML そのもの**（`samlResponse2`）も捨てていた（「必要に応じて読んで拡張可能」というコメントだけが在った）。
        ///
        /// **判定は「署名の検証」と「Issuer の一致」の両方**である（従来と同じ条件）。
        /// **どちらで落ちたかを `Reason` に出す。**
        /// </remarks>
        public static Saml2Result VerifySaml2Response(
            string samlResponse, string queryString, string sigAlg,
            string relayState, string expectedRelayState, bool isGet)
        {
            Saml2Result ret = new Saml2Result()
            {
                Verdict = "ABNORMAL_END",
                Reason = "",
                Binding = isGet ? "Redirect（GET。署名はクエリ文字列に付く）" : "POST（署名は XML の中）",
                SigAlg = sigAlg ?? "",
                RelayState = relayState ?? "",
                RelayStateMatched = string.IsNullOrEmpty(expectedRelayState)
                    ? (bool?)null : (relayState == expectedRelayState),
                SignatureVerified = false,
                IssuerMatched = false,
                NameId = "",
                Issuer = "",
                Audience = "",
                InResponseTo = "",
                Recipient = "",
                NotOnOrAfter = "",
                StatusCode = "",
                NameIdFormat = "",
                AuthnContextClassRef = "",
                ResponseXml = ""
            };

            if (string.IsNullOrEmpty(samlResponse))
            {
                ret.Reason = "SAMLResponse が無い。";
                return ret;
            }

            // **Redirect Binding は RSAwithSHA1 だけを受ける**（従来どおり）。
            if (isGet && SAML2Const.RSAwithSHA1 != sigAlg)
            {
                ret.Reason = "SigAlg が RSAwithSHA1 ではないため、検証していない : "
                    + (string.IsNullOrEmpty(sigAlg) ? "（無し）" : sigAlg);
                return ret;
            }

            string nameId = "";
            string iss = "";
            string aud = "";
            string inResponseTo = "";
            string recipient = "";
            DateTime? notOnOrAfter = null;

            SAML2Enum.StatusCode? statusCode = null;
            SAML2Enum.NameIDFormat? nameIDFormat = null;
            SAML2Enum.AuthnContextClassRef? authnContextClassRef = null;

            XmlDocument samlResponse2 = null;

            try
            {
                ret.SignatureVerified = SAML2Client.VerifyResponse(
                    isGet ? queryString : "", samlResponse,
                    out nameId, out iss, out aud,
                    out inResponseTo, out recipient, out notOnOrAfter,
                    out statusCode, out nameIDFormat, out authnContextClassRef, out samlResponse2);
            }
            catch (Exception ex)
            {
                // **応答が XML でない・署名の要素が無いなどで例外になっても、画面は出す。**
                ret.Reason = "応答を読めなかった : " + ex.GetType().Name;
                return ret;
            }

            // 読み取れたものは、検証の成否に関わらず見せる（どこで落ちたかを見るため）。
            ret.NameId = nameId ?? "";
            ret.Issuer = iss ?? "";
            ret.Audience = aud ?? "";
            ret.InResponseTo = inResponseTo ?? "";
            ret.Recipient = recipient ?? "";
            ret.NotOnOrAfter = (notOnOrAfter == null)
                ? "" : ((DateTime)notOnOrAfter).ToString("yyyy-MM-dd HH:mm:ss");
            ret.StatusCode = (statusCode == null) ? "" : statusCode.ToString();
            ret.NameIdFormat = (nameIDFormat == null) ? "" : nameIDFormat.ToString();
            ret.AuthnContextClassRef = (authnContextClassRef == null) ? "" : authnContextClassRef.ToString();
            ret.ResponseXml = SelfTestClient.FormatXml(samlResponse2);

            ret.IssuerMatched = (ret.Issuer == Config.IssuerId);

            if (!ret.SignatureVerified)
            {
                ret.Reason = "署名を検証できなかった"
                    + (string.IsNullOrEmpty(ret.StatusCode) ? "。" : "（StatusCode=" + ret.StatusCode + "）。");
            }
            else if (!ret.IssuerMatched)
            {
                ret.Reason = "Issuer が設定と違う : "
                    + (string.IsNullOrEmpty(ret.Issuer) ? "（無し）" : ret.Issuer)
                    + "（期待 : " + Config.IssuerId + "）";
            }
            else
            {
                ret.Verdict = "NORMAL_END";
                ret.Reason = "署名を検証し、Issuer も一致した。";
            }

            return ret;
        }

        /// <summary>XML を字下げして文字列にする（目視のため）</summary>
        /// <param name="xml">XmlDocument（null 可）</param>
        /// <returns>字下げした XML（読めなければ元のまま、それも無ければ空）</returns>
        private static string FormatXml(XmlDocument xml)
        {
            if (xml == null)
            {
                return "";
            }

            try
            {
                StringBuilder sb = new StringBuilder();

                XmlWriterSettings settings = new XmlWriterSettings()
                {
                    Indent = true,
                    IndentChars = "  ",
                    OmitXmlDeclaration = true
                };

                using (XmlWriter writer = XmlWriter.Create(sb, settings))
                {
                    xml.WriteTo(writer);
                }

                return sb.ToString();
            }
            catch
            {
                // 字下げできなければ、そのまま出す（目視の妨げにはならない）。
                return xml.OuterXml;
            }
        }

        #endregion

        #region 応答を読む

        /// <summary>JSON として読む</summary>
        /// <param name="text">応答</param>
        /// <returns>JObject（読めなければ null）</returns>
        /// <remarks>**応答が JSON でなくても例外にしない**（#241 と同じ方針）。</remarks>
        private static JObject TryReadJson(string text)
        {
            try
            {
                return (JObject)JsonConvert.DeserializeObject(text ?? "");
            }
            catch
            {
                // エラー画面の HTML などが返っている。呼び出し側が生の応答を見せる。
                return null;
            }
        }

        /// <summary>応答から error / error_description を読む（画面に出す文字列）</summary>
        /// <param name="json">応答（null 可）</param>
        /// <param name="whenNull">JSON でなかったときの文字列</param>
        /// <returns>表示する文字列</returns>
        private static string ErrorOf(JObject json, string whenNull)
        {
            if (json == null)
            {
                return whenNull;
            }

            string error = (string)json[OAuth2AndOIDCConst.error] ?? "（error なし）";
            string description = (string)json[OAuth2AndOIDCConst.error_description] ?? "";

            return string.IsNullOrEmpty(description) ? error : (error + " : " + description);
        }

        #endregion

        #region 預ける（/ros・/par）

        /// <summary>預けた結果</summary>
        public class PushResult
        {
            /// <summary>預け先のエンドポイント</summary>
            public string Endpoint { get; set; }

            /// <summary>預けた Request Object（署名付き JWT）</summary>
            public string RequestObject { get; set; }

            /// <summary>Request Object の payload（JSON）</summary>
            public string RequestObjectJson { get; set; }

            /// <summary>応答（そのまま）</summary>
            public string Response { get; set; }

            /// <summary>request_uri（取れなければ空）</summary>
            public string RequestUri { get; set; }

            /// <summary>expires_in（`/par` だけが返す。無ければ空）</summary>
            public string ExpiresIn { get; set; }
        }

        /// <summary>Request Object を `/ros` に預ける（独自。RFC 9101 §5.2.1 の任意機能）</summary>
        /// <param name="clientId">client_id</param>
        /// <param name="responseType">response_type</param>
        /// <param name="responseMode">response_mode</param>
        /// <param name="redirectUri">redirect_uri</param>
        /// <param name="state">state</param>
        /// <param name="nonce">nonce</param>
        /// <param name="claims">claims</param>
        /// <returns>預けた結果</returns>
        /// <remarks>**クライアント認証は無い**（Request Object の署名だけを見る口）。</remarks>
        public static async Task<PushResult> RegisterRequestObjectAsync(
            string clientId, string responseType, string responseMode,
            string redirectUri, string state, string nonce, ClaimsInRO claims)
        {
            string endpoint = Config.OAuth2AuthorizationServerEndpointsRootURI
                + OAuth2AndOIDCParams.RequestObjectRegUri;

            PushResult ret = SelfTestClient.NewResult(endpoint, SelfTestClient.CreateRequestObject(
                clientId, endpoint, responseType, responseMode,
                redirectUri, Const.OidcScopes, state, nonce, claims));

            if (string.IsNullOrEmpty(ret.RequestObject))
            {
                return ret;
            }

            ret.Response = await Helper.GetInstance().RegisterRequestObjectAsync(
                new Uri(endpoint), ret.RequestObject);

            SelfTestClient.ReadResponse(ret);

            return ret;
        }

        /// <summary>認可リクエストを `/par` に預ける（PAR。RFC 9126）</summary>
        /// <param name="clientId">client_id</param>
        /// <param name="responseType">response_type</param>
        /// <param name="responseMode">response_mode</param>
        /// <param name="redirectUri">redirect_uri</param>
        /// <param name="state">state</param>
        /// <param name="nonce">nonce</param>
        /// <param name="claims">claims</param>
        /// <returns>預けた結果</returns>
        /// <remarks>
        /// **`/ros` との違いはクライアント認証**（RFC 9126 §2）。
        /// **FAPI 2.0 はこれを MTLS か private_key_jwt に限っている**ので、private_key_jwt で送る。
        /// </remarks>
        public static async Task<PushResult> PushAuthorizationRequestAsync(
            string clientId, string responseType, string responseMode,
            string redirectUri, string state, string nonce, ClaimsInRO claims)
        {
            string endpoint = Config.OAuth2AuthorizationServerEndpointsRootURI
                + OAuth2AndOIDCParams.AuthRequestPushUri;

            PushResult ret = SelfTestClient.NewResult(endpoint, SelfTestClient.CreateRequestObject(
                clientId, endpoint, responseType, responseMode,
                redirectUri, Const.OidcScopes, state, nonce, claims));

            if (string.IsNullOrEmpty(ret.RequestObject))
            {
                return ret;
            }

            ret.Response = await Helper.GetInstance().PushAuthorizationRequestAsync(
                new Uri(endpoint), ret.RequestObject, clientId,
                SelfTestClient.CreateClientAssertion(clientId, new TimeSpan(0, 0, 30), Const.OidcScopes));

            SelfTestClient.ReadResponse(ret);

            return ret;
        }

        /// <summary>結果の入れ物を作る</summary>
        /// <param name="endpoint">預け先</param>
        /// <param name="requestObject">Request Object</param>
        /// <returns>PushResult</returns>
        private static PushResult NewResult(string endpoint, string requestObject)
        {
            PushResult ret = new PushResult()
            {
                Endpoint = endpoint,
                RequestObject = requestObject,
                RequestObjectJson = "",
                Response = "",
                RequestUri = "",
                ExpiresIn = ""
            };

            if (!string.IsNullOrEmpty(requestObject))
            {
                // 目視のために payload を JSON で持つ（署名の検証は済んでいる）。
                ret.RequestObjectJson = CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(requestObject.Split('.')[1]), CustomEncode.us_ascii);
            }

            return ret;
        }

        /// <summary>応答から request_uri / expires_in を取り出す</summary>
        /// <param name="ret">PushResult</param>
        /// <remarks>**応答が JSON でなくても例外にしない**（#241 と同じ方針）。</remarks>
        private static void ReadResponse(PushResult ret)
        {
            try
            {
                JObject json = (JObject)JsonConvert.DeserializeObject(ret.Response ?? "");

                if (json != null)
                {
                    ret.RequestUri = (string)json[OAuth2AndOIDCConst.request_uri] ?? "";
                    ret.ExpiresIn = (string)json["expires_in"] ?? "";
                }
            }
            catch
            {
                // 応答が JSON でない（エラー画面など）。呼び出し側は Response を見せる。
            }
        }

        #endregion
    }
}
