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
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
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
