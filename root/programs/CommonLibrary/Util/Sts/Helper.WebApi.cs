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
//* クラス名        ：Helper
//* クラス日本語名  ：Helper（ライブラリ）の WebAPI の呼び出し（自己テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         CIBA の認証要求で、要求と応答を Dispose する（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
#else
using MultiPurposeAuthSite;
#endif

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Net.Http;
using System.Net.Http.Headers;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>Helper（WebAPI の呼び出し（自己テスト用））</summary>
    /// <remarks>
    /// **クライアント（RP）として、この認可サーバを呼ぶ**（各フローの WebAPI）。
    /// **呼ぶのは自己テスト（`SelfTestClient`・HomeController・AccountController.SelfTest）と、テスト用の口だけ**で、
    /// **本番の処理からは呼ばない**（ID 連携は Open棟梁 の `OAuth2AndOIDCClient` を直接使う。#140）。
    /// **配置の決まりでは `Util/Test` が合う**が、移すには呼び出し側の付け替えが要るので、#321 と一緒に扱う。
    /// </remarks>
    public partial class Helper
    {
        #region instanceメソッド

        #region HTTP

        #region 基本 4 フローのWebAPI

        /// <summary>
        /// Authentication Code : codeからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code);
        }

        /// <summary>
        /// Resource Owner Password Credentials Grant
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="username">string</param>
        /// <param name="password">string</param>
        /// <param name="scopes">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> ResourceOwnerPasswordCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret,
            string username, string password, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.ResourceOwnerPasswordCredentialsGrantAsync(
                tokenEndpointUri, client_id, client_secret, username, password, scopes);
        }

        /// <summary>
        /// Client Credentials Grant
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="scopes">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> ClientCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.ClientCredentialsGrantAsync(
                tokenEndpointUri, client_id, client_secret, scopes);
        }

        /// <summary>Refresh Tokenを使用してAccess Tokenを更新する。</summary>
        /// <param name="tokenEndpointUri">tokenEndpointUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="refreshToken">refreshToken</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> UpdateAccessTokenByRefreshTokenAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string refreshToken)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.UpdateAccessTokenByRefreshTokenAsync(
                tokenEndpointUri, client_id, client_secret, refreshToken);
        }

        #endregion

        #region その他の 基本 WebAPI

        /// <summary>UserInfoエンドポイントで、認可ユーザのClaim情報を取得する。</summary>
        /// <param name="accessToken">accessToken</param>
        /// <returns>結果のJSON文字列（認可したユーザのClaim情報）</returns>
        public async Task<string> GetUserInfoAsync(string accessToken)
        {
            // 通信用の変数

            // 認可したユーザのClaim情報を取得するWebAPI
            Uri userInfoUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            // コンテナ化サポート
            userInfoUri = Helper.GetContainerizatedAuthZServerUri(userInfoUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetUserInfoAsync(userInfoUri, accessToken);
        }

        #endregion

        #region 拡張フローのWebAPI

        #region PKCE

        /// <summary>
        /// PKCE : code, code_verifierからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="code_verifier">code_verifier</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code, string code_verifier)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code, code_verifier);
        }

        #endregion

        #region Revoke & Introspect

        /// <summary>Revokeエンドポイントで、Tokenを無効化する。</summary>
        /// <param name="revokeTokenEndpointUri">RevokeエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> RevokeTokenAsync(
            Uri revokeTokenEndpointUri, string client_id, string client_secret, string token, string token_type_hint)
        {
            // コンテナ化サポート
            revokeTokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(revokeTokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.RevokeTokenAsync(
                revokeTokenEndpointUri, client_id, client_secret, token, token_type_hint);
        }

        /// <summary>Introspectエンドポイントで、Tokenを無効化する。</summary>
        /// <param name="introspectTokenEndpointUri">IntrospectエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> IntrospectTokenAsync(
            Uri introspectTokenEndpointUri, string client_id, string client_secret, string token, string token_type_hint)
        {
            // コンテナ化サポート
            introspectTokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(introspectTokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.IntrospectTokenAsync(
                introspectTokenEndpointUri, client_id, client_secret, token, token_type_hint);
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>
        /// Tokenエンドポイントで、
        /// JWT bearer token authorizationグラント種別の要求を行う。</summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="assertion">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> JwtBearerTokenFlowAsync(Uri tokenEndpointUri, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.JwtBearerTokenFlowAsync(tokenEndpointUri, assertion);
        }

        #endregion

        #region Device AuthZ
        /// <summary>
        /// Device AuthZの認可リクエスト（WebAPI）
        /// </summary>
        /// <param name="deviceAuthZUri">Uri</param>
        /// <param name="clientId">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> DeviceAuthZRequestAsync(Uri deviceAuthZUri, string clientId)
        {
            // コンテナ化サポート
            deviceAuthZUri = Helper.GetContainerizatedAuthZServerUri(deviceAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.DeviceAuthZRequestAsync(deviceAuthZUri, clientId);
        }

        /// <summary>
        /// Device AuthZのTokenリクエスト（WebAPI）
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="device_code">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByDeviceAuthZAsync(
            Uri tokenEndpointUri, string client_id, string device_code)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByDeviceAuthZAsync(
                tokenEndpointUri, client_id, device_code);
        }
        #endregion

        #region FAPI (Financial-grade API) 

        /// <summary>
        /// FAPI1 : code, assertionからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="assertion">assertion</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string redirect_uri, string code, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, redirect_uri, code, assertion);
        }

        /// <summary>
        /// FAPI2 : RequestObjectを登録する。
        /// </summary>
        /// <param name="requestObjectRegUri">Uri</param>
        /// <param name="requestObject">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> RegisterRequestObjectAsync(Uri requestObjectRegUri, string requestObject)
        {
            // コンテナ化サポート
            requestObjectRegUri = Helper.GetContainerizatedAuthZServerUri(requestObjectRegUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.RegisterRequestObjectAsync(requestObjectRegUri, requestObject);
        }

        /// <summary>
        /// 認可リクエストを PAR（RFC 9126）に預ける（WebAPI）（#246）
        /// </summary>
        /// <param name="authRequestPushUri">PAR エンドポイント</param>
        /// <param name="requestObject">Request Object（署名付き JWT）</param>
        /// <param name="client_id">client_id</param>
        /// <param name="clientAssertion">client_assertion（private_key_jwt）</param>
        /// <returns>結果の JSON 文字列（request_uri と expires_in）</returns>
        /// <remarks>
        /// **`/ros`（独自）との違いは、クライアント認証があること**（RFC 9126 §2）。
        /// **FAPI 2.0 はこの認証を private_key_jwt か MTLS に限っている**ので、
        /// ここは private_key_jwt で呼ぶ（`client_assertion` の `aud` は**トークン エンドポイント**）。
        ///
        /// 送るのは `request`（JAR）1 つ。**認可エンドポイントのパラメタを、
        /// フォームで直接預ける形も RFC 9126 は許している**（Open棟梁 の別のオーバーロード）。
        /// </remarks>
        public async Task<string> PushAuthorizationRequestAsync(
            Uri authRequestPushUri, string requestObject, string client_id, string clientAssertion)
        {
            // コンテナ化サポート
            authRequestPushUri = Helper.GetContainerizatedAuthZServerUri(authRequestPushUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.PushAuthorizationRequestAsync(
                authRequestPushUri, requestObject,
                client_id, null, clientAssertion,
                OAuth2AndOIDCEnum.AuthMethods.private_key_jwt);
        }

        #region CIBA
        /// <summary>
        /// FAPI CIBA : RequestObjectを使用した認可リクエスト（WebAPI）
        /// </summary>
        /// <param name="cibaAuthZUri">Uri</param>
        /// <param name="requestObjectUri">string</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **request_uri を渡す独自拡張の形**（CIBA Core には無い）。
        /// **クライアント認証もしない**ので、#234 の段階 3 以降は認可サーバに断られる。
        /// 新しい呼び出しは <see cref="CibaAuthZRequestAsync(Uri, string, string, string)"/> を使う。
        /// </remarks>
        public async Task<string> CibaAuthZRequestAsync(Uri cibaAuthZUri, string requestObjectUri)
        {
            // コンテナ化サポート
            cibaAuthZUri = Helper.GetContainerizatedAuthZServerUri(cibaAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.CibaAuthZRequestAsync(cibaAuthZUri, requestObjectUri);
        }

        /// <summary>
        /// FAPI CIBA : 署名した認証要求（request）を、クライアント認証を添えて送る（WebAPI）
        /// </summary>
        /// <param name="cibaAuthZUri">Uri</param>
        /// <param name="requestObject">署名付きJWT</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **CIBA Core が定めている形**（§7.1 : クライアント認証は MUST、§7.1.1 : 要求は request パラメタ）。
        ///
        /// **Open棟梁 の OAuth2AndOIDCClient を使わない。**
        /// `CibaAuthZRequestAsync(Uri, string)` は request_uri を渡す前提で、
        /// 資格情報を渡す引数が無いため（OpenTouryoProject/OpenTouryo#592）。
        /// ここは `/chage_to_user` などと同じく、自前で組み立てる。
        /// </remarks>
        public async Task<string> CibaAuthZRequestAsync(
            Uri cibaAuthZUri, string requestObject, string client_id, string client_secret)
        {
            // コンテナ化サポート
            cibaAuthZUri = Helper.GetContainerizatedAuthZServerUri(cibaAuthZUri);

            // **要求と応答を Dispose する**（#294）。
            using (HttpRequestMessage httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = cibaAuthZUri,
            })
            {
                // client_secret_basic（RFC 6749 2.3.1）
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                    OAuth2AndOIDCConst.Basic,
                    CustomEncode.ToBase64String(CustomEncode.StringToByte(
                        string.Format("{0}:{1}",
                            CustomEncode.UrlEncode(client_id),
                            CustomEncode.UrlEncode(client_secret)), CustomEncode.us_ascii)));

                // CIBA Core 7.1.1 : 認証要求のパラメタは JWT の中だけに置く。
                httpRequestMessage.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                        { OAuth2AndOIDCConst.request, requestObject },
                    });
                httpRequestMessage.Content.Headers.ContentType =
                    new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                using (HttpResponseMessage httpResponseMessage = await _oAuth2HttpClient.SendAsync(httpRequestMessage))
                {
                    return await httpResponseMessage.Content.ReadAsStringAsync();
                }
            }
        }

        /// <summary>
        /// FAPI2 CIBAのTokenリクエスト（WebAPI）
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="auth_req_id">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCibaAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string auth_req_id)
        {
            // コンテナ化サポート
            tokenEndpointUri = Helper.GetContainerizatedAuthZServerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCibaAsync(
                tokenEndpointUri, client_id, client_secret, auth_req_id);
        }
        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}