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
//* クラス名        ：SelfTestWebApi
//* クラス日本語名  ：自己テスト用の WebAPI の呼び出し（この認可サーバを RP として呼ぶ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         CIBA の認証要求で、要求と応答を Dispose する（#294）
//*  2026/11/01  玄人 幸道         Util/Sts/Helper.WebApi.cs から移し、static クラスにした（配置の見直し。#321）
//*  2026/10/31  玄人 幸道         IntrospectTokenAsync の要約を直した（#294）
//*  2026/11/06  玄人 幸道         CIBA の要求を Open棟梁 の CibaAuthZRequestAsync（資格情報を受ける版。OpenTouryo#592）で送る（#337）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>自己テスト用の WebAPI の呼び出し</summary>
    /// <remarks>
    /// **クライアント（RP）として、この認可サーバを呼ぶ**（各フローの WebAPI）。
    /// **呼ぶのは自己テスト（`SelfTestClient`・HomeController・AccountController.SelfTest）と、テスト用の口だけ**で、
    /// **本番の処理からは呼ばない**（ID 連携は Open棟梁 の `OAuth2AndOIDCClient` を直接使う。#140）。
    ///
    /// **以前は `Util/Sts/Helper` の partial（`Helper.WebApi.cs`）だった**（#321 で移した）。
    /// **`HttpClient` とコンテナ化への対応は `Helper` に残してある**
    /// （**本番の処理も使う** — `OAuth2AndOIDCClient.HttpClient` を Back-Channel Logout や ID 連携が使う）。
    /// </remarks>
    public static class SelfTestWebApi
    {
        #region staticメソッド

        #region コンテナ化サポート

        /// <summary>宛先をコンテナから届く形にする（`Helper.GetContainerizatedAuthZServerUri`）</summary>
        /// <param name="uri">Uri</param>
        /// <returns>Uri</returns>
        /// <remarks>
        /// **先に `Helper` を作る** — **コンストラクタが `OAuth2AndOIDCClient.HttpClient` を設定する**
        /// （クライアント証明書を持つ `HttpClient`）。**static のメソッドを呼ぶだけでは作られないことがある**
        /// （`Helper` の static フィールドに触れないため）。**以前は `Helper` のインスタンス メソッドだった**ので、要らなかった。
        /// </remarks>
        private static Uri ToContainerUri(Uri uri)
        {
            Helper.GetInstance();
            return Helper.GetContainerizatedAuthZServerUri(uri);
        }

        #endregion

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
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> ResourceOwnerPasswordCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret,
            string username, string password, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> ClientCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> UpdateAccessTokenByRefreshTokenAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string refreshToken)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.UpdateAccessTokenByRefreshTokenAsync(
                tokenEndpointUri, client_id, client_secret, refreshToken);
        }

        #endregion

        #region その他の 基本 WebAPI

        /// <summary>UserInfoエンドポイントで、認可ユーザのClaim情報を取得する。</summary>
        /// <param name="accessToken">accessToken</param>
        /// <returns>結果のJSON文字列（認可したユーザのClaim情報）</returns>
        public static async Task<string> GetUserInfoAsync(string accessToken)
        {
            // 通信用の変数

            // 認可したユーザのClaim情報を取得するWebAPI
            Uri userInfoUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            // コンテナ化サポート
            userInfoUri = SelfTestWebApi.ToContainerUri(userInfoUri);

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
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code, string code_verifier)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> RevokeTokenAsync(
            Uri revokeTokenEndpointUri, string client_id, string client_secret, string token, string token_type_hint)
        {
            // コンテナ化サポート
            revokeTokenEndpointUri = SelfTestWebApi.ToContainerUri(revokeTokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.RevokeTokenAsync(
                revokeTokenEndpointUri, client_id, client_secret, token, token_type_hint);
        }

        /// <summary>Introspectエンドポイントで、Tokenの状態を照会する。</summary>
        /// <param name="introspectTokenEndpointUri">IntrospectエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> IntrospectTokenAsync(
            Uri introspectTokenEndpointUri, string client_id, string client_secret, string token, string token_type_hint)
        {
            // コンテナ化サポート
            introspectTokenEndpointUri = SelfTestWebApi.ToContainerUri(introspectTokenEndpointUri);

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
        public static async Task<string> JwtBearerTokenFlowAsync(Uri tokenEndpointUri, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> DeviceAuthZRequestAsync(Uri deviceAuthZUri, string clientId)
        {
            // コンテナ化サポート
            deviceAuthZUri = SelfTestWebApi.ToContainerUri(deviceAuthZUri);

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
        public static async Task<string> GetAccessTokenByDeviceAuthZAsync(
            Uri tokenEndpointUri, string client_id, string device_code)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string redirect_uri, string code, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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
        public static async Task<string> RegisterRequestObjectAsync(Uri requestObjectRegUri, string requestObject)
        {
            // コンテナ化サポート
            requestObjectRegUri = SelfTestWebApi.ToContainerUri(requestObjectRegUri);

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
        /// ここは private_key_jwt で呼ぶ（`client_assertion` の `aud` は `SelfTestClient.CreateClientAssertion` が決める）。
        ///
        /// 送るのは `request`（JAR）1 つ。**認可エンドポイントのパラメタを、
        /// フォームで直接預ける形も RFC 9126 は許している**（Open棟梁 の別のオーバーロード）。
        /// </remarks>
        public static async Task<string> PushAuthorizationRequestAsync(
            Uri authRequestPushUri, string requestObject, string client_id, string clientAssertion)
        {
            // コンテナ化サポート
            authRequestPushUri = SelfTestWebApi.ToContainerUri(authRequestPushUri);

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
        /// 新しい呼び出しは <see cref="SelfTestWebApi.CibaAuthZRequestAsync(Uri, string, string, string)"/> を使う。
        /// </remarks>
        public static async Task<string> CibaAuthZRequestAsync(Uri cibaAuthZUri, string requestObjectUri)
        {
            // コンテナ化サポート
            cibaAuthZUri = SelfTestWebApi.ToContainerUri(cibaAuthZUri);

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
        /// **Open棟梁 の `OAuth2AndOIDCClient.CibaAuthZRequestAsync`（資格情報を受ける版）で送る**（#337）。
        /// 以前は、資格情報を渡す引数が無かった（OpenTouryoProject/OpenTouryo#592）ので、自前で組み立てていた。
        /// **送るものは同じ**（client_secret_basic。id と秘密を符号化してから Base64 にする。本文は `request` だけ）。
        /// </remarks>
        public static async Task<string> CibaAuthZRequestAsync(
            Uri cibaAuthZUri, string requestObject, string client_id, string client_secret)
        {
            // コンテナ化サポート
            cibaAuthZUri = SelfTestWebApi.ToContainerUri(cibaAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.CibaAuthZRequestAsync(
                cibaAuthZUri, requestObject, client_id, client_secret,
                OAuth2AndOIDCEnum.AuthMethods.client_secret_basic);
        }

        /// <summary>
        /// FAPI2 CIBAのTokenリクエスト（WebAPI）
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="auth_req_id">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByCibaAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string auth_req_id)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

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