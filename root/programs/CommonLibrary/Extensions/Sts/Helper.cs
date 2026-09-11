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
//* クラス日本語名  ：Helper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/03/04  西野 大介         FAPI CIBA対応実施
//*  2020/08/04  西野 大介         コンテナ化対応実施
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2021/06/02  西野 大介         テスト用 証明書 検証 無効化コード追加
//*  2026/09/07  玄人 幸道         nonceをstateから捏造しないよう修正（#191）
//*  2026/09/11  玄人 幸道         scopes_supported に無いスコープを発行しないよう、一覧と絞り込みを追加（#198）
//*  2026/09/11  玄人 幸道         クライアントの登録（scope）で、発行するスコープを絞る（#198 の後半）
//*  2026/09/11  玄人 幸道         GetScopesSupported を Claim関連ヘルパ から scopes_supported の region へ移す
//**********************************************************************************

using MultiPurposeAuthSite.ViewModels;

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
#if NETFX
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
#else
using MultiPurposeAuthSite;
#endif

using MultiPurposeAuthSite.Network;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using System.Web;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>Helper（ライブラリ）</summary>
    public class Helper
    {
        #region member variable

        /// <summary>Singleton (instance)</summary>
        private static Helper _oAuth2Helper = new Helper();

        /// <summary>クライアント識別子情報</summary>
        private readonly Dictionary<string, Dictionary<string, string>> _oauth2ClientsInfo = null;

        /// <summary>
        /// OAuth Server
        /// ・AuthorizationServerのTokenエンドポイント、
        /// ・ResourceServerの保護リソース（WebAPI）
        /// にアクセスするためのHttpClient
        /// 
        /// </summary>
        /// <remarks>
        /// HttpClientの類の使い方 - マイクロソフト系技術情報 Wiki
        ///  > HttpClientクラス > ポイント
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?HttpClient%E3%81%AE%E9%A1%9E%E3%81%AE%E4%BD%BF%E3%81%84%E6%96%B9#l0c18008
        /// Singletonで使うので、ここではstaticではない。
        /// </remarks>
        private HttpClient _oAuth2HttpClient = null;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        private Helper()
        {
            // クライアント識別子情報
            this._oauth2ClientsInfo = Config.OAuth2ClientsInformation;

            // OAuth ServerにアクセスするためのHttpClient
            this._oAuth2HttpClient = HttpClientBuilder(EnumProxyType.Intranet);

            // ライブラリを使用
            OAuth2AndOIDCClient.HttpClient = this._oAuth2HttpClient;
        }

        #endregion

        #region property

        /// <summary>
        /// OauthClientsInfo
        /// </summary>
        private Dictionary<string, Dictionary<string, string>> Oauth2ClientsInfo
        {
            get
            {
                return this._oauth2ClientsInfo;
            }
        }

        /// <summary>
        /// OAuthHttpClient
        /// </summary>
        private HttpClient OAuth2HttpClient
        {
            get
            {
                return this._oAuth2HttpClient;
            }
        }

        #endregion

        #region GetInstance

        /// <summary>GetInstance</summary>
        /// <returns>OAuthHelper</returns>
        public static Helper GetInstance()
        {
            return Helper._oAuth2Helper;
        }

        #endregion

        #region instanceメソッド

        #region HTTP

        #region ClientBuilder

        /// <summary>
        /// AuthZ Serverにアクセスするための
        /// HttpClientを生成するメソッド
        /// </summary>
        /// <returns>
        /// HttpClient
        /// </returns>
        private HttpClient HttpClientBuilder(EnumProxyType proxyType)
        {
            IWebProxy proxy = null;

            switch (proxyType)
            {
                case EnumProxyType.Internet:
                    proxy = CreateProxy.GetInternetProxy();
                    break;
                case EnumProxyType.Intranet:
                    proxy = CreateProxy.GetIntranetProxy();
                    break;
                case EnumProxyType.Debug:
                    proxy = CreateProxy.GetDebugProxy();
                    break;
            }

            // ASP.NET＋クライアント証明書 - マイクロソフト系技術情報 Wiki
            // https://techinfoofmicrosofttech.osscons.jp/index.php?ASP.NET%EF%BC%8B%E3%82%AF%E3%83%A9%E3%82%A4%E3%82%A2%E3%83%B3%E3%83%88%E8%A8%BC%E6%98%8E%E6%9B%B8

#if NETCORE
            // - Equivalent to WebRequestHandler in .net Core · Issue #26223 · dotnet/corefx
            //   https://github.com/dotnet/corefx/issues/26223
            //   - https://docs.microsoft.com/ja-jp/dotnet/api/system.net.http.webrequesthandler?view=netcore-2.2
            //   - https://docs.microsoft.com/ja-jp/dotnet/api/system.net.http.webrequesthandler?view=netcore-3.0
            // 
            // On the netcore, WebRequestHandler is not yet supported,
            // but HttpClientHandleralso has ClientCertificates member.
            // 
            // - c# - Add client certificate to .net core Httpclient - Stack Overflow
            //   https://stackoverflow.com/questions/40014047/add-client-certificate-to-net-core-httpclient

            HttpClientHandler handler = new HttpClientHandler
            {
                Proxy = proxy,
                //ClientCertificateOptions = ClientCertificateOption.Automatic
            };

            // Browser（Resource Owner）からではなくでClientから
            if (!string.IsNullOrEmpty(CmnClientParams.ClientCertPfxFilePath))
            {
                handler.ClientCertificates.Add(//new X509Certificate2(
                    X509CertificateLoader.LoadPkcs12FromFile(
                        CmnClientParams.ClientCertPfxFilePath,
                        CmnClientParams.ClientCertPfxPassword,
                        X509KeyStorageFlags.MachineKeySet));
            }
#else
            WebRequestHandler handler = new WebRequestHandler
            {
                Proxy = proxy,
                //ClientCertificateOptions = ClientCertificateOption.Automatic
            };

            // Browser（Resource Owner）からではなくでClientから
            if (!string.IsNullOrEmpty(CmnClientParams.ClientCertPfxFilePath))
            {
                handler.ClientCertificates.Add(new X509Certificate(
                    CmnClientParams.ClientCertPfxFilePath,
                    CmnClientParams.ClientCertPfxPassword,
                    X509KeyStorageFlags.MachineKeySet));
            }
#endif
            //// 無効な証明書を無視（テスト用）
            //handler.ServerCertificateCustomValidationCallback
            //    = (message, cert, chain, errors) => { return true; };

            return new HttpClient(handler);
            //return new HttpClient();
        }

        #endregion

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

        #region CIBA
        /// <summary>
        /// FAPI CIBA : RequestObjectを使用した認可リクエスト（WebAPI）
        /// </summary>
        /// <param name="cibaAuthZUri">Uri</param>
        /// <param name="requestObjectUri">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> CibaAuthZRequestAsync(Uri cibaAuthZUri, string requestObjectUri)
        {
            // コンテナ化サポート
            cibaAuthZUri = Helper.GetContainerizatedAuthZServerUri(cibaAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.CibaAuthZRequestAsync(cibaAuthZUri, requestObjectUri);
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

        #region OAuth2（ResourcesServer）WebAPI

        /// <summary>認可したユーザに課金するWebAPIを呼び出す</summary>
        /// <param name="accessToken">accessToken</param>
        /// <param name="currency">通貨</param>
        /// <param name="amount">料金</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> CallOAuth2ChageToUserWebAPIAsync(
            string accessToken, string currency, string amount)
        {
            // 通信用の変数

            // 課金用のWebAPI
            Uri webApiEndpointUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.ChageToUserWebAPI);

            // コンテナ化サポート
            webApiEndpointUri = Helper.GetContainerizatedAuthZServerUri(webApiEndpointUri);

            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri,
            };

            // HttpRequestMessage (Headers & Content)
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(OAuth2AndOIDCConst.Bearer, accessToken);
            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "currency", currency },
                    { "amount", amount },
                });
            httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            // HttpResponseMessage
            httpResponseMessage = await _oAuth2HttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        #endregion

        #endregion

        #region Credential( → DataProvider)

        #region Client authentication

        #region GetClientSecret

        /// <summary>client_idからclient_secretを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>client_secret</returns>
        public string GetClientSecret(string client_id)
        {
            return this.GetClientSecret(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからclient_secretを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>client_secret</returns>
        public string GetClientSecret(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("client_secret"))
                {
                    return this.Oauth2ClientsInfo[client_id]["client_secret"];
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.ClientSecret;
            }

            return "";
        }

        #endregion

        #region GetClientsRedirectUri

        /// <summary>client_idからresponse_typeに対応するredirect_uriを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <returns>redirect_uri</returns>
        public string GetClientsRedirectUri(string client_id, string response_type)
        {
            return this.GetClientsRedirectUri(client_id, response_type, out bool isResourceOwner);
        }

        /// <summary>client_idからresponse_typeに対応するredirect_uriを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>redirect_uri</returns>
        public string GetClientsRedirectUri(string client_id, string response_type, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";
            response_type = response_type ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (string.IsNullOrEmpty(response_type))
                {
                    // ...
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    // Code
                    if (this.Oauth2ClientsInfo[client_id].ContainsKey("redirect_uri_code"))
                    {
                        return this.Oauth2ClientsInfo[client_id]["redirect_uri_code"];
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    // Others
                    if (this.Oauth2ClientsInfo[client_id].ContainsKey("redirect_uri_token"))
                    {
                        return this.Oauth2ClientsInfo[client_id]["redirect_uri_token"];
                    }
                }
            }

            // Saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);

            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);

                if (string.IsNullOrEmpty(response_type))
                {
                    // ...
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    // Code
                    return model.RedirectUriCode;
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    // Others
                    return model.RedirectUriToken;
                }
            }

            return "";
        }

        #endregion

        #region GetAssertionConsumerServiceURL

        /// <summary>client_idからAssertionConsumerServiceURLを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>AssertionConsumerServiceURL</returns>
        public string GetAssertionConsumerServiceURL(string client_id)
        {
            return this.GetAssertionConsumerServiceURL(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからAssertionConsumerServiceURLを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>AssertionConsumerServiceURL</returns>
        public string GetAssertionConsumerServiceURL(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("redirect_uri_saml"))
                {
                    return this.Oauth2ClientsInfo[client_id]["redirect_uri_saml"];
                }
            }

            // Saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);

            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.RedirectUriSaml;
            }

            return "";
        }

        #endregion

        #region GetJwkPublickey

        #region GetJwkRsaPublickey

        /// <summary>client_idからjwk_rsa_publickeyを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>jwk_rsa_publickey</returns>
        public string GetJwkRsaPublickey(string client_id)
        {
            return this.GetJwkRsaPublickey(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからjwk_rsa_publickeyを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>jwk_rsa_publickey</returns>
        public string GetJwkRsaPublickey(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("jwk_rsa_publickey"))
                {
                    return this.Oauth2ClientsInfo[client_id]["jwk_rsa_publickey"];
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.JwkRsaPublickey;
            }

            return "";
        }

        #endregion

        #region GetJwkECDsaPublickey

        /// <summary>client_idからjwk_ecdsa_publickeyを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>jwk_ecdsa_publickey</returns>
        public string GetJwkECDsaPublickey(string client_id)
        {
            return this.GetJwkECDsaPublickey(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからjwk_ecdsa_publickeyを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>jwk_ecdsa_publickey</returns>
        public string GetJwkECDsaPublickey(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("jwk_ecdsa_publickey"))
                {
                    return this.Oauth2ClientsInfo[client_id]["jwk_ecdsa_publickey"];
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.JwkECDsaPublickey;
            }

            return "";
        }

        #endregion

        #endregion

        #region GetTlsClientAuthSubjectDn

        /// <summary>client_idからtls_client_auth_subject_dnを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>tls_client_auth_subject_dn</returns>
        public string GetTlsClientAuthSubjectDn(string client_id)
        {
            return this.GetTlsClientAuthSubjectDn(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからtls_client_auth_subject_dnを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>tls_client_auth_subject_dn</returns>
        public string GetTlsClientAuthSubjectDn(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("tls_client_auth_subject_dn"))
                {
                    return this.Oauth2ClientsInfo[client_id]["tls_client_auth_subject_dn"];
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.TlsClientAuthSubjectDn;
            }

            return "";
        }

        #endregion

        #endregion

        #region Subject Types

        /// <summary>client_idからSubjectTypesを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>SubjectTypes</returns>
        public string GetSubjectTypes(string client_id)
        {
            return this.GetSubjectTypes(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからClientModeを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>ClientMode</returns>
        public string GetSubjectTypes(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey("subject_types"))
                {
                    // 設定値
                    return this.Oauth2ClientsInfo[client_id]["subject_types"];
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.SubjectTypes.uname.ToStringByEmit();
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);

                if (!string.IsNullOrEmpty(model.SubjectTypes))
                {
                    // 設定値
                    return model.SubjectTypes;
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.SubjectTypes.uname.ToStringByEmit();
                }
            }

            return ""; // エラーになる。
        }

        #endregion

        #region Client Mode

        /// <summary>client_idからClientModeを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>ClientMode</returns>
        public string GetClientMode(string client_id)
        {
            return this.GetClientMode(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからClientModeを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>ClientMode</returns>
        public string GetClientMode(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey("oauth2_oidc_mode"))
                {
                    // 設定値
                    return this.Oauth2ClientsInfo[client_id]["oauth2_oidc_mode"];
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit();
                }
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);

                if (!string.IsNullOrEmpty(model.ClientMode))
                {
                    // 設定値
                    return model.ClientMode;
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit();
                }
            }

            return ""; // エラーになる。
        }

        #endregion

        #region Client Scope

        /// <summary>client_idから、要求してよいスコープ（登録の scope）を取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>スコープの一覧（登録が無ければ null ＝ 制限しない）</returns>
        /// <remarks>
        /// RFC 7591 2 の client metadata の scope と同じく、スペース区切りで登録する（#198）。
        /// 空文字列を登録した場合は、空の一覧（＝ どのスコープも許さない）になる。
        /// saml2OAuth2Data（管理画面で登録したクライアント）には、まだこの項目が無いので制限しない。
        /// </remarks>
        public List<string> GetClientScopes(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey("scope") && dic["scope"] != null)
                {
                    List<string> ret = new List<string>();

                    foreach (string s in dic["scope"].Split(' '))
                    {
                        if (!string.IsNullOrEmpty(s) && !ret.Contains(s))
                        {
                            ret.Add(s);
                        }
                    }

                    return ret;
                }
            }

            // 登録が無い
            return null;
        }

        #endregion

        #region Client Name

        #region GetClientName

        /// <summary>client_idからclient_nameを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>client_name</returns>
        public string GetClientName(string client_id)
        {
            return this.GetClientName(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからclient_nameを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>client_name</returns>
        public string GetClientName(string client_id, out bool isResourceOwner)
        {
            isResourceOwner = false;
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                return this.Oauth2ClientsInfo[client_id]["client_name"];
            }

            // saml2OAuth2Dataを検索
            string saml2OAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(saml2OAuth2Data))
            {
                isResourceOwner = true;
                ManageAddSaml2OAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddSaml2OAuth2DataViewModel>(saml2OAuth2Data);
                return model.ClientName;
            }

            return "";
        }

        #endregion

        #region GetClientIdByName

        /// <summary>clientNameからclientIdを取得</summary>
        /// <param name="clientName">string</param>
        /// <returns>指定したclientNameのclientId</returns>
        public string GetClientIdByName(string clientName)
        {
            return this.GetClientIdByName(clientName, out bool isResourceOwner);
        }

        /// <summary>clientNameからclientIdを取得</summary>
        /// <param name="clientName">string</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>指定したclientNameのclientId</returns>
        public string GetClientIdByName(string clientName, out bool isResourceOwner)
        {
            isResourceOwner = false;

            // *.config内を検索
            foreach (string clientId in this.Oauth2ClientsInfo.Keys)
            {
                Dictionary<string, string> client
                    = this.Oauth2ClientsInfo[clientId];

                string temp = client["client_name"];
                if (temp.ToLower() == clientName.ToLower())
                {
                    return clientId;
                }
            }

            ApplicationUser user = null;

            // ★ CommonLibraryから、Manager系への依存を
            //    CmnStoreに変更して、段階的に削減する。

            //// UserStoreを検索
            //ApplicationUserManager userManager
            //    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            //user = userManager.FindByName(); // 同期版でOK。

            user = CmnUserStore.FindByName(clientName);

            isResourceOwner = true;
            return user.ClientID;
        }
        #endregion

        #endregion

        #endregion

        #endregion

        #region staticメソッド

        #region scopes_supported

        /// <summary>認可サーバが扱うスコープの一覧（Discovery の scopes_supported と同じもの）</summary>
        /// <returns>スコープの一覧</returns>
        /// <remarks>
        /// Discovery の広告（CmnEndpoints.OpenIDConfig）と、発行時の絞り込み（FilterSupportedScopes）の
        /// 両方で使う。別々に持つと一方だけ直してずれるので、ここ 1 か所で決める（#198）。
        /// </remarks>
        public static List<string> GetScopesSupported()
        {
            List<string> scopes = new List<string>()
            {
                OAuth2AndOIDCConst.Scope_Profile,
                OAuth2AndOIDCConst.Scope_Email,
                OAuth2AndOIDCConst.Scope_Phone,
                OAuth2AndOIDCConst.Scope_Address,
                OAuth2AndOIDCConst.Scope_Auth,
                OAuth2AndOIDCConst.Scope_UserID,
                OAuth2AndOIDCConst.Scope_Roles
            };

            // openid は OIDC が有効なときだけ
            if (Config.EnableOpenIDConnect)
            {
                scopes.Add(OAuth2AndOIDCConst.Scope_Openid);
            }

            return scopes;
        }

        #endregion

        #region Claim関連ヘルパ

        /// <summary>要求されたスコープのうち、認可サーバが扱うもの（scopes_supported）だけを残す</summary>
        /// <param name="scopes">要求されたスコープ</param>
        /// <returns>発行するスコープ</returns>
        /// <remarks>
        /// 以前は、要求されたスコープをそのままトークンに載せていた。
        /// Discovery で宣言していない任意の文字列（admin など）も、認可サーバの署名付きで発行されていた（#198）。
        /// RFC 6749 3.3 : 認可サーバは、要求されたスコープの一部または全部を無視してよい。
        /// ここでは拒否（invalid_scope）ではなく、扱えないものを外す。空の要素と重複も外す。
        /// クライアントごとの制限（#198 の後半）は、client_id を取る多重定義で行う。
        /// </remarks>
        public static IEnumerable<string> FilterSupportedScopes(IEnumerable<string> scopes)
        {
            List<string> supported = Helper.GetScopesSupported();
            List<string> ret = new List<string>();

            if (scopes == null)
            {
                return ret;
            }

            foreach (string s in scopes)
            {
                if (supported.Contains(s) && !ret.Contains(s))
                {
                    ret.Add(s);
                }
            }

            return ret;
        }

        /// <summary>要求されたスコープのうち、認可サーバが扱い、かつクライアントに許されたものだけを残す</summary>
        /// <param name="scopes">要求されたスコープ</param>
        /// <param name="client_id">client_id（JWT bearer では iss）</param>
        /// <returns>発行するスコープ</returns>
        /// <remarks>
        /// scopes_supported での絞り込み（#198 の前半）に加え、
        /// クライアントの登録に scope があれば、その範囲にも収める（#198 の後半）。
        /// 登録が無いクライアントは、既存の登録を壊さないよう、ここでは制限しない。
        /// </remarks>
        public static IEnumerable<string> FilterSupportedScopes(IEnumerable<string> scopes, string client_id)
        {
            List<string> ret = new List<string>();
            List<string> permitted = Helper.GetInstance().GetClientScopes(client_id);

            foreach (string s in Helper.FilterSupportedScopes(scopes))
            {
                if (permitted == null || permitted.Contains(s))
                {
                    ret.Add(s);
                }
            }

            return ret;
        }

        /// <summary>認証の場合クレームをフィルタリング</summary>
        /// <param name="scopes">フィルタ前のscopes</param>
        /// <returns>フィルタ後のscopes</returns>
        public static IEnumerable<string> FilterClaimAtAuth(IEnumerable<string> scopes)
        {
            List<string> temp = new List<string>();
            temp.Add(OAuth2AndOIDCConst.Scope_Auth);

            // フィルタ・コード
            foreach (string s in scopes)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    temp.Add(OAuth2AndOIDCConst.Scope_Openid);
                }
                else if (s == OAuth2AndOIDCConst.Scope_UserID)
                {
                    temp.Add(OAuth2AndOIDCConst.Scope_UserID);
                }
            }

            return temp;
        }

        /// <summary>
        /// ClaimsIdentityに所定のClaimを追加する。
        /// </summary>
        /// <param name="claims">ClaimsIdentity</param>
        /// <param name="client_id">string</param>
        /// <param name="scopes">string[]</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <param name="jti">string</param>
        /// <returns>ClaimsIdentity</returns>
        public static ClaimsIdentity AddClaim(ClaimsIdentity identity,
            string client_id, IEnumerable<string> scopes, JObject claims, string nonce)
        // string exp, string nbf, string iat, string jtiは不要（Unprotectで決定、読取専用）。
        {
            // 発行者の情報を含める。

            #region 標準

            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnIssuerClaim, Config.IssuerId));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnAudienceClaim, client_id));

            foreach (string scope in scopes)
            {
                // その他のscopeは、Claimの下記urnに組み込む。
                identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnScopesClaim, scope));
            }

            #endregion

            #region 拡張

            // OpenID Connect

            // nonce
            // 認可リクエストで指定された場合だけ、その値をそのまま入れる（OIDC Core 3.1.3.6）。
            // 指定が無ければ、nonceクレーム自体を作らない。
            // ※ 以前はstateを代入していたが、送られていない値をnonceとして返すことになる（#191）。
            if (!string.IsNullOrEmpty(nonce))
            {
                identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnNonceClaim, nonce));
            }

            // auth_time
            // AccountControllerで追加

            // FAPI2 (RequestObject)
            if (claims != null)
            {
                identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnClaimsClaim, claims.ToString()));
            }

            #endregion

            return identity;
        }

        #endregion

        #region コンテナ化サポート

        /// <summary>GetContainerizatedAuthZServerUri</summary>
        /// <param name="orgUri">Uri</param>
        /// <returns>Uri</returns>
        public static Uri GetContainerizatedAuthZServerUri(Uri orgUri)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // コンテナではない
            }
            else
            {
                string temp = "";

                // コンテナの可能性
                temp = Config.OAuth2ContainerizatedAuthSvrFqdnAndPort;
                if (!string.IsNullOrEmpty(temp))
                {
                    // 置換
                    string orgStr = orgUri.ToString();
                    return new Uri(orgStr.Replace(orgUri.Authority, temp));
                }

                temp = Config.OAuth2ContainerizatedAuthSvrEPRootURI;
                if (!string.IsNullOrEmpty(temp))
                {
                    // 置換
                    string orgStr = orgUri.ToString();
                    return new Uri(orgStr.Replace(orgUri.Scheme + "://" + orgUri.Authority, temp));
                }
            }

            // 置換条件に合致しなかった場合。
            return orgUri;
        }

        #endregion

        #endregion
    }
}