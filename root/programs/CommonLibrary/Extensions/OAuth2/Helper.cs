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
//* クラス名        ：OAuth2.Helper
//* クラス日本語名  ：OAuth2.Helper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
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

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Extensions.OAuth2
{
    /// <summary>OAuth2.Helper（ライブラリ）</summary>
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
        /// TOAuth Serverにアクセスするための
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

            WebRequestHandler handler = new WebRequestHandler
            {
                Proxy = proxy,
                //ClientCertificateOptions = ClientCertificateOption.Automatic
            };

            // Browser（Resource Owner）からではなくでClientから
            if (!string.IsNullOrEmpty(OAuth2AndOIDCParams.ClientCertPfx))
            {
                handler.ClientCertificates.Add(new X509Certificate(
                    OAuth2AndOIDCParams.ClientCertPfx,
                    OAuth2AndOIDCParams.ClientCertPwd,
                    X509KeyStorageFlags.MachineKeySet));
            }

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
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code);
        }

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
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code, code_verifier);
        }

        /// <summary>
        /// FAPI1 : code, code_verifierからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="assertion">assertion</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string redirect_uri, string code, string assertion)
        {
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, redirect_uri, code, assertion);
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
            return await OAuth2AndOIDCClient.UpdateAccessTokenByRefreshTokenAsync(
                tokenEndpointUri, client_id, client_secret, refreshToken);
        }

        /// <summary>UserInfoエンドポイントで、認可ユーザのClaim情報を取得する。</summary>
        /// <param name="accessToken">accessToken</param>
        /// <returns>結果のJSON文字列（認可したユーザのClaim情報）</returns>
        public async Task<string> GetUserInfoAsync(string accessToken)
        {
            // 通信用の変数

            // 認可したユーザのClaim情報を取得するWebAPI
            Uri userInfoUri = new Uri(
                Config.OAuth2ResourceServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            return await OAuth2AndOIDCClient.GetUserInfoAsync(userInfoUri, accessToken);
        }

        #endregion

        #region 拡張フローのWebAPI

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
            return await OAuth2AndOIDCClient.IntrospectTokenAsync(
                introspectTokenEndpointUri, client_id, client_secret, token, token_type_hint);
        }

        #endregion
        
        #region JWT Bearer Token Flow

        /// <summary>
        /// Token2エンドポイントで、
        /// JWT bearer token authorizationグラント種別の要求を行う。</summary>
        /// <param name="token2EndpointUri">Token2エンドポイントのUri</param>
        /// <param name="assertion">string</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> JwtBearerTokenFlowAsync(Uri token2EndpointUri, string assertion)
        {
            return await OAuth2AndOIDCClient.JwtBearerTokenFlowAsync(token2EndpointUri, assertion);
        }

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
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.TestChageToUserWebAPI);

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

            // oAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
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
                if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
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
                    if (this.Oauth2ClientsInfo[client_id].ContainsKey("redirect_uri_token"))
                    {
                        return this.Oauth2ClientsInfo[client_id]["redirect_uri_token"];
                    }
                }
            }

            // OAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);

            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);

                if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    return model.RedirectUriCode;
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    return model.RedirectUriToken;
                }
            }

            return "";
        }

        #endregion

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

            // oAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
                return model.JwkRsaPublickey;
            }

            return "";
        }

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

            // oAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
                return model.TlsClientAuthSubjectDn;
            }

            return "";
        }

        #endregion

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
                    return OAuth2AndOIDCEnum.ClientMode.normal.ToString1();
                }
            }

            // oAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);

                if (!string.IsNullOrEmpty(model.ClientMode))
                {
                    // 設定値
                    return model.ClientMode;
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.ClientMode.normal.ToString1();
                }
            }

            return ""; // エラーになる。
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

            // oAuth2Dataを検索
            string oAuth2Data = DataProvider.Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                isResourceOwner = true;
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
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

        #region Claim関連ヘルパ

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
        /// <param name="state">string</param>
        /// <param name="scopes">string[]</param>
        /// <param name="nonce">string</param>
        /// <param name="jti">string</param>
        /// <returns>ClaimsIdentity</returns>
        public static ClaimsIdentity AddClaim(ClaimsIdentity claims, 
            string client_id, string state, IEnumerable<string> scopes, string nonce)
            // string exp, string nbf, string iat, string jtiは不要（Unprotectで決定、読取専用）。
        {
            // 発行者の情報を含める。

            #region 標準

            claims.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_Issuer, Config.OAuth2IssuerId));
            claims.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_Audience, client_id));

            foreach (string scope in scopes)
            {
                // その他のscopeは、Claimの下記urnに組み込む。
                claims.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_Scopes, scope));
            }

            #endregion

            #region 拡張

            // OpenID Connect
            if (string.IsNullOrEmpty(nonce))
            {
                claims.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_Nonce, state));
            }
            else
            {
                claims.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_Nonce, nonce));
            }

            #endregion

            return claims;
        }

        #endregion
        
        #endregion
    }
}