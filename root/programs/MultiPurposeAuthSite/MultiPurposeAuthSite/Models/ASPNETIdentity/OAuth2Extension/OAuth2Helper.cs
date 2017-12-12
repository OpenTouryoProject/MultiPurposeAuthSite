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
//* クラス名        ：OAuth2Helper
//* クラス日本語名  ：OAuth2Helper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.Util;
using MultiPurposeAuthSite.Models.ViewModels;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using System.Web;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension
{
    /// <summary>OAuth2Helper（ライブラリ）</summary>
    public class OAuth2Helper
    {
        #region member variable

        /// <summary>Singleton (instance)</summary>
        private static OAuth2Helper _oAuthHelper = new OAuth2Helper();

        /// <summary>クライアント識別子情報</summary>
        private Dictionary<string, Dictionary<string, string>> _oauthClientsInfo = null;

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
        private HttpClient _oAuthHttpClient = null;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        private OAuth2Helper()
        {
            // クライアント識別子情報
            this._oauthClientsInfo =
                JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, string>>>(ASPNETIdentityConfig.OAuthClientsInformation);
            // OAuth ServerにアクセスするためのHttpClient
            this._oAuthHttpClient = HttpClientBuilder(EnumProxyType.Intranet);
        }

        #endregion

        #region property

        /// <summary>
        /// OauthClientsInfo
        /// </summary>
        private Dictionary<string, Dictionary<string, string>> OauthClientsInfo
        {
            get
            {
                return this._oauthClientsInfo;
            }
        }

        /// <summary>
        /// OAuthHttpClient
        /// </summary>
        private HttpClient OAuthHttpClient
        {
            get
            {
                return this._oAuthHttpClient;
            }
        }

        #endregion

        #region GetInstance

        /// <summary>GetInstance</summary>
        /// <returns>OAuthHelper</returns>
        public static OAuth2Helper GetInstance()
        {
            return OAuth2Helper._oAuthHelper;
        }

        #endregion

        #region instanceメソッド

        #region HttpClient

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

            HttpClientHandler handler = new HttpClientHandler
            {
                Proxy = proxy,
            };

            return new HttpClient(handler);
            //return new HttpClient();
        }

        #endregion

        #region Access Token And UserInfo

        /// <summary>仲介コードからAccess Tokenを取得する。</summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">仲介コード</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code)
        {
            // 4.1.3.  アクセストークンリクエスト
            // http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req

            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = tokenEndpointUri,
            };

            // HttpRequestMessage (Headers & Content)

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                CustomEncode.ToBase64String(CustomEncode.StringToByte(
                    string.Format("{0}:{1}", client_id, client_secret), CustomEncode.us_ascii)));

            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "grant_type", "authorization_code" },
                    { "code", code },
                    { "redirect_uri", HttpUtility.HtmlEncode(redirect_uri) },
                });

            // HttpResponseMessage
            httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        /// <summary>Refresh Tokenを使用してAccess Tokenを更新</summary>
        /// <param name="tokenEndpointUri">tokenEndpointUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="refreshToken">refreshToken</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> UpdateAccessTokenByRefreshTokenAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string refreshToken)
        {
            // 6.  アクセストークンの更新
            // http://openid-foundation-japan.github.io/rfc6749.ja.html#token-refresh

            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = tokenEndpointUri,
            };

            // HttpRequestMessage (Headers & Content)

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                CustomEncode.ToBase64String(CustomEncode.StringToByte(
                    string.Format("{0}:{1}", client_id, client_secret), CustomEncode.us_ascii)));

            // HttpRequestMessage (Content)
            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken },
                });

            // HttpResponseMessage
            httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        /// <summary>認可したユーザのClaim情報を取得するWebAPIを呼び出す</summary>
        /// <param name="accessToken">accessToken</param>
        /// <returns>結果のJSON文字列（認可したユーザのClaim情報）</returns>
        public async Task<string> CallUserInfoEndpointAsync(string accessToken)
        {
            // 通信用の変数

            // 認可したユーザのClaim情報を取得するWebAPI
            Uri webApiEndpointUri = new Uri(
                ASPNETIdentityConfig.OAuthResourceServerEndpointsRootURI
                + ASPNETIdentityConfig.OAuthGetUserClaimsWebAPI);

            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = webApiEndpointUri,
            };

            // HttpRequestMessage (Headers)
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            // HttpResponseMessage
            httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        /// <summary>Revokeエンドポイントで、Access Tokenを無効化する。</summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> RevokeTokenAsync(
            Uri revokeTokenEndpointUri, string client_id, string client_secret, string token, string token_type_hint)
        {
            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = revokeTokenEndpointUri,
            };

            // HttpRequestMessage (Headers & Content)

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                CustomEncode.ToBase64String(CustomEncode.StringToByte(
                    string.Format("{0}:{1}", client_id, client_secret), CustomEncode.us_ascii)));

            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "token", token },
                    { "token_type_hint", token_type_hint },
                });

            // HttpResponseMessage
            httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        #endregion

        #region OAuth2（ResourcesServer）WebAPI

        /// <summary>認可したユーザに課金するWebAPIを呼び出す</summary>
        /// <param name="accessToken">accessToken</param>
        /// <param name="currency">通貨</param>
        /// <param name="amount">料金</param>
        /// <returns>結果のJSON文字列</returns>
        public async Task<string> CallOAuthChageToUserWebAPIAsync(
            string accessToken, string currency, string amount)
        {
            // 通信用の変数

            // 認証用のWebAPI（認証を認可したユーザのClaim情報を取得）
            Uri webApiEndpointUri = new Uri(
                ASPNETIdentityConfig.OAuthResourceServerEndpointsRootURI
                + ASPNETIdentityConfig.OAuthChageToUserWebAPI);

            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri,
            };

            // HttpRequestMessage (Headers & Content)
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "currency", currency },
                    { "amount", amount },
                });
            httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            // HttpResponseMessage
            httpResponseMessage = await _oAuthHttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
        }

        #endregion

        #endregion

        #region OAuth2関連ヘルパ
        
        /// <summary>client_idからclient_secretを取得する（Client認証で使用する）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>client_secret</returns>
        public string GetClientSecret(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.OauthClientsInfo.ContainsKey(client_id))
            {
                return this.OauthClientsInfo[client_id]["client_secret"];
            }

            // oAuth2Dataを検索
            string oAuth2Data = OAuth2DataProvider.GetInstance().Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
                return model.ClientSecret;
            }

            return "";
            
        }

        /// <summary>client_idからclient_nameを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>client_name</returns>
        /// <remarks>
        /// Client Credentialsグラント種別の場合に、
        /// ・AccessTokenFormatJwt
        /// ・OAuthResourceApiController
        /// からclient_id（aud）に対応するsubを取得するために利用される。
        /// </remarks>
        public string GetClientName(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.OauthClientsInfo.ContainsKey(client_id))
            {
                return this.OauthClientsInfo[client_id]["client_name"];
            }

            // oAuth2Dataを検索
            string oAuth2Data = OAuth2DataProvider.GetInstance().Get(client_id);
            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);
                return model.ClientName;
            }

            return ""; 
        }

        /// <summary>client_idからresponse_typeに対応するredirect_uriを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <returns>redirect_uri</returns>
        /// <remarks>
        /// ApplicationOAuthBearerTokenProviderで、
        /// redirect_uriが指定されていない場合、
        /// client_idの既定のredirect_uriを取得する。
        /// </remarks>
        public string GetClientsRedirectUri(string client_id, string response_type)
        {
            client_id = client_id ?? "";
            response_type = response_type ?? "";

            // *.config内を検索
            if (this.OauthClientsInfo.ContainsKey(client_id))
            {
                if (response_type.ToLower() == "code")
                {
                    return this.OauthClientsInfo[client_id]["redirect_uri_code"];
                }
                else if (response_type.ToLower() == "token")
                {
                    return this.OauthClientsInfo[client_id]["redirect_uri_token"];
                }
            }

            // OAuth2Dataを検索
            string oAuth2Data = OAuth2DataProvider.GetInstance().Get(client_id);

            if (!string.IsNullOrEmpty(oAuth2Data))
            {
                ManageAddOAuth2DataViewModel model = JsonConvert.DeserializeObject<ManageAddOAuth2DataViewModel>(oAuth2Data);

                if (response_type.ToLower() == "code")
                {
                    return model.RedirectUriCode;
                }
                else if (response_type.ToLower() == "token")
                {
                    return model.RedirectUriToken;
                }
            }

            return "";
        }

        /// <summary>clientNameからclientIdを取得</summary>
        /// <returns>指定したclientNameのclientId</returns>
        public string GetClientIdByName(string clientName)
        {
            // *.config内を検索
            foreach (string clientId in this.OauthClientsInfo.Keys)
            {
                Dictionary<string, string> client
                    = this.OauthClientsInfo[clientId];

                string temp = client["client_name"];
                if (temp.ToLower() == clientName.ToLower())
                {
                    return clientId;
                }
            }

            // UserStoreを検索
            ApplicationUserManager userManager
                = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            ApplicationUser user = userManager.FindByName(clientName); // 同期版でOK。

            return user.ClientID;
        }

        #endregion

        #endregion

        #region staticメソッド

        #region Claim関連ヘルパ

        /// <summary>認証の場合クレームをフィルタリング</summary>
        public static IEnumerable<string> FilterClaimAtAuth(IEnumerable<string> scopes)
        {
            List<string> temp = new List<string>();
            temp.Add(ASPNETIdentityConst.Scope_Auth);

            // フィルタ・コード
            foreach (string s in scopes)
            {
                if (s == ASPNETIdentityConst.Scope_Openid)
                {
                    temp.Add(ASPNETIdentityConst.Scope_Openid);
                }
                else if (s == ASPNETIdentityConst.Scope_Userid)
                {
                    temp.Add(ASPNETIdentityConst.Scope_Userid);
                }
            }

            return temp;
        }

        /// <summary>
        /// ClaimsIdentityに所定のClaimを追加する。
        /// </summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">string[]</param>
        /// <param name="nonce">string</param>
        /// <param name="jti">string</param>
        /// <returns>ClaimsIdentity</returns>
        public static ClaimsIdentity AddClaim(ClaimsIdentity identity, 
            string client_id, string state, IEnumerable<string> scopes,
             string nonce, string jti)
        {
            // 発行者の情報を含める。

            #region 標準

            identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Issuer, ASPNETIdentityConfig.OAuthIssuerId));
            identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Audience, client_id));

            foreach (string scope in scopes)
            {
                // その他のscopeは、Claimの下記urnに組み込む。
                identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Scope, scope));
            }

            #endregion

            #region 拡張

            // OpenID Connect
            if (string.IsNullOrEmpty(nonce))
            {
                identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Nonce, state));
            }
            else
            {
                identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Nonce, nonce));
            }

            // Token Revocation
            if (!string.IsNullOrEmpty(jti))
            {
                identity.AddClaim(new Claim(ASPNETIdentityConst.Claim_Jti, jti));
            }

            #endregion

            return identity;
        }

        #endregion

        #endregion
    }
}