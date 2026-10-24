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
//*  2026/09/18  玄人 幸道         クライアント単位の PKCE 必須化（require_pkce）を追加（#221）
//*  2026/09/25  玄人 幸道         CIBA の認証要求をクライアント認証つきで送る口を追加（#234 の段階 3）
//*  2026/09/27  玄人 幸道         post_logout_redirect_uri を引く口を追加（#232）
//*  2026/09/28  玄人 幸道         PAR（/par）に認可リクエストを預ける口を追加（#246）
//*  2026/10/01  玄人 幸道         subject_types の既定値を public に変更（#151 の段階 4）
//*  2026/10/01  玄人 幸道         GetClientIdByName が、見つからないときに例外にならないようにした
//*  2026/10/02  玄人 幸道         id_token_signed_response_alg を引く口を追加（#129 の段階 2）
//*  2026/10/03  玄人 幸道         検証する側のalgを引く口を追加（#262）
//*  2026/10/04  玄人 幸道         CORSのオリジン導出のため、publicクライアントのredirect_uriを返す口を追加（#265）
//*  2026/10/04  玄人 幸道         web_originsと画面登録ぶんを返す口を追加（#266）
//*  2026/10/06  玄人 幸道         クライアント登録を専用列から読む（#270）
//*  2026/10/18  玄人 幸道         scope をDBからも読み、grant_types / response_types を追加（#307 の段階 1）
//*  2026/10/18  玄人 幸道         クライアント登録の有無を返す口を追加（#307 の段階 2）
//*  2026/10/18  玄人 幸道         登録された redirect_uri の 1 本目を取る口を追加（#306）
//*  2026/10/19  玄人 幸道         token_endpoint_auth_method を引く口を追加（#307 の段階 3）
//*  2026/10/20  玄人 幸道         逆引きを OwnerUserId で引くようにした（#307 の段階 5-a）
//*  2026/10/20  玄人 幸道         クライアントの所有者を引く口を追加（#307 の段階 5-b）
//*  2026/10/21  玄人 幸道         jwks_uri を引く口を追加（#309 の段階 1）
//*  2026/10/21  玄人 幸道         設定ファイルの jwks_uri を集める口を追加（#309 の段階 2）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri を引く口と HttpClient を渡す口を追加（#310 の段階 2）
//*  2026/10/21  玄人 幸道         frontchannel_logout_uri を引く口を追加（#310 の段階 3）
//*  2026/10/22  玄人 幸道         空白区切りの分解と HttpClient の口を Open棟梁 に移した（#294）
//*  2026/10/24  玄人 幸道         openid を常に広告するようにした（EnableOpenIDConnect の廃止。#314）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
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
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Str;

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

            HttpRequestMessage httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = cibaAuthZUri,
            };

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

            HttpResponseMessage httpResponseMessage = await _oAuth2HttpClient.SendAsync(httpRequestMessage);
            return await httpResponseMessage.Content.ReadAsStringAsync();
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
                return model.ClientSecret;
            }

            return "";
        }

        #endregion

        #region HasClient

        /// <summary>client_id の登録が在るか（#307 の段階 2）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>登録が在れば true</returns>
        /// <remarks>
        /// **「クライアントがまだ在るか」を確かめるための口**である
        /// （**アクセス トークンの検証が使う**。`CmnAccessToken.VerifyAccessToken`）。
        ///
        /// > **以前は `GetClientSecret(aud) != null` で確かめていたが、効いていなかった** —
        /// > **`GetClientSecret` は、未登録の `client_id` でも `""` を返す**（`null` ではない）。
        /// > **そのため、登録を消しても、既に発行されたアクセス トークンが
        /// > 期限切れまで通っていた**（#307 の段階 2 で修正）。
        ///
        /// **「秘密が空でないか」で判定してはならない** —
        /// **秘密を持たないクライアント**（PKCE だけの public クライアント）**のトークンまで止まる。**
        /// **見るのは「行が在るか」**である。
        /// </remarks>
        public bool HasClient(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                return true;
            }

            // saml2OAuth2Dataを検索
            return DataProvider.Get(client_id) != null;
        }

        #endregion

        #region GetClientsRedirectUri

        /// <summary>登録された redirect_uri の 1 本目を取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <returns>redirect_uri（登録が無ければ空）</returns>
        /// <remarks>
        /// **登録は n 件になった**（#306）。**ここは 1 本目を返す。**
        /// **照合には使わないこと** — **照合は `GetClientsRedirectUris`**（全件）を使う。
        /// **画面に 1 本だけ出したい所**（自己テストの画面）**のために残してある。**
        /// </remarks>
        public string GetClientsRedirectUri(string client_id, string response_type)
        {
            return this.GetClientsRedirectUri(client_id, response_type, out bool isResourceOwner);
        }

        /// <summary>登録された redirect_uri の 1 本目を取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>redirect_uri（登録が無ければ空）</returns>
        public string GetClientsRedirectUri(string client_id, string response_type, out bool isResourceOwner)
        {
            string[] uris = OAuth2AndOIDCSpec.SplitSpaceDelimited(
                this.GetClientsRedirectUriList(client_id, response_type, out isResourceOwner));

            return (0 < uris.Length) ? uris[0] : "";
        }

        /// <summary>登録された redirect_uri を全件取得する（#306）。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <returns>redirect_uri の並び（登録が無ければ 0 件）</returns>
        /// <remarks>
        /// **1 つのクライアントに n 件登録できる**（#306）。
        /// **登録は空白区切りの 1 つの文字列**で、**設定ファイルでも DB の列でも同じ形**である。
        ///
        /// **照合は、この全件に対して行う**（`CmnEndpoints.CheckRedirectUri`）。
        /// **定数値の解決は呼び出し側**（要素ごとに `GetRedirectUriFromConstr` を通す）。
        /// </remarks>
        public string[] GetClientsRedirectUris(string client_id, string response_type)
        {
            return OAuth2AndOIDCSpec.SplitSpaceDelimited(
                this.GetClientsRedirectUriList(client_id, response_type, out bool isResourceOwner));
        }

        /// <summary>登録された redirect_uri を、登録されたままの形で取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">response_type</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>空白区切りの列挙（登録が無ければ空）</returns>
        private string GetClientsRedirectUriList(string client_id, string response_type, out bool isResourceOwner)
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;

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

        #region GetClientsFrontChannelLogoutUri

        /// <summary>client_idからfrontchannel_logout_uriを取得する（#310 の段階 3）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>frontchannel_logout_uri（登録が無ければ空）</returns>
        /// <remarks>
        /// **登録が無い相手には、ブラウザ経由でも伝えない**
        /// （**Front-Channel Logout に対応していない RP** である）。
        /// 登録は 1 本（`backchannel_logout_uri` と同じ形）。
        /// 定数値（`test_self_fclogout`）の解決は、呼び出し側（`FrontChannelLogout`）で行う。
        /// </remarks>
        public string GetClientsFrontChannelLogoutUri(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("frontchannel_logout_uri"))
                {
                    return this.Oauth2ClientsInfo[client_id]["frontchannel_logout_uri"];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                return model.FrontChannelLogoutUri ?? "";
            }

            return "";
        }

        #endregion

        #region GetClientsBackChannelLogoutUri

        /// <summary>client_idからbackchannel_logout_uriを取得する（#310 の段階 2）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>backchannel_logout_uri（登録が無ければ空）</returns>
        /// <remarks>
        /// **登録が無い相手には、ログアウトを伝えない**
        /// （**Back-Channel Logout に対応していない RP** である）。
        /// 登録は 1 本（既存の `post_logout_redirect_uri` と同じ形）。
        /// 定数値（`test_self_bclogout`）の解決は、呼び出し側（`BackChannelLogout`）で行う。
        /// </remarks>
        public string GetClientsBackChannelLogoutUri(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("backchannel_logout_uri"))
                {
                    return this.Oauth2ClientsInfo[client_id]["backchannel_logout_uri"];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                return model.BackChannelLogoutUri ?? "";
            }

            return "";
        }

        #endregion

        #region GetClientsPostLogoutRedirectUri

        /// <summary>client_idからpost_logout_redirect_uriを取得する（#232）。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>post_logout_redirect_uri（登録が無ければ空）</returns>
        /// <remarks>
        /// **RP-Initiated Logout 1.0 §3 は、登録値と完全一致しなければ戻してはならない**としている。
        /// 登録は 1 本（既存の redirect_uri_code / redirect_uri_token と同じ形）。
        /// 定数値（test_self_logout）の解決は、呼び出し側（CmnEndpoints）で行う。
        /// </remarks>
        public string GetClientsPostLogoutRedirectUri(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                if (this.Oauth2ClientsInfo[client_id].ContainsKey("post_logout_redirect_uri"))
                {
                    return this.Oauth2ClientsInfo[client_id]["post_logout_redirect_uri"];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                return model.PostLogoutRedirectUri ?? "";
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
                return model.JwkECDsaPublickey;
            }

            return "";
        }

        #endregion

        #endregion

        #region GetJwksUri

        /// <summary>client_id から jwks_uri を取得する（#309 の段階 1）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>jwks_uri（**登録が無ければ null**）</returns>
        /// <remarks>
        /// **鍵を URL から引くクライアント**（RFC 7591 §2 の `jwks_uri`）。
        /// **`jwks`（列の鍵）とは排他**である（**動的登録は、両方在る要求を断る**）。
        /// **設定ファイルのクライアントでも書ける**（`jwks_uri` の鍵）。
        ///
        /// **ここでは取りに行かない** — **URL を返すだけ**である。
        /// **読む側（`CmnEndpoints.ClientAuthentication`）は同期**なので、
        /// **取得はキャッシュ越しに行う**（`RemoteJwkSetStore.PickJwksFromCache`）。
        /// </remarks>
        public string GetJwksUri(string client_id)
        {
            return this.GetRegisteredValue(client_id, "jwks_uri", model => model.JwksUri);
        }

        #endregion

        #region GetConfiguredJwksUris

        /// <summary>設定ファイルに書かれた `jwks_uri` を全件返す（#309 の段階 2）</summary>
        /// <returns>URL の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **起動のときに温めるために要る**（`JwksUriWarmUp`）。
        /// **`OAuth2ClientsInformation` の各クライアントの `jwks_uri`** を集める。
        ///
        /// **user store を読めない配備でも効く**ので、**こちらを先に温める。**
        /// </remarks>
        public List<string> GetConfiguredJwksUris()
        {
            List<string> urls = new List<string>();

            foreach (Dictionary<string, string> client in this.Oauth2ClientsInfo.Values)
            {
                if (client.ContainsKey("jwks_uri")
                    && !string.IsNullOrEmpty(client["jwks_uri"]))
                {
                    urls.Add(client["jwks_uri"]);
                }
            }

            return urls;
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

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
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
        /// <remarks>
        /// **登録に subject_types が無いときの既定値は `public`**。
        /// **扱う値は `public` と `pairwise` の 2 つ**（OIDC Core §8）。
        ///
        /// `sub` は「その RP の中で利用者を指す識別子」であって、表示用の属性ではない。
        /// **利用者名を RP に渡したいなら `preferred_username`**（`UserClaimsMapping`）。
        ///
        /// **既定値を変えても、既に発行した `sub` は動かない。**
        /// `SubjectIdProvider` が (Sector, UserId) → sub を記録しており、
        /// **PPIDExtension は、まずそこを引く**（#151 の段階 2）。
        /// つまり**効くのは、まだ `sub` を発行していない組み合わせだけ**である。
        /// </remarks>
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
                    return OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit();
                }
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;

                if (!string.IsNullOrEmpty(model.SubjectTypes))
                {
                    // 設定値
                    return model.SubjectTypes;
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit();
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;

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
        ///
        /// **saml2OAuth2Data（管理画面・動的登録で作ったクライアント）の `Scopes` 列も見る**（#307 の段階 1）。
        /// **以前は構成ファイルだけを見ていた** ので、
        /// **DB に登録したクライアントは「登録が無い」扱いになり、**
        /// **#198 の「クライアントごとの絞り」が一切効いていなかった**
        /// （`scopes_supported` の絞りだけが効いていた）。
        ///
        /// **列が空なら、従来どおり制限しない** — **既存の登録を壊さないため。**
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
                    return OAuth2AndOIDCSpec.ToDistinctList(dic["scope"]);
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（従来どおり）。
                return null;
            }

            // saml2OAuth2Dataを検索（#307 の段階 1）
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null && !string.IsNullOrWhiteSpace(model.Scopes))
            {
                return OAuth2AndOIDCSpec.ToDistinctList(model.Scopes);
            }

            // 登録が無い
            return null;
        }

        #endregion

        #region Client GrantTypes / ResponseTypes（#307 の段階 1）

        /// <summary>client_id から、使ってよいグラント（登録の grant_types）を取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>グラントの一覧（登録が無ければ null ＝ 制限しない）</returns>
        /// <remarks>
        /// **RFC 7591 §2 の `grant_types`。** **空白区切りで登録する**（`scope` と同じ流儀）。
        ///
        /// **空（未登録）なら制限しない** — **既存の登録を壊さないため。**
        /// **RFC 7591 §2 の既定（`authorization_code`）を、既存の登録に当てはめてはならない**
        /// （既存のクライアントはこの列を持たないので、当てはめると
        /// **`authorization_code` 以外が通らなくなる**という破壊になる）。
        /// **既定を書き込むのは、動的登録で作るときだけ**である。
        /// </remarks>
        public List<string> GetClientGrantTypes(string client_id)
        {
            return this.GetClientTypeList(client_id, "grant_types", false);
        }

        /// <summary>client_id から、使ってよい response_type（登録の response_types）を取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>response_type の一覧（登録が無ければ null ＝ 制限しない）</returns>
        /// <remarks>
        /// **RFC 7591 §2 の `response_types`。**
        ///
        /// **要素の中の空白は、そのままでは持てない**（区切りと区別が付かない）ので、
        /// **`code id_token` のような組み合わせは `code+id_token` と書く。**
        /// **ここで空白へ戻してから返す**（突き合わせる相手は、要求の `response_type` である）。
        /// </remarks>
        public List<string> GetClientResponseTypes(string client_id)
        {
            return this.GetClientTypeList(client_id, "response_types", true);
        }

        /// <summary>登録の列挙（grant_types / response_types）を読む</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="key">構成ファイルのキー（grant_types / response_types）</param>
        /// <param name="unescapeSpace">要素の中の「+」を空白に戻すか</param>
        /// <returns>一覧（登録が無ければ null ＝ 制限しない）</returns>
        /// <remarks>
        /// **構成ファイル → saml2OAuth2Data の順に見る**（他の `Get*` と同じ）。
        /// **読み出しの入口を 1 か所に保つ**ため、2 つの項目で共用している。
        /// </remarks>
        private List<string> GetClientTypeList(string client_id, string key, bool unescapeSpace)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey(key) && !string.IsNullOrWhiteSpace(dic[key]))
                {
                    return Helper.ToDistinctList(dic[key], unescapeSpace);
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る。**
                return null;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                string value = (key == "grant_types") ? model.GrantTypes : model.ResponseTypes;

                if (!string.IsNullOrWhiteSpace(value))
                {
                    return Helper.ToDistinctList(value, unescapeSpace);
                }
            }

            // 登録が無い
            return null;
        }

        /// <summary>空白区切りの登録値を、重複の無い一覧にする</summary>
        /// <param name="value">登録値</param>
        /// <param name="unescapeSpace">要素の中の「+」を空白に戻すか</param>
        /// <returns>一覧</returns>
        /// <remarks>
        /// **切り方は `OAuth2AndOIDCSpec.SplitSpaceDelimited` と同じ**（半角・全角の空白・タブ・改行。空の要素は捨てる）。
        /// **`+` を戻さないなら、`OAuth2AndOIDCSpec.ToDistinctList` を使う。**
        /// </remarks>
        public static List<string> ToDistinctList(string value, bool unescapeSpace)
        {
            List<string> ret = new List<string>();

            foreach (string s in OAuth2AndOIDCSpec.SplitSpaceDelimited(value))
            {
                string item = unescapeSpace ? s.Replace("+", " ") : s;

                if (!ret.Contains(item))
                {
                    ret.Add(item);
                }
            }

            return ret;
        }

        #endregion

        #region Client PKCE

        /// <summary>client_idから、PKCEを必須とするかどうかを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>必須なら true（登録が無ければ false）</returns>
        /// <remarks>
        /// **サーバ全体の Config.RequirePkce とは OR で組み合わせる（#221）。**
        /// クライアント側で true にはできるが、**サーバが締めているものを緩めることはできない。**
        ///
        /// 未設定は false（＝サーバの設定に従う）。
        /// **保存済みの登録には、この項目が無い。** JSON に無ければ既定値の false になるので、
        /// 従来どおりの動作が続く（oauth2_oidc_mode のような「静かに緩む」問題は起きない）。
        /// </remarks>
        public bool GetClientRequirePkce(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey("require_pkce"))
                {
                    // **空文字列で Convert.ToBoolean は例外になる**ので、TryParse で読む。
                    bool.TryParse(dic["require_pkce"], out bool require);
                    return require;
                }

                return false;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {

                return model.RequirePkce;
            }

            // 登録が無い
            return false;
        }

        #endregion

        #region id_token_signed_response_alg

        /// <summary>client_id から id_token_signed_response_alg を取得する（#129 の段階 2）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>alg（登録が無ければ RS256）</returns>
        /// <remarks>
        /// **そのクライアントに発行する access_token と id_token の署名 alg** である
        /// （OIDC Dynamic Registration の `id_token_signed_response_alg`）。
        ///
        /// **`/token` の id_token は、access_token のヘッダ alg に従って署名する**実装なので、
        /// **2 つを揃える**（CIBA が ES256 を使う既存の作りと同じ形）。
        ///
        /// | | |
        /// |---|---|
        /// | 登録が無い | **`RS256`**（＝ 従来どおり） |
        /// | 既知でない値 | **入口で拒否する**（`CmnEndpoints.CheckClientMode`。#224 と同じ方針） |
        ///
        /// **CIBA は ES256 のまま**である（FAPI-CIBA が PS256 / ES256 を求めるため、登録値で上書きしない）。
        /// **JARM（`authorization_signing_alg_values_supported`）も RS256 のまま。**
        /// </remarks>
        public string GetIdTokenSignedResponseAlg(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey("id_token_signed_response_alg")
                    && !string.IsNullOrEmpty(dic["id_token_signed_response_alg"]))
                {
                    return dic["id_token_signed_response_alg"];
                }

                return JwtConst.RS256;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {

                if (!string.IsNullOrEmpty(model.IdTokenSignedResponseAlg))
                {
                    return model.IdTokenSignedResponseAlg;
                }
            }

            // 登録が無い
            return JwtConst.RS256;
        }

        #endregion

        #region token_endpoint_auth_signing_alg / request_object_signing_alg

        /// <summary>client_id から token_endpoint_auth_signing_alg を取得する（#262）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>alg（**登録が無ければ null** ＝ 絞らない）</returns>
        /// <remarks>
        /// **`client_assertion`（`private_key_jwt`）を、この alg だけに絞る**
        /// （OIDC Registration 1.0 §2 の `token_endpoint_auth_signing_alg`）。
        ///
        /// **発行する側（`GetIdTokenSignedResponseAlg`）と既定が逆**である。
        ///
        /// | | |
        /// |---|---|
        /// | **発行する側** | 登録が無ければ **`RS256`**（何かで署名しなければならない） |
        /// | **受ける側（これ）** | 登録が無ければ **null** ＝ **絞らない**（従来どおり、登録された鍵で順に試す） |
        ///
        /// **既知でない値は、使う側（`CmnEndpoints.ClientAuthentication`）が拒否する。**
        /// 受ける集合は `CmnEndpoints.TokenEndpointAuthSigningAlgs`。
        /// </remarks>
        public string GetTokenEndpointAuthSigningAlg(string client_id)
        {
            return this.GetRegisteredValue(client_id, "token_endpoint_auth_signing_alg",
                model => model.TokenEndpointAuthSigningAlg);
        }

        /// <summary>client_id から request_object_signing_alg を取得する（#262）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>alg（**登録が無ければ null** ＝ 絞らない）</returns>
        /// <remarks>
        /// **Request Object（`/ros` / `/par` / `request` パラメタ）を、この alg だけに絞る**
        /// （OIDC Registration 1.0 §2 の `request_object_signing_alg`）。
        ///
        /// **CIBA の `request` は対象外**である。**あちらは `ES256` 固定**で、
        /// **仕様でも別の登録項目**（`backchannel_authentication_request_signing_alg`）になっている。
        ///
        /// 受ける集合は `CmnEndpoints.RequestObjectSigningAlgs`。
        /// </remarks>
        public string GetRequestObjectSigningAlg(string client_id)
        {
            return this.GetRegisteredValue(client_id, "request_object_signing_alg",
                model => model.RequestObjectSigningAlg);
        }

        #endregion

        #region token_endpoint_auth_method

        /// <summary>client_id から token_endpoint_auth_method を取得する（#307 の段階 3）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>方法（**登録が無ければ null** ＝ 秘密ベースの 2 つ）</returns>
        /// <remarks>
        /// **RFC 7591 §2 の `token_endpoint_auth_method`。**
        /// **登録が無い（null / 空）なら `client_secret_basic` / `client_secret_post` を暗黙に許す**
        /// （**既存の登録を壊さないため**ではなく、**強い方法は明示を要する**という決定による。
        /// #307 の段階 3）。
        ///
        /// **既知でない値は、使う側（`CmnEndpoints.AllowsAuthMethod`）が拒否する**
        /// （#224 の段階 2 と同じ方針。「一番厳しいものに倒す」はしない）。
        /// 受ける集合は `CmnEndpoints.TokenEndpointAuthMethods`。
        /// </remarks>
        public string GetTokenEndpointAuthMethod(string client_id)
        {
            return this.GetRegisteredValue(client_id, "token_endpoint_auth_method",
                model => model.TokenEndpointAuthMethod);
        }

        /// <summary>登録された値を引く（構成ファイル → saml2OAuth2Data。#262）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="key">*.config の項目名</param>
        /// <param name="fromModel">画面登録（saml2OAuth2Data）から取り出す式</param>
        /// <returns>登録値（登録が無ければ null）</returns>
        /// <remarks>
        /// **同じ引き方をする項目が複数ある**ので、1 か所にまとめた
        /// （`token_endpoint_auth_signing_alg` / `request_object_signing_alg` /
        /// **`token_endpoint_auth_method`**（#307 の段階 3））。
        /// **`GetIdTokenSignedResponseAlg` と違い、既定値を持たない**（null ＝ 絞らない）。
        /// </remarks>
        private string GetRegisteredValue(string client_id, string key,
            Func<ManageAddSaml2OAuth2DataViewModel, string> fromModel)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (dic.ContainsKey(key)
                    && !string.IsNullOrEmpty(dic[key]))
                {
                    return dic[key];
                }

                return null;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {

                string value = fromModel(model);

                if (!string.IsNullOrEmpty(value))
                {
                    return value;
                }
            }

            // 登録が無い（＝ 絞らない）
            return null;
        }

        #endregion

        #region GetConfigClientsPublicRedirectUris

        /// <summary>
        /// 構成ファイルに登録された **public クライアント**の `redirect_uri_*` を返す（#265）
        /// </summary>
        /// <returns>登録値（記号のまま。重複は除いていない）</returns>
        /// <remarks>
        /// **CORS で許可するオリジンを導くために使う**（`CmnEndpoints.GetCorsAllowedOrigins`）。
        /// **記号の解決とオリジンの取り出しは、呼ぶ側で行う**（`GetRedirectUriFromConstr` が在る側）。
        ///
        /// | | |
        /// |---|---|
        /// | **public クライアントに限る** | `client_secret` が空のもの。**confidential は `/token` をサーバ間で呼ぶ**ので、ブラウザから叩かせる必要が無い |
        /// | **構成ファイルに限る** | **画面登録（`saml2OAuth2Data`）は含めない。** プリフライト（`OPTIONS`）は `client_id` を持たないため**オリジンの集合全体**が要るが、`DataProvider` に全件を列挙する口が無く、分散キャッシュも無い（E-2） |
        ///
        /// **画面登録の SPA は、`Config.CorsAllowedOrigins` に足して通す。**
        /// </remarks>
        public List<string> GetConfigClientsPublicRedirectUris()
        {
            List<string> uris = new List<string>();

            foreach (string clientId in this.Oauth2ClientsInfo.Keys)
            {
                Dictionary<string, string> client = this.Oauth2ClientsInfo[clientId];

                // **confidential は対象外**（client_secret を持つもの）。
                if (client.ContainsKey("client_secret")
                    && !string.IsNullOrEmpty(client["client_secret"]))
                {
                    continue;
                }

                // **`web_origins` が書かれていれば、それを使う**（#266）。
                //   **書いたときは、導出しない**（登録どおりに絞る）。
                if (client.ContainsKey("web_origins")
                    && !string.IsNullOrEmpty(client["web_origins"]))
                {
                    uris.Add(client["web_origins"]);
                    continue;
                }

                foreach (string key in new string[] { "redirect_uri_code", "redirect_uri_token" })
                {
                    if (client.ContainsKey(key)
                        && !string.IsNullOrEmpty(client[key]))
                    {
                        uris.Add(client[key]);
                    }
                }
            }

            return uris;
        }

        #endregion

        #region GetStoredClientsPublicRedirectUris

        /// <summary>
        /// **画面から登録された public クライアント**の `web_origins` / `redirect_uri_*` を返す（#266）
        /// </summary>
        /// <returns>登録値（記号のまま。重複は除いていない）</returns>
        /// <remarks>
        /// **構成ファイル側（`GetConfigClientsPublicRedirectUris`）と同じ規則**で選ぶ。
        ///
        /// | | |
        /// |---|---|
        /// | **public クライアントに限る** | `client_secret` が空のもの |
        /// | **`web_origins` が在れば、それを使う** | **書いたときは導出しない** |
        /// | **無ければ `redirect_uri_*`** | #265 の挙動 |
        ///
        /// **`DataProvider.GetAllUris` を呼ぶので、毎回呼ばないこと。**
        /// **読むのは URI 関連の列だけ**（#270 で列にしたので、絞れる）。
        /// 呼ぶ側（`CmnEndpoints.GetCorsAllowedOrigins`）がキャッシュする。
        /// </remarks>
        public List<string> GetStoredClientsPublicRedirectUris()
        {
            List<string> uris = new List<string>();

            foreach (ManageAddSaml2OAuth2DataViewModel model in DataProvider.GetAllUris())
            {
                if (model == null)
                {
                    continue;
                }

                // **confidential は対象外。**
                if (!string.IsNullOrEmpty(model.ClientSecret))
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(model.WebOrigins))
                {
                    uris.Add(model.WebOrigins);
                    continue;
                }

                if (!string.IsNullOrEmpty(model.RedirectUriCode))
                {
                    uris.Add(model.RedirectUriCode);
                }

                if (!string.IsNullOrEmpty(model.RedirectUriToken))
                {
                    uris.Add(model.RedirectUriToken);
                }
            }

            return uris;
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
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
                return model.ClientName;
            }

            return "";
        }

        #endregion

        #region GetOwnerUserId（#307 の段階 5-b）

        /// <summary>client_id から、そのクライアントの所有者（`Users.Id`）を引く</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>所有者の `Users.Id`（決まらなければ空）</returns>
        /// <remarks>
        /// **`client_credentials` で動的登録を叩くときに、登録の所有者を決めるため**に在る
        /// （#307 の段階 5-b）。**トークンに利用者が居ない**ので、
        /// **「認証したクライアントの所有者」を、作る登録の所有者にする。**
        ///
        /// | クライアントの出どころ | 所有者 |
        /// |---|---|
        /// | **構成ファイル**（`OAuth2ClientsInformation`） | **`owner` 属性**（**利用者名**）を引いて、その利用者の `Users.Id` |
        /// | **登録の表**（`Saml2OAuth2Data`） | **`OwnerUserId`**（そのまま。`Users.Id` である） |
        ///
        /// **構成ファイルが「名前」なのは、人が書く物だから**である
        /// （**`Users.Id` は書けない**）。
        /// **その代わり、利用者名を変えたら設定も直す必要がある** —
        /// **表の側は id なので切れない**（段階 5-a-1 でそう移した）。
        ///
        /// **決まらないことがある**（**どれも空を返す**）。
        ///
        /// | | |
        /// |---|---|
        /// | **`owner` を書いていない構成ファイルのクライアント** | **配備全体のもの**で、1 人の持ち物ではない |
        /// | **`owner` に書いた利用者が居ない** | **設定の誤り**（**名前を変えた後に直し忘れた**ときもここ） |
        /// | **所有者の無い登録**（種データ） | **`OwnerUserId` が空** |
        /// | **登録が無い `client_id`** | — |
        ///
        /// **呼ぶ側は、空を「所有者が決まらない」として断ること**
        /// （`ClientRegistrationProvider.Register` は `403` ＋ `access_denied`）。
        /// </remarks>
        public string GetOwnerUserId(string client_id)
        {
            client_id = client_id ?? "";

            // *.config内を検索
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                Dictionary<string, string> dic = this.Oauth2ClientsInfo[client_id];

                if (!dic.ContainsKey("owner")
                    || string.IsNullOrWhiteSpace(dic["owner"]))
                {
                    //  **構成ファイルに在るクライアントは、ここで打ち切る**
                    //    （`GetClientScopes` と同じ流儀）。
                    return "";
                }

                ApplicationUser owner = CmnUserStore.FindByName(dic["owner"].Trim());

                //  **居ないことがある**（設定の誤り）。**空を返す** —
                //    **null 参照で 500 にしない**（#210 / #241 と同じ性質）。
                return (owner == null) ? "" : owner.Id;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.Get(client_id);

            return (model == null || string.IsNullOrEmpty(model.OwnerUserId))
                ? "" : model.OwnerUserId;
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
        /// <remarks>
        /// **利用者名で引いたときは、その人の登録のうち 1 件を返す**（#307 の段階 5-a）。
        ///
        /// **以前は `Users.ClientID`（1 枠）を返していた。**
        /// **1 利用者 n クライアント**になったので、**「1 件」の意味が変わった。**
        ///
        /// | | |
        /// |---|---|
        /// | **どれを返すか決めていない** | **`DataProvider.GetFirstByOwner`**（並びは決めていない） |
        /// | **0 件なら空** | **以前は「宙に浮いた GUID」が返っていた**（登録が無くても値が入っていた） |
        ///
        /// **呼ぶ側は「その人のクライアント 1 つ」で足りる所だけ**である —
        /// **自己テストの導線**（`HomeController` の「ログイン・ユーザの Client」）と、
        /// **認可ログの `User Account`**（1 行）。
        /// **n 件から選ばせるのは、管理画面の話**（#307 の段階 5-a-2）。
        /// </remarks>
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

            // **見つからないことがある。**
            //   クライアント名でも利用者名でもない値を渡されると、
            //   **以前は null 参照で、処理されない例外（HTTP 500）になっていた**
            //   （#210 / #241 と同じ性質。#151 の段階 4 で踏んだ）。
            if (user == null)
            {
                return "";
            }

            //  **その人の登録のうち 1 件**（#307 の段階 5-a）。
            //    **0 件なら空を返す** — **以前は「宙に浮いた GUID」が返っていた。**
            ManageAddSaml2OAuth2DataViewModel model = DataProvider.GetFirstByOwner(user.Id);

            if (model == null)
            {
                return "";
            }

            isResourceOwner = true;
            return model.ClientID;
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
                OAuth2AndOIDCConst.Scope_Roles
            };

            // openid（**OIDC は常に有効**。#314 で EnableOpenIDConnect を廃止した）
            scopes.Add(OAuth2AndOIDCConst.Scope_Openid);

            //  **クライアント登録の管理 API 専用の scope は、動的登録を開けた配備だけ**
            //    （#307 の段階 1）。**閉じている配備では、広告も発行もしない。**
            if (Config.EnableDynamicClientRegistration)
            {
                scopes.Add(Const.ScopeClientRegistration);
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
        ///
        /// **`Const.ScopeClientRegistration`（クライアント登録の管理 API）だけは、倒し方が逆**
        /// （#307 の段階 1）。**登録に明記していなければ出さない。**
        ///
        /// | | 倒し方 |
        /// |---|---|
        /// | 普通の scope | **登録が無ければ制限しない**（従来どおり） |
        /// | **`client_registration`** | **登録に明記していなければ出さない** |
        ///
        /// **理由** : **この scope は「クライアント登録を作れる」権限**である。
        /// **「登録が無ければ制限しない」を当てはめると、**
        /// **`scope` を登録していない既存のクライアントが全て、**
        /// **ROPC で登録を作れることになる。**
        /// </remarks>
        public static IEnumerable<string> FilterSupportedScopes(IEnumerable<string> scopes, string client_id)
        {
            List<string> ret = new List<string>();
            List<string> permitted = Helper.GetInstance().GetClientScopes(client_id);

            foreach (string s in Helper.FilterSupportedScopes(scopes))
            {
                if (s == Const.ScopeClientRegistration)
                {
                    //  **明記されているときだけ通す**（#307 の段階 1）。
                    if (permitted != null && permitted.Contains(s))
                    {
                        ret.Add(s);
                    }
                }
                else if (permitted == null || permitted.Contains(s))
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

            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnIssuerClaim, CmnServerParams.IssuerId));
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