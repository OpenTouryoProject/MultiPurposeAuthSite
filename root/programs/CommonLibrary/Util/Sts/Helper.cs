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
//*  2026/10/18  玄人 幸道         登録された redirect_uri の 1 本目を取る口を追加（#306）
//*  2026/10/21  玄人 幸道         jwks_uri を引く口を追加（#309 の段階 1）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri を引く口と HttpClient を渡す口を追加（#310 の段階 2）
//*  2026/10/24  玄人 幸道         openid を常に広告するようにした（EnableOpenIDConnect の廃止。#314）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//*  2026/10/25  玄人 幸道         auth を、登録に明記したクライアントにだけ出すようにした（#294）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Sts へ移した（配置の見直し。#294）
//*  2026/10/31  玄人 幸道         partial に分割した（WebApi / ClientCredential / ClientUri / ClientMetadata / Scope。#294）
//*  2026/10/31  玄人 幸道         コンテナ化の宛先の書き換えで、%xx を戻さず、先頭の scheme://authority だけを替える（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
#else
using MultiPurposeAuthSite;
#endif

using MultiPurposeAuthSite.Network;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using System.Net;
using System.Net.Http;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>Helper（ライブラリ）</summary>
    public partial class Helper
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

        #endregion

        #endregion

        #region staticメソッド

        #region コンテナ化サポート

        /// <summary>GetContainerizatedAuthZServerUri</summary>
        /// <param name="orgUri">Uri</param>
        /// <returns>Uri</returns>
        /// <remarks>
        /// **替えるのは先頭の `scheme://authority` だけ**（#294）。
        /// **以前は `Uri.ToString()` と文字列の `Replace` で組み直していた**ので、
        ///
        /// - **`%xx` が戻った**（`ToString` は escape を外す。`%26` が `&amp;` になり、別のパラメタに化ける）
        /// - **クエリの中の同じ authority も書き換えた**（`redirect_uri` の値など）
        ///
        /// **残りは `AbsoluteUri`（escape したまま）から切り出す。**
        /// </remarks>
        public static Uri GetContainerizatedAuthZServerUri(Uri orgUri)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // コンテナではない
            }
            else
            {
                string temp = "";

                // 先頭の scheme://authority と、その後ろ（escape したまま）
                string prefix = orgUri.GetLeftPart(UriPartial.Authority);
                string rest = orgUri.AbsoluteUri.Substring(prefix.Length);

                // コンテナの可能性
                temp = Config.OAuth2ContainerizatedAuthSvrFqdnAndPort;
                if (!string.IsNullOrEmpty(temp))
                {
                    // 置換（ホスト名とポートだけ。スキームは元のまま）
                    return new Uri(orgUri.Scheme + "://" + temp + rest);
                }

                temp = Config.OAuth2ContainerizatedAuthSvrEPRootURI;
                if (!string.IsNullOrEmpty(temp))
                {
                    // 置換（スキームごと）
                    return new Uri(temp + rest);
                }
            }

            // 置換条件に合致しなかった場合。
            return orgUri;
        }

        #endregion

        #endregion
    }
}