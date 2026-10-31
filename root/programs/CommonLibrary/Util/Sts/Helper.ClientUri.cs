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
//* クラス日本語名  ：Helper（ライブラリ）の クライアントの戻り先（redirect_uri・ログアウト・ACS）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.ViewModels;

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Extensions.Sts;

using System.Collections.Generic;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>Helper（クライアントの戻り先（redirect_uri・ログアウト・ACS））</summary>
    public partial class Helper
    {
        #region instanceメソッド

        #region Credential( → Saml2OAuth2DataProvider)

        #region Client authentication

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
                    if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientRedirectUriCode))
                    {
                        return this.Oauth2ClientsInfo[client_id][Const.ClientRedirectUriCode];
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
                    if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientRedirectUriToken))
                    {
                        return this.Oauth2ClientsInfo[client_id][Const.ClientRedirectUriToken];
                    }
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientFrontChannelLogoutUri))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientFrontChannelLogoutUri];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientBackChannelLogoutUri))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientBackChannelLogoutUri];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientPostLogoutRedirectUri))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientPostLogoutRedirectUri];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientRedirectUriSaml))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientRedirectUriSaml];
                }
            }

            // Saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
                return model.RedirectUriSaml;
            }

            return "";
        }

        #endregion

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
        /// | **構成ファイルに限る** | **画面登録（`saml2OAuth2Data`）は含めない。** プリフライト（`OPTIONS`）は `client_id` を持たないため**オリジンの集合全体**が要るが、`Saml2OAuth2DataProvider` に全件を列挙する口が無く、分散キャッシュも無い（E-2） |
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
                if (client.ContainsKey(OAuth2AndOIDCConst.client_secret)
                    && !string.IsNullOrEmpty(client[OAuth2AndOIDCConst.client_secret]))
                {
                    continue;
                }

                // **`web_origins` が書かれていれば、それを使う**（#266）。
                //   **書いたときは、導出しない**（登録どおりに絞る）。
                if (client.ContainsKey(Const.ClientWebOrigins)
                    && !string.IsNullOrEmpty(client[Const.ClientWebOrigins]))
                {
                    uris.Add(client[Const.ClientWebOrigins]);
                    continue;
                }

                foreach (string key in new string[] { Const.ClientRedirectUriCode, Const.ClientRedirectUriToken })
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
        /// **`Saml2OAuth2DataProvider.GetAllUris` を呼ぶので、毎回呼ばないこと。**
        /// **読むのは URI 関連の列だけ**（#270 で列にしたので、絞れる）。
        /// 呼ぶ側（`CmnEndpoints.GetCorsAllowedOrigins`）がキャッシュする。
        /// </remarks>
        public List<string> GetStoredClientsPublicRedirectUris()
        {
            List<string> uris = new List<string>();

            foreach (ManageAddSaml2OAuth2DataViewModel model in Saml2OAuth2DataProvider.GetAllUris())
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

        #endregion

        #endregion
    }
}