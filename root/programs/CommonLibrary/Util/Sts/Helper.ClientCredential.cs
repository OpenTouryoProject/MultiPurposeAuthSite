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
//* クラス日本語名  ：Helper（ライブラリ）の クライアントの資格情報（秘密・公開鍵・jwks_uri・証明書の DN）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         構成ファイルに在るクライアントは、項目が無くても画面登録を読みに行かない（#294）
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
    /// <summary>Helper（クライアントの資格情報（秘密・公開鍵・jwks_uri・証明書の DN））</summary>
    public partial class Helper
    {
        #region instanceメソッド

        #region Credential( → Saml2OAuth2DataProvider)

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(OAuth2AndOIDCConst.client_secret))
                {
                    return this.Oauth2ClientsInfo[client_id][OAuth2AndOIDCConst.client_secret];
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（#294。`GetClientScopes` などと同じ流儀）。
                //   以前は項目が無いと、同じ client_id の画面登録（saml2OAuth2Data）を読みに行っていた。
                return "";
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
            return Saml2OAuth2DataProvider.Get(client_id) != null;
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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientJwkRsaPublicKey))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientJwkRsaPublicKey];
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（#294。`GetClientScopes` などと同じ流儀）。
                //   以前は項目が無いと、同じ client_id の画面登録（saml2OAuth2Data）を読みに行っていた。
                return "";
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientJwkEcdsaPublicKey))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientJwkEcdsaPublicKey];
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（#294。`GetClientScopes` などと同じ流儀）。
                //   以前は項目が無いと、同じ client_id の画面登録（saml2OAuth2Data）を読みに行っていた。
                return "";
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
            return this.GetRegisteredValue(client_id, OAuth2AndOIDCConst.jwks_uri, model => model.JwksUri);
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
                if (client.ContainsKey(OAuth2AndOIDCConst.jwks_uri)
                    && !string.IsNullOrEmpty(client[OAuth2AndOIDCConst.jwks_uri]))
                {
                    urls.Add(client[OAuth2AndOIDCConst.jwks_uri]);
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
                if (this.Oauth2ClientsInfo[client_id].ContainsKey(Const.ClientTlsClientAuthSubjectDn))
                {
                    return this.Oauth2ClientsInfo[client_id][Const.ClientTlsClientAuthSubjectDn];
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（#294。`GetClientScopes` などと同じ流儀）。
                //   以前は項目が無いと、同じ client_id の画面登録（saml2OAuth2Data）を読みに行っていた。
                return "";
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

            if (model != null)
            {
                isResourceOwner = true;
                return model.TlsClientAuthSubjectDn;
            }

            return "";
        }

        #endregion

        #endregion

        #endregion

        #endregion
    }
}