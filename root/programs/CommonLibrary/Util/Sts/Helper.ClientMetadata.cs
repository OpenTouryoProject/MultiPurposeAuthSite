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
//* クラス日本語名  ：Helper（ライブラリ）の クライアントの登録項目（subject_types・ClientMode・scope・alg・名前など）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         client_name の無い登録で落ちない。名前の照合で大文字小文字を区別する。コメント（#294）
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
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>Helper（クライアントの登録項目（subject_types・ClientMode・scope・alg・名前など））</summary>
    public partial class Helper
    {
        #region instanceメソッド

        #region Credential( → Saml2OAuth2DataProvider)

        #region Subject Types

        /// <summary>client_idからSubjectTypesを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>SubjectTypes</returns>
        public string GetSubjectTypes(string client_id)
        {
            return this.GetSubjectTypes(client_id, out bool isResourceOwner);
        }

        /// <summary>client_idからSubjectTypesを取得する。</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="isResourceOwner">bool</param>
        /// <returns>SubjectTypes</returns>
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

                if (dic.ContainsKey(Const.ClientSubjectTypes))
                {
                    // 設定値
                    return this.Oauth2ClientsInfo[client_id][Const.ClientSubjectTypes];
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit();
                }
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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

                if (dic.ContainsKey(Const.ClientMode))
                {
                    // 設定値
                    return this.Oauth2ClientsInfo[client_id][Const.ClientMode];
                }
                else
                {
                    // 既定値
                    return OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit();
                }
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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

                if (dic.ContainsKey(OAuth2AndOIDCConst.scope) && dic[OAuth2AndOIDCConst.scope] != null)
                {
                    return OAuth2AndOIDCSpec.ToDistinctList(dic[OAuth2AndOIDCConst.scope]);
                }

                // **構成ファイルに在るクライアントは、ここで打ち切る**（従来どおり）。
                return null;
            }

            // saml2OAuth2Dataを検索（#307 の段階 1）
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
            return this.GetClientTypeList(client_id, Const.ClientGrantTypes, false);
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
            return this.GetClientTypeList(client_id, Const.ClientResponseTypes, true);
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
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

            if (model != null)
            {
                string value = (key == Const.ClientGrantTypes) ? model.GrantTypes : model.ResponseTypes;

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

                if (dic.ContainsKey(Const.ClientRequirePkce))
                {
                    // **空文字列で Convert.ToBoolean は例外になる**ので、TryParse で読む。
                    bool.TryParse(dic[Const.ClientRequirePkce], out bool require);
                    return require;
                }

                return false;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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

                if (dic.ContainsKey(Const.ClientIdTokenSignedResponseAlg)
                    && !string.IsNullOrEmpty(dic[Const.ClientIdTokenSignedResponseAlg]))
                {
                    return dic[Const.ClientIdTokenSignedResponseAlg];
                }

                return JwtConst.RS256;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
            return this.GetRegisteredValue(client_id, Const.ClientTokenEndpointAuthSigningAlg,
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
            return this.GetRegisteredValue(client_id, Const.ClientRequestObjectSigningAlg,
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
            return this.GetRegisteredValue(client_id, Const.ClientTokenEndpointAuthMethod,
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
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
            //   **client_name が無くても落ちない**（#294。以前は KeyNotFoundException で 500）。
            if (this.Oauth2ClientsInfo.ContainsKey(client_id))
            {
                return this.Oauth2ClientsInfo[client_id].TryGetValue(Const.ClientName, out string name)
                    ? (name ?? "") : "";
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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

                if (!dic.ContainsKey(Const.ClientOwner)
                    || string.IsNullOrWhiteSpace(dic[Const.ClientOwner]))
                {
                    //  **構成ファイルに在るクライアントは、ここで打ち切る**
                    //    （`GetClientScopes` と同じ流儀）。
                    return "";
                }

                ApplicationUser owner = CmnUserStore.FindByName(dic[Const.ClientOwner].Trim());

                //  **居ないことがある**（設定の誤り）。**空を返す** —
                //    **null 参照で 500 にしない**（#210 / #241 と同じ性質）。
                return (owner == null) ? "" : owner.Id;
            }

            // saml2OAuth2Dataを検索
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(client_id);

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
        /// | **どれを返すか決めていない** | **`Saml2OAuth2DataProvider.GetFirstByOwner`**（並びは決めていない） |
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

            if (string.IsNullOrEmpty(clientName))
            {
                // **null で落ちない**（#294。以前は NullReferenceException）。
                return "";
            }

            // *.config内を検索
            //   **大文字小文字を区別する**（#294）。**以前は区別しなかった**ので、
            //   **クライアント名と大文字小文字だけ違う利用者**（例 : `testclient`）を引くと、
            //   **その人の登録ではなく、構成ファイルのクライアントが返った。**
            //   **client_name の無い登録も落ちない**（以前は KeyNotFoundException で 500）。
            foreach (string clientId in this.Oauth2ClientsInfo.Keys)
            {
                Dictionary<string, string> client
                    = this.Oauth2ClientsInfo[clientId];

                if (client.TryGetValue(Const.ClientName, out string temp)
                    && string.Equals(temp, clientName, StringComparison.Ordinal))
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
            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.GetFirstByOwner(user.Id);

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
    }
}