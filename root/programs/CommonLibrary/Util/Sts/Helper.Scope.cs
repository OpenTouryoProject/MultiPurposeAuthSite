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
//* クラス日本語名  ：Helper（ライブラリ）の scope とクレーム（static）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
#else
using MultiPurposeAuthSite;
#endif

using System.Collections.Generic;
using System.Security.Claims;

#if NETFX
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>Helper（scope とクレーム（static））</summary>
    public partial class Helper
    {
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
        /// **`Const.ScopeClientRegistration`（クライアント登録の管理 API）と
        /// `OAuth2AndOIDCConst.Scope_Auth`（同意画面を出さない）だけは、倒し方が逆**
        /// （#307 の段階 1 / #294）。**登録に明記していなければ出さない。**
        ///
        /// | | 倒し方 |
        /// |---|---|
        /// | 普通の scope | **登録が無ければ制限しない**（従来どおり） |
        /// | **`client_registration`** | **登録に明記していなければ出さない** |
        /// | **`auth`** | **登録に明記していなければ出さない** |
        ///
        /// **理由** : どちらも、**要求する側が自分で付けてよい scope ではない。**
        /// **「登録が無ければ制限しない」を当てはめると、**
        /// **`scope` を登録していない既存のクライアントが全て、**
        ///
        /// - `client_registration` : **ROPC で登録を作れることになる。**
        /// - `auth` : **同意画面を飛ばせることになる**（同意を求めるかを、クライアントが決めてしまう）。
        ///   **飛ばしてよいかは、登録を管理する人が決める**（Keycloak の「Consent Required」と同じ考え方）。
        /// </remarks>
        public static IEnumerable<string> FilterSupportedScopes(IEnumerable<string> scopes, string client_id)
        {
            List<string> ret = new List<string>();
            List<string> permitted = Helper.GetInstance().GetClientScopes(client_id);

            foreach (string s in Helper.FilterSupportedScopes(scopes))
            {
                if (s == Const.ScopeClientRegistration
                    || s == OAuth2AndOIDCConst.Scope_Auth)
                {
                    //  **明記されているときだけ通す**（#307 の段階 1 / #294）。
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

        #endregion
    }
}