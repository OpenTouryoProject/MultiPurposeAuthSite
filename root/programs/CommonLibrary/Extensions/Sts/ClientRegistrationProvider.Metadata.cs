//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：ClientRegistrationProvider
//* クラス日本語名  ：動的クライアント登録（RFC 7591）の metadata の検査
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/26  玄人 幸道         新規（ClientRegistrationProvider.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         動的登録で device_code × private_key_jwt を断らない（両方の口が受けるようにした。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.Linq;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>ClientRegistrationProvider（metadata の検査）</summary>
    public static partial class ClientRegistrationProvider
    {
        #region 検査

        /// <summary>要求のメタデータを検査して、保存する形にする</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="model">保存する形（出力）</param>
        /// <param name="code">誤りのコード（RFC 7591 §3.2.2）</param>
        /// <param name="description">誤りの説明</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **知らないメタデータは無視する**（RFC 7591 §3.2.1 が認めている）。
        /// **ただし、無視すると黙って弱くなるものは断る**（`jwks` / `jwks_uri` /
        /// `token_endpoint_auth_method`）。
        ///
        /// **`software_statement` は、一番先に見る。**
        /// **主張を本文へ重ねてから、以降の検査にかける** —
        /// **statement が主張した値も、同じ検査を通る**
        /// （**署名が付いていても、この配備が扱えない値は通さない**）。
        /// </remarks>
        private static bool Validate(
            JObject metadata, ManageAddSaml2OAuth2DataViewModel model,
            out string code, out string description)
        {
            code = Const.InvalidClientMetadata;
            description = "";

            // 以下、全て登録するClientに関する内容の検査

            #region software_statement（RFC 7591 §2.3 / §3.1.1）

            //  **署名付きの添え状を検証し、主張されたメタデータを本文へ重ねる。**
            //    **statement が勝つ**（§2.3 は MUST）。**以降の検査は、重ねた後の値で行う。**
            //
            //  **`POST` も `PUT` も、ここを通る**（**検査は 1 か所**）。
            //    **黙って無視してはならない** — **クライアントは「主張した内容で登録された」と考える。**
            SoftwareStatementProvider.Result statement =
                SoftwareStatementProvider.Apply(metadata, out description);

            if (statement == SoftwareStatementProvider.Result.Invalid)
            {
                code = Const.InvalidSoftwareStatement;
                return false;
            }

            if (statement == SoftwareStatementProvider.Result.Unapproved)
            {
                code = Const.UnapprovedSoftwareStatement;
                return false;
            }

            //  **statement を必須にしている配備では、添えていない登録を断る。**
            //
            //  **`PUT` にも効く。** **効かせないと、`PUT` で statement を省いて
            //    「主張されていた値」を自分の値に書き換えられる**
            //    （**statement は保管しないので、省かれたことしか分からない**）。
            //
            //  **コードは `invalid_client_metadata`**（上で設定済み）。
            //    **提示されていないものを「approved でない」とは言えない** —
            //    **必須の項目が無い**のだから、メタデータの不備である。
            if (statement == SoftwareStatementProvider.Result.None
                && Config.RequireSoftwareStatement)
            {
                description = "This deployment requires a software_statement.";
                return false;
            }

            #endregion

            #region jwks / jwks_uri（RFC 7591 §2）

            //  **両方を入れてはならない**（RFC 7591 §2 の MUST NOT）。
            //    **どちらの鍵で認証するのかが決まらない**ので、断る。
            //    **`software_statement` を重ねた後で見る** — **statement が片方を主張したときも、同じ検査を通す。**
            if (ClientRegistrationProvider.Has(metadata, Const.ClientJwks)
                && !string.IsNullOrEmpty(
                    ClientRegistrationProvider.GetString(metadata, OAuth2AndOIDCConst.jwks_uri)))
            {
                description = "The jwks and jwks_uri must not both be present.";
                return false;
            }

            //  **`jwks_uri`（鍵を URL から引く）**。
            //    **鍵の入れ替えを、登録を直さずにできる**ようにするための項目である。
            //
            //  **要求の経路では取りに行かない**（`CmnEndpoints.ClientAuthentication` は
            //    `static bool` で、`/token` などから同期で呼ばれる）。
            //    **取りに行くのは、この口と背景である**
            //    （`WarmUpJwksUriAsync` / `RemoteJwkSetStore.RefillInBackground`）。
            if (!ClientRegistrationProvider.SetUri(metadata, OAuth2AndOIDCConst.jwks_uri,
                Const.MaxLengthOfUri, v => model.JwksUri = v, ref description))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(model.JwksUri))
            {
                //  **平文の HTTP では受けない** — **鍵そのものを差し替えられる**
                //    （**署名の検証鍵なので、差し替えられればクライアント認証が破れる**）。
                //    **ループバックだけは許す**（RFC 8252 §7.3 と同じ扱い。開発と試験のため）。
                if (!RemoteJwkSetStore.IsUsableKeySource(model.JwksUri))
                {
                    description = "The jwks_uri must use https. (loopback may use http)";
                    return false;
                }

                //  **読めないものは、ここで断る** —
                //    **後から黙って `private_key_jwt` が通らなくなるより、
                //    登録のその場で分かる方が良い。**
                //
                //  **取りに行ったのは、この口の手前である**（`WarmUpJwksUriAsync`）。
                //    **`software_statement` が主張した `jwks_uri` も温めてある。**
                //    **あちらは署名を検証しないで読む**が、
                //    **行き先の範囲は本文と同じ**であり、**ここ（検証済み）が信頼を決める。**
                if (!RemoteJwkSetStore.HasKeysInCache(model.JwksUri))
                {
                    description = "The jwks_uri could not be read.";
                    return false;
                }
            }

            #endregion

            #region クライアント認証の方法と、その材料

            //  **方法は 1 つ**（RFC 7591 §2）。**既知でない値は拒否する**
            //    （#224 と同じ方針。「一番厳しいものに倒す」はしない）。
            //
            //  **空（省略）は `client_secret_basic` / `client_secret_post`**（RFC 7591 §2 の既定）。
            //    **列も空のまま**にして、**`AllowsAuthMethod` が暗黙に許す。**
            string authMethod = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTokenEndpointAuthMethod);

            if (!string.IsNullOrEmpty(authMethod)
                && Array.IndexOf(CmnEndpoints.TokenEndpointAuthMethods, authMethod) < 0)
            {
                description = string.Format(
                    "The token_endpoint_auth_method ({0}) is not supported by this deployment.",
                    authMethod);
                return false;
            }

            model.TokenEndpointAuthMethod = authMethod;

            //  **`jwks`（RFC 7517 §5 の JWK Set）を、鍵の 2 列に移す。**
            //    **列は「JWK 1 本」**なので、**RSA 1 本 ＋ EC 1 本まで**である。
            if (ClientRegistrationProvider.Has(metadata, Const.ClientJwks))
            {
                if (!ClientRegistrationProvider.ParseJwks(
                    metadata, model, out description))
                {
                    return false;
                }
            }

            //  **mTLS の Subject DN**（RFC 8705 §2.1.2）。
            //    **照合は `x509.Subject` との完全一致**である（`CmnEndpoints.ClientAuthentication`）。
            string subjectDn = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTlsClientAuthSubjectDn);

            if (!string.IsNullOrEmpty(subjectDn))
            {
                //  **列の幅と同じ**（`TlsClientAuthSubjectDn` は 512）。
                if (Const.MaxLengthOfUri < subjectDn.Length)
                {
                    description = "The tls_client_auth_subject_dn is too long.";
                    return false;
                }

                model.TlsClientAuthSubjectDn = subjectDn;
            }

            //  **`client_assertion` の alg を絞る**（#262 の列。OIDC Registration 1.0 §2）。
            //    **空なら絞らない**（登録された鍵で順に試す）。
            string authSigningAlg = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTokenEndpointAuthSigningAlg);

            if (!string.IsNullOrEmpty(authSigningAlg))
            {
                if (Array.IndexOf(
                    CmnEndpoints.TokenEndpointAuthSigningAlgs, authSigningAlg) < 0)
                {
                    description = string.Format(
                        "The token_endpoint_auth_signing_alg ({0}) is not supported "
                        + "by this deployment.", authSigningAlg);
                    return false;
                }

                model.TokenEndpointAuthSigningAlg = authSigningAlg;
            }

            //  **方法に必要な材料が無ければ、登録を断る**（**認証できない登録を作らない**）。
            //    **黙って作ると、クライアントは「登録した方法で認証できる」と考えるが、
            //    永久に通らない。** **`PUT` でも同じ**（材料は毎回送ること）。
            //
            //  **`jwks_uri` も材料である。**
            //    **鍵は URL の先に在る** — **ここを数えないと、
            //    `jwks_uri` だけを送った登録が断られる。**
            if (authMethod == OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit()
                && string.IsNullOrEmpty(model.JwkRsaPublickey)
                && string.IsNullOrEmpty(model.JwkECDsaPublickey)
                && string.IsNullOrEmpty(model.JwksUri))
            {
                description = "The token_endpoint_auth_method private_key_jwt requires "
                    + "jwks or jwks_uri.";
                return false;
            }

            if (authMethod == OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit()
                && string.IsNullOrEmpty(model.TlsClientAuthSubjectDn))
            {
                description = "The token_endpoint_auth_method tls_client_auth requires "
                    + "tls_client_auth_subject_dn.";
                return false;
            }

            #endregion

            #region grant_types / response_types

            //  **RFC 7591 §2 の既定** : `grant_types` は `authorization_code`、
            //    `response_types` は `code`。
            //
            //  **既定を書き込むのは、ここ（動的登録）だけである。**
            //    **既存の登録（列が空）に当てはめてはならない** —
            //    **当てはめると「`authorization_code` 以外が通らなくなる」破壊になる。**
            List<string> grantTypes = ClientRegistrationProvider.GetStrings(metadata, Const.ClientGrantTypes);
            List<string> responseTypes = ClientRegistrationProvider.GetStrings(metadata, Const.ClientResponseTypes);

            if (grantTypes.Count == 0)
            {
                grantTypes = new List<string>() { OAuth2AndOIDCConst.AuthorizationCodeGrantType };
            }

            if (responseTypes.Count == 0)
            {
                responseTypes = new List<string>() { OAuth2AndOIDCConst.AuthorizationCodeResponseType };
            }

            //  **この配備が扱うグラントか**（Discovery の `grant_types_supported` と同じ一覧）。
            //    **動的登録のための細い道（`client_credentials`）は、登録では受け付けない。**
            List<string> supportedGrantTypes = CmnEndpoints.SupportedGrantTypes(false);

            foreach (string grantType in grantTypes)
            {
                if (!supportedGrantTypes.Contains(grantType))
                {
                    description = string.Format(
                        "The grant_type ({0}) is not supported by this deployment.", grantType);
                    return false;
                }
            }

            //  **この配備が扱う response_type か。**
            List<string> supportedResponseTypes = CmnEndpoints.SupportedResponseTypes();

            foreach (string responseType in responseTypes)
            {
                if (!supportedResponseTypes.Any(
                    x => ClientRegistrationProvider.IsSameTypeSet(x, responseType)))
                {
                    description = string.Format(
                        "The response_type ({0}) is not supported by this deployment.", responseType);
                    return false;
                }
            }

            //  **`grant_types` と `response_types` の対応**（RFC 7591 §2 の表）。
            //    **`code` を使うなら `authorization_code`、`token` / `id_token` を使うなら
            //    `implicit` が要る。** **片方だけ登録すると、使えない組み合わせになる。**
            bool usesCode = responseTypes.Any(x => ClientRegistrationProvider
                .Elements(x).Contains(OAuth2AndOIDCConst.AuthorizationCodeResponseType));

            bool usesToken = responseTypes.Any(x => ClientRegistrationProvider.Elements(x).Any(
                e => e == OAuth2AndOIDCConst.ImplicitResponseType
                || e == OAuth2AndOIDCConst.IDToken));

            if (usesCode && !grantTypes.Contains(OAuth2AndOIDCConst.AuthorizationCodeGrantType))
            {
                description = "The response_type code requires the authorization_code grant_type.";
                return false;
            }

            if (usesToken && !grantTypes.Contains(OAuth2AndOIDCConst.ImplicitGrantType))
            {
                description = "The response_type token / id_token requires the implicit grant_type.";
                return false;
            }

            //  **列に入れる形**（空白区切り。**要素の中の空白は `+` にする**）。
            model.GrantTypes = string.Join(" ", grantTypes);
            model.ResponseTypes = string.Join(" ", responseTypes.Select(
                x => string.Join("+", ClientRegistrationProvider.Elements(x))));

            if (Const.MaxLengthOfTypeList < model.GrantTypes.Length
                || Const.MaxLengthOfTypeList < model.ResponseTypes.Length)
            {
                description = "The grant_types / response_types are too long.";
                return false;
            }

            //  **デバイス フロー × `private_key_jwt` は、断らない**（#294）。
            //    **以前は RFC 8628 の口（`/device_authz` と `/token`）が `client_assertion` を読んでおらず、
            //    その組み合わせでは永久に認証できなかったので、登録の時点で断っていた。**
            //    **いまは両方の口が受ける**（`CmnEndpoints.DeviceAuthZClientAuthentication`）。

            #endregion

            #region redirect_uris / scope

            #region redirect_uris

            List<string> redirectUris = ClientRegistrationProvider.GetStrings(metadata, OAuth2AndOIDCConst.redirect_uris);

            if (usesCode || usesToken)
            {
                //  **折り返し先を使う経路なら、必須**（OIDC DCR 1.0 §2）。
                if (redirectUris.Count == 0)
                {
                    code = Const.InvalidRedirectUri;
                    description = "redirect_uris is required.";
                    return false;
                }
            }

            foreach (string redirectUri in redirectUris)
            {
                if (!ClientRegistrationProvider.IsValidRedirectUri(redirectUri))
                {
                    code = Const.InvalidRedirectUri;
                    description = string.Format(
                        "The redirect_uri ({0}) must be an absolute URI without a fragment.",
                        redirectUri);
                    return false;
                }
            }

            string uriList = string.Join(" ", redirectUris);

            if (Const.MaxLengthOfUriList < uriList.Length)
            {
                code = Const.InvalidRedirectUri;
                description = "The redirect_uris are too long.";
                return false;
            }

            //  **列は `response_type` で分かれている**ので、使う経路の列に入れる
            //    （`Helper.GetClientsRedirectUriList` が、`code` は `RedirectUriCode`、
            //    それ以外は `RedirectUriToken` を引く）。
            //    **両方を使う登録（Hybrid）では、同じ値を両方に入れる。**
            if (usesCode)
            {
                model.RedirectUriCode = uriList;
            }

            if (usesToken)
            {
                model.RedirectUriToken = uriList;
            }

            #endregion

            #region scope

            List<string> scopes = OAuth2AndOIDCSpec.ToDistinctList(
                ClientRegistrationProvider.GetString(metadata, OAuth2AndOIDCConst.scope));

            if (0 < scopes.Count)
            {
                List<string> supportedScopes = Helper.GetScopesSupported();

                foreach (string scope in scopes)
                {
                    //  **自分と同じ強さの scope を、自分で配らせない。**
                    //  **`client_registration` は「クライアント登録を作れる」権限**であり、
                    //    **動的登録で付けられるようにすると、権限を際限なく増やせる。**
                    //    **配るのは、管理画面か構成ファイルからだけ**にする。
                    //  **`auth`（同意画面を出さない）も同じ**（#294）。
                    //    **自分で登録できると、同意画面を飛ばすかをクライアントが決めることになる。**
                    if (scope == Const.ScopeClientRegistration
                        || scope == OAuth2AndOIDCConst.Scope_Auth)
                    {
                        description = string.Format(
                            "The scope ({0}) cannot be granted by the dynamic client registration.",
                            scope);
                        return false;
                    }

                    if (!supportedScopes.Contains(scope))
                    {
                        description = string.Format(
                            "The scope ({0}) is not supported by this deployment.", scope);
                        return false;
                    }
                }

                model.Scopes = string.Join(" ", scopes);

                if (Const.MaxLengthOfScopeList < model.Scopes.Length)
                {
                    description = "The scope is too long.";
                    return false;
                }
            }

            #endregion

            #endregion

            #region その他（保存して返すだけ）

            if (!ClientRegistrationProvider.SetUri(metadata, Const.ClientUri,
                Const.MaxLengthOfUri, v => model.ClientUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientLogoUri,
                    Const.MaxLengthOfUri, v => model.LogoUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientTosUri,
                    Const.MaxLengthOfUri, v => model.TosUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientPolicyUri,
                    Const.MaxLengthOfUri, v => model.PolicyUri = v, ref description))
            {
                return false;
            }

            model.Contacts = string.Join(" ",
                ClientRegistrationProvider.GetStrings(metadata, Const.ClientContacts));

            model.SoftwareId = ClientRegistrationProvider.GetString(metadata, Const.ClientSoftwareId);
            model.SoftwareVersion = ClientRegistrationProvider.GetString(metadata, Const.ClientSoftwareVersion);

            if (Const.MaxLengthOfContacts < (model.Contacts ?? "").Length
                || Const.MaxLengthOfSoftwareId < (model.SoftwareId ?? "").Length
                || Const.MaxLengthOfSoftwareVersion < (model.SoftwareVersion ?? "").Length)
            {
                description = "The contacts / software_id / software_version are too long.";
                return false;
            }

            #endregion

            #region OIDC の登録項目（既に列が在るもの）

            //  **`subject_type`**（OIDC DCR 1.0 §2）。**扱う値は public / pairwise**（OIDC Core §8）。
            string subjectType = ClientRegistrationProvider.GetString(metadata, Const.ClientSubjectType);

            if (!string.IsNullOrEmpty(subjectType))
            {
                if (subjectType != OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit()
                    && subjectType != OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                {
                    description = string.Format(
                        "The subject_type ({0}) is not supported.", subjectType);
                    return false;
                }

                model.SubjectTypes = subjectType;
            }

            //  **`id_token_signed_response_alg`**（列は #129 で足してある）。
            //    **扱える alg でなければ断る** — **ここで止めないと、
            //    発行の直前に既定（RS256）へ落ちて、登録の誤りが分からない。**
            string signingAlg = ClientRegistrationProvider.GetString(
                metadata, Const.ClientIdTokenSignedResponseAlg);

            if (!string.IsNullOrEmpty(signingAlg))
            {
                if (!JwsFactory.IsSupported(signingAlg))
                {
                    description = string.Format(
                        "The id_token_signed_response_alg ({0}) is not supported.", signingAlg);
                    return false;
                }

                model.IdTokenSignedResponseAlg = signingAlg;
            }

            #endregion

            //  **登録種別は normal。** **FAPI の登録は、鍵や証明書の登録を要する。**
            model.ClientMode = OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit();

            code = "";
            return true;
        }

        #endregion

        #region 補助

        #region metadataの読み書き

        /// <summary>そのメタデータが在るか（null でない値として）</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>在れば true</returns>
        private static bool Has(JObject metadata, string name)
        {
            JToken token = metadata[name];

            return token != null && token.Type != JTokenType.Null;
        }

        /// <summary>文字列のメタデータを読む</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ空）</returns>
        private static string GetString(JObject metadata, string name)
        {
            return ClientRegistrationProvider.Has(metadata, name)
                ? (metadata[name].Type == JTokenType.String
                    ? (string)metadata[name] : metadata[name].ToString())
                : "";
        }

        /// <summary>配列のメタデータを読む</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>値の一覧（無ければ 0 件）</returns>
        /// <remarks>
        /// **配列でも、空白区切りの文字列でも受ける。**
        /// **仕様は配列**（RFC 7591 §2）だが、**この実装は列挙を空白区切りで持つ**ので、
        /// **どちらで来ても同じに扱える方が、取り違えが起きない。**
        /// **空の要素と重複は捨てる。**
        /// </remarks>
        private static List<string> GetStrings(JObject metadata, string name)
        {
            List<string> ret = new List<string>();

            if (!ClientRegistrationProvider.Has(metadata, name))
            {
                return ret;
            }

            JToken token = metadata[name];

            if (token.Type == JTokenType.Array)
            {
                foreach (JToken item in (JArray)token)
                {
                    string value = ((string)item ?? "").Trim();

                    if (!string.IsNullOrEmpty(value) && !ret.Contains(value))
                    {
                        ret.Add(value);
                    }
                }

                return ret;
            }

            return OAuth2AndOIDCSpec.ToDistinctList(ClientRegistrationProvider.GetString(metadata, name));
        }

        /// <summary>URI のメタデータを読んで入れる</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <param name="maxLength">上限</param>
        /// <param name="set">入れ先</param>
        /// <param name="description">誤りの説明</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>**絶対 URI でなければ断る**（表示用でも、相対の値は意味を持たない）。</remarks>
        private static bool SetUri(JObject metadata, string name, int maxLength,
            Action<string> set, ref string description)
        {
            string value = ClientRegistrationProvider.GetString(metadata, name);

            if (string.IsNullOrEmpty(value))
            {
                return true;
            }

            if (maxLength < value.Length)
            {
                description = string.Format("The {0} is too long.", name);
                return false;
            }

            if (!Uri.IsWellFormedUriString(value, UriKind.Absolute))
            {
                description = string.Format("The {0} must be an absolute URI.", name);
                return false;
            }

            set(value);
            return true;
        }

        /// <summary>`jwks` を読んで、鍵の 2 列に入れる</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="model">保存する形（入出力）</param>
        /// <param name="description">誤りの説明（出力）</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **列は「JWK 1 本を Base64URL にしたもの」が 2 本**
        /// （`JwkRsaPublickey` / `JwkECDsaPublickey`）。**JWK Set は持てない。**
        /// **`CmnEndpoints.ClientAuthentication` が、この 2 本を順に試す。**
        ///
        /// **断る形**（**どれも「黙って落とすと、後で認証に失敗する」もの**）。
        ///
        /// | | |
        /// |---|---|
        /// | `keys` が無い・空・配列でない | RFC 7517 §5 |
        /// | **同じ `kty` が 2 本以上** | **列が 1 本しか持てない。** 先頭を採ると、**もう一方の鍵で署名したときに失敗する** |
        /// | **`RSA` / `EC` 以外の `kty`** | **この実装が検証できない**（`JwtAssertion.Verify` が `kty` で RSA / EC を選ぶ） |
        /// | **`use` が `sig` でない** | **クライアント認証に使う鍵である**（暗号用を黙って受けない。RFC 7517 §4.2） |
        ///
        /// ※ クライアント認証に使う、クライアントの公開鍵（サーバの鍵・software_statement の発行者の鍵とは別）
        /// </remarks>
        private static bool ParseJwks(JObject metadata,
            ManageAddSaml2OAuth2DataViewModel model, out string description)
        {
            description = "";

            JToken jwks = metadata[Const.ClientJwks];

            if (jwks.Type != JTokenType.Object)
            {
                description = "The jwks must be a JSON object (RFC 7517 Section 5).";
                return false;
            }

            JToken keys = jwks[JwtConst.keys];

            if (keys == null || keys.Type != JTokenType.Array || !keys.Any())
            {
                description = "The jwks must have a non-empty keys array "
                    + "(RFC 7517 Section 5).";
                return false;
            }

            foreach (JToken key in keys)
            {
                if (key.Type != JTokenType.Object)
                {
                    description = "Each key in the jwks must be a JSON object.";
                    return false;
                }

                JObject jwk = (JObject)key;

                //  **署名の検証に使う鍵だけを受ける**（RFC 7517 §4.2。`use` は任意）。
                string use = (string)jwk[Const.JwkUse];

                if (!string.IsNullOrEmpty(use) && use != Const.JwkUseSig)
                {
                    description = "This deployment uses the jwks for client authentication, "
                        + "so each key must have use=sig (or no use).";
                    return false;
                }

                string kty = (string)jwk[JwtConst.kty];
                string encoded = CmnEndpoints.EncodeRegisteredJwk(jwk);

                if (kty == JwtConst.RSA)
                {
                    if (!string.IsNullOrEmpty(model.JwkRsaPublickey))
                    {
                        description = "This deployment stores one RSA key per client, "
                            + "so the jwks must not have two RSA keys.";
                        return false;
                    }

                    model.JwkRsaPublickey = encoded;
                }
                else if (kty == JwtConst.EC)
                {
                    if (!string.IsNullOrEmpty(model.JwkECDsaPublickey))
                    {
                        description = "This deployment stores one EC key per client, "
                            + "so the jwks must not have two EC keys.";
                        return false;
                    }

                    model.JwkECDsaPublickey = encoded;
                }
                else
                {
                    description = string.Format(
                        "The key type ({0}) is not supported by this deployment. "
                        + "Use RSA or EC.", kty);
                    return false;
                }
            }

            return true;
        }

        #endregion

        #region redirect_uri

        /// <summary>折り返し先として使える値か</summary>
        /// <param name="redirectUri">redirect_uri</param>
        /// <returns>使えるなら true</returns>
        /// <remarks>
        /// **絶対 URI で、フラグメントを持たないこと**（RFC 6749 §3.1.2）。
        /// **ワイルドカードは受けない**（#263 / #306 と同じ方針。照合は完全一致）。
        /// **長さは 1 本ぶんの上限まで**（`Const.MaxLengthOfUri`）。
        /// </remarks>
        private static bool IsValidRedirectUri(string redirectUri)
        {
            if (string.IsNullOrEmpty(redirectUri)
                || Const.MaxLengthOfUri < redirectUri.Length
                || redirectUri.Contains("*"))
            {
                return false;
            }

            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri uri))
            {
                return false;
            }

            //  **フラグメントは禁止**（RFC 6749 §3.1.2）。
            return string.IsNullOrEmpty(uri.Fragment);
        }

        #endregion

        #region response_type

        /// <summary>response_type の要素に分ける</summary>
        /// <param name="responseType">response_type（空白か「+」で区切られている）</param>
        /// <returns>要素の並び</returns>
        /// <remarks>
        /// **列には `+` で繋いで入れる**（空白は区切りと区別が付かない）。
        /// **要求の JSON では空白で来る**（`code id_token`）。**どちらでも読めるようにする。**
        /// </remarks>
        private static string[] Elements(string responseType)
        {
            return (responseType ?? "").ToLower().Split(
                new char[] { ' ', '+' }, StringSplitOptions.RemoveEmptyEntries);
        }

        /// <summary>2 つの response_type が、同じ組み合わせか</summary>
        /// <param name="a">response_type</param>
        /// <param name="b">response_type</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **要素の集合として比べる**
        /// （OAuth 2.0 Multiple Response Types §4 : 順序は意味を持たない）。
        /// </remarks>
        private static bool IsSameTypeSet(string a, string b)
        {
            string[] x = ClientRegistrationProvider.Elements(a);
            string[] y = ClientRegistrationProvider.Elements(b);

            return x.Length == y.Length && x.All(t => y.Contains(t));
        }

        #endregion

        #endregion
    }
}
