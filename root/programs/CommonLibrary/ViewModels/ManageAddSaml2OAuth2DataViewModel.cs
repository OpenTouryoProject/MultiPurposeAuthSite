//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddSaml2OAuth2DataViewModel
//* クラス日本語名  ：Saml2, OAuth2関連の非構造化データ設定用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2019/12/25  西野 大介         PPID、PKCE 4 SPA対応による見直し
//*  2020/03/04  西野 大介         CIBA対応実施
//*  2026/09/18  玄人 幸道         クライアント単位の PKCE 必須化（require_pkce）を追加（#221）
//*  2026/09/27  玄人 幸道         post_logout_redirect_uri（RP-Initiated Logout）を追加（#232）
//*  2026/10/01  玄人 幸道         subject_types の選択肢を public 先頭にした（#151 の段階 4）
//*  2026/10/02  玄人 幸道         subject_types の選択肢を OIDC の登録値だけにした（#151 の段階 5）
//*  2026/10/02  玄人 幸道         id_token_signed_response_alg を追加（#129 の段階 2）
//*  2026/10/02  玄人 幸道         署名アルゴリズムの選択肢を SigningKeys の表から作る（#129 の段階 3）
//*  2026/10/03  玄人 幸道         検証する側のalgの登録項目を追加（#262）
//*  2026/10/04  玄人 幸道         web_origins を追加（#266）
//*  2026/10/04  玄人 幸道         画面の選択肢を直列化しないようにした（#266 で踏んだ）
//*  2026/10/09  玄人 幸道         各項目の説明を追加（#277 の段階 1）
//*  2026/10/09  玄人 幸道         redirect_ の候補（datalist）を追加（#277 の段階 3）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

#if NETFX
using System.Web.Mvc;
#elif NETCORE
using Microsoft.AspNetCore.Mvc.Rendering;
#endif

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>Saml2, OAuth2関連の非構造化データ設定用のVM</summary>
    public class ManageAddSaml2OAuth2DataViewModel : BaseViewModel
    {
        /// <summary>ClientID</summary>
        [Display(Name = "ClientID", Description = "ClientIDDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // ユーザ入力でないので不要
        [JsonIgnore] // これはJsonConvertしない。
        public string ClientID { get; set; }

        /// <summary>ClientSecret</summary>
        [Display(Name = "ClientSecret", Description = "ClientSecretDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // ユーザ入力でないので不要
        [JsonProperty(PropertyName = "client_secret")]
        public string ClientSecret { get; set; }

        /// <summary>RedirectUriSaml</summary>
        [Display(Name = "RedirectUriSaml", Description = "RedirectUriSamlDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_saml")]
        public string RedirectUriSaml { get; set; }

        /// <summary>RedirectUriCode</summary>
        [Display(Name = "RedirectUriCode", Description = "RedirectUriCodeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_code")]
        public string RedirectUriCode { get; set; }

        /// <summary>RedirectUriToken</summary>
        [Display(Name = "RedirectUriToken", Description = "RedirectUriTokenDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_token")]
        public string RedirectUriToken { get; set; }

        /// <summary>PostLogoutRedirectUri（#232）</summary>
        /// <remarks>
        /// **ログアウト後に戻ってよい URL**（RP-Initiated Logout 1.0 §3.1 の post_logout_redirect_uris）。
        /// 仕様は配列だが、既存の redirect_uri_* と同じく **1 本**で持つ。
        /// **登録が無ければ、ログアウト後に RP へは戻さない。**
        /// </remarks>
        [Display(Name = "PostLogoutRedirectUri", Description = "PostLogoutRedirectUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "post_logout_redirect_uri")]
        public string PostLogoutRedirectUri { get; set; }

        /// <summary>JwkRsaPublickey</summary>
        [Display(Name = "JwkRsaPublickey", Description = "JwkRsaPublickeyDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "jwk_rsa_publickey")]
        public string JwkRsaPublickey { get; set; }

        /// <summary>JwkECDsaPublickey</summary>
        [Display(Name = "JwkECDsaPublickey", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "jwk_ecdsa_publickey")]
        public string JwkECDsaPublickey { get; set; }
        

        /// <summary>TlsClientAuthSubjectDn</summary>
        [Display(Name = "TlsClientAuthSubjectDn", Description = "TlsClientAuthSubjectDnDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "tls_client_auth_subject_dn")]
        public string TlsClientAuthSubjectDn { get; set; }


        #region redirect_ の候補（#277 の段階 3）

        //  **画面の候補（`<datalist>`）である。** 登録の内容ではない。
        //    **`[JsonIgnore]` を忘れないこと** — 付けていないと、
        //    **候補そのものが saml2OAuth2Data に書き込まれる**（#266 で踏んだ）。
        //
        //  **値は `Const` から引く。** **画面とサーバで食い違わせない**ため
        //    （サーバ側は `CheckRedirectUri` / `CmnEndpoints` がこの記号を解決する）。
        //
        //  **`redirect_uri_saml` の管理画面用（`redirect_uri_saml_manage`）は、まだ無い。**
        //    **管理画面に SAML のテスト ボタンを足すとき**（#277 の段階 5）に増える。

        /// <summary>redirect_uri_saml の候補</summary>
        [JsonIgnore]
        public List<string> RedirectUriSamlCandidates
        {
            get
            {
                return new List<string>() { Const.TestSelfSaml };
            }
        }

        /// <summary>redirect_uri_code の候補</summary>
        [JsonIgnore]
        public List<string> RedirectUriCodeCandidates
        {
            get
            {
                return new List<string>() { Const.TestSelfCode, Const.TestSelfCodeManage };
            }
        }

        /// <summary>redirect_uri_token の候補</summary>
        [JsonIgnore]
        public List<string> RedirectUriTokenCandidates
        {
            get
            {
                // **使わないなら "-" を入れる**（段階 1 の説明と同じ）。
                return new List<string>() { Const.TestSelfToken, "-" };
            }
        }

        /// <summary>post_logout_redirect_uri の候補</summary>
        [JsonIgnore]
        public List<string> PostLogoutRedirectUriCandidates
        {
            get
            {
                return new List<string>() { Const.TestSelfLogout };
            }
        }

        #endregion

        #region SubjectTypes 
        /// <summary>SubjectTypes</summary>
        [Display(Name = "SubjectTypes", Description = "SubjectTypesDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "subject_types")]
        public string SubjectTypes { get; set; }

        /// <summary>SubjectTypesアイテムリスト</summary>
        /// <remarks>
        /// **先頭が既定の選択**なので、**public を先頭に置く**。
        /// **利用者名を渡したいなら `preferred_username`**（`UserClaimsMapping`）。
        /// </remarks>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        //   **付けていないと、選択肢そのものが saml2OAuth2Data に書き込まれる。**
        //   `Ddl*Items` を全部足すと **2 KB 近くになり**、
        //   **Oracle / PostgreSQL の UnstructuredData（varchar(2000)）に収まらない**
        //   （`CreateTestUsers` の登録が 3,108 文字になって 22001 で落ちた。実測）。
        [JsonIgnore]
        public List<SelectListItem> DdlSubjectTypesItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() {
                        Text = "public",
                        Value = OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "pairwise",
                        Value = OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit() }
                };
            }
        }
        #endregion

        #region IdTokenSignedResponseAlg

        /// <summary>IdTokenSignedResponseAlg</summary>
        /// <remarks>
        /// **そのクライアントに発行する access_token と id_token の署名 alg**（#129 の段階 2）。
        /// **空なら `RS256`**（＝ 従来どおり）。
        /// </remarks>
        [Display(Name = "IdTokenSignedResponseAlg", Description = "IdTokenSignedResponseAlgDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "id_token_signed_response_alg")]
        public string IdTokenSignedResponseAlg { get; set; }

        /// <summary>IdTokenSignedResponseAlg アイテムリスト</summary>
        /// <remarks>
        /// **一覧は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// **並びも表のまま**で、**既定（`RS256`）が先頭に来る。**
        /// ＝ **表に 1 行足せば、画面の選択肢も増える。**
        /// </remarks>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        //   **付けていないと、選択肢そのものが saml2OAuth2Data に書き込まれる。**
        //   `Ddl*Items` を全部足すと **2 KB 近くになり**、
        //   **Oracle / PostgreSQL の UnstructuredData（varchar(2000)）に収まらない**
        //   （`CreateTestUsers` の登録が 3,108 文字になって 22001 で落ちた。実測）。
        [JsonIgnore]
        public List<SelectListItem> DdlIdTokenSignedResponseAlgItems
        {
            get
            {
                List<SelectListItem> items = new List<SelectListItem>();

                foreach (string alg in TokenProviders.SigningKeys.SupportedAlgs)
                {
                    items.Add(new SelectListItem()
                    {
                        // 先頭が既定（登録しなかったときの値）。
                        Text = (items.Count == 0) ? alg + "（既定）" : alg,
                        Value = alg
                    });
                }

                return items;
            }
        }

        #endregion

        #region WebOrigins

        /// <summary>WebOrigins</summary>
        /// <remarks>
        /// **CORS で許可するオリジン**（#266。空白かカンマ区切り）。
        /// **空なら `redirect_uri_*` から導く**（#265 の挙動。Keycloak の Web origins の
        /// 既定値 `+`、Entra ID の SPA プラットフォームと同じ考え方）。
        ///
        /// **public クライアント（`client_secret` を持たないもの）にだけ効く。**
        /// confidential は `/token` をサーバ間で呼ぶので、ブラウザから叩かせる必要が無い。
        ///
        /// **末尾の `/` は付けない**（CORS の比較はオリジン同士で、パスを含まない）。
        /// **`*` は書かない**（オリジンとして扱えない値は落ちる）。
        /// </remarks>
        [Display(Name = "WebOrigins", Description = "WebOriginsDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "web_origins")]
        public string WebOrigins { get; set; }

        #endregion

        #region TokenEndpointAuthSigningAlg / RequestObjectSigningAlg

        /// <summary>TokenEndpointAuthSigningAlg</summary>
        /// <remarks>
        /// **`client_assertion`（`private_key_jwt`）を、この alg だけに絞る**（#262）。
        /// **空なら絞らない**（登録された鍵で順に試す ＝ 従来どおり）。
        /// </remarks>
        [Display(Name = "TokenEndpointAuthSigningAlg", Description = "TokenEndpointAuthSigningAlgDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "token_endpoint_auth_signing_alg")]
        public string TokenEndpointAuthSigningAlg { get; set; }

        /// <summary>TokenEndpointAuthSigningAlg アイテムリスト</summary>
        /// <remarks>
        /// **一覧は `CmnEndpoints.TokenEndpointAuthSigningAlgs` が持つ**（広告もそこから作る）。
        /// ＝ **受ける alg が増えれば、画面の選択肢も増える**（`SigningKeys` と同じ考え方）。
        /// **先頭は空**（＝ 絞らない）である。
        /// </remarks>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        //   **付けていないと、選択肢そのものが saml2OAuth2Data に書き込まれる。**
        //   `Ddl*Items` を全部足すと **2 KB 近くになり**、
        //   **Oracle / PostgreSQL の UnstructuredData（varchar(2000)）に収まらない**
        //   （`CreateTestUsers` の登録が 3,108 文字になって 22001 で落ちた。実測）。
        [JsonIgnore]
        public List<SelectListItem> DdlTokenEndpointAuthSigningAlgItems
        {
            get
            {
                return ManageAddSaml2OAuth2DataViewModel.VerifyingAlgItems(
                    TokenProviders.CmnEndpoints.TokenEndpointAuthSigningAlgs);
            }
        }

        /// <summary>RequestObjectSigningAlg</summary>
        /// <remarks>
        /// **Request Object（`/ros` / `/par` / `request`）を、この alg だけに絞る**（#262）。
        /// **空なら絞らない。**
        ///
        /// **CIBA の `request` は対象外**である（`ES256` 固定で、仕様でも別の登録項目）。
        /// </remarks>
        [Display(Name = "RequestObjectSigningAlg", Description = "RequestObjectSigningAlgDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "request_object_signing_alg")]
        public string RequestObjectSigningAlg { get; set; }

        /// <summary>RequestObjectSigningAlg アイテムリスト</summary>
        /// <remarks>
        /// **一覧は `CmnEndpoints.RequestObjectSigningAlgs` が持つ。**
        /// **いまは `RS256` だけ**である（上流の `RequestObject.Verify` が RS256 固定のため）。
        /// **増やすのは「広げる側」の話**で、#262 では扱っていない。
        /// </remarks>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        //   **付けていないと、選択肢そのものが saml2OAuth2Data に書き込まれる。**
        //   `Ddl*Items` を全部足すと **2 KB 近くになり**、
        //   **Oracle / PostgreSQL の UnstructuredData（varchar(2000)）に収まらない**
        //   （`CreateTestUsers` の登録が 3,108 文字になって 22001 で落ちた。実測）。
        [JsonIgnore]
        public List<SelectListItem> DdlRequestObjectSigningAlgItems
        {
            get
            {
                return ManageAddSaml2OAuth2DataViewModel.VerifyingAlgItems(
                    TokenProviders.CmnEndpoints.RequestObjectSigningAlgs);
            }
        }

        /// <summary>検証する側の alg の選択肢を作る（先頭は「絞らない」）</summary>
        /// <param name="algs">受ける alg</param>
        /// <returns>選択肢</returns>
        private static List<SelectListItem> VerifyingAlgItems(string[] algs)
        {
            List<SelectListItem> items = new List<SelectListItem>()
            {
                // **空 ＝ 絞らない**（登録しないのと同じ）。
                new SelectListItem() { Text = "（絞らない）", Value = "" }
            };

            foreach (string alg in algs)
            {
                items.Add(new SelectListItem() { Text = alg, Value = alg });
            }

            return items;
        }

        #endregion

        #region ClientType
        ///// <summary>ClientType</summary>
        //[Display(Name = "ClientType", ResourceType = typeof(Resources.CommonViewModels))]
        //[JsonProperty(PropertyName = "client_type")]
        //public string ClientType { get; set; }

        ///// <summary>ClientTypeアイテムリスト</summary>
        //public List<SelectListItem> DdlClientTypeItems
        //{
        //    get
        //    {
        //        return new List<SelectListItem>()
        //        {
        //            new SelectListItem() {
        //                Text = "Confidential Client",
        //                Value = OAuth2AndOIDCEnum.ClientType.confidential.ToStringByEmit() },
        //            new SelectListItem() {
        //                Text = "Public Client(SPA)",
        //                Value = OAuth2AndOIDCEnum.ClientType.public_spa.ToStringByEmit() },
        //            new SelectListItem() {
        //                Text = "Public Client(Native)",
        //                Value = OAuth2AndOIDCEnum.ClientType.public_native.ToStringByEmit() }
        //        };
        //    }
        //}
        #endregion

        #region ClientMode
        /// <summary>ClientMode</summary>
        [Display(Name = "ClientMode", Description = "ClientModeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "oauth2_oidc_mode")]
        public string ClientMode { get; set; }

        /// <summary>ClientModeアイテムリスト</summary>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        //   **付けていないと、選択肢そのものが saml2OAuth2Data に書き込まれる。**
        //   `Ddl*Items` を全部足すと **2 KB 近くになり**、
        //   **Oracle / PostgreSQL の UnstructuredData（varchar(2000)）に収まらない**
        //   （`CreateTestUsers` の登録が 3,108 文字になって 22001 で落ちた。実測）。
        [JsonIgnore]
        public List<SelectListItem> DdlClientModeItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() {
                        Text = "Saml2, OAuth2.0 / OIDC",
                        Value = OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part1",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part2",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() }
                };
            }
        }
        #endregion

        #region RequirePkce
        /// <summary>PKCEを必須とするか（#221）</summary>
        /// <remarks>
        /// **サーバ全体の Config.RequirePkce とは OR で組み合わせる。**
        /// クライアント側で true にはできるが、**サーバが締めているものを緩めることはできない。**
        ///
        /// **保存済みの登録には、この項目が無い。** JSON に無ければ既定値の false になるので、
        /// 従来どおりの動作が続く。
        /// </remarks>
        [Display(Name = "RequirePkce", Description = "RequirePkceDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "require_pkce")]
        public bool RequirePkce { get; set; }
        #endregion

        /// <summary>ClientName</summary>
        [Display(Name = "ClientName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfClientName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = OAuth2AndOIDCConst.sub)]
        public string ClientName { get; set; }
    }
}