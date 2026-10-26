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
//*  2026/10/10  玄人 幸道         管理画面用の候補についての見通しを現状に合わせた（#277）
//*  2026/10/18  玄人 幸道         RFC 7591 §2 のクライアント メタデータを追加（#307 の段階 1）
//*  2026/10/18  玄人 幸道         registration_access_token のハッシュの列を追加（#307 の段階 2）
//*  2026/10/18  玄人 幸道         redirect_uri を n 件入れられるようにした（#306）
//*  2026/10/19  玄人 幸道         token_endpoint_auth_method の列を追加（#307 の段階 3）
//*  2026/10/20  玄人 幸道         所有者（OwnerUserId）を追加（#307 の段階 5-a-1）
//*  2026/10/20  玄人 幸道         編集中の印（Editing）を追加（#307 の段階 5-a-2）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri を追加（#310 の段階 2）
//*  2026/10/21  玄人 幸道         frontchannel_logout_uri を追加（#310 の段階 3）
//*  2026/10/22  玄人 幸道         alg の一覧を Open棟梁 の JwsFactory から引くようにした（#294）
//*  2026/10/24  玄人 幸道         文字列リテラルを Const / OAuth2AndOIDCConst の定数にした（#294）
//*  2026/10/24  玄人 幸道         選択肢の文言を resx にした（#294）
//*  2026/10/25  玄人 幸道         クライアントの登録種別の名前を oauth2_oidc_mode から client_mode に改名した（#294）
//*  2026/10/25  玄人 幸道         Scopes の注に auth を足した（#294）
//*  2026/10/26  玄人 幸道         DataProvider の改名（Saml2OAuth2DataProvider）に追従した（#294）
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
using Touryo.Infrastructure.Public.Security.Jwt;

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
        [JsonProperty(PropertyName = OAuth2AndOIDCConst.client_secret)]
        public string ClientSecret { get; set; }

        /// <summary>RedirectUriSaml</summary>
        [Display(Name = "RedirectUriSaml", Description = "RedirectUriSamlDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientRedirectUriSaml)]
        public string RedirectUriSaml { get; set; }

        /// <summary>RedirectUriCode</summary>
        [Display(Name = "RedirectUriCode", Description = "RedirectUriCodeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        //  **n 件を空白区切りで入れられる**（#306）。**上限は列挙用のもの。**
        [StringLength(
            Const.MaxLengthOfUriList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientRedirectUriCode)]
        public string RedirectUriCode { get; set; }

        /// <summary>RedirectUriToken</summary>
        [Display(Name = "RedirectUriToken", Description = "RedirectUriTokenDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        //  **n 件を空白区切りで入れられる**（#306）。
        [StringLength(
            Const.MaxLengthOfUriList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientRedirectUriToken)]
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
        [JsonProperty(PropertyName = Const.ClientPostLogoutRedirectUri)]
        public string PostLogoutRedirectUri { get; set; }

        /// <summary>FrontChannelLogoutUri（#310 の段階 3）</summary>
        /// <remarks>
        /// **ブラウザ経由でログアウトを伝える先**
        /// （OIDC Front-Channel Logout 1.0 §2 の frontchannel_logout_uri）。
        /// **登録が無ければ、その RP には伝えない。**
        ///
        /// **`iframe` で開かれる URL** である。**`iss` と `sid` が付く。**
        /// **`https` を求める**（**ループバックの `http` だけ許す**）。
        /// **判定は開く側**（`FrontChannelLogout`）**で行う** — **`backchannel_logout_uri` と同じ規則。**
        ///
        /// **`frontchannel_logout_session_required` は持たない。**
        /// **この実装は必ず `iss` と `sid` を付ける**ので、
        /// **「要るか」を RP ごとに持つ意味が無い**（Discovery では
        /// `frontchannel_logout_session_supported` を true で広告している）。
        /// </remarks>
        [Display(Name = "FrontChannelLogoutUri", Description = "FrontChannelLogoutUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientFrontChannelLogoutUri)]
        public string FrontChannelLogoutUri { get; set; }

        /// <summary>BackChannelLogoutUri（#310 の段階 2）</summary>
        /// <remarks>
        /// **ログアウトを伝える先**（OIDC Back-Channel Logout 1.0 §2.2 の backchannel_logout_uri）。
        /// **登録が無ければ、その RP には伝えない。**
        ///
        /// **`https` を求める**（**ループバックの `http` だけ許す**）。
        /// **判定は送る側**（`BackChannelLogout`）**で行う** — **鍵の出どころと同じ規則**である。
        ///
        /// **`backchannel_logout_session_required` は持たない。**
        /// **この実装は `logout_token` に必ず `sid` を入れる**ので、
        /// **「要るか」を RP ごとに持つ意味が無い**（Discovery では
        /// `backchannel_logout_session_supported` を true で広告している）。
        /// </remarks>
        [Display(Name = "BackChannelLogoutUri", Description = "BackChannelLogoutUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientBackChannelLogoutUri)]
        public string BackChannelLogoutUri { get; set; }

        /// <summary>JwkRsaPublickey</summary>
        [Display(Name = "JwkRsaPublickey", Description = "JwkRsaPublickeyDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientJwkRsaPublicKey)]
        public string JwkRsaPublickey { get; set; }

        /// <summary>JwkECDsaPublickey</summary>
        [Display(Name = "JwkECDsaPublickey", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientJwkEcdsaPublicKey)]
        public string JwkECDsaPublickey { get; set; }
        

        /// <summary>TlsClientAuthSubjectDn</summary>
        [Display(Name = "TlsClientAuthSubjectDn", Description = "TlsClientAuthSubjectDnDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientTlsClientAuthSubjectDn)]
        public string TlsClientAuthSubjectDn { get; set; }


        #region redirect_ の候補（#277 の段階 3）

        //  **画面の候補（`<datalist>`）である。** 登録の内容ではない。
        //    **`[JsonIgnore]` を忘れないこと** — 付けていないと、
        //    **候補そのものが saml2OAuth2Data に書き込まれる**（#266 で踏んだ）。
        //
        //  **値は `Const` から引く。** **画面とサーバで食い違わせない**ため
        //    （サーバ側は `CheckRedirectUri` / `CmnEndpoints` がこの記号を解決する）。
        //
        //  **`redirect_uri_saml` の管理画面用（`redirect_uri_saml_manage`）は、無い。**
        //    **管理画面の SAML のテスト ボタンは落とした**（自己テスト画面と重複するため。
        //    `ANALYSIS.md` 13 節）ので、**増える予定も無い。**

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
                return new List<string>() { Const.TestSelfCode };
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

        /// <summary>frontchannel_logout_uri の候補（#310 の段階 3）</summary>
        [JsonIgnore]
        public List<string> FrontChannelLogoutUriCandidates
        {
            get
            {
                // **使わないなら "-" を入れる**（他の項目と同じ）。
                return new List<string>() { Const.TestSelfFrontChannelLogout, "-" };
            }
        }

        /// <summary>backchannel_logout_uri の候補（#310 の段階 2）</summary>
        [JsonIgnore]
        public List<string> BackChannelLogoutUriCandidates
        {
            get
            {
                // **使わないなら "-" を入れる**（他の項目と同じ）。
                return new List<string>() { Const.TestSelfBackChannelLogout, "-" };
            }
        }

        #endregion

        #region SubjectTypes 
        /// <summary>SubjectTypes</summary>
        [Display(Name = "SubjectTypes", Description = "SubjectTypesDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientSubjectTypes)]
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
        [JsonProperty(PropertyName = Const.ClientIdTokenSignedResponseAlg)]
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

                foreach (string alg in JwsFactory.SupportedAlgs)
                {
                    items.Add(new SelectListItem()
                    {
                        // 先頭が既定（登録しなかったときの値）。
                        Text = (items.Count == 0) ? string.Format(Resources.CommonViewModels.DdlDefaultAlg, alg) : alg,
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
        //  **元から列挙だが、上限が 1 本ぶんのままだった**（#306 で揃えた）。
        //    **列は NCLOB / text / nvarchar(max) なので、DDL は変えていない。**
        [StringLength(
            Const.MaxLengthOfUriList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientWebOrigins)]
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
        [JsonProperty(PropertyName = Const.ClientTokenEndpointAuthSigningAlg)]
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
        [JsonProperty(PropertyName = Const.ClientRequestObjectSigningAlg)]
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
                new SelectListItem() { Text = Resources.CommonViewModels.DdlNotNarrowed, Value = "" }
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
        [JsonProperty(PropertyName = Const.ClientMode)]
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
        [JsonProperty(PropertyName = Const.ClientRequirePkce)]
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

        #region RFC 7591 §2 のクライアント メタデータ（#307 の段階 1）

        //  **RFC 7591 §2 の登録項目を、専用の列で持つ**（#307 の段階 1）。
        //
        //  **宣言の順は、`Saml2OAuth2DataProvider.Columns` の並びと同じに保つこと**（#270 の約束）。
        //    **末尾に足している**ので、**既存のデータベースは `ALTER … ADD` で
        //    物理的な並びも同じになる**（作り直した `CREATE` と食い違わない）。
        //
        //  **「効かせる」のは 3 つだけ**（`Scopes` / `GrantTypes` / `ResponseTypes`）。
        //    **残りは保存して返すだけ**である（**仕様が振る舞いを定めていない**か、
        //    **引く実装がまだ無い**）。

        /// <summary>Scopes（RFC 7591 §2 の scope）</summary>
        /// <remarks>
        /// **このクライアントが要求してよい scope**（空白区切り。#198）。
        /// **空なら絞らない**（**既存の登録を壊さないため**）。
        ///
        /// **`Helper.GetClientScopes` が、構成ファイルに続いてこの列も見る**（#307 の段階 1）。
        /// **以前は構成ファイルだけを見ており、画面から登録したクライアントには
        /// 「クライアントごとの絞り」が効いていなかった。**
        ///
        /// > **`Const.ScopeClientRegistration` と `OAuth2AndOIDCConst.Scope_Auth` だけは、倒し方が逆である** —
        /// > **ここに明記していなければ出さない**（`Helper.FilterSupportedScopes`。#294）。
        /// </remarks>
        [Display(Name = "Scopes", Description = "ScopesDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfScopeList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = OAuth2AndOIDCConst.scope)]
        public string Scopes { get; set; }

        /// <summary>GrantTypes（RFC 7591 §2 の grant_types）</summary>
        /// <remarks>
        /// **このクライアントが使ってよいグラント**（空白区切り）。
        /// **空なら絞らない**（従来どおり `ClientModePolicy` と配備ぜんたいの設定で決まる）。
        ///
        /// **`CmnEndpoints.CheckClientGrantType` が、`ClientModePolicy` の手前で絞る**
        /// （#307 の段階 1）。**保存して返すだけにはしない** —
        /// **登録が「`authorization_code` だけ」と言っているのに
        /// 認可サーバが他も通すのでは、登録の意味が無い。**
        ///
        /// **動的登録（DCR）で登録するときは、RFC 7591 §2 の既定
        /// （`authorization_code`）を書き込む**（**空のままにはしない**）。
        /// </remarks>
        [Display(Name = "GrantTypes", Description = "GrantTypesDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfTypeList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientGrantTypes)]
        public string GrantTypes { get; set; }

        /// <summary>ResponseTypes（RFC 7591 §2 の response_types）</summary>
        /// <remarks>
        /// **このクライアントが使ってよい `response_type`**（空白区切り）。
        /// **空なら絞らない。**
        ///
        /// **要素の中の空白は、そのままでは持てない**（区切りと区別が付かない）。
        /// **`code id_token` のような組み合わせは `+` で繋いで 1 要素にする**
        /// （`code+id_token`）。**比較のときに空白へ戻す。**
        ///
        /// **絞りは認可エンドポイント**（`CmnEndpoints.CheckAuthZEndpoint`）**で効く** —
        /// **利用者を操作させる前に断る**ため。
        /// </remarks>
        [Display(Name = "ResponseTypes", Description = "ResponseTypesDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfTypeList,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientResponseTypes)]
        public string ResponseTypes { get; set; }

        /// <summary>JwksUri（RFC 7591 §2 の jwks_uri）</summary>
        /// <remarks>
        /// **列は在るが、動的登録では段階 1 では受け付けない**（`invalid_client_metadata`）。
        ///
        /// **鍵をこの URL から引く実装が無い** — **クライアントの鍵は
        /// `JwkRsaPublickey` / `JwkECDsaPublickey` の列から読んでいる。**
        /// **受け取って無視すると、`private_key_jwt`（#239）や
        /// Request Object（JAR）の検証が黙って通らなくなる。**
        ///
        /// **列を先に足すのは、DDL を 2 度変えないため。**
        /// **受け付けるのは、鍵を引く実装と一緒に（段階 3）。**
        /// </remarks>
        [Display(Name = "JwksUri", Description = "JwksUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = OAuth2AndOIDCConst.jwks_uri)]
        public string JwksUri { get; set; }

        /// <summary>ClientUri（RFC 7591 §2 の client_uri）</summary>
        /// <remarks>**保存して返すだけ**（仕様が振る舞いを定めていない。表示用）。</remarks>
        [Display(Name = "ClientUri", Description = "ClientUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientUri)]
        public string ClientUri { get; set; }

        /// <summary>LogoUri（RFC 7591 §2 の logo_uri）</summary>
        /// <remarks>**保存して返すだけ。**</remarks>
        [Display(Name = "LogoUri", Description = "LogoUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientLogoUri)]
        public string LogoUri { get; set; }

        /// <summary>TosUri（RFC 7591 §2 の tos_uri）</summary>
        /// <remarks>**保存して返すだけ。**</remarks>
        [Display(Name = "TosUri", Description = "TosUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientTosUri)]
        public string TosUri { get; set; }

        /// <summary>PolicyUri（RFC 7591 §2 の policy_uri）</summary>
        /// <remarks>**保存して返すだけ。**</remarks>
        [Display(Name = "PolicyUri", Description = "PolicyUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientPolicyUri)]
        public string PolicyUri { get; set; }

        /// <summary>Contacts（RFC 7591 §2 の contacts）</summary>
        /// <remarks>
        /// **保存して返すだけ**（連絡先。空白区切り）。
        /// **仕様は配列だが、他の列挙と同じく空白区切りの 1 つの文字列で持つ**（#306 と同じ形）。
        /// </remarks>
        [Display(Name = "Contacts", Description = "ContactsDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfContacts,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientContacts)]
        public string Contacts { get; set; }

        /// <summary>SoftwareId（RFC 7591 §2 の software_id）</summary>
        /// <remarks>
        /// **保存して返すだけ。**
        /// **同じソフトウェアの、どの配備でも同じ値**（RFC 7591 §2）。
        /// **`client_id` とは別物**である。
        /// </remarks>
        [Display(Name = "SoftwareId", Description = "SoftwareIdDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfSoftwareId,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientSoftwareId)]
        public string SoftwareId { get; set; }

        /// <summary>SoftwareVersion（RFC 7591 §2 の software_version）</summary>
        /// <remarks>**保存して返すだけ。**</remarks>
        [Display(Name = "SoftwareVersion", Description = "SoftwareVersionDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfSoftwareVersion,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientSoftwareVersion)]
        public string SoftwareVersion { get; set; }

        #endregion

        #region 管理 API（RFC 7592。#307 の段階 2）

        /// <summary>RegistrationAccessToken（**ハッシュが入る**。RFC 7592 §2）</summary>
        /// <remarks>
        /// **`registration_client_uri`（`…/register/{client_id}`）への
        /// `GET` / `PUT` / `DELETE` を許す、その 1 件だけのトークン**である。
        ///
        /// | | |
        /// |---|---|
        /// | **入るもの** | **ハッシュ**（`ClientRegistrationProvider.Hash`）。**平文は登録の応答で 1 回だけ返す** |
        /// | **画面** | **出さない** — **照合にしか使わない**（再表示できない） |
        /// | **画面の保存** | **消えないように持ち越す**（`ManageController`。**行を丸ごと上書きする**ため） |
        ///
        /// **暗号化（`SecretProtector`）はしない** — **ハッシュであり、元に戻す必要が無い。**
        /// </remarks>
        [StringLength(
            Const.MaxLengthOfTokenHash,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = Const.ClientRegistrationAccessTokenHash)]
        public string RegistrationAccessToken { get; set; }

        #endregion

        #region token_endpoint_auth_method（#307 の段階 3）

        /// <summary>TokenEndpointAuthMethod（RFC 7591 §2 の token_endpoint_auth_method）</summary>
        /// <remarks>
        /// **このクライアントが、クライアント認証に使う方法**（**値は 1 つ**）。
        ///
        /// | 登録 | 通る方法 |
        /// |---|---|
        /// | **空**（未登録） | **`client_secret_basic` と `client_secret_post`**（**暗黙に許す**） |
        /// | `client_secret_basic` / `client_secret_post` | 同上（**明示しても同じ**） |
        /// | **`private_key_jwt`** | **`client_assertion` だけ**（**秘密では通らない**） |
        /// | **`tls_client_auth`** | **クライアント証明書だけ**（同上） |
        ///
        /// **つまり「強い方法は明示が要る」**（#307 の段階 3 の決定）。
        /// **判定は `CmnEndpoints.AllowsAuthMethod`** で、
        /// **`/token` / `/par` / `/revoke` / `/introspect` / `/ciba_authz` /
        /// `refresh_token` の全部に効く。**
        ///
        /// **`client_secret` は、方法に関わらず発行する**（段階 3 の決定）。
        /// **デバイス フローのように、秘密しか使えない口が在る**ためである
        /// （RFC 8628 の口は `client_assertion` を読んでいない）。
        /// </remarks>
        [Display(Name = "TokenEndpointAuthMethod", Description = "TokenEndpointAuthMethodDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(Const.MaxLengthOfAuthMethod)]
        [JsonProperty(PropertyName = Const.ClientTokenEndpointAuthMethod)]
        public string TokenEndpointAuthMethod { get; set; }

        /// <summary>TokenEndpointAuthMethod アイテムリスト</summary>
        /// <remarks>
        /// **一覧は `CmnEndpoints.TokenEndpointAuthMethods` が持つ**（広告もそこから作る）。
        /// **先頭は空**（＝ 明示しない ＝ 秘密ベースの 2 つ）である。
        /// </remarks>
        // **直列化しない。** これは**画面の選択肢**で、登録の内容ではない（#266 で踏んだ）。
        [JsonIgnore]
        public List<SelectListItem> DdlTokenEndpointAuthMethodItems
        {
            get
            {
                List<SelectListItem> items = new List<SelectListItem>()
                {
                    // **空 ＝ 明示しない**（秘密ベースの 2 つを暗黙に許す）。
                    new SelectListItem() { Text = Resources.CommonViewModels.DdlTokenEndpointAuthMethodNone, Value = "" }
                };

                foreach (string method in TokenProviders.CmnEndpoints.TokenEndpointAuthMethods)
                {
                    items.Add(new SelectListItem() { Text = method, Value = method });
                }

                return items;
            }
        }

        #endregion
        #region 所有者（#307 の段階 5-a）

        /// <summary>この登録の所有者（`Users.Id`）</summary>
        /// <remarks>
        /// **以前は `Users.ClientID`（利用者の 1 枠）が所有を表していた。**
        /// **それを、こちらへ移した**（#307 の段階 5-a）。**1 利用者 n クライアント**になる。
        ///
        /// | | |
        /// |---|---|
        /// | **`Users.Id` を指す** | **名前ではない** — **利用者名を変えても切れない**（`ClientName` は名前なので切れる） |
        /// | **空（NULL）が在り得る** | **構成ファイル発の種データ**（所有者が居ない）／**移行中の行** |
        /// | **外部キー** | **`Users.Id` へ `ON DELETE CASCADE`** — **利用者を消すと、その人の登録は全部消える** |
        ///
        /// **`ClientName`（所有者の利用者名）は、ラベルとして残してある** —
        /// **`Helper.GetClientName` が「登録が在るか」の判定と、
        /// `client_credentials` の `sub` に使っている**ためである。
        ///
        /// **画面からは入れられない**（**入力項目ではない**）。
        /// **動的登録と管理画面が、サインインしている利用者から入れる。**
        /// </remarks>
        // **直列化しない。** **動的登録の応答に出す項目ではない**（RFC 7591 §2 に無い）。
        [JsonIgnore]
        [StringLength(38)]
        public string OwnerUserId { get; set; }

        #endregion
        #region 編集中の印（#307 の段階 5-a-2）

        /// <summary>既に在る登録を編集しているか（"1" なら編集）</summary>
        /// <remarks>
        /// **一覧から「編集」で開いたことを、画面が覚えておくための印**である
        /// （#307 の段階 5-a-2）。
        ///
        /// | | |
        /// |---|---|
        /// | **編集のとき** | **`client_id` を作り直すボタンを出さない** — **押すと別のクライアントになり**、**`registration_access_token` も引き継げない**（**更新ではなく、新規の登録になってしまう**） |
        /// | **新規のとき** | **出す**（**`client_id` は画面が発行する**。「3 回押し」の 1 回目） |
        ///
        /// **hidden で持ち回る** — **この画面は、押すたびに同じフォームを送り直す**ので、
        /// **印も一緒に往復させないと、2 回目で消える。**
        ///
        /// **文字列である。** **`bool` だと、`false` のときに hidden が
        /// 「False」という値で往復し、`Harvest`（E2E）とブラウザで扱いが揺れる** —
        /// **空か "1" の 2 通りに寄せる。**
        ///
        /// **保管しない**（**列ではない**）。**直列化もしない**（RFC 7591 §2 に無い）。
        /// </remarks>
        [JsonIgnore]
        public string Editing { get; set; }

        #endregion
    }
}