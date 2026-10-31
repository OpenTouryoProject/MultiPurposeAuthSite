//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストの OAuth2 / OIDC（認可コード・PKCE・Implicit・Hybrid）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         値を URL 符号化する。SPA の PKCE で response_mode を二重にしない（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Web.Mvc;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストの OAuth2 / OIDC（認可コード・PKCE・Implicit・Hybrid））</summary>
    public partial class HomeController
    {
        #region Assemble

        #region OAuth2/OIDC
        /// <summary>クエリの値を符号化する（#294）</summary>
        /// <param name="value">値（null は空）</param>
        /// <returns>符号化した値</returns>
        /// <remarks>
        /// **以前は符号化せずに連結していた。** 画面から来る値（prompt・max_age・response_mode）に
        /// `&` を入れると、別のパラメタを差し込めた（自分への要求なので、影響は自己テストの中だけ）。
        /// scope・response_type の空白も、そのまま載っていた（RFC 6749 Appendix B / RFC 3986）。
        /// </remarks>
        private static string Enc(string value)
        {
            return Uri.EscapeDataString(value ?? "");
        }

        /// <summary>OAuth2スターターに追加のパラメタを組み込む</summary>
        /// <param name="redirect">string</param>
        /// <param name="response_type">string</param>
        /// <returns>OAuth2スターター</returns>
        private string AndAddAdditionalParamToOAuth2Starter(string redirect, string response_type)
        {
            // RedirectUriの追加
            if (this.ClarifyRedirectUri)
            {
                string temp = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
                this.RedirectUri = CmnEndpoints.GetRedirectUriFromConstr(temp);
                redirect += "&" + OAuth2AndOIDCConst.redirect_uri + "=" + Enc(this.RedirectUri);
            }

            // ResponseModeの指定
            if (!string.IsNullOrEmpty(this.ResponseMode))
            {
                redirect += "&" + OAuth2AndOIDCConst.response_mode + "=" + Enc(this.ResponseMode);
            }

            // **prompt と max_age の指定**（#246 の項目 3）。
            //   認可画面（同意）の出方を、画面から試せるようにするためにある。
            //   **ここは認可エンドポイントへ行く全てのスターターが通る**ので、1 か所で足りる。
            if (!string.IsNullOrEmpty(this.Prompt))
            {
                redirect += "&" + OAuth2AndOIDCConst.prompt + "=" + Enc(this.Prompt);
            }

            if (!string.IsNullOrEmpty(this.MaxAge))
            {
                redirect += "&" + OAuth2AndOIDCConst.max_age + "=" + Enc(this.MaxAge);
            }

            return redirect;
        }

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        private string AssembleOAuth2Starter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    Enc(this.ClientId), Enc(response_type), Enc(Const.SelfTestScopes), Enc(this.State));

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOIDCスターター</returns>
        private string AssembleOidcStarter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    Enc(this.ClientId), Enc(response_type), Enc(Const.OidcScopes), Enc(this.State))
                    + "&nonce=" + Enc(this.Nonce)
                    // **画面で max_age を選んでいれば、そちらを使う**（#246 の項目 3）。
                    //   選んでいなければ、従来どおり 600 秒を付ける。
                    + (string.IsNullOrEmpty(this.MaxAge) ? "&max_age=600" : "");

            temp = AndAddAdditionalParamToOAuth2Starter(temp, response_type);

            return temp;
        }
        #endregion

        #endregion

        #region Action Method

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Authorization Code Flow (OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_OIDC()
        {
            this.InitOAuth2Params();

            // Assemble
            // **prompt は固定しない**（#272 の段階 2）。
            //   以前は、画面で選んでいなければ **`prompt=none` を付けていた**
            //   （同意画面を飛ばして 1 回のクリックで通すため）。
            //   **同意を記録するようになったので、それでは回らない。**
            //   **記録が無い配備では、初回に必ず `consent_required` になる。**
            //   いまは**初回だけ同意画面を通る**（2 回目以降は記録が効いて飛ぶ）。
            //   **`prompt` を試したいときは、画面の選択で指定する**（#246 の項目 3）。
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region PKCE

        /// <summary>Test Authorization Code Flow (PKCE plain)</summary>
        /// <param name="toSpa">bool</param>
        /// <returns>ActionResult</returns>
        private ActionResult PKCE_Plain(bool toSpa = false)
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;

            // Authorization Code Grant Flow with PKCE
            //   **SPA 向けは fragment で受ける。** 画面で選んだ response_mode より優先する
            //   （以前は後から足していたので、選んでいると response_mode が 2 つ載った。RFC 6749 3.1。#294）。
            if (toSpa) this.ResponseMode = OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + Enc(this.CodeChallenge)
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_plain;

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (PKCE S256)</summary>
        /// <param name="toSpa">bool</param>
        /// <returns>ActionResult</returns>
        private ActionResult PKCE_S256(bool toSpa = false)
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);

            // Authorization Code Grant Flow with PKCE
            //   **SPA 向けは fragment で受ける**（PKCE_Plain と同じ。#294）。
            if (toSpa) this.ResponseMode = OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + Enc(this.CodeChallenge)
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256;

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Implicit Flow

        #region OAuth2

        /// <summary>Test Implicit Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit()
        {
            this.InitOAuth2Params();

            // Assemble
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.ImplicitResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Implicit Flow 'id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC1()
        {
            this.InitOAuth2Params();

            // Assemble 'id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit1_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC2()
        {
            this.InitOAuth2Params();

            // Assemble 'id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit2_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Hybrid Flow

        #region OIDC

        /// <summary>Test Hybrid Flow 'code id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC1()
        {
            this.InitOAuth2Params();

            // Assemble 'code id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC2()
        {
            this.InitOAuth2Params();

            // Assemble 'code token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC3()
        {
            this.InitOAuth2Params();

            // Assemble 'code id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid3_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #endregion
    }
}