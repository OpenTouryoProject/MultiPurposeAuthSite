//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/02/28  西野 大介         エラーメッセージ通知の改善
//*  2020/03/04  西野 大介         CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2020/12/21  西野 大介         Device AuthZ対応実施
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/07  玄人 幸道         expires_inが常に0になる不具合を修正（#182）
//*  2026/09/08  玄人 幸道         エラー応答とRedirect URLをRFC 6749に合わせる（#187）
//*  2026/09/16  玄人 幸道         2FAのコード送信の失敗を、画面に戻して伝える（#214）
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認の待ち受け（TwoFactorPushStatus）を追加（#216）
//*  2026/09/18  玄人 幸道         認可リクエストの code_challenge を検証に渡す（#220）
//*  2026/09/27  玄人 幸道         RP-Initiated Logout（/end_session）を追加（#232）
//*  2026/09/28  玄人 幸道         FAPI2 の自己テストのトークン交換を private_key_jwt にした（#246）
//*  2026/09/28  玄人 幸道         max_age の超過で再認証し、prompt=none なら login_required を返す（#247）
//*  2026/09/30  玄人 幸道         ID 連携の Error に理由のトレースを足す（#253）
//*  2026/09/30  玄人 幸道         未サインイン＋prompt=none で login_required を返す（#254）
//*  2026/09/30  玄人 幸道         自身が書く Cookie の名前に接頭辞を付けられるようにした（#255）
//*  2026/09/30  玄人 幸道         既存アカウントへメアドで結ぶとき email_verified を確かめるようにした（#140 の段階 1）
//*  2026/09/30  玄人 幸道         Facebook / Twitter 固有のメアド取得を削除（#249）
//*  2026/10/01  玄人 幸道         利用者名とメアドの両方でサインインできるようにし、サインアップを見直した（#151 の段階 3）
//*  2026/10/03  玄人 幸道         テスト利用者の名前に接尾辞を付けられるようにした（#260）
//*  2026/10/03  玄人 幸道         E2E専用のクライアント登録を種データにした（#264）
//*  2026/10/03  玄人 幸道         2人目のテスト利用者に標準クレームのサンプルを仕込む（#261）
//*  2026/10/04  玄人 幸道         response_typeを正規化して受ける（#267）
//*  2026/10/06  玄人 幸道         種データのクライアント登録を専用列で作る（#270）
//*  2026/10/06  玄人 幸道         promptの照合を集合に寄せた（#272 の段階 1）
//*  2026/10/07  玄人 幸道         WebAuthn / MsPass のサインインを削除（#137）
//*  2026/10/07  玄人 幸道         SAML2の応答を3分岐にし、SP側の照合に期待値を渡した（#276）
//*  2026/10/10  玄人 幸道         ID連携からprompt=noneを外し、エラー応答を受け取る（#287）
//*  2026/10/10  玄人 幸道         SAML2のID連携を追加（#286の段階2）
//*  2026/10/12  玄人 幸道         上流の id_token を、上流の鍵で検証するようにした（#289 の段階 1）
//*  2026/10/13  玄人 幸道         上流の SSO の口を、メタデータから引くようにした（#291）
//*  2026/10/14  玄人 幸道         ID 連携の上流を、設定の n 件から選べるようにした（#292 の段階 1）
//*  2026/10/16  玄人 幸道         user_code の投入の失敗を数える（#305 の段階 2）
//*  2026/10/20  玄人 幸道         クライアントごとの利用者を作らなくした（#307 の段階 5-a-1）
//*  2026/10/21  玄人 幸道         OP のセッションの識別子と sid クレームを追加（#310 の段階 1）
//*  2026/10/25  玄人 幸道         認可エンドポイントと SAML2 のエラーを OPERATION に記録する（障害対応のため。#294）
//**********************************************************************************

/*
- ASP.NET Identity（OWIN）を用いた認証・認可およびアカウント管理機能の基盤や共通処理を提供するコントローラーの一部。
- 属性 (Attributes): [Authorize]（原則として認証済みのユーザーのみアクセス可能）
- 主要なマネージャーは、OWIN のコンテキストから取得する（プロパティ）。
  - ApplicationUserManager UserManager: ユーザー管理のためのマネージャー。
  - ApplicationRoleManager RoleManager: ロール管理のためのマネージャー。
  - ApplicationSignInManager SignInManager: サインイン管理のためのマネージャー。
  - IAuthenticationManager AuthenticationManager: 認証（Cookie）の管理。
- 段階ごとの決定と経緯（partial の全ファイル分）は、root/programs/DesignNotes/AccountController.md に在る。
*/

using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Util.Sts;

using System.Collections.Generic;
using System.Configuration;

using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Web.Configuration;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>AccountのController（テンプレート）</summary>
    [Authorize]
    public partial class AccountController : MyBaseMVController
    {
        #region constructor

        /// <summary>constructor</summary>
        public AccountController() { }

        #endregion

        #region property

        /// <summary>SessionCookieName</summary>
        private string SessionCookieName
        {
            get
            {
                return ((SessionStateSection)ConfigurationManager.GetSection("system.web/sessionState")).CookieName;
            }
        }

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private ApplicationSignInManager SignInManager
        {
            get
            {
                return HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
        }

        /// <summary>AuthenticationManager</summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        #endregion

        #endregion

        #region Dispose

        /// <summary>Dispose</summary>
        /// <param name="disposing">bool</param>
        protected override void Dispose(bool disposing)
        {
            // メンバのdisposingを実装しているらしい。
            if (disposing)
            {
            }

            base.Dispose(disposing);
        }

        #endregion

        #region Helper

        #region Controller → View

        /// <summary>
        /// ModelStateDictionaryに
        /// IdentityResult.Errorsの情報を移送
        /// </summary>
        /// <param name="result">IdentityResult</param>
        private void AddErrors(IdentityResult result)
        {
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        /// <summary>
        /// ModelStateDictionaryに
        /// IEnumerable(string)の情報を移送
        /// </summary>
        /// <param name="errors">IEnumerable<string></param>
        private void AddErrors(IEnumerable<string> errors)
        {
            foreach (string error in errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        /// <summary>RedirectToActionする。</summary>
        /// <param name="returnUrl">returnUrl</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        #endregion

        #endregion
    }
}