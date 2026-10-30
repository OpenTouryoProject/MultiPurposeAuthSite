//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2026/09/17  玄人 幸道         再サインインでブラウザ記憶(2FA)を付けないようにした
//*  2026/09/30  玄人 幸道         Facebook / Twitter 固有のメアド取得を削除（#249）
//*  2026/09/30  玄人 幸道         auth_time Cookie の名前を設定から取るようにした（#255）
//*  2026/10/01  玄人 幸道         メアドの追加・削除を引退させ、利用者名の変更と分けた（#151 の段階 3）
//*  2026/10/04  玄人 幸道         折り返し先の既定をtest_self_code_manageに（C-10）
//*  2026/10/04  玄人 幸道         登録の保存でCORSのキャッシュを捨てる（#266）
//*  2026/10/06  玄人 幸道         クライアント登録を専用列に保存する（#270）
//*  2026/10/06  玄人 幸道         CORSの許可オリジンのキャッシュをやめた（#271）
//*  2026/10/06  玄人 幸道         同意の一覧と取り消しを追加（#272 の段階 2）
//*  2026/10/07  玄人 幸道         WebAuthn / MsPass の画面を削除（#137）
//*  2026/10/09  西野 大介         オンライン決済サービス、トークン取得処理の削除
//*  2026/10/14  玄人 幸道         GDPR削除を物理削除に（DBストアなら CASCADE で関連明細も消える。
//*  2026/10/18  玄人 幸道         画面の保存で registration_access_token を消さない（#307 の段階 2）
//*  2026/10/26  玄人 幸道         クライアント登録の保存で、画面に欄の無い EC の公開鍵を持ち越すようにした（#294）
//*  2026/10/26  玄人 幸道         クライアント登録の削除で、全利用者の同意も消すようにした（#294）
//*  2026/10/28  玄人 幸道         auth_time の Cookie を、改ざんできない形で書く（#294）
//*  2026/10/29  玄人 幸道         partial に分割（Account / TwoFactor / ExternalLogin / Data / OAuth2Data / Helper。#294）
//*  2026/10/29  玄人 幸道         ManageController.*.cs のレビュー指摘を反映（各ファイルの履歴を参照。#294）
//*  2026/10/30  玄人 幸道         ManageController.*.cs の 2 回目のレビュー指摘を反映（各ファイルの履歴を参照。#294）
//*  2026/10/30  玄人 幸道         利用者を引けなければ、管理画面をエラー画面にする（net10.0 版に揃えた。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Manager;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System.Threading.Tasks;

using System.Web;
using System.Web.Mvc;
//using System.Web.Http;
using System.Net.Http;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>ManageController</summary>
    [Authorize]
    public partial class ManageController : MyBaseMVController
    {
        #region Enum

        /// <summary>列挙型</summary>
        public enum EnumManageMessageId
        {
            /// <summary>ChangeUserNameSuccess</summary>
            ChangeUserNameSuccess,
            /// <summary>ChangeUserNameFailure</summary>
            ChangeUserNameFailure,
            /// <summary>ChangeEmailSuccess</summary>
            ChangeEmailSuccess,
            /// <summary>ChangeEmailFailure</summary>
            ChangeEmailFailure,
            /// <summary>SetPasswordSuccess</summary>
            SetPasswordSuccess,
            /// <summary>ChangePasswordSuccess</summary>
            ChangePasswordSuccess,
            /// <summary>RemoveExternalLoginSuccess</summary>
            RemoveExternalLoginSuccess,
            /// <summary>RevokeConsentSuccess（#272 の段階 2）</summary>
            RevokeConsentSuccess,
            /// <summary>AccountConflictInSocialLogin</summary>
            AccountConflictInSocialLogin,
            /// <summary>SetTwoFactorSuccess</summary>
            SetTwoFactorSuccess,
            /// <summary>AddPhoneSuccess</summary>
            AddPhoneSuccess,
            /// <summary>RemovePhoneSuccess</summary>
            RemovePhoneSuccess,
            /// <summary>AddUnstructuredDataSuccess</summary>
            AddUnstructuredDataSuccess,
            /// <summary>RemoveUnstructuredDataSuccess</summary>
            RemoveUnstructuredDataSuccess,
            /// <summary>AddSaml2OAuth2DataSuccess</summary>
            AddSaml2OAuth2DataSuccess,
            /// <summary>RemoveSaml2OAuth2DataSuccess</summary>
            RemoveSaml2OAuth2DataSuccess,
            /// <summary>PasswordIncorrect（パスワードの再確認に失敗。#294）</summary>
            PasswordIncorrect,
            /// <summary>PasswordNotSet（再確認するパスワードが無い。#294）</summary>
            PasswordNotSet,
            /// <summary>Error</summary>
            Error
        }


        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public ManageController() { }

        #endregion

        #region property (GetOwinContext)

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

        #region Action Method

        #region 管理画面（初期表示）

        /// <summary>
        /// 管理画面（初期表示）
        /// GET: /Manage/Index
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Index(EnumManageMessageId? message)
        {
            if (Config.EnableEditingOfUserAttribute)
            {
                // 色々な結果メッセージの設定
                ViewBag.StatusMessage =
                message == EnumManageMessageId.SetPasswordSuccess ? Resources.ManageController.SetPasswordSuccess
                : message == EnumManageMessageId.ChangeUserNameSuccess ? Resources.ManageController.ChangeUserNameSuccess
                : message == EnumManageMessageId.ChangeUserNameFailure ? Resources.ManageController.ChangeUserNameFailure
                : message == EnumManageMessageId.ChangeEmailSuccess ? Resources.ManageController.ChangeEmailSuccess
                : message == EnumManageMessageId.ChangeEmailFailure ? Resources.ManageController.ChangeEmailFailure
                : message == EnumManageMessageId.ChangePasswordSuccess ? Resources.ManageController.ChangePasswordSuccess
                : message == EnumManageMessageId.RemoveExternalLoginSuccess ? Resources.ManageController.RemoveExternalLoginSuccess
                : message == EnumManageMessageId.RevokeConsentSuccess ? Resources.ManageController.RevokeConsentSuccess
                : message == EnumManageMessageId.AccountConflictInSocialLogin ? Resources.ManageController.AccountConflictInSocialLogin
                : message == EnumManageMessageId.SetTwoFactorSuccess ? Resources.ManageController.SetTwoFactorSuccess
                : message == EnumManageMessageId.AddPhoneSuccess ? Resources.ManageController.AddPhoneSuccess
                : message == EnumManageMessageId.RemovePhoneSuccess ? Resources.ManageController.RemovePhoneSuccess
                : message == EnumManageMessageId.AddUnstructuredDataSuccess ? Resources.ManageController.AddUnstructuredDataSuccess
                : message == EnumManageMessageId.RemoveUnstructuredDataSuccess ? Resources.ManageController.RemoveUnstructuredDataSuccess
                : message == EnumManageMessageId.AddSaml2OAuth2DataSuccess ? Resources.ManageController.AddSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.RemoveSaml2OAuth2DataSuccess ? Resources.ManageController.RemoveSaml2OAuth2DataSuccess
                : message == EnumManageMessageId.PasswordIncorrect ? Resources.ManageController.PasswordIncorrect
                : message == EnumManageMessageId.PasswordNotSet ? Resources.ManageController.PasswordNotSet
                : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                : "";

                // ユーザの取得
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                //  **利用者を引けなければ、エラー画面にする**（#294。net10.0 版と同じ）。
                //    **Cookie が有効なまま利用者が消された**ときに、以前は 500 になっていた。
                if (user != null)
                {
                    // モデルの生成
                    //  **所有者の登録の件数**（#307 の段階 5-a-2）。
                    //    **1 利用者 n クライアント**になったので、**件数を数える** —
                    //    **「在る / 無い」だけでは、何件在るのかが分からない。**
                    //    **中身は一覧の画面（`Saml2OAuth2DataList`）で見せる。**
                    int saml2OAuth2DataCount = Sts.Saml2OAuth2DataProvider.GetByOwner(user.Id).Count;
                    bool hasSaml2OAuth2Data = (0 < saml2OAuth2DataCount);

                    ManageIndexViewModel model = new ManageIndexViewModel
                    {
                        // パスワード
                        HasPassword = await UserManager.HasPasswordAsync(user.Id),
                        // ログイン
                        Logins = user.Logins,
                        // E-mail
                        Email = user.Email,
                        // 電話番号
                        PhoneNumber = user.PhoneNumber,
                        // 2FA
                        TwoFactor = user.TwoFactorEnabled,
                        // 非構造化データ
                        HasUnstructuredData = !string.IsNullOrEmpty(user.UnstructuredData),
                        // Saml2OAuth2Data
                        HasSaml2OAuth2Data = hasSaml2OAuth2Data,
                        Saml2OAuth2DataCount = saml2OAuth2DataCount
                    };

                    // 管理画面の表示
                    return View(model);
                }
            }

            // エラー画面
            return View("Error");
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
    }
}
