//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：IdFederationAdminController
//* クラス日本語名  ：ID 連携の上流 IdP の管理画面
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.ViewModels;

using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;

using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Web;
using System.Web.Mvc;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;

using Touryo.Infrastructure.Business.Presentation;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>
    /// ID 連携の上流 IdP の管理画面（#292 の段階 2）
    /// </summary>
    /// <remarks>
    /// **上流の登録は「配備全体のもの」**である。
    /// **下流（クライアント）の登録とは所有者が違う** —
    /// `Saml2OAuth2Data` は `Users.ClientID` に紐づく「その利用者の登録」であり、
    /// `Manage/AddSaml2OAuth2Data` が編むのは**自分の分**である。
    /// **上流は配備の設定**なので、**`UsersAdmin` / `RolesAdmin` と同じ位置**に置いた。
    ///
    /// **認可も `UsersAdmin` と同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`）。
    ///
    /// | | |
    /// |---|---|
    /// | 読む先 | **設定 → user store の順**（`Co.IdFederationUpstreams`。同じ鍵は設定が勝つ） |
    /// | **この画面が編むのは user store の行だけ** | **設定ファイルの行は、ここからは触れない**（画面には出すが、編めない） |
    ///
    /// **`client_secret` は平文で入る**（`Saml2OAuth2Data` と同じ扱い）。
    /// **上流へ送る値なので、元に戻せる形でなければならない。**
    /// </remarks>
    [Authorize]
    public class IdFederationAdminController : MyBaseMVController
    {
        /// <summary>列挙型</summary>
        public enum EnumAdminMessageId
        {
            /// <summary>AddSuccess</summary>
            AddSuccess,
            /// <summary>EditSuccess</summary>
            EditSuccess,
            /// <summary>DeleteSuccess</summary>
            DeleteSuccess,
            /// <summary>Error</summary>
            Error
        }

        #region constructor & property

        /// <summary>constructor</summary>
        public IdFederationAdminController() { }

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        #endregion

        #region 認証・認可系

        /// <summary>
        /// [Authorize(Roles = Const.Role_Admin)]の代替
        /// ※ constructorでは動かないので、このように実装することになった。
        /// </summary>
        /// <remarks>**`UsersAdminController.Authorize` と同じ**（#292 の段階 2）。</remarks>
        private void Authorize()
        {
            if (Config.EnableAdministrationOfUsersAndRoles)
            {
                string uid = User.Identity.GetUserId();

                if (string.IsNullOrWhiteSpace(uid))
                {
                    // 未認証
                    throw new SecurityException(Resources.AdminController.UnAuthenticate);
                }
                else
                {
                    IList<string> roles = UserManager.GetRoles(uid);

                    if (roles.Any(x => x == Const.Role_SystemAdmin))
                    {
                        return;
                    }
                    else
                    {
                        // 認証されない。
                        throw new SecurityException(Resources.AdminController.UnAuthorized);
                    }
                }
            }
            else
            {
                // ロックダウンされている。
                throw new SecurityException(Resources.AdminController.LockedDown);
            }
        }

        #endregion

        #region Action Method

        #region Reference

        /// <summary>
        /// 上流 IdP の一覧表示画面
        /// GET: /IdFederationAdmin/Index
        /// </summary>
        /// <param name="message">EnumAdminMessageId?</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Index(EnumAdminMessageId? message)
        {
            this.Authorize();

            // 色々な結果メッセージの設定
            ViewBag.StatusMessage =
                message == EnumAdminMessageId.AddSuccess ? Resources.AdminController.AddSuccess
                : message == EnumAdminMessageId.EditSuccess ? Resources.AdminController.EditSuccess
                : message == EnumAdminMessageId.DeleteSuccess ? Resources.AdminController.DeleteSuccess
                : message == EnumAdminMessageId.Error ? Resources.AdminController.Error
                : "";

            return View(IdFederationUpstreamProvider.GetAll());
        }

        #endregion

        #region Create

        /// <summary>
        /// 上流 IdP の追加画面（初期表示）
        /// GET: /IdFederationAdmin/Create
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Create()
        {
            this.Authorize();

            //  **既定は OIDC で有効**（**よく足す方を既定にする**）。
            return View(new IdFederationUpstreamViewModel()
            {
                Protocol = IdFederationUpstream.Oidc,
                Enabled = true
            });
        }

        /// <summary>
        /// 上流 IdP の追加画面（追加）
        /// POST: /IdFederationAdmin/Create
        /// </summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IdFederationUpstreamViewModel model)
        {
            this.Authorize();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            //  **同じ鍵は足せない**（設定ファイル側も含めて見る）。
            //    **設定が勝つ規則**なので、**設定に在る鍵を DB に入れても使われない。**
            if (IdFederationUpstreamProvider.Get(model.UpstreamKey) != null
                || IdFederationUpstreams.Get(model.UpstreamKey) != null)
            {
                ModelState.AddModelError("", Resources.AdminController.IdFederationKeyAlreadyExists);

                return View(model);
            }

            IdFederationUpstreamProvider.Create(model);

            // オペレーション・トレース・ログ出力（**値は出さない。鍵と protocol だけ**）
            Logging.MyOperationTrace(string.Format(
                "An ID federation upstream was added. (key: {0}, protocol: {1})",
                model.UpstreamKey, model.Protocol));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.AddSuccess });
        }

        #endregion

        #region Edit

        /// <summary>
        /// 上流 IdP の編集画面（初期表示）
        /// GET: /IdFederationAdmin/Edit
        /// </summary>
        /// <param name="key">鍵</param>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Edit(string key)
        {
            this.Authorize();

            IdFederationUpstreamViewModel model = IdFederationUpstreamProvider.Get(key);

            if (model == null)
            {
                //  **設定ファイルの行は編めない**（この画面は user store の行だけを編む）。
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            return View(model);
        }

        /// <summary>
        /// 上流 IdP の編集画面（更新）
        /// POST: /IdFederationAdmin/Edit
        /// </summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(IdFederationUpstreamViewModel model)
        {
            this.Authorize();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (IdFederationUpstreamProvider.Get(model.UpstreamKey) == null)
            {
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            IdFederationUpstreamProvider.Update(model);

            Logging.MyOperationTrace(string.Format(
                "An ID federation upstream was updated. (key: {0}, protocol: {1})",
                model.UpstreamKey, model.Protocol));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.EditSuccess });
        }

        #endregion

        #region Delete

        /// <summary>
        /// 上流 IdP の削除
        /// POST: /IdFederationAdmin/Delete
        /// </summary>
        /// <param name="key">鍵</param>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **POST で受ける**（GET で消さない）。**画面は一覧の行から押す。**
        /// </remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(string key)
        {
            this.Authorize();

            if (IdFederationUpstreamProvider.Get(key) == null)
            {
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            IdFederationUpstreamProvider.Delete(key);

            Logging.MyOperationTrace(string.Format(
                "An ID federation upstream was deleted. (key: {0})", key));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.DeleteSuccess });
        }

        #endregion

        #endregion
    }
}
