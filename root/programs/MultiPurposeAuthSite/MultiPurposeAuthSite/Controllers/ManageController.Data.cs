//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController の利用者データ
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//**********************************************************************************

/*
非構造化データ、
GDPR の参照・削除を担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;

using System.IO;
using System.Text;
using System.Threading.Tasks;

using System.Web.Mvc;

using Microsoft.AspNet.Identity;

using Newtonsoft.Json;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController の利用者データ**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region Unstructured Data

        #region Create

        /// <summary>
        /// 非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddUnstructuredData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> AddUnstructuredData()
        {
            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                ManageAddUnstructuredDataViewModel model = null;

                if (string.IsNullOrEmpty(user.UnstructuredData))
                {
                    model = new ManageAddUnstructuredDataViewModel();
                }
                else
                {
                    model = JsonConvert.DeserializeObject<ManageAddUnstructuredDataViewModel>(user.UnstructuredData);
                }

                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// 非構造化データの追加・編集画面（非構造化データ設定）
        /// POST: /Manage/AddUnstructuredData
        /// </summary>
        /// <param name="model">ManageAddUnstructuredDataViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddUnstructuredData(ManageAddUnstructuredDataViewModel model)
        {
            // 二重送信防止機能のテスト
            // System.Threading.Thread.Sleep(5000);

            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddUnstructuredDataViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddUnstructuredDataViewModelの検証に成功

                    // ユーザの検索
                    ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                    if (user != null)
                    {
                        // ユーザを取得できた。
                        user.UnstructuredData = JsonConvert.SerializeObject(model);

                        // ユーザーの保存
                        IdentityResult result = await UserManager.UpdateAsync(user);

                        // 結果の確認
                        if (result.Succeeded)
                        {
                            // 成功

                            // 再ログイン
                            await this.ReSignInAsync();
                            return RedirectToAction("Index", new { Message = EnumManageMessageId.AddUnstructuredDataSuccess });
                        }
                        else
                        {
                            // 失敗
                            this.AddErrors(result);
                        }
                    }
                    else
                    {
                        // ユーザを取得できなかった。
                    }
                }
                else
                {
                    // ManageAddUnstructuredDataViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Delete

        /// <summary>
        /// 非構造化データの削除
        /// POST: /Manage/RemoveUnstructuredData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveUnstructuredData()
        {
            if (Config.CanEditUnstructuredData
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // 非構造化データのクリア
                user.UnstructuredData = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync())
                    {
                        // 再ログインに成功
                        return RedirectToAction("Index", new { Message = EnumManageMessageId.RemoveUnstructuredDataSuccess });
                    }
                    else
                    {
                        // 再ログインに失敗
                    }
                }
                else
                {
                    // 非構造化データ 削除の失敗
                }

                // Index - Error
                return RedirectToAction("Index", new { Message = EnumManageMessageId.Error });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion

        #region GDPR

        /// <summary>
        /// GDPR対策処理
        /// GET: /Manage/ManageGdprData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public ActionResult ManageGdprData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// GDPR対策のユーザデータ照会処理
        /// POST: /Manage/ReferGdprPersonalData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ReferGdprPersonalData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                using (MemoryStream ms = new MemoryStream())
                {
                    using (StreamWriter streamWriter = new StreamWriter(ms, Encoding.GetEncoding(CustomEncode.UTF_8)))
                    {
                        streamWriter.WriteLine(JsonConvert.SerializeObject(user));
                        streamWriter.Flush();
                    }

                    return File(ms.ToArray(), "application/json", "user.json");
                }
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// GDPR対策のユーザデータ削除処理
        /// POST: /Manage/DeleteGdprPersonalData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteGdprPersonalData()
        {
            if (Config.CanUseGdprFunction)
            //&& Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // 物理削除 DBストアなら `ON DELETE CASCADE` で関連明細も消える。
                IdentityResult result = await UserManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    // サインアウト（Cookieの削除）
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

                    //// オペレーション・トレース・ログ出力
                    //Logging.MyOperationTrace(string.Format("{0}({1}) has signed out.", user.Id, user.UserName));

                    // リダイレクト "Index", "Home"へ
                    return RedirectToAction("Index", "Home");
                }
                else { }
            }
            else { }

            // エラー画面
            return View("Error");
        }

        #endregion
    }
}
