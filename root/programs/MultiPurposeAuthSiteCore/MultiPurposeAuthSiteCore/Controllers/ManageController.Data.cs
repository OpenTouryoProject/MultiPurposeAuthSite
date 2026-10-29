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
非構造化データ、FIDO（WebAuthn）の資格情報、
GDPR の参照・削除を担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;

using System;
using System.IO;
using System.Text;
using Stj = System.Text.Json;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Fido2NetLib;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Log;

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
                ApplicationUser user = await UserManager.GetUserAsync(User);

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
                    ApplicationUser user = await UserManager.GetUserAsync(User);

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
                            await this.ReSignInAsync(user.Id);
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
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // 非構造化データのクリア
                user.UnstructuredData = "";
                // ユーザーの保存
                IdentityResult result = await UserManager.UpdateAsync(user);

                // 結果の確認
                if (result.Succeeded)
                {
                    // 支払元情報 削除の成功

                    // 再ログイン
                    if (await this.ReSignInAsync(user.Id))
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

        #region FIDO Data（WebAuthn）

        //  **MsPass（Microsoft Passport）の画面は落とした**（#137）。
        //    **`navigator.authentication` は EdgeHTML 専用の前身 API** で、
        //    **動く実行環境が無い。**

        /// <summary>
        /// WebAuthnの資格情報の登録画面（初期表示）
        /// GET: /Manage/AddWebAuthnData
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> AddWebAuthnData()
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);
                ViewBag.SequenceNo = "0";
                ViewBag.UserName = user.UserName;
                ViewBag.FIDO2Data = "";

                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// WebAuthnの資格情報の登録画面
        /// POST: /Manage/AddWebAuthnData
        /// </summary>
        /// <param name="fido2Data">string</param>
        /// <param name="sequenceNo">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        //  **画面とは form post で 3 往復する**（`ffWebauthn.js`）。
        //    - sequenceNo=0 : 画面からの条件 → CredentialCreateOptions を返す
        //    - sequenceNo=1 : 認証器が作った attestation → 検証して保存
        //    - sequenceNo=2 : 結果を見せた後、Index へ戻る
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddWebAuthnData(string fido2Data, string sequenceNo)
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);
                ViewBag.UserName = user.UserName;

                if (sequenceNo == "0")
                {
                    string temp = "";

                    try
                    {
                        JObject requestJSON = JsonConvert.DeserializeObject<JObject>(fido2Data);

                        string username = (string)requestJSON[Const.WebAuthnRequestUserName];
                        bool residentKey = (bool)requestJSON["authenticatorSelection"]["residentKey"];
                        string authenticatorAttachment = (string)requestJSON["authenticatorSelection"]["authenticatorAttachment"];
                        string userVerification = (string)requestJSON["authenticatorSelection"]["userVerification"];
                        string attestation = (string)requestJSON["attestation"];

                        // **サインイン中の利用者と違うなら、その場で落とす。**
                        //   **以前は if で囲っているだけだった**ので、
                        //   **違う利用者名を送ると options が空のまま返っていた。**
                        if (username != user.UserName)
                        {
                            throw new Exception("The username does not match the signed-in user.");
                        }

                        FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();

                        CredentialCreateOptions options = webAuthnHelper.CredentialCreationOptions(
                            username, attestation, authenticatorAttachment, residentKey, userVerification);

                        // **Sessionに保存**（challenge を後で照合するため）
                        string optionsJson = options.ToJson();
                        HttpContext.Session.SetString(Const.WebAuthnSessionCredentialCreateOptions, optionsJson);

                        temp = FIDO.WebAuthnHelper.ToOkJson(optionsJson);
                    }
                    catch (Exception e)
                    {
                        //  **障害対応のため、記録する**（#294）。**以前は画面へ返すだけだった。**
                        Logging.MyOperationTrace(string.Format(
                            Resources.Diagnostics.LogWebAuthnRegistrationFailed, LogSanitizer.Sanitize(e.Message, Const.LogDetailMaxLength)));
                        temp = FIDO.WebAuthnHelper.ToErrorJson(e);
                    }

                    // Htmlを返す。
                    ViewBag.SequenceNo = "1";
                    ViewBag.FIDO2Data = temp;

                    return View();
                }
                else if (sequenceNo == "1")
                {
                    string temp = "";

                    try
                    {
                        // **System.Text.Json で読む。**
                        //   **4.x の生データは STJ の属性で base64url を扱っている**ので、
                        //   **Newtonsoft で読むと byte[] が壊れる。**
                        AuthenticatorAttestationRawResponse attestationResponse
                            = Stj.JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(fido2Data);

                        FIDO.WebAuthnHelper webAuthnHelper = new FIDO.WebAuthnHelper();

                        // Sessionから復元
                        CredentialCreateOptions options = CredentialCreateOptions.FromJson(
                            HttpContext.Session.GetString(Const.WebAuthnSessionCredentialCreateOptions));

                        await webAuthnHelper.AuthenticatorAttestation(attestationResponse, options);

                        // **一度使った challenge は捨てる**（使い回しを防ぐ）。
                        HttpContext.Session.Remove(Const.WebAuthnSessionCredentialCreateOptions);

                        // **成否だけを返す。** 資格情報の中身を画面へ戻す必要は無い。
                        temp = FIDO.WebAuthnHelper.ToOkJson("");
                    }
                    catch (Exception e)
                    {
                        //  **障害対応のため、記録する**（#294）。**以前は画面へ返すだけだった。**
                        Logging.MyOperationTrace(string.Format(
                            Resources.Diagnostics.LogWebAuthnRegistrationFailed, LogSanitizer.Sanitize(e.Message, Const.LogDetailMaxLength)));
                        temp = FIDO.WebAuthnHelper.ToErrorJson(e);
                    }

                    // Htmlを返す。
                    ViewBag.SequenceNo = "2";
                    ViewBag.FIDO2Data = temp;

                    return View();
                }
                else if (sequenceNo == "2")
                {
                    return RedirectToAction("Index", new { Message = EnumManageMessageId.AddWebAuthnDataSuccess });
                }
            }

            // エラー画面
            return View("Error");
        }

        /// <summary>
        /// WebAuthnの資格情報の一覧・削除
        /// POST: /Manage/RemoveWebAuthnData
        /// </summary>
        /// <param name="publicKeys">string[]（選ばれた PublicKeyId。base64url）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **`string` ではなく `string[]` で受ける**（#277 の段階 6）。
        ///
        /// **画面は同じ名前のチェックボックスを並べる**ので、
        /// **選んだ数だけ同名の値が送られてくる**（`publicKeys=A&publicKeys=B`）。
        ///
        /// **`string` で受けると、ASP.NET Core は先頭の 1 つだけを採る**
        /// （`ValueProviderResult.FirstValue`）。**実測 : 2 つ送って `A` だけが届いた。**
        /// **そのため「複数選んでも 1 件しか消えない」状態だった。**
        ///
        /// **カンマ区切りの前提は、net48（MVC 5）のもの**である
        /// （あちらは複数値を "," で連結する）。**この画面は net10.0 版だけに在る**ので、
        /// **連結を当てにせず、配列で受けて素直に回す。**
        /// </remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveWebAuthnData(string[] publicKeys)
        {
            if ((Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // 削除処理
                if (publicKeys != null)
                {
                    foreach (string publicKey in publicKeys)
                    {
                        if (string.IsNullOrEmpty(publicKey))
                        {
                            continue;
                        }

                        // **利用者名を WHERE に入れている**ので、
                        // **他人の資格情報の id を送っても消せない。**
                        FIDO.DataProvider.Delete(publicKey, user.UserName);
                    }
                }

                // 残っている資格情報の一覧
                ViewBag.ExistingPubCredDescriptorId
                    = FIDO.DataProvider.GetCredentialIdsByUser(user.UserName);

                // Htmlを返す。
                return View();
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

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
                ApplicationUser user = await UserManager.GetUserAsync(User);

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
                ApplicationUser user = await UserManager.GetUserAsync(User);

                // **WebAuthnを消す ※ `mem` ストアでログインできないように対策
                FIDO.DataProvider.DeleteByUser(user.UserName);

                // 物理削除 DBストアなら `ON DELETE CASCADE` で関連明細も消える。
                IdentityResult result = await UserManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    // サインアウト（Cookieの削除）
                    await SignInManager.SignOutAsync();
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
