//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：MobileAppTokenProvider
//* クラス日本語名  ：2FAのコードを、認証デバイスへプッシュ通知で送るプロバイダ
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/16  玄人 幸道         新規（#216）
//**********************************************************************************

using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Notifications;

using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;

/// <summary>MultiPurposeAuthSite.Manager</summary>
namespace MultiPurposeAuthSite.Manager
{
    /// <summary>
    /// 2FAのコードを、認証デバイス（authentication_device）へプッシュ通知で送るプロバイダ（#216）
    /// </summary>
    /// <remarks>
    /// **コードの生成と検証は、メール / SMS と同じ仕組み（TOTP ＋ SecurityStamp）に任せる。**
    /// このクラスが足すのは「送り先」だけ。
    ///
    /// net10.0 版は、AccountController.SendCode の中で一覧に MobileApp を足し、
    /// コードは Email プロバイダで作って送り先だけ振り分けている（#213）。
    /// net48（ASP.NET Identity 2.x）には 2FA プロバイダを登録する口があるので、
    /// **そちらの作法に沿う**（SendCode も VerifyCode も変更しなくてよい）。
    /// </remarks>
    public class MobileAppTokenProvider : TotpSecurityStampBasedTokenProvider<ApplicationUser, string>
    {
        /// <summary>
        /// 2FAプロバイダの名前（登録するキー）
        /// </summary>
        /// <remarks>
        /// **他のプロバイダと違い、リソースではなく固定の文字列にする。**
        /// 登録のキーは、そのままコードの purpose になり、検証にも使う。
        /// リソースにすると、カルチャによって値が変わる（"Email Code" / "電子メール コード"）ため、
        /// **要求ごとにカルチャが違うと一致しなくなる。**
        /// 2FA のプッシュ承認（/2fa_result）は、ブラウザではなく**認証デバイスから来る要求**で
        /// 検証するので、ここが culture に依存すると壊れる。
        /// net10.0 版が使っている名前（MobileApp）と同じにしておく。
        /// </remarks>
        public const string ProviderName = "MobileApp";

        /// <summary>
        /// このプロバイダを使えるか（プッシュ通知の宛先があるか）
        /// </summary>
        /// <param name="manager">UserManager</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>端末が登録されていれば true</returns>
        /// <remarks>
        /// 2FAのコードの送り先を選ぶ画面（SendCode）の一覧は、
        /// UserManager.GetValidTwoFactorProvidersAsync がこれを見て作る。
        /// </remarks>
        public override Task<bool> IsValidProviderForUserAsync(
            UserManager<ApplicationUser, string> manager, ApplicationUser user)
        {
            return Task.FromResult(!string.IsNullOrEmpty(user.DeviceToken));
        }

        /// <summary>
        /// コードを認証デバイスへ送る
        /// </summary>
        /// <param name="token">2FAのコード</param>
        /// <param name="manager">UserManager</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **通知の title は "2FA" 固定。** 認証デバイスは title で画面を切り替える。
        /// data の code も、認証デバイスが読むキーと揃える。
        /// </remarks>
        public override Task NotifyAsync(
            string token, UserManager<ApplicationUser, string> manager, ApplicationUser user)
        {
            return FcmService.GetInstance().SendAsync(
                user.DeviceToken, "2FA", "Two factor authentication",
                new Dictionary<string, string>()
                {
                    { "code", token }
                });
        }

        /// <summary>
        /// コードに混ぜる、利用者ごとの値
        /// </summary>
        /// <param name="purpose">purpose（登録した 2FAプロバイダの名前）</param>
        /// <param name="manager">UserManager</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>利用者ごとの値を非同期に返す</returns>
        /// <remarks>
        /// **宛先（DeviceToken）ではなく、利用者の ID を混ぜる。**
        /// 端末を登録し直すと DeviceToken は変わるので、
        /// 宛先を混ぜると、送信済みのコードが検証できなくなる。
        /// </remarks>
        public override Task<string> GetUserModifierAsync(
            string purpose, UserManager<ApplicationUser, string> manager, ApplicationUser user)
        {
            return Task.FromResult(ProviderName + ":" + purpose + ":" + user.Id);
        }
    }
}
