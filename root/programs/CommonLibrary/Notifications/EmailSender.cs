//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：EmailSender
//* クラス日本語名  ：EmailSender
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//**********************************************************************************

using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>EmailSender</summary>
    public class EmailSender : IEmailSender
    {
        /// <summary></summary>
        /// <param name="email"></param>
        /// <param name="subject"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Task.CompletedTask;
        }

        /// <summary></summary>
        /// <param name="email"></param>
        /// <param name="link"></param>
        /// <returns></returns>
        public Task SendEmailConfirmationAsync(string email, string link)
        {
            return this.SendEmailAsync(email, "Confirm your email",
                $"Please confirm your account by clicking this link: <a href='{HtmlEncoder.Default.Encode(link)}'>link</a>");
        }
    }
}
