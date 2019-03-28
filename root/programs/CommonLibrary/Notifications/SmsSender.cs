//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：SmsSender
//* クラス日本語名  ：SmsSender
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//**********************************************************************************

using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>SmsSender</summary>
    public class SmsSender : ISmsSender
    {
        /// <summary>SendEmailAsync</summary>
        /// <param name="destination">string</param>
        /// <param name="body">string</param>
        /// <returns>非同期操作</returns>
        public Task SendAsync(string destination, string body)
        {
            return CmnSms.SendAsync(destination, body);
        }
    }
}
