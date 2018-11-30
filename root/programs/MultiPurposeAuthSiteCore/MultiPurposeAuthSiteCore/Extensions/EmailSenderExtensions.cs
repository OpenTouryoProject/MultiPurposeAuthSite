//**********************************************************************************
//* �e���v���[�g
//**********************************************************************************

// �ȉ���License�ɏ]���A����Project��Template�Ƃ��Ďg�p�\�ł��BRelease����Copyright�\������Sublicense���ĉ������B
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* �N���X��        �FEmailSenderExtensions
//* �N���X���{�ꖼ  �FEmailSenderExtensions
//*
//* �쐬����        �F�|
//* �쐬��          �F�|
//* �X�V����        �F�|
//*
//*  ����        �X�V��            ���e
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  ���� ���         �V�K
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using MultiPurposeAuthSiteCore.Services;

namespace MultiPurposeAuthSiteCore.Services
{
    public static class EmailSenderExtensions
    {
        public static Task SendEmailConfirmationAsync(this IEmailSender emailSender, string email, string link)
        {
            return emailSender.SendEmailAsync(email, "Confirm your email",
                $"Please confirm your account by clicking this link: <a href='{HtmlEncoder.Default.Encode(link)}'>link</a>");
        }
    }
}
