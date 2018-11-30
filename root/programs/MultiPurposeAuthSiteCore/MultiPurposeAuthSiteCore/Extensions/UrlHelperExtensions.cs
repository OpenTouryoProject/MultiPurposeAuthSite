//**********************************************************************************
//* �e���v���[�g
//**********************************************************************************

// �ȉ���License�ɏ]���A����Project��Template�Ƃ��Ďg�p�\�ł��BRelease����Copyright�\������Sublicense���ĉ������B
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* �N���X��        �FUrlHelperExtensions
//* �N���X���{�ꖼ  �FUrlHelperExtensions
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
using System.Threading.Tasks;
using MultiPurposeAuthSite.Controllers;

namespace Microsoft.AspNetCore.Mvc
{
    public static class UrlHelperExtensions
    {
        public static string EmailConfirmationLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
        {
            return urlHelper.Action(
                action: nameof(AccountController.ConfirmEmail),
                controller: "Account",
                values: new { userId, code },
                protocol: scheme);
        }

        public static string ResetPasswordCallbackLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
        {
            return urlHelper.Action(
                action: nameof(AccountController.ResetPassword),
                controller: "Account",
                values: new { userId, code },
                protocol: scheme);
        }
    }
}
