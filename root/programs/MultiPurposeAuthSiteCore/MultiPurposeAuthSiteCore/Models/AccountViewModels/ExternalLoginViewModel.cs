//**********************************************************************************
//* �e���v���[�g
//**********************************************************************************

// �ȉ���License�ɏ]���A����Project��Template�Ƃ��Ďg�p�\�ł��BRelease����Copyright�\������Sublicense���ĉ������B
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* �N���X��        �FExternalLoginViewModel
//* �N���X���{�ꖼ  �FExternalLoginViewModel
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
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Models.AccountViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
