//**********************************************************************************
//* �e���v���[�g
//**********************************************************************************

// �ȉ���License�ɏ]���A����Project��Template�Ƃ��Ďg�p�\�ł��BRelease����Copyright�\������Sublicense���ĉ������B
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* �N���X��        �FErrorViewModel
//* �N���X���{�ꖼ  �FErrorViewModel
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

namespace MultiPurposeAuthSite.Models
{
    public class ErrorViewModel
    {
        public string RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}