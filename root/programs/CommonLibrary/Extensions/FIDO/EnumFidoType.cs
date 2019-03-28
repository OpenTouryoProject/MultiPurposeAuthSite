//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：EnumFidoType
//* クラス日本語名  ：EnumFidoType列挙型
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/06  西野 大介         新規
//**********************************************************************************

namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>列挙型</summary>
    public enum EnumFidoType
    {
        /// <summary>None</summary>
        None,
        /// <summary>MsPass (Microsoft Passport)</summary>
        MsPass,
        /// <summary>WebAuthn</summary>
        WebAuthn
    }
}
