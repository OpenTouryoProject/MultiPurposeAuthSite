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
//* クラス名        ：CheckRole
//* クラス日本語名  ：CheckRole（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/05  西野 大介         新規
//**********************************************************************************

using System.Linq;
using System.Collections.Generic;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Util
{
    /// <summary>ロールの確認クラス</summary>
    public class CheckRole
    {
        /// <summary>IsSystemAdmin</summary>
        /// <param name="roles">IList<string></param>
        /// <returns>IsSystemAdmin</returns>
        public static bool IsSystemAdmin(IList<string> roles)
        {
            return roles.Where(x => x == ASPNETIdentityConst.Role_SystemAdmin).Any();
        }

        /// <summary>IsAdmin</summary>
        /// <param name="roles">IList<string></param>
        /// <returns>IsAdmin</returns>
        public static bool IsAdmin(IList<string> roles)
        {
            return roles.Where(x => x == ASPNETIdentityConst.Role_Admin).Any();
        }

        /// <summary>IsUser</summary>
        /// <param name="roles">IList<string></param>
        /// <returns>IsUser</returns>
        public static bool IsUser(IList<string> roles)
        {
            return roles.Where(x => x == ASPNETIdentityConst.Role_User).Any();
        }
    }
}