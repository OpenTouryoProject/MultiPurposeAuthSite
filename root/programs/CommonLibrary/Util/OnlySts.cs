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
//* クラス名        ：OnlySts
//* クラス日本語名  ：OnlySts（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/09/09  西野 大介         新規
//**********************************************************************************

using System;
using MultiPurposeAuthSite.Co;

namespace MultiPurposeAuthSite.Util
{
    /// <summary>ユーザストアを停止させる例外</summary>
    public class StopUserStoreException : Exception
    {
        /// <summary>constructor</summary>
        /// <param name="message">string</param>
        public StopUserStoreException(string message) : base(message) { }
    }

    /// <summary>
    /// 提供する機能をSTSだけにする場合の支援機能
    /// </summary>
    public class OnlySts
    {
        /// <summary>
        /// STS機能のみを提供する設定かどうかチェックする。
        /// </summary>
        /// <returns>
        /// ・true : STSのみの場合。
        /// ・false : STSのみでない場合。
        /// </returns>
        public static bool STSOnly_P
        {
            get
            {
                return OnlySts.Check();
            }
        }

        /// <summary>
        /// STS機能のみを提供する設定かどうかチェックする。
        /// </summary>
        /// <returns>
        /// STSのみの場合に例外を返す。
        /// </returns>
        public static void STSOnly_M()
        {
            if (OnlySts.Check())
            {
                // STSのみの場合。
                //string trace = Environment.StackTrace;
                throw new StopUserStoreException("StopUserStoreException");
            }
        }

        /// <summary>
        /// STS機能のみを提供する設定かどうかチェックする。
        /// </summary>
        /// <returns>
        /// ・true : STSのみの場合。
        /// ・false : STSのみでない場合。
        /// </returns>
        private static bool Check()
        {
            if (Config.EnableSignupProcess
                || Config.EnableEditingOfUserAttribute
                || Config.EnableAdministrationOfUsersAndRoles)
            {
                // STSのみでない場合。
                return false;
            }
            else
            {
                // STSのみの場合。
                return true;
            }
        }
    }
}