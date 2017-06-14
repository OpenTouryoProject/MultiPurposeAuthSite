//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：Log
//* クラス日本語名  ：Log（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/14  西野 大介         新規
//**********************************************************************************

using System.Diagnostics;
using Touryo.Infrastructure.Public.Log;
using MultiPurposeAuthSite.Models.ASPNETIdentity;

namespace MultiPurposeAuthSite.Models.Util
{
    /// <summary>Log</summary>
    public class Log
    {
        /// <summary>MyOperationTrace</summary>
        /// <param name="log">string</param>
        public static void MyOperationTrace(string log)
        {
            // UserStoreのトレース情報をデバッグ時にログ出力
            if (ASPNETIdentityConfig.IsDebug)
            {
                // デバッグ時
                Debug.WriteLine(log);
                LogIF.DebugLog("OPERATION", log);

            }
            else
            {
                // 本番時
                LogIF.DebugLog("OPERATION", log);
            }
        }
    }
}