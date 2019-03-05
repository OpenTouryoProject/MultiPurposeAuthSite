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
//* クラス名        ：Fido2ServerController
//* クラス日本語名  ：Fido2ServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/05  西野 大介         新規
//**********************************************************************************

using System.Collections.Generic;

using System.Web.Http;
using System.Net.Http.Formatting;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>Fido2ServerのApiController（ライブラリ）</summary>
    [Authorize]
    public class Fido2ServerController : ApiController
    {
        #region /token

        /// <summary>
        /// Tokenエンドポイント
        /// POST: /token
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        public Dictionary<string, string> OAuth2Token(FormDataCollection formData)
        {
            return null;
        }

        #endregion
    }
}