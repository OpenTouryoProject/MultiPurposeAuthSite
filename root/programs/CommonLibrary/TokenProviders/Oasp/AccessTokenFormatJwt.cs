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
//* クラス名        ：AccessTokenFormatJwt
//* クラス日本語名  ：Access TokenのJWTカスタマイズクラス
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;

using Microsoft.Owin.Security;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>AccessTokenFormatJwt</summary>
    public class AccessTokenFormatJwt: ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>constructor</summary>
        public AccessTokenFormatJwt() { }

        /// <summary>Protect</summary>
        /// <param name="ticket">AuthenticationTicket</param>
        /// <returns>JWT文字列</returns>
        public string Protect(AuthenticationTicket ticket)
        {
            // チェック
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            return CmnAccessToken.CreateAccessTokenFromClaims(ticket.Identity.Name, ticket.Identity.Claims, 
                ticket.Properties.ExpiresUtc.Value, ticket.Properties.IssuedUtc.Value);
        }

        /// <summary>Unprotect</summary>
        /// <param name="jwt">JWT文字列</param>
        /// <returns>AuthenticationTicket</returns>
        public AuthenticationTicket Unprotect(string jwt)
        {
            // Unprotectを廃止し、
            //  - MyBaseAsyncApiControllerや
            //  - CmnAccessTokenを使用する。
            return null;
        }
    }
}