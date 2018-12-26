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
//* クラス名        ：OidcTokenEditor
//* クラス日本語名  ：OIDC用のtoken編集処理クラス
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/02/05  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Extensions.OIDC
{
    /// <summary>OIDC用のtoken編集処理クラス</summary>
    /// <remarks>
    /// ・OIDC対応（AccessTokenからIdTokenを生成）
    ///   書き換えで対応するので、AccessTokenからIdTokenを生成する拡張メソッドを新設した。
    ///   
    /// ・Hybrid Flow対応（access_token_payloadを処理）
    ///   codeのフローをtokenのフローに変更するため、tokenをcodeプロバイダを使用して生成する必要があった。
    ///   この際、OAuthAuthorizationServerHandler経由でのAuthorizationCodeProviderの呼び出しが実装できなかったため、
    ///   （ApplicationUserから、ticketを生成する）抜け道を準備したが、今度は、
    ///   AccessTokenFormatJwtから、ApplicationUserManagerにアクセスできなかったため、この拡張メソッドを新設した。
    ///   また、ticketのシリアライズしたものはサイズが大き過ぎたため、access_tokenのpayloadを使用することとした。
    /// </remarks>
    public class OidcTokenEditor
    {
        
    }
}