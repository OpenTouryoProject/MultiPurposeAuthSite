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
//* クラス名        ：FIDO.WebAuthnHelper
//* クラス日本語名  ：FIDO.WebAuthnHelper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/07  西野 大介         新規
//**********************************************************************************

using System;

using Fido2NetLib;
using Fido2NetLib.Development;

namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// FIDO.WebAuthnHelper（ライブラリ）
    /// https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/Controller.cs
    /// </summary>
    public class WebAuthnHelper
    {
        /// <summary>
        /// 開発時のストレージ
        /// </summary>
        private static readonly DevelopmentInMemoryStore DemoStorage = new DevelopmentInMemoryStore();

        #region mem & prop & constructor

        #region mem & prop

        /// <summary>
        /// fido2-net-lib
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?fido2-net-lib
        /// </summary>
        private Fido2 _lib;

        /// <summary>
        /// FIDO Alliance MetaData Service
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?FIDO%E8%AA%8D%E8%A8%BC%E5%99%A8#d6659b25
        /// </summary>
        private IMetadataService _mds;

        /// <summary>
        /// Origin of the website: "http(s)://..."
        /// </summary>
        private string _origin;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public WebAuthnHelper()
        {
            _origin = "https://localhost:44329";

            _lib = new Fido2(new Fido2.Configuration()
            {
                ServerDomain = "localhost",
                ServerName = "Fido2 test",
                Origin = _origin,
                // Only create and use Metadataservice if we have an acesskey
                MetadataService = null // MDSMetadata.Instance("accesskey", "cachedirPath");
            });
        }

        #endregion

        #endregion

        #region methods

        #region 登録フロー

        /// <summary></summary>
        /// <param name="username">string</param>
        public void CredentialCreationOptions(string username)
        {
        }

        public void AuthenticatorAttestation()
        {
        }
        #endregion

        #region 認証フロー
        public void CredentialGetOptions()
        {
        }

        public void AuthenticatorAssertion()
        {
        }
        #endregion

        #endregion
    }
}