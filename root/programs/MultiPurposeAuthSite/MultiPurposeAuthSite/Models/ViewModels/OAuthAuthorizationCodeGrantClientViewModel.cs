// OAuth 2.0 テスト用 モデルなので、必要に応じて流用 or 削除して下さい。

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
//* クラス名        ：OAuthAuthorizationCodeGrantClientViewModel
//* クラス日本語名  ：Claimを返すための共通ViewModel（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>OAuthAuthorizationCodeGrantClient画面のViewModel（ライブラリ）</summary>
    public class OAuthAuthorizationCodeGrantClientViewModel : BaseViewModel
    {
        /// <summary>Code</summary>
        public string Code { get; set; }

        /// <summary>AccessTokenJWT</summary>
        public string AccessTokenJWT { get; set; }

        /// <summary>AccessTokenJwtToJson</summary>
        public string AccessTokenJwtToJson { get; set; }

        /// <summary>RefreshToken</summary>
        public string RefreshToken { get; set; }

        /// <summary>Response</summary>
        public string Response { get; set; }

        /// <summary>PointOfView</summary>
        public string PointOfView { get; set; }
    }
}