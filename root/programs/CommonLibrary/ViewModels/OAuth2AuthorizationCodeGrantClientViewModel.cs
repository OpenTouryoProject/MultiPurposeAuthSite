// OAuth 2.0 テスト用 モデルなので、必要に応じて流用 or 削除して下さい。

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
//* クラス名        ：OAuth2AuthorizationCodeGrantClientViewModel
//* クラス日本語名  ：Claimを返すための共通ViewModel
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2026/09/28  玄人 幸道         クライアント認証の方式を持たせた（#246 の項目 3）
//**********************************************************************************

using System;
using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>OAuth2AuthorizationCodeGrantClient画面のViewModel（ライブラリ）</summary>
    [Serializable]
    public class OAuth2AuthorizationCodeGrantClientViewModel : BaseViewModel
    {
        /// <summary>ClientId</summary>
        [Display(Name = "ClientId")]
        public string ClientId { get; set; }

        /// <summary>State</summary>
        [Display(Name = "State")]
        public string State { get; set; }

        /// <summary>Code</summary>
        [Display(Name = "Code")]
        public string Code { get; set; }

        /// <summary>AccessToken</summary>
        public string AccessToken { get; set; }

        /// <summary>AccessTokenJwtToJson</summary>
        public string AccessTokenJwtToJson { get; set; }

        /// <summary>IdToken</summary>
        public string IdToken { get; set; }

        /// <summary>IdTokenJwtToJson</summary>
        public string IdTokenJwtToJson { get; set; }

        /// <summary>RefreshToken</summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// トークン要求に使ったクライアント認証の方式（#246 の項目 3）
        /// </summary>
        /// <remarks>
        /// **画面からは何を送ったのかが分からなかった**ので、出すことにした。
        /// 値は自己テストが自分で入れる（サーバの応答に入っているものではない）。
        /// </remarks>
        public string AuthMethod { get; set; }

        /// <summary>Response</summary>
        public string Response { get; set; }
    }
}