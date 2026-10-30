//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：ManageSaml2OAuth2DataListViewModel
//* クラス日本語名  ：自分のクライアント登録の一覧のVM
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/20  玄人 幸道         新規（#307 の段階 5-a-2 / D-4）
//**********************************************************************************

using System.Collections.Generic;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>クライアント登録の一覧の 1 行（#307 の段階 5-a-2）</summary>
    /// <remarks>
    /// **一覧に出す分だけを持つ。**
    /// **`client_secret` と `registration_access_token` は持たない** —
    /// **一覧に出さない値を View へ渡さない**（出し忘れでは防げないため、器ごと分ける）。
    /// </remarks>
    public class Saml2OAuth2DataRowViewModel
    {
        /// <summary>client_id</summary>
        public string ClientID { get; set; }

        /// <summary>client_mode（fapi1 ほか）</summary>
        public string ClientMode { get; set; }

        /// <summary>redirect_uri（認可コード）</summary>
        public string RedirectUriCode { get; set; }

        /// <summary>動的登録（RFC 7591）で作られたか</summary>
        /// <remarks>
        /// **`registration_access_token` を持っているかで見る**（#307 の段階 2）。
        ///
        /// **画面から作った登録は持たない。**
        /// **動的登録で作った登録は持つ**ので、
        /// **「この行は RP が自分で作って、管理 API で直せる」ことが分かる。**
        ///
        /// **トークンそのものは出さない**（**保管しているのはハッシュ**で、再表示もできない）。
        /// </remarks>
        public bool IsDynamic { get; set; }
    }

    /// <summary>自分のクライアント登録の一覧のVM（#307 の段階 5-a-2）</summary>
    /// <remarks>
    /// **1 利用者 n クライアント**（段階 5-a-1）になったので、**並べて選べる画面が要る。**
    ///
    /// **段階 5-a-1 までの画面は「所有者の先頭 1 件」を出していた** —
    /// **2 件目以降は、動的登録で作れても画面から触れなかった。**
    ///
    /// | | |
    /// |---|---|
    /// | **並び** | **`client_id` の昇順**（`Saml2OAuth2DataProvider.GetByOwner`。方言 3 つと `mem` で同じ） |
    /// | **出るもの** | **所有者が自分の登録だけ** — **所有者の無い登録**（構成ファイル発の種データ）**は出ない** |
    /// | **上限** | **無い**（段階 5-a-1 の決め。**ページングもしない**） |
    /// </remarks>
    public class ManageSaml2OAuth2DataListViewModel : BaseViewModel
    {
        /// <summary>クライアント登録の一覧</summary>
        public List<Saml2OAuth2DataRowViewModel> Registrations { get; set; }
    }
}
