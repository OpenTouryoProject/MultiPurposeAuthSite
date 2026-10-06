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
//* クラス名        ：ManageConsentGrantsViewModel
//* クラス日本語名  ：同意（consent grant）の一覧のVM
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/06  玄人 幸道         新規（#272 の段階 2 / D-6）
//**********************************************************************************

using System.Collections.Generic;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>同意の一覧の 1 件（#272 の段階 2）</summary>
    public class ConsentGrantViewModel
    {
        /// <summary>client_id</summary>
        public string ClientId { get; set; }

        /// <summary>client_name（引けなければ client_id）</summary>
        public string ClientName { get; set; }

        /// <summary>許可した scope（空白区切り）</summary>
        public string Scopes { get; set; }
    }

    /// <summary>同意（consent grant）の一覧のVM（#272 の段階 2）</summary>
    /// <remarks>
    /// **利用者が「どのアプリケーションに何を許したか」を見て、取り消すための画面**である。
    ///
    /// **取り消しても、発行済みのトークンは失効しない。**
    /// そちらは `/revoke`（RFC 7009）の役目である。
    /// **取り消しの効果は「次の認可で同意画面が出る」**こと
    /// （`prompt=none` なら `consent_required`）。
    /// </remarks>
    public class ManageConsentGrantsViewModel : BaseViewModel
    {
        /// <summary>同意の一覧</summary>
        public List<ConsentGrantViewModel> Grants { get; set; }
    }
}
