//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HtmlHelperExtensions
//* クラス日本語名  ：Viewから項目の説明を引くための拡張（#277）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/09  玄人 幸道         新規（#277 の段階 1）
//**********************************************************************************

using System;
using System.Linq.Expressions;

#if NETFX
using System.Web.Mvc;
#elif NETCORE
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
#endif

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>
    /// View から **項目の説明**（`[Display(Description = ...)]`）を引く（#277 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **説明は ViewModel に 1 か所だけ書く。**
    /// **net48 版と net10.0 版で同じ View を保つ**ため、取り出し方の違いをここで吸収する。
    ///
    /// | | 取り出し方 |
    /// |---|---|
    /// | net48（MVC 5） | `ModelMetadata.FromLambdaExpression` |
    /// | net10.0（ASP.NET Core） | `ViewData.ModelExplorer.Metadata.Properties[名前]` |
    ///
    /// **枠組みに `DescriptionFor` は無い**（`LabelFor` はあるが、説明用の対はない）。
    ///
    /// **無ければ空文字を返す。** View 側で `if` を書かずに済ませるため。
    /// </remarks>
    public static class HtmlHelperExtensions
    {
#if NETFX
        /// <summary>項目の説明を返す（無ければ空文字）</summary>
        /// <typeparam name="TModel">モデル</typeparam>
        /// <typeparam name="TResult">プロパティの型</typeparam>
        /// <param name="html">HtmlHelper</param>
        /// <param name="expression">プロパティを指す式</param>
        /// <returns>説明。無ければ空文字</returns>
        public static string DescriptionFor<TModel, TResult>(
            this HtmlHelper<TModel> html, Expression<Func<TModel, TResult>> expression)
        {
            ModelMetadata metadata = ModelMetadata.FromLambdaExpression(expression, html.ViewData);

            return metadata.Description ?? "";
        }
#elif NETCORE
        /// <summary>項目の説明を返す（無ければ空文字）</summary>
        /// <typeparam name="TModel">モデル</typeparam>
        /// <typeparam name="TResult">プロパティの型</typeparam>
        /// <param name="html">IHtmlHelper</param>
        /// <param name="expression">プロパティを指す式</param>
        /// <returns>説明。無ければ空文字</returns>
        /// <remarks>
        /// **`ModelExpressionProvider` は DI から取る必要がある**ので使わない。
        /// **式からプロパティ名を取り出し、メタデータを名前で引く。**
        /// </remarks>
        public static string DescriptionFor<TModel, TResult>(
            this IHtmlHelper<TModel> html, Expression<Func<TModel, TResult>> expression)
        {
            string name = HtmlHelperExtensions.MemberName(expression.Body);

            if (string.IsNullOrEmpty(name))
            {
                return "";
            }

            ModelMetadata metadata = html.ViewData.ModelExplorer.Metadata.Properties[name];

            return (metadata == null) ? "" : (metadata.Description ?? "");
        }

        /// <summary>式からプロパティ名を取り出す（取り出せなければ null）</summary>
        /// <param name="expression">式</param>
        /// <returns>プロパティ名</returns>
        /// <remarks>
        /// **`bool` のプロパティは `Convert` に包まれることがある**ので、そこを剥がす。
        /// </remarks>
        private static string MemberName(Expression expression)
        {
            UnaryExpression unary = expression as UnaryExpression;

            if (unary != null)
            {
                return HtmlHelperExtensions.MemberName(unary.Operand);
            }

            MemberExpression member = expression as MemberExpression;

            return (member == null) ? null : member.Member.Name;
        }
#endif
    }
}
