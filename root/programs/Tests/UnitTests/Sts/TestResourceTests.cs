//**********************************************************************************
//* クラス名        ：TestResourceTests
//* クラス日本語名  ：テスト用の資源（/TestResource）の開閉の単体テスト（#425）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規作成（#425）
//**********************************************************************************

using MultiPurposeAuthSite.Util.Test;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>テスト用の資源（/TestResource）の開閉</summary>
    public class TestResourceTests
    {
        /// <summary>IsDebug で、閉じる指定が無いときだけ開く</summary>
        /// <param name="isDebug">IsDebug</param>
        /// <param name="lockedDown">IsLockedDownTestEndpoints</param>
        /// <param name="expected">開くか</param>
        [Theory]
        [Basis("#425（設計：Util.Test.TestResource の remarks。本番の構成（IsDebug=false）では、キーを書き忘れても開かない）")]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        [InlineData(false, false, false)]
        [InlineData(false, true, false)]
        public void IsDebugで閉じる指定が無いときだけ開く(bool isDebug, bool lockedDown, bool expected)
        {
            Assert.Equal(expected, TestResource.IsOpenFor(isDebug, lockedDown));
        }
    }
}