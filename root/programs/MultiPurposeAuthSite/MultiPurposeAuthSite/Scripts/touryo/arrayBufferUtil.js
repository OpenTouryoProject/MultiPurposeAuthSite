//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

// Apache License
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

//**********************************************************************************
//* �t�@�C����        �FarrayBufferUtil.js
//* �t�@�C�����{�ꖼ  �FarrayBuffer����
//*
//* �쐬����        �F�|
//* �쐬��          �F�|
//* �X�V����        �F�|
//*
//*  ����        �X�V��            ���e
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/0?  ���� ���         �V�K�쐬
//**********************************************************************************

// ---------------------------------------------------------------
// To Base64Url
// ---------------------------------------------------------------
// ����    Array or ArrayBuffer
// �߂�l  Base64Url String
// ---------------------------------------------------------------
function Fx_CoerceToBase64Url(thing) {
    // Array or ArrayBuffer to Uint8Array
    // - Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }
    // - ArrayBuffer to Uint8Array
    if (thing instanceof ArrayBuffer) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to base64
    if (thing instanceof Uint8Array) {
        var str = "";
        var len = thing.byteLength;

        for (var i = 0; i < len; i++) {
            str += String.fromCharCode(thing[i]);
        }
        thing = window.btoa(str);
    }

    // Check type of thing.
    if (typeof thing !== "string") {
        throw new Error("could not coerce to string");
    }

    // base64 to base64url.
    // NOTE: "=" at the end of challenge is optional, strip it off here
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

// ---------------------------------------------------------------
// To ArrayBuffer
// ---------------------------------------------------------------
// ����    base64url or base64 String
// �߂�l  ArrayBuffer
// ---------------------------------------------------------------
function Fx_CoerceToArrayBuffer(thing) {
    if (typeof thing === "string") {
        // base64url or base64 String to Uint8Array
        // - base64url to base64
        thing = thing.replace(/-/g, "+").replace(/_/g, "/");
        // - base64 to Uint8Array
        var str = window.atob(thing);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        thing = bytes;
    }
    else {
        // Array to Uint8Array
        if (Array.isArray(thing)) {
            thing = new Uint8Array(thing);
        }
    }

    // Uint8Array to ArrayBuffer
    if (thing instanceof Uint8Array) {
        thing = thing.buffer;
    }

    // Check type of thing.
    if (!(thing instanceof ArrayBuffer)) {
        throw new TypeError("could not coerce to ArrayBuffer");
    }

    return thing;
}
