// ---------------------------------------------------------------
// �����_���ȕ�����𐶐�����
// ---------------------------------------------------------------
// ����    len
// �߂�l  Random String
// ---------------------------------------------------------------
function Fx_GetRandomString(len) {
    //�g�p�����̒�`
    var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&=~/*-+";

    //�����_���ȕ�����̐���
    var result = "";
    for (var i = 0; i < len; i++) {
        result += str.charAt(Math.floor(Math.random() * str.length));
    }
    return result;
}

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

// ---------------------------------------------------------------
// Debug�o��
// ---------------------------------------------------------------
// ����    testLabel: ���x��, object: �I�u�W�F�N�g
// �߂�l  �|
// ---------------------------------------------------------------
function Fx_DebugOutput(testLabel, object) {
    console.log(testLabel);
    if (object) {
        console.log(object);
        console.log(JSON.stringify(object));
    }
}