"use strict";
//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const os = require("os");
const bindings = require("bindings"); // eslint-disable-line @typescript-eslint/no-require-imports
const SC = bindings('libsignal_client_' + os.platform());
class PublicKey {
    constructor(handle) {
        this.nativeHandle = handle;
    }
    static fromNativeHandle(handle) {
        return new PublicKey(handle);
    }
    static deserialize(buf) {
        return new PublicKey(SC.PublicKey_deserialize(buf));
    }
    serialize() {
        return SC.PublicKey_serialize(this.nativeHandle);
    }
    verify(msg, sig) {
        return SC.PublicKey_verify(this.nativeHandle, msg, sig);
    }
    _unsafeGetNativeHandle() {
        return this.nativeHandle;
    }
}
exports.PublicKey = PublicKey;
class PrivateKey {
    constructor(handle) {
        this.nativeHandle = handle;
    }
    static generate() {
        return new PrivateKey(SC.PrivateKey_generate());
    }
    static deserialize(buf) {
        return new PrivateKey(SC.PrivateKey_deserialize(buf));
    }
    serialize() {
        return SC.PrivateKey_serialize(this.nativeHandle);
    }
    sign(msg) {
        return SC.PrivateKey_sign(this.nativeHandle, msg);
    }
    agree(other_key) {
        return SC.PrivateKey_agree(this.nativeHandle, other_key._unsafeGetNativeHandle());
    }
    getPublicKey() {
        return PublicKey.fromNativeHandle(SC.PrivateKey_getPublicKey(this.nativeHandle));
    }
}
exports.PrivateKey = PrivateKey;
