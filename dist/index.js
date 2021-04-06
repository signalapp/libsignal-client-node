"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const os = require("os");
const uuid = require("uuid");
const bindings = require("bindings"); // eslint-disable-line @typescript-eslint/no-require-imports
const NativeImpl = bindings('libsignal_client_' + os.platform() + '_' + process.arch);
exports.initLogger = NativeImpl.initLogger, exports.LogLevel = NativeImpl.LogLevel;
class HKDF {
    constructor(version) {
        this.version = version;
    }
    static new(version) {
        return new HKDF(version);
    }
    deriveSecrets(outputLength, keyMaterial, label, salt) {
        return NativeImpl.HKDF_DeriveSecrets(outputLength, this.version, keyMaterial, label, salt);
    }
}
exports.HKDF = HKDF;
class ScannableFingerprint {
    constructor(scannable) {
        this.scannable = scannable;
    }
    static _fromBuffer(scannable) {
        return new ScannableFingerprint(scannable);
    }
    compare(other) {
        return NativeImpl.ScannableFingerprint_Compare(this.scannable, other.scannable);
    }
    toBuffer() {
        return this.scannable;
    }
}
exports.ScannableFingerprint = ScannableFingerprint;
class DisplayableFingerprint {
    constructor(display) {
        this.display = display;
    }
    static _fromString(display) {
        return new DisplayableFingerprint(display);
    }
    toString() {
        return this.display;
    }
}
exports.DisplayableFingerprint = DisplayableFingerprint;
class Fingerprint {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static new(iterations, version, localIdentifier, localKey, remoteIdentifier, remoteKey) {
        return new Fingerprint(NativeImpl.Fingerprint_New(iterations, version, localIdentifier, localKey, remoteIdentifier, remoteKey));
    }
    displayableFingerprint() {
        return DisplayableFingerprint._fromString(NativeImpl.Fingerprint_DisplayString(this));
    }
    scannableFingerprint() {
        return ScannableFingerprint._fromBuffer(NativeImpl.Fingerprint_ScannableEncoding(this));
    }
}
exports.Fingerprint = Fingerprint;
class Aes256GcmSiv {
    constructor(key) {
        this._nativeHandle = NativeImpl.Aes256GcmSiv_New(key);
    }
    static new(key) {
        return new Aes256GcmSiv(key);
    }
    encrypt(message, nonce, associated_data) {
        return NativeImpl.Aes256GcmSiv_Encrypt(this, message, nonce, associated_data);
    }
    decrypt(message, nonce, associated_data) {
        return NativeImpl.Aes256GcmSiv_Decrypt(this, message, nonce, associated_data);
    }
}
exports.Aes256GcmSiv = Aes256GcmSiv;
class ProtocolAddress {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(handle) {
        return new ProtocolAddress(handle);
    }
    static new(name, deviceId) {
        return new ProtocolAddress(NativeImpl.ProtocolAddress_New(name, deviceId));
    }
    name() {
        return NativeImpl.ProtocolAddress_Name(this);
    }
    deviceId() {
        return NativeImpl.ProtocolAddress_DeviceId(this);
    }
}
exports.ProtocolAddress = ProtocolAddress;
class PublicKey {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(handle) {
        return new PublicKey(handle);
    }
    static deserialize(buf) {
        return new PublicKey(NativeImpl.PublicKey_Deserialize(buf));
    }
    /// Returns -1, 0, or 1
    compare(other) {
        return NativeImpl.PublicKey_Compare(this, other);
    }
    serialize() {
        return NativeImpl.PublicKey_Serialize(this);
    }
    getPublicKeyBytes() {
        return NativeImpl.PublicKey_GetPublicKeyBytes(this);
    }
    verify(msg, sig) {
        return NativeImpl.PublicKey_Verify(this, msg, sig);
    }
}
exports.PublicKey = PublicKey;
class PrivateKey {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(handle) {
        return new PrivateKey(handle);
    }
    static generate() {
        return new PrivateKey(NativeImpl.PrivateKey_Generate());
    }
    static deserialize(buf) {
        return new PrivateKey(NativeImpl.PrivateKey_Deserialize(buf));
    }
    serialize() {
        return NativeImpl.PrivateKey_Serialize(this);
    }
    sign(msg) {
        return NativeImpl.PrivateKey_Sign(this, msg);
    }
    agree(other_key) {
        return NativeImpl.PrivateKey_Agree(this, other_key);
    }
    getPublicKey() {
        return PublicKey._fromNativeHandle(NativeImpl.PrivateKey_GetPublicKey(this));
    }
}
exports.PrivateKey = PrivateKey;
class IdentityKeyPair {
    constructor(publicKey, privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    static new(publicKey, privateKey) {
        return new IdentityKeyPair(publicKey, privateKey);
    }
    serialize() {
        return NativeImpl.IdentityKeyPair_Serialize(this.publicKey, this.privateKey);
    }
}
exports.IdentityKeyPair = IdentityKeyPair;
class PreKeyBundle {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(registration_id, device_id, prekey_id, prekey, signed_prekey_id, signed_prekey, signed_prekey_signature, identity_key) {
        return new PreKeyBundle(NativeImpl.PreKeyBundle_New(registration_id, device_id, prekey_id, prekey != null ? prekey : null, 
        //prekey?,
        signed_prekey_id, signed_prekey, signed_prekey_signature, identity_key));
    }
    deviceId() {
        return NativeImpl.PreKeyBundle_GetDeviceId(this);
    }
    identityKey() {
        return PublicKey._fromNativeHandle(NativeImpl.PreKeyBundle_GetIdentityKey(this));
    }
    preKeyId() {
        return NativeImpl.PreKeyBundle_GetPreKeyId(this);
    }
    preKeyPublic() {
        const handle = NativeImpl.PreKeyBundle_GetPreKeyPublic(this);
        if (handle == null) {
            return null;
        }
        else {
            return PublicKey._fromNativeHandle(handle);
        }
    }
    registrationId() {
        return NativeImpl.PreKeyBundle_GetRegistrationId(this);
    }
    signedPreKeyId() {
        return NativeImpl.PreKeyBundle_GetSignedPreKeyId(this);
    }
    signedPreKeyPublic() {
        return PublicKey._fromNativeHandle(NativeImpl.PreKeyBundle_GetSignedPreKeyPublic(this));
    }
    signedPreKeySignature() {
        return NativeImpl.PreKeyBundle_GetSignedPreKeySignature(this);
    }
}
exports.PreKeyBundle = PreKeyBundle;
class PreKeyRecord {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new PreKeyRecord(nativeHandle);
    }
    static new(id, pubKey, privKey) {
        return new PreKeyRecord(NativeImpl.PreKeyRecord_New(id, pubKey, privKey));
    }
    static deserialize(buffer) {
        return new PreKeyRecord(NativeImpl.PreKeyRecord_Deserialize(buffer));
    }
    id() {
        return NativeImpl.PreKeyRecord_GetId(this);
    }
    privateKey() {
        return PrivateKey._fromNativeHandle(NativeImpl.PreKeyRecord_GetPrivateKey(this));
    }
    publicKey() {
        return PublicKey._fromNativeHandle(NativeImpl.PreKeyRecord_GetPublicKey(this));
    }
    serialize() {
        return NativeImpl.PreKeyRecord_Serialize(this);
    }
}
exports.PreKeyRecord = PreKeyRecord;
class SignedPreKeyRecord {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SignedPreKeyRecord(nativeHandle);
    }
    static new(id, timestamp, pubKey, privKey, signature) {
        return new SignedPreKeyRecord(NativeImpl.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature));
    }
    static deserialize(buffer) {
        return new SignedPreKeyRecord(NativeImpl.SignedPreKeyRecord_Deserialize(buffer));
    }
    id() {
        return NativeImpl.SignedPreKeyRecord_GetId(this);
    }
    privateKey() {
        return PrivateKey._fromNativeHandle(NativeImpl.SignedPreKeyRecord_GetPrivateKey(this));
    }
    publicKey() {
        return PublicKey._fromNativeHandle(NativeImpl.SignedPreKeyRecord_GetPublicKey(this));
    }
    serialize() {
        return NativeImpl.SignedPreKeyRecord_Serialize(this);
    }
    signature() {
        return NativeImpl.SignedPreKeyRecord_GetSignature(this);
    }
    timestamp() {
        return NativeImpl.SignedPreKeyRecord_GetTimestamp(this);
    }
}
exports.SignedPreKeyRecord = SignedPreKeyRecord;
class SignalMessage {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(messageVersion, macKey, senderRatchetKey, counter, previousCounter, ciphertext, senderIdentityKey, receiverIdentityKey) {
        return new SignalMessage(NativeImpl.SignalMessage_New(messageVersion, macKey, senderRatchetKey, counter, previousCounter, ciphertext, senderIdentityKey, receiverIdentityKey));
    }
    static deserialize(buffer) {
        return new SignalMessage(NativeImpl.SignalMessage_Deserialize(buffer));
    }
    body() {
        return NativeImpl.SignalMessage_GetBody(this);
    }
    counter() {
        return NativeImpl.SignalMessage_GetCounter(this);
    }
    messageVersion() {
        return NativeImpl.SignalMessage_GetMessageVersion(this);
    }
    serialize() {
        return NativeImpl.SignalMessage_GetSerialized(this);
    }
    verifyMac(senderIdentityKey, recevierIdentityKey, macKey) {
        return NativeImpl.SignalMessage_VerifyMac(this, senderIdentityKey, recevierIdentityKey, macKey);
    }
}
exports.SignalMessage = SignalMessage;
class PreKeySignalMessage {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(messageVersion, registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, signalMessage) {
        return new PreKeySignalMessage(NativeImpl.PreKeySignalMessage_New(messageVersion, registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, signalMessage));
    }
    static deserialize(buffer) {
        return new PreKeySignalMessage(NativeImpl.PreKeySignalMessage_Deserialize(buffer));
    }
    preKeyId() {
        return NativeImpl.PreKeySignalMessage_GetPreKeyId(this);
    }
    registrationId() {
        return NativeImpl.PreKeySignalMessage_GetRegistrationId(this);
    }
    signedPreKeyId() {
        return NativeImpl.PreKeySignalMessage_GetSignedPreKeyId(this);
    }
    version() {
        return NativeImpl.PreKeySignalMessage_GetVersion(this);
    }
    serialize() {
        return NativeImpl.PreKeySignalMessage_Serialize(this);
    }
}
exports.PreKeySignalMessage = PreKeySignalMessage;
class SessionRecord {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SessionRecord(nativeHandle);
    }
    static deserialize(buffer) {
        return new SessionRecord(NativeImpl.SessionRecord_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.SessionRecord_Serialize(this);
    }
    archiveCurrentState() {
        NativeImpl.SessionRecord_ArchiveCurrentState(this);
    }
    localRegistrationId() {
        return NativeImpl.SessionRecord_GetLocalRegistrationId(this);
    }
    remoteRegistrationId() {
        return NativeImpl.SessionRecord_GetRemoteRegistrationId(this);
    }
    hasCurrentState() {
        return NativeImpl.SessionRecord_HasCurrentState(this);
    }
}
exports.SessionRecord = SessionRecord;
class ServerCertificate {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new ServerCertificate(nativeHandle);
    }
    static new(keyId, serverKey, trustRoot) {
        return new ServerCertificate(NativeImpl.ServerCertificate_New(keyId, serverKey, trustRoot));
    }
    static deserialize(buffer) {
        return new ServerCertificate(NativeImpl.ServerCertificate_Deserialize(buffer));
    }
    certificateData() {
        return NativeImpl.ServerCertificate_GetCertificate(this);
    }
    key() {
        return PublicKey._fromNativeHandle(NativeImpl.ServerCertificate_GetKey(this));
    }
    keyId() {
        return NativeImpl.ServerCertificate_GetKeyId(this);
    }
    serialize() {
        return NativeImpl.ServerCertificate_GetSerialized(this);
    }
    signature() {
        return NativeImpl.ServerCertificate_GetSignature(this);
    }
}
exports.ServerCertificate = ServerCertificate;
class SenderKeyRecord {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SenderKeyRecord(nativeHandle);
    }
    static new() {
        return new SenderKeyRecord(NativeImpl.SenderKeyRecord_New());
    }
    static deserialize(buffer) {
        return new SenderKeyRecord(NativeImpl.SenderKeyRecord_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.SenderKeyRecord_Serialize(this);
    }
}
exports.SenderKeyRecord = SenderKeyRecord;
class SenderCertificate {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SenderCertificate(nativeHandle);
    }
    static new(senderUuid, senderE164, senderDeviceId, senderKey, expiration, signerCert, signerKey) {
        return new SenderCertificate(NativeImpl.SenderCertificate_New(senderUuid, senderE164, senderDeviceId, senderKey, expiration, signerCert, signerKey));
    }
    static deserialize(buffer) {
        return new SenderCertificate(NativeImpl.SenderCertificate_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.SenderCertificate_GetSerialized(this);
    }
    certificate() {
        return NativeImpl.SenderCertificate_GetCertificate(this);
    }
    expiration() {
        return NativeImpl.SenderCertificate_GetExpiration(this);
    }
    key() {
        return PublicKey._fromNativeHandle(NativeImpl.SenderCertificate_GetKey(this));
    }
    senderE164() {
        return NativeImpl.SenderCertificate_GetSenderE164(this);
    }
    senderUuid() {
        return NativeImpl.SenderCertificate_GetSenderUuid(this);
    }
    senderDeviceId() {
        return NativeImpl.SenderCertificate_GetDeviceId(this);
    }
    serverCertificate() {
        return ServerCertificate._fromNativeHandle(NativeImpl.SenderCertificate_GetServerCertificate(this));
    }
    signature() {
        return NativeImpl.SenderCertificate_GetSignature(this);
    }
    validate(trustRoot, time) {
        return NativeImpl.SenderCertificate_Validate(this, trustRoot, time);
    }
}
exports.SenderCertificate = SenderCertificate;
class SenderKeyDistributionMessage {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static create(sender, distributionId, store) {
        return __awaiter(this, void 0, void 0, function* () {
            const handle = yield NativeImpl.SenderKeyDistributionMessage_Create(sender, Buffer.from(uuid.parse(distributionId)), store, null);
            return new SenderKeyDistributionMessage(handle);
        });
    }
    static new(distributionId, chainId, iteration, chainKey, pk) {
        return new SenderKeyDistributionMessage(NativeImpl.SenderKeyDistributionMessage_New(Buffer.from(uuid.parse(distributionId)), chainId, iteration, chainKey, pk));
    }
    static deserialize(buffer) {
        return new SenderKeyDistributionMessage(NativeImpl.SenderKeyDistributionMessage_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.SenderKeyDistributionMessage_Serialize(this);
    }
    chainKey() {
        return NativeImpl.SenderKeyDistributionMessage_GetChainKey(this);
    }
    iteration() {
        return NativeImpl.SenderKeyDistributionMessage_GetIteration(this);
    }
    chainId() {
        return NativeImpl.SenderKeyDistributionMessage_GetChainId(this);
    }
    distributionId() {
        return uuid.stringify(NativeImpl.SenderKeyDistributionMessage_GetDistributionId(this));
    }
}
exports.SenderKeyDistributionMessage = SenderKeyDistributionMessage;
function processSenderKeyDistributionMessage(sender, message, store) {
    return __awaiter(this, void 0, void 0, function* () {
        yield NativeImpl.SenderKeyDistributionMessage_Process(sender, message, store, null);
    });
}
exports.processSenderKeyDistributionMessage = processSenderKeyDistributionMessage;
class SenderKeyMessage {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static new(distributionId, chainId, iteration, ciphertext, pk) {
        return new SenderKeyMessage(NativeImpl.SenderKeyMessage_New(Buffer.from(uuid.parse(distributionId)), chainId, iteration, ciphertext, pk));
    }
    static deserialize(buffer) {
        return new SenderKeyMessage(NativeImpl.SenderKeyMessage_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.SenderKeyMessage_Serialize(this);
    }
    ciphertext() {
        return NativeImpl.SenderKeyMessage_GetCipherText(this);
    }
    iteration() {
        return NativeImpl.SenderKeyMessage_GetIteration(this);
    }
    chainId() {
        return NativeImpl.SenderKeyMessage_GetChainId(this);
    }
    distributionId() {
        return uuid.stringify(NativeImpl.SenderKeyMessage_GetDistributionId(this));
    }
    verifySignature(key) {
        return NativeImpl.SenderKeyMessage_VerifySignature(this, key);
    }
}
exports.SenderKeyMessage = SenderKeyMessage;
class UnidentifiedSenderMessageContent {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new UnidentifiedSenderMessageContent(nativeHandle);
    }
    static new(message, sender, contentHint, groupId) {
        return new UnidentifiedSenderMessageContent(NativeImpl.UnidentifiedSenderMessageContent_New(message, sender, contentHint, groupId));
    }
    static deserialize(buffer) {
        return new UnidentifiedSenderMessageContent(NativeImpl.UnidentifiedSenderMessageContent_Deserialize(buffer));
    }
    serialize() {
        return NativeImpl.UnidentifiedSenderMessageContent_Serialize(this);
    }
    contents() {
        return NativeImpl.UnidentifiedSenderMessageContent_GetContents(this);
    }
    msgType() {
        return NativeImpl.UnidentifiedSenderMessageContent_GetMsgType(this);
    }
    senderCertificate() {
        return SenderCertificate._fromNativeHandle(NativeImpl.UnidentifiedSenderMessageContent_GetSenderCert(this));
    }
    contentHint() {
        return NativeImpl.UnidentifiedSenderMessageContent_GetContentHint(this);
    }
    groupId() {
        return NativeImpl.UnidentifiedSenderMessageContent_GetGroupId(this);
    }
}
exports.UnidentifiedSenderMessageContent = UnidentifiedSenderMessageContent;
class SessionStore {
    _saveSession(name, record) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.saveSession(ProtocolAddress._fromNativeHandle(name), SessionRecord._fromNativeHandle(record));
        });
    }
    _getSession(name) {
        return __awaiter(this, void 0, void 0, function* () {
            const sess = yield this.getSession(ProtocolAddress._fromNativeHandle(name));
            if (sess == null) {
                return null;
            }
            else {
                return sess._nativeHandle;
            }
        });
    }
}
exports.SessionStore = SessionStore;
class IdentityKeyStore {
    _getIdentityKey() {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield this.getIdentityKey();
            return key._nativeHandle;
        });
    }
    _getLocalRegistrationId() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.getLocalRegistrationId();
        });
    }
    _saveIdentity(name, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.saveIdentity(ProtocolAddress._fromNativeHandle(name), PublicKey._fromNativeHandle(key));
        });
    }
    _isTrustedIdentity(name, key, sending) {
        return __awaiter(this, void 0, void 0, function* () {
            const direction = sending ? 0 /* Sending */ : 1 /* Receiving */;
            return this.isTrustedIdentity(ProtocolAddress._fromNativeHandle(name), PublicKey._fromNativeHandle(key), direction);
        });
    }
    _getIdentity(name) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield this.getIdentity(ProtocolAddress._fromNativeHandle(name));
            if (key == null) {
                return Promise.resolve(null);
            }
            else {
                return key._nativeHandle;
            }
        });
    }
}
exports.IdentityKeyStore = IdentityKeyStore;
class PreKeyStore {
    _savePreKey(id, record) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.savePreKey(id, PreKeyRecord._fromNativeHandle(record));
        });
    }
    _getPreKey(id) {
        return __awaiter(this, void 0, void 0, function* () {
            const pk = yield this.getPreKey(id);
            return pk._nativeHandle;
        });
    }
    _removePreKey(id) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.removePreKey(id);
        });
    }
}
exports.PreKeyStore = PreKeyStore;
class SignedPreKeyStore {
    _saveSignedPreKey(id, record) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.saveSignedPreKey(id, SignedPreKeyRecord._fromNativeHandle(record));
        });
    }
    _getSignedPreKey(id) {
        return __awaiter(this, void 0, void 0, function* () {
            const pk = yield this.getSignedPreKey(id);
            return pk._nativeHandle;
        });
    }
}
exports.SignedPreKeyStore = SignedPreKeyStore;
class SenderKeyStore {
    _saveSenderKey(sender, distributionId, record) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.saveSenderKey(ProtocolAddress._fromNativeHandle(sender), uuid.stringify(distributionId), SenderKeyRecord._fromNativeHandle(record));
        });
    }
    _getSenderKey(sender, distributionId) {
        return __awaiter(this, void 0, void 0, function* () {
            const skr = yield this.getSenderKey(ProtocolAddress._fromNativeHandle(sender), uuid.stringify(distributionId));
            if (skr == null) {
                return null;
            }
            else {
                return skr._nativeHandle;
            }
        });
    }
}
exports.SenderKeyStore = SenderKeyStore;
function groupEncrypt(sender, distributionId, store, message) {
    return __awaiter(this, void 0, void 0, function* () {
        return CiphertextMessage._fromNativeHandle(yield NativeImpl.GroupCipher_EncryptMessage(sender, Buffer.from(uuid.parse(distributionId)), message, store, null));
    });
}
exports.groupEncrypt = groupEncrypt;
function groupDecrypt(sender, store, message) {
    return __awaiter(this, void 0, void 0, function* () {
        return NativeImpl.GroupCipher_DecryptMessage(sender, message, store, null);
    });
}
exports.groupDecrypt = groupDecrypt;
class SealedSenderDecryptionResult {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SealedSenderDecryptionResult(nativeHandle);
    }
    message() {
        return NativeImpl.SealedSenderDecryptionResult_Message(this);
    }
    senderE164() {
        return NativeImpl.SealedSenderDecryptionResult_GetSenderE164(this);
    }
    senderUuid() {
        return NativeImpl.SealedSenderDecryptionResult_GetSenderUuid(this);
    }
    deviceId() {
        return NativeImpl.SealedSenderDecryptionResult_GetDeviceId(this);
    }
}
exports.SealedSenderDecryptionResult = SealedSenderDecryptionResult;
class CiphertextMessage {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new CiphertextMessage(nativeHandle);
    }
    serialize() {
        return NativeImpl.CiphertextMessage_Serialize(this);
    }
    type() {
        return NativeImpl.CiphertextMessage_Type(this);
    }
}
exports.CiphertextMessage = CiphertextMessage;
function processPreKeyBundle(bundle, address, sessionStore, identityStore) {
    return NativeImpl.SessionBuilder_ProcessPreKeyBundle(bundle, address, sessionStore, identityStore, null);
}
exports.processPreKeyBundle = processPreKeyBundle;
function signalEncrypt(message, address, sessionStore, identityStore) {
    return __awaiter(this, void 0, void 0, function* () {
        return CiphertextMessage._fromNativeHandle(yield NativeImpl.SessionCipher_EncryptMessage(message, address, sessionStore, identityStore, null));
    });
}
exports.signalEncrypt = signalEncrypt;
function signalDecrypt(message, address, sessionStore, identityStore) {
    return NativeImpl.SessionCipher_DecryptSignalMessage(message, address, sessionStore, identityStore, null);
}
exports.signalDecrypt = signalDecrypt;
function signalDecryptPreKey(message, address, sessionStore, identityStore, prekeyStore, signedPrekeyStore) {
    return NativeImpl.SessionCipher_DecryptPreKeySignalMessage(message, address, sessionStore, identityStore, prekeyStore, signedPrekeyStore, null);
}
exports.signalDecryptPreKey = signalDecryptPreKey;
function sealedSenderEncryptMessage(message, address, senderCert, sessionStore, identityStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const ciphertext = yield signalEncrypt(message, address, sessionStore, identityStore);
        const usmc = UnidentifiedSenderMessageContent.new(ciphertext, senderCert, 0 /* Default */, null);
        return yield sealedSenderEncrypt(usmc, address, identityStore);
    });
}
exports.sealedSenderEncryptMessage = sealedSenderEncryptMessage;
function sealedSenderEncrypt(content, address, identityStore) {
    return NativeImpl.SealedSender_Encrypt(address, content, identityStore, null);
}
exports.sealedSenderEncrypt = sealedSenderEncrypt;
function sealedSenderMultiRecipientEncrypt(content, recipients, identityStore) {
    return NativeImpl.SealedSender_MultiRecipientEncrypt(recipients, content, identityStore, null);
}
exports.sealedSenderMultiRecipientEncrypt = sealedSenderMultiRecipientEncrypt;
// For testing only
function sealedSenderMultiRecipientMessageForSingleRecipient(message) {
    return NativeImpl.SealedSender_MultiRecipientMessageForSingleRecipient(message);
}
exports.sealedSenderMultiRecipientMessageForSingleRecipient = sealedSenderMultiRecipientMessageForSingleRecipient;
function sealedSenderDecryptMessage(message, trustRoot, timestamp, localE164, localUuid, localDeviceId, sessionStore, identityStore, prekeyStore, signedPrekeyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const ssdr = yield NativeImpl.SealedSender_DecryptMessage(message, trustRoot, timestamp, localE164, localUuid, localDeviceId, sessionStore, identityStore, prekeyStore, signedPrekeyStore);
        if (ssdr == null) {
            return null;
        }
        return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
    });
}
exports.sealedSenderDecryptMessage = sealedSenderDecryptMessage;
function sealedSenderDecryptToUsmc(message, identityStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const usmc = yield NativeImpl.SealedSender_DecryptToUsmc(message, identityStore, null);
        return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
    });
}
exports.sealedSenderDecryptToUsmc = sealedSenderDecryptToUsmc;
//# sourceMappingURL=index.js.map