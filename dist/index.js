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
const bindings = require("bindings"); // eslint-disable-line @typescript-eslint/no-require-imports
const SC = bindings('libsignal_client_' + os.platform() + '_' + process.arch);
exports.initLogger = SC.initLogger, exports.LogLevel = SC.LogLevel;
class HKDF {
    constructor(version) {
        this.version = version;
    }
    static new(version) {
        return new HKDF(version);
    }
    deriveSecrets(outputLength, keyMaterial, label, salt) {
        return SC.HKDF_DeriveSecrets(outputLength, this.version, keyMaterial, label, salt);
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
        return SC.ScannableFingerprint_Compare(this.scannable, other.scannable);
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
        return new Fingerprint(SC.Fingerprint_New(iterations, version, localIdentifier, localKey, remoteIdentifier, remoteKey));
    }
    displayableFingerprint() {
        return DisplayableFingerprint._fromString(SC.Fingerprint_DisplayString(this));
    }
    scannableFingerprint() {
        return ScannableFingerprint._fromBuffer(SC.Fingerprint_ScannableEncoding(this));
    }
}
exports.Fingerprint = Fingerprint;
class Aes256GcmSiv {
    constructor(key) {
        this._nativeHandle = SC.Aes256GcmSiv_New(key);
    }
    static new(key) {
        return new Aes256GcmSiv(key);
    }
    encrypt(message, nonce, associated_data) {
        return SC.Aes256GcmSiv_Encrypt(this, message, nonce, associated_data);
    }
    decrypt(message, nonce, associated_data) {
        return SC.Aes256GcmSiv_Decrypt(this, message, nonce, associated_data);
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
        return new ProtocolAddress(SC.ProtocolAddress_New(name, deviceId));
    }
    name() {
        return SC.ProtocolAddress_Name(this);
    }
    deviceId() {
        return SC.ProtocolAddress_DeviceId(this);
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
        return new PublicKey(SC.PublicKey_Deserialize(buf));
    }
    /// Returns -1, 0, or 1
    compare(other) {
        return SC.PublicKey_Compare(this, other);
    }
    serialize() {
        return SC.PublicKey_Serialize(this);
    }
    getPublicKeyBytes() {
        return SC.PublicKey_GetPublicKeyBytes(this);
    }
    verify(msg, sig) {
        return SC.PublicKey_Verify(this, msg, sig);
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
        return new PrivateKey(SC.PrivateKey_Generate());
    }
    static deserialize(buf) {
        return new PrivateKey(SC.PrivateKey_Deserialize(buf));
    }
    serialize() {
        return SC.PrivateKey_Serialize(this);
    }
    sign(msg) {
        return SC.PrivateKey_Sign(this, msg);
    }
    agree(other_key) {
        return SC.PrivateKey_Agree(this, other_key);
    }
    getPublicKey() {
        return PublicKey._fromNativeHandle(SC.PrivateKey_GetPublicKey(this));
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
        return SC.IdentityKeyPair_Serialize(this.publicKey, this.privateKey);
    }
}
exports.IdentityKeyPair = IdentityKeyPair;
class PreKeyBundle {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(registration_id, device_id, prekey_id, prekey, signed_prekey_id, signed_prekey, signed_prekey_signature, identity_key) {
        return new PreKeyBundle(SC.PreKeyBundle_New(registration_id, device_id, prekey_id, prekey != null ? prekey : null, 
        //prekey?,
        signed_prekey_id, signed_prekey, signed_prekey_signature, identity_key));
    }
    deviceId() {
        return SC.PreKeyBundle_GetDeviceId(this);
    }
    identityKey() {
        return PublicKey._fromNativeHandle(SC.PreKeyBundle_GetIdentityKey(this));
    }
    preKeyId() {
        return SC.PreKeyBundle_GetPreKeyId(this);
    }
    preKeyPublic() {
        const handle = SC.PreKeyBundle_GetPreKeyPublic(this);
        if (handle == null) {
            return null;
        }
        else {
            return PublicKey._fromNativeHandle(handle);
        }
    }
    registrationId() {
        return SC.PreKeyBundle_GetRegistrationId(this);
    }
    signedPreKeyId() {
        return SC.PreKeyBundle_GetSignedPreKeyId(this);
    }
    signedPreKeyPublic() {
        return PublicKey._fromNativeHandle(SC.PreKeyBundle_GetSignedPreKeyPublic(this));
    }
    signedPreKeySignature() {
        return SC.PreKeyBundle_GetSignedPreKeySignature(this);
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
        return new PreKeyRecord(SC.PreKeyRecord_New(id, pubKey, privKey));
    }
    static deserialize(buffer) {
        return new PreKeyRecord(SC.PreKeyRecord_Deserialize(buffer));
    }
    id() {
        return SC.PreKeyRecord_GetId(this);
    }
    privateKey() {
        return PrivateKey._fromNativeHandle(SC.PreKeyRecord_GetPrivateKey(this));
    }
    publicKey() {
        return PublicKey._fromNativeHandle(SC.PreKeyRecord_GetPublicKey(this));
    }
    serialize() {
        return SC.PreKeyRecord_Serialize(this);
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
        return new SignedPreKeyRecord(SC.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature));
    }
    static deserialize(buffer) {
        return new SignedPreKeyRecord(SC.SignedPreKeyRecord_Deserialize(buffer));
    }
    id() {
        return SC.SignedPreKeyRecord_GetId(this);
    }
    privateKey() {
        return PrivateKey._fromNativeHandle(SC.SignedPreKeyRecord_GetPrivateKey(this));
    }
    publicKey() {
        return PublicKey._fromNativeHandle(SC.SignedPreKeyRecord_GetPublicKey(this));
    }
    serialize() {
        return SC.SignedPreKeyRecord_Serialize(this);
    }
    signature() {
        return SC.SignedPreKeyRecord_GetSignature(this);
    }
    timestamp() {
        return SC.SignedPreKeyRecord_GetTimestamp(this);
    }
}
exports.SignedPreKeyRecord = SignedPreKeyRecord;
class SignalMessage {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(messageVersion, macKey, senderRatchetKey, counter, previousCounter, ciphertext, senderIdentityKey, receiverIdentityKey) {
        return new SignalMessage(SC.SignalMessage_New(messageVersion, macKey, senderRatchetKey, counter, previousCounter, ciphertext, senderIdentityKey, receiverIdentityKey));
    }
    static deserialize(buffer) {
        return new SignalMessage(SC.SignalMessage_Deserialize(buffer));
    }
    body() {
        return SC.SignalMessage_GetBody(this);
    }
    counter() {
        return SC.SignalMessage_GetCounter(this);
    }
    messageVersion() {
        return SC.SignalMessage_GetMessageVersion(this);
    }
    serialize() {
        return SC.SignalMessage_GetSerialized(this);
    }
    verifyMac(senderIdentityKey, recevierIdentityKey, macKey) {
        return SC.SignalMessage_VerifyMac(this, senderIdentityKey, recevierIdentityKey, macKey);
    }
}
exports.SignalMessage = SignalMessage;
class PreKeySignalMessage {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static new(messageVersion, registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, signalMessage) {
        return new PreKeySignalMessage(SC.PreKeySignalMessage_New(messageVersion, registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, signalMessage));
    }
    static deserialize(buffer) {
        return new PreKeySignalMessage(SC.PreKeySignalMessage_Deserialize(buffer));
    }
    preKeyId() {
        return SC.PreKeySignalMessage_GetPreKeyId(this);
    }
    registrationId() {
        return SC.PreKeySignalMessage_GetRegistrationId(this);
    }
    signedPreKeyId() {
        return SC.PreKeySignalMessage_GetSignedPreKeyId(this);
    }
    version() {
        return SC.PreKeySignalMessage_GetVersion(this);
    }
    serialize() {
        return SC.PreKeySignalMessage_Serialize(this);
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
        return new SessionRecord(SC.SessionRecord_Deserialize(buffer));
    }
    serialize() {
        return SC.SessionRecord_Serialize(this);
    }
    archiveCurrentState() {
        SC.SessionRecord_ArchiveCurrentState(this);
    }
    localRegistrationId() {
        return SC.SessionRecord_GetLocalRegistrationId(this);
    }
    remoteRegistrationId() {
        return SC.SessionRecord_GetRemoteRegistrationId(this);
    }
}
exports.SessionRecord = SessionRecord;
class SenderKeyName {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new SenderKeyName(nativeHandle);
    }
    static new(groupId, senderName, senderDeviceId) {
        return new SenderKeyName(SC.SenderKeyName_New(groupId, senderName, senderDeviceId));
    }
    groupId() {
        return SC.SenderKeyName_GetGroupId(this);
    }
    senderName() {
        return SC.SenderKeyName_GetSenderName(this);
    }
    senderDeviceId() {
        return SC.SenderKeyName_GetSenderDeviceId(this);
    }
}
exports.SenderKeyName = SenderKeyName;
class ServerCertificate {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static _fromNativeHandle(nativeHandle) {
        return new ServerCertificate(nativeHandle);
    }
    static new(keyId, serverKey, trustRoot) {
        return new ServerCertificate(SC.ServerCertificate_New(keyId, serverKey, trustRoot));
    }
    static deserialize(buffer) {
        return new ServerCertificate(SC.ServerCertificate_Deserialize(buffer));
    }
    certificateData() {
        return SC.ServerCertificate_GetCertificate(this);
    }
    key() {
        return PublicKey._fromNativeHandle(SC.ServerCertificate_GetKey(this));
    }
    keyId() {
        return SC.ServerCertificate_GetKeyId(this);
    }
    serialize() {
        return SC.ServerCertificate_GetSerialized(this);
    }
    signature() {
        return SC.ServerCertificate_GetSignature(this);
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
        return new SenderKeyRecord(SC.SenderKeyRecord_New());
    }
    static deserialize(buffer) {
        return new SenderKeyRecord(SC.SenderKeyRecord_Deserialize(buffer));
    }
    serialize() {
        return SC.SenderKeyRecord_Serialize(this);
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
        return new SenderCertificate(SC.SenderCertificate_New(senderUuid, senderE164, senderDeviceId, senderKey, expiration, signerCert, signerKey));
    }
    static deserialize(buffer) {
        return new SenderCertificate(SC.SenderCertificate_Deserialize(buffer));
    }
    serialize() {
        return SC.SenderCertificate_GetSerialized(this);
    }
    certificate() {
        return SC.SenderCertificate_GetCertificate(this);
    }
    expiration() {
        return SC.SenderCertificate_GetExpiration(this);
    }
    key() {
        return PublicKey._fromNativeHandle(SC.SenderCertificate_GetKey(this));
    }
    senderE164() {
        return SC.SenderCertificate_GetSenderE164(this);
    }
    senderUuid() {
        return SC.SenderCertificate_GetSenderUuid(this);
    }
    senderDeviceId() {
        return SC.SenderCertificate_GetDeviceId(this);
    }
    serverCertificate() {
        return ServerCertificate._fromNativeHandle(SC.SenderCertificate_GetServerCertificate(this));
    }
    signature() {
        return SC.SenderCertificate_GetSignature(this);
    }
    validate(trustRoot, time) {
        return SC.SenderCertificate_Validate(this, trustRoot, time);
    }
}
exports.SenderCertificate = SenderCertificate;
class SenderKeyDistributionMessage {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static create(name, store) {
        return __awaiter(this, void 0, void 0, function* () {
            const handle = yield SC.SenderKeyDistributionMessage_Create(name, store);
            return new SenderKeyDistributionMessage(handle);
        });
    }
    static new(keyId, iteration, chainKey, pk) {
        return new SenderKeyDistributionMessage(SC.SenderKeyDistributionMessage_New(keyId, iteration, chainKey, pk));
    }
    static deserialize(buffer) {
        return new SenderKeyDistributionMessage(SC.SenderKeyDistributionMessage_Deserialize(buffer));
    }
    serialize() {
        return SC.SenderKeyDistributionMessage_Serialize(this);
    }
    chainKey() {
        return SC.SenderKeyDistributionMessage_GetChainKey(this);
    }
    iteration() {
        return SC.SenderKeyDistributionMessage_GetIteration(this);
    }
    id() {
        return SC.SenderKeyDistributionMessage_GetId(this);
    }
}
exports.SenderKeyDistributionMessage = SenderKeyDistributionMessage;
function processSenderKeyDistributionMessage(name, message, store) {
    return __awaiter(this, void 0, void 0, function* () {
        yield SC.SenderKeyDistributionMessage_Process(name, message, store);
    });
}
exports.processSenderKeyDistributionMessage = processSenderKeyDistributionMessage;
class SenderKeyMessage {
    constructor(nativeHandle) {
        this._nativeHandle = nativeHandle;
    }
    static new(keyId, iteration, ciphertext, pk) {
        return new SenderKeyMessage(SC.SenderKeyMessage_New(keyId, iteration, ciphertext, pk));
    }
    static deserialize(buffer) {
        return new SenderKeyMessage(SC.SenderKeyMessage_Deserialize(buffer));
    }
    serialize() {
        return SC.SenderKeyMessage_Serialize(this);
    }
    ciphertext() {
        return SC.SenderKeyMessage_GetCipherText(this);
    }
    iteration() {
        return SC.SenderKeyMessage_GetIteration(this);
    }
    keyId() {
        return SC.SenderKeyMessage_GetKeyId(this);
    }
    verifySignature(key) {
        return SC.SenderKeyMessage_VerifySignature(this, key);
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
    static deserialize(buffer) {
        return new UnidentifiedSenderMessageContent(SC.UnidentifiedSenderMessageContent_Deserialize(buffer));
    }
    serialize() {
        return SC.UnidentifiedSenderMessageContent_Serialize(this);
    }
    contents() {
        return SC.UnidentifiedSenderMessageContent_GetContents(this);
    }
    msgType() {
        return SC.UnidentifiedSenderMessageContent_GetMsgType(this);
    }
    senderCertificate() {
        return SenderCertificate._fromNativeHandle(SC.UnidentifiedSenderMessageContent_GetSenderCert(this));
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
    _saveSenderKey(name, record) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.saveSenderKey(SenderKeyName._fromNativeHandle(name), SenderKeyRecord._fromNativeHandle(record));
        });
    }
    _getSenderKey(name) {
        return __awaiter(this, void 0, void 0, function* () {
            const skr = yield this.getSenderKey(SenderKeyName._fromNativeHandle(name));
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
function groupEncrypt(name, store, message) {
    return __awaiter(this, void 0, void 0, function* () {
        return SC.GroupCipher_Encrypt(name, store, message);
    });
}
exports.groupEncrypt = groupEncrypt;
function groupDecrypt(name, store, message) {
    return __awaiter(this, void 0, void 0, function* () {
        return SC.GroupCipher_Decrypt(name, store, message);
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
        return SC.SealedSenderDecryptionResult_Message(this);
    }
    senderE164() {
        return SC.SealedSenderDecryptionResult_GetSenderE164(this);
    }
    senderUuid() {
        return SC.SealedSenderDecryptionResult_GetSenderUuid(this);
    }
    deviceId() {
        return SC.SealedSenderDecryptionResult_GetDeviceId(this);
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
        return SC.CiphertextMessage_Serialize(this);
    }
    type() {
        return SC.CiphertextMessage_Type(this);
    }
}
exports.CiphertextMessage = CiphertextMessage;
function processPreKeyBundle(bundle, address, sessionStore, identityStore) {
    return SC.SessionBuilder_ProcessPreKeyBundle(bundle, address, sessionStore, identityStore);
}
exports.processPreKeyBundle = processPreKeyBundle;
function signalEncrypt(message, address, sessionStore, identityStore) {
    return __awaiter(this, void 0, void 0, function* () {
        return CiphertextMessage._fromNativeHandle(yield SC.SessionCipher_EncryptMessage(message, address, sessionStore, identityStore));
    });
}
exports.signalEncrypt = signalEncrypt;
function signalDecrypt(message, address, sessionStore, identityStore) {
    return SC.SessionCipher_DecryptSignalMessage(message, address, sessionStore, identityStore);
}
exports.signalDecrypt = signalDecrypt;
function signalDecryptPreKey(message, address, sessionStore, identityStore, prekeyStore, signedPrekeyStore) {
    return SC.SessionCipher_DecryptPreKeySignalMessage(message, address, sessionStore, identityStore, prekeyStore, signedPrekeyStore);
}
exports.signalDecryptPreKey = signalDecryptPreKey;
function sealedSenderEncryptMessage(message, address, senderCert, sessionStore, identityStore) {
    return SC.SealedSender_EncryptMessage(message, address, senderCert, sessionStore, identityStore);
}
exports.sealedSenderEncryptMessage = sealedSenderEncryptMessage;
function sealedSenderDecryptMessage(message, trustRoot, timestamp, localE164, localUuid, localDeviceId, sessionStore, identityStore, prekeyStore, signedPrekeyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const ssdr = yield SC.SealedSender_DecryptMessage(message, trustRoot, timestamp, localE164, localUuid, localDeviceId, sessionStore, identityStore, prekeyStore, signedPrekeyStore);
        return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
    });
}
exports.sealedSenderDecryptMessage = sealedSenderDecryptMessage;
function sealedSenderDecryptToUsmc(message, identityStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const usmc = yield SC.SealedSender_DecryptToUsmc(message, identityStore);
        return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
    });
}
exports.sealedSenderDecryptToUsmc = sealedSenderDecryptToUsmc;
//# sourceMappingURL=index.js.map