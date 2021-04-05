/// <reference types="node" />
import * as Native from './Native';
export declare const initLogger: typeof Native.initLogger, LogLevel: typeof Native.LogLevel;
export declare const enum CiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 4,
    SenderKeyDistribution = 5
}
export declare const enum Direction {
    Sending = 0,
    Receiving = 1
}
export declare type Uuid = string;
export declare class HKDF {
    private readonly version;
    private constructor();
    static new(version: number): HKDF;
    deriveSecrets(outputLength: number, keyMaterial: Buffer, label: Buffer, salt: Buffer | null): Buffer;
}
export declare class ScannableFingerprint {
    private readonly scannable;
    private constructor();
    static _fromBuffer(scannable: Buffer): ScannableFingerprint;
    compare(other: ScannableFingerprint): boolean;
    toBuffer(): Buffer;
}
export declare class DisplayableFingerprint {
    private readonly display;
    private constructor();
    static _fromString(display: string): DisplayableFingerprint;
    toString(): string;
}
export declare class Fingerprint {
    readonly _nativeHandle: Native.Fingerprint;
    private constructor();
    static new(iterations: number, version: number, localIdentifier: Buffer, localKey: PublicKey, remoteIdentifier: Buffer, remoteKey: PublicKey): Fingerprint;
    displayableFingerprint(): DisplayableFingerprint;
    scannableFingerprint(): ScannableFingerprint;
}
export declare class Aes256GcmSiv {
    readonly _nativeHandle: Native.Aes256GcmSiv;
    private constructor();
    static new(key: Buffer): Aes256GcmSiv;
    encrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
    decrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
}
export declare class ProtocolAddress {
    readonly _nativeHandle: Native.ProtocolAddress;
    private constructor();
    static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress;
    static new(name: string, deviceId: number): ProtocolAddress;
    name(): string;
    deviceId(): number;
}
export declare class PublicKey {
    readonly _nativeHandle: Native.PublicKey;
    private constructor();
    static _fromNativeHandle(handle: Native.PublicKey): PublicKey;
    static deserialize(buf: Buffer): PublicKey;
    compare(other: PublicKey): number;
    serialize(): Buffer;
    getPublicKeyBytes(): Buffer;
    verify(msg: Buffer, sig: Buffer): boolean;
}
export declare class PrivateKey {
    readonly _nativeHandle: Native.PrivateKey;
    private constructor();
    static _fromNativeHandle(handle: Native.PrivateKey): PrivateKey;
    static generate(): PrivateKey;
    static deserialize(buf: Buffer): PrivateKey;
    serialize(): Buffer;
    sign(msg: Buffer): Buffer;
    agree(other_key: PublicKey): Buffer;
    getPublicKey(): PublicKey;
}
export declare class IdentityKeyPair {
    private readonly publicKey;
    private readonly privateKey;
    constructor(publicKey: PublicKey, privateKey: PrivateKey);
    static new(publicKey: PublicKey, privateKey: PrivateKey): IdentityKeyPair;
    serialize(): Buffer;
}
export declare class PreKeyBundle {
    readonly _nativeHandle: Native.PreKeyBundle;
    private constructor();
    static new(registration_id: number, device_id: number, prekey_id: number | null, prekey: PublicKey | null, signed_prekey_id: number, signed_prekey: PublicKey, signed_prekey_signature: Buffer, identity_key: PublicKey): PreKeyBundle;
    deviceId(): number;
    identityKey(): PublicKey;
    preKeyId(): number | null;
    preKeyPublic(): PublicKey | null;
    registrationId(): number;
    signedPreKeyId(): number;
    signedPreKeyPublic(): PublicKey;
    signedPreKeySignature(): Buffer;
}
export declare class PreKeyRecord {
    readonly _nativeHandle: Native.PreKeyRecord;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.PreKeyRecord): PreKeyRecord;
    static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord;
    static deserialize(buffer: Buffer): PreKeyRecord;
    id(): number;
    privateKey(): PrivateKey;
    publicKey(): PublicKey;
    serialize(): Buffer;
}
export declare class SignedPreKeyRecord {
    readonly _nativeHandle: Native.SignedPreKeyRecord;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.SignedPreKeyRecord): SignedPreKeyRecord;
    static new(id: number, timestamp: number, pubKey: PublicKey, privKey: PrivateKey, signature: Buffer): SignedPreKeyRecord;
    static deserialize(buffer: Buffer): SignedPreKeyRecord;
    id(): number;
    privateKey(): PrivateKey;
    publicKey(): PublicKey;
    serialize(): Buffer;
    signature(): Buffer;
    timestamp(): number;
}
export declare class SignalMessage {
    readonly _nativeHandle: Native.SignalMessage;
    private constructor();
    static new(messageVersion: number, macKey: Buffer, senderRatchetKey: PublicKey, counter: number, previousCounter: number, ciphertext: Buffer, senderIdentityKey: PublicKey, receiverIdentityKey: PublicKey): SignalMessage;
    static deserialize(buffer: Buffer): SignalMessage;
    body(): Buffer;
    counter(): number;
    messageVersion(): number;
    serialize(): Buffer;
    verifyMac(senderIdentityKey: PublicKey, recevierIdentityKey: PublicKey, macKey: Buffer): boolean;
}
export declare class PreKeySignalMessage {
    readonly _nativeHandle: Native.PreKeySignalMessage;
    private constructor();
    static new(messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: PublicKey, identityKey: PublicKey, signalMessage: SignalMessage): PreKeySignalMessage;
    static deserialize(buffer: Buffer): PreKeySignalMessage;
    preKeyId(): number | null;
    registrationId(): number;
    signedPreKeyId(): number;
    version(): number;
    serialize(): Buffer;
}
export declare class SessionRecord {
    readonly _nativeHandle: Native.SessionRecord;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.SessionRecord): SessionRecord;
    static deserialize(buffer: Buffer): SessionRecord;
    serialize(): Buffer;
    archiveCurrentState(): void;
    localRegistrationId(): number;
    remoteRegistrationId(): number;
    hasCurrentState(): boolean;
}
export declare class ServerCertificate {
    readonly _nativeHandle: Native.ServerCertificate;
    static _fromNativeHandle(nativeHandle: Native.ServerCertificate): ServerCertificate;
    private constructor();
    static new(keyId: number, serverKey: PublicKey, trustRoot: PrivateKey): ServerCertificate;
    static deserialize(buffer: Buffer): ServerCertificate;
    certificateData(): Buffer;
    key(): PublicKey;
    keyId(): number;
    serialize(): Buffer;
    signature(): Buffer;
}
export declare class SenderKeyRecord {
    readonly _nativeHandle: Native.SenderKeyRecord;
    static _fromNativeHandle(nativeHandle: Native.SenderKeyRecord): SenderKeyRecord;
    private constructor();
    static new(): SenderKeyRecord;
    static deserialize(buffer: Buffer): SenderKeyRecord;
    serialize(): Buffer;
}
export declare class SenderCertificate {
    readonly _nativeHandle: Native.SenderCertificate;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.SenderCertificate): SenderCertificate;
    static new(senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: PublicKey, expiration: number, signerCert: ServerCertificate, signerKey: PrivateKey): SenderCertificate;
    static deserialize(buffer: Buffer): SenderCertificate;
    serialize(): Buffer;
    certificate(): Buffer;
    expiration(): number;
    key(): PublicKey;
    senderE164(): string | null;
    senderUuid(): string;
    senderDeviceId(): number;
    serverCertificate(): ServerCertificate;
    signature(): Buffer;
    validate(trustRoot: PublicKey, time: number): boolean;
}
export declare class SenderKeyDistributionMessage {
    readonly _nativeHandle: Native.SenderKeyDistributionMessage;
    private constructor();
    static create(sender: ProtocolAddress, distributionId: Uuid, store: SenderKeyStore): Promise<SenderKeyDistributionMessage>;
    static new(distributionId: Uuid, chainId: number, iteration: number, chainKey: Buffer, pk: PublicKey): SenderKeyDistributionMessage;
    static deserialize(buffer: Buffer): SenderKeyDistributionMessage;
    serialize(): Buffer;
    chainKey(): Buffer;
    iteration(): number;
    chainId(): number;
    distributionId(): Uuid;
}
export declare function processSenderKeyDistributionMessage(sender: ProtocolAddress, message: SenderKeyDistributionMessage, store: SenderKeyStore): Promise<void>;
export declare class SenderKeyMessage {
    readonly _nativeHandle: Native.SenderKeyMessage;
    private constructor();
    static new(distributionId: Uuid, chainId: number, iteration: number, ciphertext: Buffer, pk: PrivateKey): SenderKeyMessage;
    static deserialize(buffer: Buffer): SenderKeyMessage;
    serialize(): Buffer;
    ciphertext(): Buffer;
    iteration(): number;
    chainId(): number;
    distributionId(): Uuid;
    verifySignature(key: PublicKey): boolean;
}
export declare class UnidentifiedSenderMessageContent {
    readonly _nativeHandle: Native.UnidentifiedSenderMessageContent;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.UnidentifiedSenderMessageContent): UnidentifiedSenderMessageContent;
    static deserialize(buffer: Buffer): UnidentifiedSenderMessageContent;
    serialize(): Buffer;
    contents(): Buffer;
    msgType(): number;
    senderCertificate(): SenderCertificate;
}
export declare abstract class SessionStore implements Native.SessionStore {
    _saveSession(name: Native.ProtocolAddress, record: Native.SessionRecord): Promise<void>;
    _getSession(name: Native.ProtocolAddress): Promise<Native.SessionRecord | null>;
    abstract saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void>;
    abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>;
}
export declare abstract class IdentityKeyStore implements Native.IdentityKeyStore {
    _getIdentityKey(): Promise<Native.PrivateKey>;
    _getLocalRegistrationId(): Promise<number>;
    _saveIdentity(name: Native.ProtocolAddress, key: Native.PublicKey): Promise<boolean>;
    _isTrustedIdentity(name: Native.ProtocolAddress, key: Native.PublicKey, sending: boolean): Promise<boolean>;
    _getIdentity(name: Native.ProtocolAddress): Promise<Native.PublicKey | null>;
    abstract getIdentityKey(): Promise<PrivateKey>;
    abstract getLocalRegistrationId(): Promise<number>;
    abstract saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<boolean>;
    abstract isTrustedIdentity(name: ProtocolAddress, key: PublicKey, direction: Direction): Promise<boolean>;
    abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}
export declare abstract class PreKeyStore implements Native.PreKeyStore {
    _savePreKey(id: number, record: Native.PreKeyRecord): Promise<void>;
    _getPreKey(id: number): Promise<Native.PreKeyRecord>;
    _removePreKey(id: number): Promise<void>;
    abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>;
    abstract getPreKey(id: number): Promise<PreKeyRecord>;
    abstract removePreKey(id: number): Promise<void>;
}
export declare abstract class SignedPreKeyStore implements Native.SignedPreKeyStore {
    _saveSignedPreKey(id: number, record: Native.SignedPreKeyRecord): Promise<void>;
    _getSignedPreKey(id: number): Promise<Native.SignedPreKeyRecord>;
    abstract saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void>;
    abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}
export declare abstract class SenderKeyStore implements Native.SenderKeyStore {
    _saveSenderKey(sender: Native.ProtocolAddress, distributionId: Native.Uuid, record: Native.SenderKeyRecord): Promise<void>;
    _getSenderKey(sender: Native.ProtocolAddress, distributionId: Native.Uuid): Promise<Native.SenderKeyRecord | null>;
    abstract saveSenderKey(sender: ProtocolAddress, distributionId: Uuid, record: SenderKeyRecord): Promise<void>;
    abstract getSenderKey(sender: ProtocolAddress, distributionId: Uuid): Promise<SenderKeyRecord | null>;
}
export declare function groupEncrypt(sender: ProtocolAddress, distributionId: Uuid, store: SenderKeyStore, message: Buffer): Promise<Buffer>;
export declare function groupDecrypt(sender: ProtocolAddress, store: SenderKeyStore, message: Buffer): Promise<Buffer>;
export declare class SealedSenderDecryptionResult {
    readonly _nativeHandle: Native.SealedSenderDecryptionResult;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.SealedSenderDecryptionResult): SealedSenderDecryptionResult;
    message(): Buffer;
    senderE164(): string | null;
    senderUuid(): string;
    deviceId(): number;
}
export declare class CiphertextMessage {
    readonly _nativeHandle: Native.CiphertextMessage;
    private constructor();
    static _fromNativeHandle(nativeHandle: Native.CiphertextMessage): CiphertextMessage;
    serialize(): Buffer;
    type(): number;
}
export declare function processPreKeyBundle(bundle: PreKeyBundle, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<void>;
export declare function signalEncrypt(message: Buffer, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<CiphertextMessage>;
export declare function signalDecrypt(message: SignalMessage, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<Buffer>;
export declare function signalDecryptPreKey(message: PreKeySignalMessage, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore): Promise<Buffer>;
export declare function sealedSenderEncryptMessage(message: Buffer, address: ProtocolAddress, senderCert: SenderCertificate, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<Buffer>;
export declare function sealedSenderDecryptMessage(message: Buffer, trustRoot: PublicKey, timestamp: number, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore): Promise<SealedSenderDecryptionResult | null>;
export declare function sealedSenderDecryptToUsmc(message: Buffer, identityStore: IdentityKeyStore): Promise<UnidentifiedSenderMessageContent>;
