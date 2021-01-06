/// <reference types="node" />
import * as SignalClient from './libsignal_client';
export declare class PublicKey {
    private readonly nativeHandle;
    private constructor();
    static fromNativeHandle(handle: SignalClient.PublicKey): PublicKey;
    static deserialize(buf: Buffer): PublicKey;
    serialize(): Buffer;
    verify(msg: Buffer, sig: Buffer): boolean;
    _unsafeGetNativeHandle(): SignalClient.PublicKey;
}
export declare class PrivateKey {
    private readonly nativeHandle;
    private constructor();
    static generate(): PrivateKey;
    static deserialize(buf: Buffer): PrivateKey;
    serialize(): Buffer;
    sign(msg: Buffer): Buffer;
    agree(other_key: PublicKey): Buffer;
    getPublicKey(): PublicKey;
}
