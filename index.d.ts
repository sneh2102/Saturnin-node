declare module 'saturnin' {
    // Constants
    export const KEY_SIZE: number;
    export const NONCE_SIZE: number;
    export const TAG_SIZE: number;
    export const HASH_SIZE: number;

    // Main AEAD functions
    export function encrypt(
        message: Buffer,
        associatedData: Buffer,
        nonce: Buffer,
        key: Buffer
    ): Buffer;

    export function decrypt(
        ciphertext: Buffer,
        associatedData: Buffer,
        nonce: Buffer,
        key: Buffer
    ): Buffer;

    // Hash function
    export function hash(
        message: Buffer
    ): Buffer;

    // Short AEAD functions
    export function shortEncrypt(
        message: Buffer,
        associatedData: Buffer,
        nonce: Buffer,
        key: Buffer
    ): Buffer;

    export function shortDecrypt(
        ciphertext: Buffer,
        associatedData: Buffer,
        nonce: Buffer,
        key: Buffer
    ): Buffer;
}