import { Logger } from './types';
export declare class KeyVault {
    private static localEncrypt;
    private static localDecrypt;
    private readonly keysClient;
    private readonly keyName;
    private readonly keyVersion;
    private readonly credentials;
    private readonly algorithm;
    private key;
    private cryptographyClientInstance;
    private logger?;
    private storedLogMessages;
    constructor(...args: any[]);
    setLogger(logger: Logger): void;
    encrypt: (payload: string) => Promise<string>;
    decrypt: (payload: string) => Promise<string>;
    encryptBig: (payload: string) => Promise<string>;
    decryptBig: (payload: string) => Promise<string>;
    private log;
    private call;
    private getCryptographyClient;
}
