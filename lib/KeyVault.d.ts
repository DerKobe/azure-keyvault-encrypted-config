import { EncryptionAlgorithm } from '@azure/keyvault-keys';
import { Logger } from './types';
export declare class KeyVault {
    private static localEncrypt;
    private static localDecrypt;
    private readonly keysClient;
    private readonly vaultBaseUri;
    private readonly keyName;
    private readonly keyVersion;
    private readonly algorithm;
    private readonly tenant;
    private readonly clientId;
    private readonly clientSecret;
    private readonly credentials;
    private key;
    private cryptographyClientInstance;
    private logger?;
    private storedLogMessages;
    constructor(tenant: string, clientId: string, clientSecret: string, keyIdentifier: string, algorithm?: EncryptionAlgorithm);
    setLogger(logger: Logger): void;
    encrypt: (payload: string) => Promise<string>;
    decrypt: (payload: string) => Promise<string>;
    encryptBig: (payload: string) => Promise<string>;
    decryptBig: (payload: string) => Promise<string>;
    private log;
    private call;
    private getCryptographyClient;
}
