import keyVaultClient, { KeyOperationResult } from 'azure-keyvault';
export declare type Logger = (...msg: any[]) => void;
export declare type CryptFunction = (payload: string) => Promise<KeyOperationResult>;
export declare class KeyVault {
    readonly client: keyVaultClient;
    private readonly vaultBaseUri;
    private readonly keyName;
    private readonly keyVersion;
    private readonly algorithm;
    private readonly clientId;
    private readonly clientSecret;
    private logger?;
    private storedLogMessages;
    constructor(clientId: string, clientSecret: string, keyIdentifier: string, algorithm?: string);
    setLogger(logger: Logger): void;
    encrypt: (payload: string) => Promise<string>;
    decrypt: (payload: string) => Promise<string>;
    private log;
    private call;
}
