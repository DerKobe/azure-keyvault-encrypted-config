import { EncryptionAlgorithm } from "@azure/keyvault-keys";
export { EncryptionAlgorithm } from "@azure/keyvault-keys";
export declare type Logger = (...msg: any[]) => void;
export declare type ExceptionLogger = (excpetion: Error) => void;
export declare type CryptFunction = (payload: string, big?: boolean) => Promise<string>;
export declare class DecryptionError extends Error {
}
export interface KeyVaultAccessConfig {
    keyIdentifier: string;
    tenant?: string;
    clientId?: string;
    clientSecret?: string;
    algorithm?: EncryptionAlgorithm;
}
