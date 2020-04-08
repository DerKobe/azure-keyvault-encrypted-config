import { EncryptionAlgorithm } from "@azure/keyvault-keys";
import { KeyVault } from './KeyVault';
import { ExceptionLogger, Logger } from "./types";
interface KeyVaultAccessConfig {
    tenant: string;
    clientId: string;
    clientSecret: string;
    keyIdentifier: string;
    algorithm?: EncryptionAlgorithm;
}
export declare const initKeyVault: (keyVaultAccessConfig: KeyVaultAccessConfig) => KeyVault;
export declare const initWithConfigContent: (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger | undefined, exceptionLogger?: ExceptionLogger | undefined) => void;
export declare const getConfig: () => Promise<any>;
export declare const setLogger: (customLogger: Logger) => void;
export {};
