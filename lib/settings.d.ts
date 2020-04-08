import { KeyVault } from './KeyVault';
import { ExceptionLogger, Logger } from "./types";
interface KeyVaultAccessConfig {
    tenant: string;
    clientId: string;
    clientSecret: string;
    keyIdentifier: string;
}
export declare const initKeyVault: (keyVaultAccessConfig: KeyVaultAccessConfig, algorithm?: "RSA-OAEP" | "RSA-OAEP-256" | "RSA1_5" | undefined) => KeyVault;
export declare const initWithConfigContent: (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger | undefined, exceptionLogger?: ExceptionLogger | undefined) => void;
export declare const getConfig: () => Promise<any>;
export declare const setLogger: (customLogger: Logger) => void;
export {};
