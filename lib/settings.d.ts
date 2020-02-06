import { ExceptionLogger, Logger } from "./types";
interface KeyVaultAccessConfig {
    clientId: string;
    clientSecret: string;
    keyIdentifier: string;
}
export declare const init: (configFilePath: string, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger | undefined, exceptionLogger?: ExceptionLogger | undefined) => void;
export declare const initWithConfigContent: (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger | undefined, exceptionLogger?: ExceptionLogger | undefined) => void;
export declare const getConfig: () => Promise<any>;
export declare const setLogger: (customLogger: Logger) => void;
export {};
