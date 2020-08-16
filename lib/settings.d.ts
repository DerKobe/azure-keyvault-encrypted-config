import { KeyVault } from './KeyVault';
import { KeyVaultAccessConfig } from './types';
import { ExceptionLogger, Logger } from './types';
export declare const initKeyVault: (keyVaultAccessConfig: KeyVaultAccessConfig) => KeyVault;
export declare const initWithConfigContent: (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger | undefined, exceptionLogger?: ExceptionLogger | undefined, decryptInSequenceAndUseLocalCache?: boolean) => void;
export declare const getConfig: () => Promise<any>;
export declare const setLogger: (customLogger: Logger) => void;
