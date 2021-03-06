import { EncryptionAlgorithm } from "@azure/keyvault-keys";
export { EncryptionAlgorithm } from "@azure/keyvault-keys";

export type Logger = (...msg: any[]) => void;
export type ExceptionLogger = (excpetion: Error) => void;
export type CryptFunction = (payload: string, big?: boolean) => Promise<string>;

export class DecryptionError extends Error {}

export interface KeyVaultAccessConfig {
  keyIdentifier: string;
  tenant?: string;
  clientId?: string;
  clientSecret?: string;
  algorithm?: EncryptionAlgorithm;
}
