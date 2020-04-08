export type Logger = (...msg: any[]) => void;
export type ExceptionLogger = (excpetion: Error) => void;
export type CryptFunction = (payload: string, big?: boolean) => Promise<string>;
export class DecryptionError extends Error {}
