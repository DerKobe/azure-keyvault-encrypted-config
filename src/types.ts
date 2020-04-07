export type Logger = (...msg: any[]) => void;
export type ExceptionLogger = (excpetion: Error) => void;
export type CryptFunction = (payload: string) => Promise<string>;
