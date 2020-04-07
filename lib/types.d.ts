export declare type Logger = (...msg: any[]) => void;
export declare type ExceptionLogger = (excpetion: Error) => void;
export declare type CryptFunction = (payload: string) => Promise<string>;
