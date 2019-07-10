interface IKeyVaultAccessConfig {
    clientId: string;
    clientSecret: string;
    keyIdentifier: string;
}
export declare const init: (configFilePath: string, keyVaultAccessConfig: IKeyVaultAccessConfig) => void;
export declare const getConfig: () => Promise<any>;
export {};
