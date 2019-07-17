import { AcquireTokenCallback, AuthenticationContext } from 'adal-node';
// @ts-ignore
import keyVaultClient, { KeyOperationResult, KeyVaultClient, KeyVaultCredentials } from 'azure-keyvault';

const STORED_MESSAGES_MAX_LENGTH = 200;

export type Logger = (...msg: any[]) => void;

export type CryptFunction = (payload: string) => Promise<KeyOperationResult>;

export class KeyVault {
  public readonly client: keyVaultClient;

  private readonly vaultBaseUri: string;
  private readonly keyName: string;
  private readonly keyVersion: string;
  private readonly algorithm: string = 'RSA-OAEP';
  private readonly clientId: string;
  private readonly clientSecret: string;

  private logger?: Logger;
  private storedLogMessages: any[] = [];

  constructor(clientId: string, clientSecret: string, keyIdentifier: string, algorithm?: string) {
    const match = keyIdentifier.match(new RegExp('(https://.+)/keys/(.+)/(.+)')) as string[];

    this.vaultBaseUri = match[1];
    this.keyName = match[2];
    this.keyVersion = match[3];
    this.algorithm = algorithm || this.algorithm;
    this.clientId = clientId;
    this.clientSecret = clientSecret;

    // Authenticator - retrieves the access token
    const authenticator = (
      challenge: any,
      callback: (error: Error | null, callback: string) => AcquireTokenCallback,
    ): any => {
      // Create a new authentication context.
      const context = new AuthenticationContext(challenge.authorization);

      // Use the context to acquire an authentication token.
      return context.acquireTokenWithClientCredentials(
        challenge.resource,
        clientId,
        clientSecret,
        (err: Error, tokenResponse: any): AcquireTokenCallback => {
          if (err) {
            throw err;
          }

          // Calculate the value to be set in the request's Authorization header and resume the call.
          const authorizationValue = `${tokenResponse.tokenType} ${tokenResponse.accessToken}`;

          return callback(null, authorizationValue);
        },
      );
    };

    const credentials = new KeyVaultCredentials(authenticator);
    this.client = new KeyVaultClient(credentials);
  }

  public setLogger(logger: Logger): void {
    this.logger = logger;

    logger(`akec: KeyVault - There are ${this.storedLogMessages.length} stored log messages.`);
    this.storedLogMessages.forEach(msg => logger(msg));
    this.storedLogMessages = [];
  }

  public encrypt = (payload: string): Promise<string> => this.call('encrypt', payload);

  public decrypt = (payload: string): Promise<string> => this.call('decrypt', payload);

  private log(...args: any[]): void {
    if (this.logger) {
      this.logger(...args);
    } else {
      this.storedLogMessages.push(args);
      if (this.storedLogMessages.length > STORED_MESSAGES_MAX_LENGTH) {
        this.storedLogMessages.shift();
      }
    }
  }

  private call(method: 'encrypt' | 'decrypt', payload: string): Promise<KeyOperationResult> {
    const buffer = Buffer.from(payload, method === 'decrypt' ? 'base64' : 'utf-8');

    return (
      this.client[method](this.vaultBaseUri, this.keyName, this.keyVersion, this.algorithm, buffer)
        .then(({ result }) => {
          this.log(`akec: KeyVault ${method} successfull`);
          return (result as Buffer).toString(method === 'decrypt' ? 'utf-8' : 'base64')
        })
        .catch(e => {
          this.log('akec: KeyVault (error)', e);
          throw e;
        })
    );
  }
}
