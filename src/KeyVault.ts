import { AcquireTokenCallback, AuthenticationContext } from 'adal-node';
// @ts-ignore
import keyVaultClient, { KeyOperationResult, KeyVaultClient, KeyVaultCredentials } from 'azure-keyvault';

export type CryptFunction = (payload: string) => Promise<KeyOperationResult>;

export class KeyVault {
  public readonly client: keyVaultClient;

  private readonly vaultBaseUri: string;
  private readonly keyName: string;
  private readonly keyVersion: string;
  private readonly algorithm: string = 'RSA-OAEP';
  private readonly clientId: string;
  private readonly clientSecret: string;

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

  public encrypt = (payload: string): Promise<string> => this.call('encrypt', payload);

  public decrypt = (payload: string): Promise<string> => this.call('decrypt', payload);

  private call(method: 'encrypt' | 'decrypt', payload: string): Promise<KeyOperationResult> {
    const buffer = Buffer.from(payload, method === 'decrypt' ? 'base64' : 'utf-8');

    const promise = this.client[method](this.vaultBaseUri, this.keyName, this.keyVersion, this.algorithm, buffer);

    return promise.then(({ result }) => (result as Buffer).toString(method === 'decrypt' ? 'utf-8' : 'base64'));
  }
}
