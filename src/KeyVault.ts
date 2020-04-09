import { ClientSecretCredential } from "@azure/identity";
import { CryptographyClient, EncryptionAlgorithm, KeyClient, KeyVaultKey } from "@azure/keyvault-keys";
import * as crypto from 'crypto';
import { Logger } from './types'

const STORED_MESSAGES_MAX_LENGTH = 200;
const CRYPTO_ALGORITHM = 'aes-256-cbc';

export class KeyVault {
  private static localEncrypt(key: string, iv: string, payload: string): string {
    const cipher = crypto.createCipheriv(CRYPTO_ALGORITHM, Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let encrypted = cipher.update(payload);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('base64');
  }

  private static localDecrypt(key: string, iv: string, payload: string): string {
    const encryptedText = Buffer.from(payload, 'base64');
    const decipher = crypto.createDecipheriv(CRYPTO_ALGORITHM, Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf-8');
  }

  private readonly keysClient: KeyClient;
  private readonly vaultBaseUri: string;
  private readonly keyName: string;
  private readonly keyVersion: string;
  private readonly algorithm: EncryptionAlgorithm = 'RSA-OAEP';
  private readonly tenant: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly credentials: ClientSecretCredential;
  private key: KeyVaultKey | undefined;
  private cryptographyClientInstance: CryptographyClient | undefined;
  private logger?: Logger;
  private storedLogMessages: any[] = [];

  constructor(tenant: string, clientId: string, clientSecret: string, keyIdentifier: string, algorithm?: EncryptionAlgorithm) {
    if (!tenant) { throw new Error('KeyVault: tenant is missing!'); }
    if (!clientId) { throw new Error('KeyVault: clientId is missing!'); }
    if (!clientSecret) { throw new Error('KeyVault: clientSecret is missing!'); }
    if (!keyIdentifier) { throw new Error('KeyVault: keyIdentifier is missing!'); }

    const match = keyIdentifier.match(new RegExp('(https://.+)/keys/(.+)/(.+)')) as string[];

    this.tenant = tenant;
    this.vaultBaseUri = match[1];
    this.keyName = match[2];
    this.keyVersion = match[3];
    this.algorithm = algorithm || this.algorithm;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.credentials = new ClientSecretCredential(this.tenant, this.clientId, this.clientSecret);
    this.keysClient = new KeyClient(this.vaultBaseUri, this.credentials);
  }

  public setLogger(logger: Logger): void {
    this.logger = logger;

    logger(`akec: KeyVault - There are ${this.storedLogMessages.length} stored log messages.`);
    this.storedLogMessages.forEach(msg => logger(msg));
    this.storedLogMessages = [];
  }

  public encrypt = (payload: string): Promise<string> => this.call('encrypt', payload);

  public decrypt = (payload: string): Promise<string> => this.call('decrypt', payload);

  public encryptBig = async (payload: string): Promise<string> => {
    const key = crypto.randomBytes(32).toString('base64');
    const iv = crypto.randomBytes(16).toString('base64');

    const encryptedSecret = await this.encrypt(`${key}~${iv}`);
    const encryptedPayload = KeyVault.localEncrypt(key, iv, payload);

    return `${encryptedSecret}|${encryptedPayload}`;
  };

  public decryptBig = async (payload: string): Promise<string> => {
    const [encryptedSecret, encryptedPayload] = payload.split('|');
    const [key, iv] = (await this.decrypt(encryptedSecret)).split('~');
    return KeyVault.localDecrypt(key, iv, encryptedPayload);
  };

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

  private async call(method: 'encrypt' | 'decrypt', payload: string): Promise<string> {
    const buffer = Buffer.from(payload, method === 'decrypt' ? 'base64' : 'utf-8');

    const cryptographyClient = await this.getCryptographyClient();

    return (
      cryptographyClient[method](this.algorithm, buffer)
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

  private async getCryptographyClient(): Promise<CryptographyClient> {
    if (!this.cryptographyClientInstance) {
      this.key = await this.keysClient.getKey(this.keyName, { version: this.keyVersion });
      this.cryptographyClientInstance = new CryptographyClient(this.key, this.credentials);
    }

    return this.cryptographyClientInstance;
  }
}
