import * as fs from 'fs';
import { CryptFunction, KeyVault } from './KeyVault';

const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BASE64 = '-Base64';

const semaphors: Array<Promise<void>> = [];
let config: any;
let hasDecryptionFinished = false;

function decryptObject(decrypt: CryptFunction, obj: any): void {
  for (const k in obj) {
    if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
      decryptObject(decrypt, obj[k]);
    } else {
      if (k.endsWith(POSTFIX_ENCRYPTED)) {
        const promise = decrypt(obj[k]);
        semaphors.push(promise);
        promise.then((val: string) => {
          obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
          delete obj[k];
        });
      } else if (k.endsWith(POSTFIX_BASE64)) {
        obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
        delete obj[k];
      }
    }
  }
}

interface IKeyVaultAccessConfig {
  clientId: string;
  clientSecret: string;
  keyIdentifier: string;
}

export const init = (configFilePath: string, keyVaultAccessConfig: IKeyVaultAccessConfig) => {
  const { clientId, clientSecret, keyIdentifier } = keyVaultAccessConfig;

  const keyVault = new KeyVault(clientId, clientSecret, keyIdentifier);

  const data = fs.readFileSync(configFilePath);
  config = JSON.parse(data.toString());

  decryptObject(keyVault.decrypt, config);
};

export const getConfig = async () => {
  if (!hasDecryptionFinished) {
    await Promise.all(semaphors).then(() => {
      hasDecryptionFinished = true;
    });
  }

  return config;
};
