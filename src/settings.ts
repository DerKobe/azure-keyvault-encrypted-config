import * as fs from 'fs';
import { CryptFunction, KeyVault } from './KeyVault';
import { makeQuerablePromise, QuerablePromise } from './QuerablePromise';
import { Logger } from "./types";

const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BASE64 = '-Base64';

const semaphors: Array<QuerablePromise<void>> = [];
let config: any;
let hasDecryptionFinished = false;
let logger = console.log;

function decryptObject(decrypt: CryptFunction, obj: any): void {
  for (const k in obj) {
    if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
      decryptObject(decrypt, obj[k]);
    } else {
      if (k.endsWith(POSTFIX_ENCRYPTED)) {
        logger(`akec: "${k}" needs to be decrypted`);
        const promise = decrypt(obj[k]);
        semaphors.push(makeQuerablePromise(promise));
        promise.then((val: string) => {
          obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
          delete obj[k];
          logger(`akec: "${k}" decryption finished`);
        });
      } else if (k.endsWith(POSTFIX_BASE64)) {
        logger(`akec: "${k}" needs to be decoded`);
        obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
        delete obj[k];
        logger(`akec: "${k}" decoding finished`);
      }
    }
  }
}

interface KeyVaultAccessConfig {
  clientId: string;
  clientSecret: string;
  keyIdentifier: string;
}

export const init = (configFilePath: string, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger) => {
  const data = fs.readFileSync(configFilePath);
  config = JSON.parse(data.toString());

  initWithConfigContent(config, keyVaultAccessConfig, logger)
};

export const initWithConfigContent = (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger) => {
  config = configContent;
  if (customLogger) {
    setLogger(customLogger);
  }

  const { clientId, clientSecret, keyIdentifier } = keyVaultAccessConfig;
  const keyVault = new KeyVault(clientId, clientSecret, keyIdentifier);
  KeyVault.setLogger(customLogger);

  decryptObject(keyVault.decrypt, config);
};

export const getConfig = async () => {
  const semaphorsState = semaphors.map(s => s.isResolved());
  logger('akec: getConfig -> semaphors state', semaphorsState);

  if (!hasDecryptionFinished) {
    await Promise.all(semaphors).then(() => {
      hasDecryptionFinished = true;
    });
  }

  return config;
};

export const setLogger = (customLogger: Logger) => {
  logger = customLogger;
};
