import * as fs from 'fs';
import { CryptFunction, KeyVault } from './KeyVault';
import { makeQuerablePromise, QuerablePromise } from './QuerablePromise';
import { Logger } from "./types";

const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BASE64 = '-Base64';

const semaphors: Array<QuerablePromise<void>> = [];
let config: any;
let hasDecryptionFinished = false;

let logger: Logger | undefined;
let storedLogMessages: any[] = [];

function decryptObject(decrypt: CryptFunction, obj: any): void {
  for (const k in obj) {
    if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
      decryptObject(decrypt, obj[k]);
    } else {
      if (k.endsWith(POSTFIX_ENCRYPTED)) {
        log(`akec: "${k}" needs to be decrypted`);
        const promise = decrypt(obj[k]);
        semaphors.push(makeQuerablePromise(promise));

        promise
          .then((val: string) => {
            obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
            delete obj[k];
            log(`akec: "${k}" decryption finished`);
          })
          .catch((reason: any) => {
            log('akec: (decryption error)', reason);
          });

      } else if (k.endsWith(POSTFIX_BASE64)) {
        log(`akec: "${k}" needs to be decoded`);
        obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
        delete obj[k];
        log(`akec: "${k}" decoding finished`);
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
  if (customLogger) { keyVault.setLogger(customLogger); }

  decryptObject(keyVault.decrypt, config);
};

export const getConfig = async () => {
  if (!hasDecryptionFinished) {
    const openSemaphors = semaphors.map(s => s.isResolved()).reduce((count, isResolved) => count + (isResolved ? 0 : 1), 0);
    log(`akec: getConfig -> open semaphors ${openSemaphors}/${semaphors.length}`);
    await Promise.all(semaphors).then(() => { hasDecryptionFinished = true; });
  }

  return config;
};

function log(...args: any[]): void {
  if (logger) {
    logger(...args)
  } else {
    storedLogMessages.push(args);
  }
}

export const setLogger = (customLogger: Logger) => {
  customLogger('akec: custom logger set');
  logger = customLogger;
  storedLogMessages.forEach(msg => customLogger(msg));
  storedLogMessages = [];
};
