import { KeyVault } from './KeyVault';
import { makeQuerablePromise, QuerablePromise } from './QuerablePromise';
import { CryptFunction, KeyVaultAccessConfig } from './types'
import { DecryptionError, ExceptionLogger, Logger } from "./types";

const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BIG_ENCRYPTED = '-BigEncrypted';
const POSTFIX_BASE64 = '-Base64';
const STORED_MESSAGES_MAX_LENGTH = 200;

const semaphors: Array<QuerablePromise<void>> = [];
let config: any;
let hasDecryptionFinished = false;

let logger: Logger;
let storedLogMessages: any[] = [];

function decryptObject(decrypt: CryptFunction, obj: any): void {
  for (const k in obj) {
    if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
      decryptObject(decrypt, obj[k]);
    } else {
      if (k.endsWith(POSTFIX_ENCRYPTED)) {
        log(`akec: "${k}" needs to be decrypted`);
        const promiseDecrypt = (
          decrypt(obj[k])
            .then((val: string) => {
              obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
              delete obj[k];
              log(`akec: "${k}" decryption finished`);
            })
            .catch((error: any) => {
              throw new DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
            })
        );
        semaphors.push(makeQuerablePromise(promiseDecrypt));

      } else if (k.endsWith(POSTFIX_BIG_ENCRYPTED)) {
        log(`akec: "${k}" needs to be decrypted locally because big payload`);
        const promiseDecryptBig = (
          decrypt(obj[k], true)
            .then((val: string) => {
              obj[k.substring(0, k.length - POSTFIX_BIG_ENCRYPTED.length)] = val;
              delete obj[k];
              log(`akec: "${k}" decryption finished`);
            })
            .catch((error: any) => {
              throw new DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
            })
        );
        semaphors.push(makeQuerablePromise(promiseDecryptBig));

      } else if (k.endsWith(POSTFIX_BASE64)) {
        log(`akec: "${k}" needs to be decoded`);
        obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
        delete obj[k];
        log(`akec: "${k}" decoding finished`);
      }
    }
  }
}

export const initKeyVault = (keyVaultAccessConfig: KeyVaultAccessConfig): KeyVault => {
  const { tenant, clientId, clientSecret, keyIdentifier, algorithm } = keyVaultAccessConfig;
  return new KeyVault(tenant, clientId, clientSecret, keyIdentifier, algorithm);
};

export const initWithConfigContent = (configContent: any, keyVaultAccessConfig: KeyVaultAccessConfig, customLogger?: Logger, exceptionLogger?: ExceptionLogger) => {
  const stringifyed = JSON.stringify(configContent);
  if (stringifyed.indexOf(POSTFIX_ENCRYPTED) === -1 && stringifyed.indexOf(POSTFIX_BIG_ENCRYPTED) === -1 && stringifyed.indexOf(POSTFIX_BASE64) === -1) {
    return configContent;
  }

  config = configContent;

  if (customLogger) {
    setLogger(customLogger);
  }

  const { tenant, clientId, clientSecret, keyIdentifier, algorithm } = keyVaultAccessConfig;

  const keyVault = new KeyVault(tenant, clientId, clientSecret, keyIdentifier, algorithm);

  if (customLogger) {
    keyVault.setLogger(customLogger);
  }

  const decrypt: CryptFunction = async (encryptedValue: string, big: boolean = false): Promise<string> => {
    let decryptedValue = '';
    try {
      decryptedValue = await keyVault[big ? 'decryptBig' : 'decrypt'](encryptedValue);
    } catch (exception) {
      if (exceptionLogger) {
        exceptionLogger(exception);
      } else {
        throw exception;
      }
    }
    return decryptedValue;
  };

  decryptObject(decrypt, config);
};

export const getConfig = async () => {
  if (!hasDecryptionFinished) {
    const openSemaphors = semaphors.map(s => s.isResolved()).reduce((count, isResolved) => count + (isResolved ? 0 : 1), 0);
    log(`akec: getConfig -> open semaphors ${openSemaphors}/${semaphors.length}`);
    await Promise.all(semaphors).then(() => {
      hasDecryptionFinished = true;
    });
  }

  return config;
};

function log(...args: any[]): void {
  if (logger) {
    logger(...args)
  } else {
    storedLogMessages.push(args);
    if (storedLogMessages.length > STORED_MESSAGES_MAX_LENGTH) {
      storedLogMessages.shift();
    }
  }
}

export const setLogger = (customLogger: Logger) => {
  customLogger('akec: custom logger set');
  logger = customLogger;
  storedLogMessages.forEach(msg => customLogger(msg));
  storedLogMessages = [];
};
