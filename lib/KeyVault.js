"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyVault = void 0;
const identity_1 = require("@azure/identity");
const keyvault_keys_1 = require("@azure/keyvault-keys");
const crypto = require("crypto");
const STORED_MESSAGES_MAX_LENGTH = 200;
const CRYPTO_ALGORITHM = 'aes-256-cbc';
class KeyVault {
    constructor(...args) {
        this.storedLogMessages = [];
        this.encrypt = (payload) => this.call('encrypt', payload);
        this.decrypt = (payload) => this.call('decrypt', payload);
        this.encryptBig = (payload) => __awaiter(this, void 0, void 0, function* () {
            const key = crypto.randomBytes(32).toString('base64');
            const iv = crypto.randomBytes(16).toString('base64');
            const encryptedSecret = yield this.encrypt(`${key}~${iv}`);
            const encryptedPayload = KeyVault.localEncrypt(key, iv, payload);
            return `${encryptedSecret}|${encryptedPayload}`;
        });
        this.decryptBig = (payload) => __awaiter(this, void 0, void 0, function* () {
            const [encryptedSecret, encryptedPayload] = payload.split('|');
            const [key, iv] = (yield this.decrypt(encryptedSecret)).split('~');
            return KeyVault.localDecrypt(key, iv, encryptedPayload);
        });
        let keyIdentifier;
        if (args.length === 2) {
            keyIdentifier = args[0];
            this.algorithm = args[1] || 'RSA-OAEP';
            this.credentials = new identity_1.DefaultAzureCredential();
        }
        else if (args.length === 4 || args.length === 5) {
            const tenant = args[0];
            const clientId = args[1];
            const clientSecret = args[2];
            keyIdentifier = args[3];
            this.algorithm = args[4] || 'RSA-OAEP';
            if (!tenant) {
                throw new Error('KeyVault: tenant is missing!');
            }
            if (!clientId) {
                throw new Error('KeyVault: clientId is missing!');
            }
            if (!clientSecret) {
                throw new Error('KeyVault: clientSecret is missing!');
            }
            if (!keyIdentifier) {
                throw new Error('KeyVault: keyIdentifier is missing!');
            }
            this.credentials = new identity_1.ClientSecretCredential(tenant, clientId, clientSecret);
        }
        else {
            throw new Error('Wrong number of parameters');
        }
        const match = keyIdentifier.match(new RegExp('(https://.+)/keys/(.+)/(.+)'));
        const vaultBaseUri = match[1];
        this.keyName = match[2];
        this.keyVersion = match[3];
        this.keysClient = new keyvault_keys_1.KeyClient(vaultBaseUri, this.credentials);
    }
    static localEncrypt(key, iv, payload) {
        const cipher = crypto.createCipheriv(CRYPTO_ALGORITHM, Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
        let encrypted = cipher.update(payload);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.toString('base64');
    }
    static localDecrypt(key, iv, payload) {
        const encryptedText = Buffer.from(payload, 'base64');
        const decipher = crypto.createDecipheriv(CRYPTO_ALGORITHM, Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString('utf-8');
    }
    setLogger(logger) {
        this.logger = logger;
        logger(`akec: KeyVault - There are ${this.storedLogMessages.length} stored log messages.`);
        this.storedLogMessages.forEach(msg => logger(msg));
        this.storedLogMessages = [];
    }
    log(...args) {
        if (this.logger) {
            this.logger(...args);
        }
        else {
            this.storedLogMessages.push(args);
            if (this.storedLogMessages.length > STORED_MESSAGES_MAX_LENGTH) {
                this.storedLogMessages.shift();
            }
        }
    }
    call(method, payload) {
        return __awaiter(this, void 0, void 0, function* () {
            const buffer = Buffer.from(payload, method === 'decrypt' ? 'base64' : 'utf-8');
            const cryptographyClient = yield this.getCryptographyClient();
            return cryptographyClient[method](this.algorithm, buffer)
                .then(({ result }) => {
                this.log(`akec: KeyVault ${method} successfull`);
                return result.toString(method === 'decrypt' ? 'utf-8' : 'base64');
            })
                .catch(e => {
                this.log('akec: KeyVault (error)', e);
                throw e;
            });
        });
    }
    getCryptographyClient() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.cryptographyClientInstance) {
                this.key = yield this.keysClient.getKey(this.keyName, { version: this.keyVersion });
                this.cryptographyClientInstance = new keyvault_keys_1.CryptographyClient(this.key, this.credentials);
            }
            return this.cryptographyClientInstance;
        });
    }
}
exports.KeyVault = KeyVault;
