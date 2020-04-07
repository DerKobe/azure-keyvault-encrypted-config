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
const identity_1 = require("@azure/identity");
const keyvault_keys_1 = require("@azure/keyvault-keys");
const STORED_MESSAGES_MAX_LENGTH = 200;
class KeyVault {
    constructor(tenant, clientId, clientSecret, keyIdentifier, algorithm) {
        this.algorithm = 'RSA-OAEP-256';
        this.storedLogMessages = [];
        this.encrypt = (payload) => this.call('encrypt', payload);
        this.decrypt = (payload) => this.call('decrypt', payload);
        const match = keyIdentifier.match(new RegExp('(https://.+)/keys/(.+)/(.+)'));
        this.tenant = tenant;
        this.vaultBaseUri = match[1];
        this.keyName = match[2];
        this.keyVersion = match[3];
        this.algorithm = algorithm || this.algorithm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.credentials = new identity_1.ClientSecretCredential(this.tenant, this.clientId, this.clientSecret);
        this.keysClient = new keyvault_keys_1.KeyClient(this.vaultBaseUri, this.credentials);
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
            return (cryptographyClient[method](this.algorithm, buffer)
                .then(({ result }) => {
                this.log(`akec: KeyVault ${method} successfull`);
                return result.toString(method === 'decrypt' ? 'utf-8' : 'base64');
            })
                .catch(e => {
                this.log('akec: KeyVault (error)', e);
                throw e;
            }));
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
