"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const adal_node_1 = require("adal-node");
// @ts-ignore
const azure_keyvault_1 = require("azure-keyvault");
class KeyVault {
    constructor(clientId, clientSecret, keyIdentifier, algorithm) {
        this.algorithm = 'RSA-OAEP';
        this.encrypt = (payload) => this.call('encrypt', payload);
        this.decrypt = (payload) => this.call('decrypt', payload);
        const match = keyIdentifier.match(new RegExp('(https://.+)/keys/(.+)/(.+)'));
        this.vaultBaseUri = match[1];
        this.keyName = match[2];
        this.keyVersion = match[3];
        this.algorithm = algorithm || this.algorithm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        // Authenticator - retrieves the access token
        const authenticator = (challenge, callback) => {
            // Create a new authentication context.
            const context = new adal_node_1.AuthenticationContext(challenge.authorization);
            // Use the context to acquire an authentication token.
            return context.acquireTokenWithClientCredentials(challenge.resource, clientId, clientSecret, (err, tokenResponse) => {
                if (err) {
                    throw err;
                }
                // Calculate the value to be set in the request's Authorization header and resume the call.
                const authorizationValue = `${tokenResponse.tokenType} ${tokenResponse.accessToken}`;
                return callback(null, authorizationValue);
            });
        };
        const credentials = new azure_keyvault_1.KeyVaultCredentials(authenticator);
        this.client = new azure_keyvault_1.KeyVaultClient(credentials);
    }
    call(method, payload) {
        const buffer = Buffer.from(payload, method === 'decrypt' ? 'base64' : 'utf-8');
        return this.client[method](this.vaultBaseUri, this.keyName, this.keyVersion, this.algorithm, buffer)
            .then(({ result }) => result.toString(method === 'decrypt' ? 'utf-8' : 'base64'))
            .catch(error => {
            // tslint:disable-next-line:no-console
            console.error(error);
        });
    }
}
exports.KeyVault = KeyVault;
