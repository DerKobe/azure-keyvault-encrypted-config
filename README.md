# azure-keyvault-encrypted-config

### Get started

##### 1. Install Package
Add the package to your project with
```bash
npm i --save git+https://git@github.com/DerKobe/azure-keyvault-encrypted-config.git
```
or
```bash
yarn add git+https://git@github.com/DerKobe/azure-keyvault-encrypted-config.git
```

If you want to use the provided command line tools anywhere you can install the package globally with
```bash
sudo npm i -g git+https://git@github.com/DerKobe/azure-keyvault-encrypted-config.git
```
or
```bash
sudo yarn global add git+https://git@github.com/DerKobe/azure-keyvault-encrypted-config.git
```


##### 2. Create Config File
Creat a json file which contains your config and mark keys which contain encrypted data with a `-Encrypted` postfix.
Additionally you can mark keys with `-Base64` when they contain Base64 encoded data which will be automatically decoded when the file is loaded.
Both postfixes will get removed in the key names when the `getConfig` Promise resolves and returns the config object.

```json
{
  "stuff": {
    "foo-Encrypted": "UeQrYx5ukdmvpMMjWpvaWE96EGi4HeKi0qrfXyN4HALPXTLn+q42UVDWyBylRCR",
    "bar": "baz"
  }
}
```

will when result in 

```js
{
  stuff: {
    foo: 'secret value',
    bar: 'baz'
  }
}
```

##### 3. Load Config In Your Code And Use It
Then you can import and use `getConfig`:

```js
import { init, getConfig } from 'azure-keyvault-encrypted-config';

const clientId = "667a8299-abf7-4ae5-b156-21afde093219";
const clientSecret = "f@+lQ6Dr&hWcSEuKkyTF_s/M2q234A9P5";
const keyIdentifier = "https://myazurekeyvault.vault.azure.net/keys/MyKeyName/2914862ab06b4c8dfe42ad095e0a4ed9";

// use either with the path to config ...
init('./config.json', { clientId, clientSecret, keyIdentifier });

// ... or directly with the config content as an object
const configContent = require(`./config.local.json`);
initWithConfigContent(configContent, { clientId, clientSecret, keyIdentifier });

getConfig().then((config) => {
  // use decrypted config here
});
```

### Command Line Helpers

In order to generate encrypted values for your config file you can use the command line tool `akec` provided by this package.
For this the KeyVault configuration via the env variables is needed. The configurtion to access the key vault key must be put into
these environment variables:
```
KEY_VAULT_CLIENT_ID
KEY_VAULT_CLIENT_SECRET
KEY_VAULT_KEY_IDENTIFIER
``` 

Usage:
```
akec encrypt myvalue 
akec decrypt Yyvoh0WE1r8ZXoRNijgv8fghJGQrAEAQ3YWJJ149SJSgT81VToX4LJmfHHof3d6I0Jl3vaf3Qb6uY5VuIDqsvS12llOMfjjp3/vCkeADF+vkVuElLPBQ4QyrVpcoqWJOv/NnQnNAC1Vn2k0U5fd7e9y4KdYmDVco026WqoAeuK2uTmVXHfkOKf3qqhZLwyWhDz07wXGiBh8eRpp3ql2aFselcGiI6QFyVr5vaEUS0juHRlfdDoexed89c3ItCFC8bAVixtJFWj1VDT0LT6IvuFPHmM5XS+9H2e7tQLRVnsLHYxkOqKFzRMBXpWJSpghJ1qhx0qrzHXMksSQoGsBvHQ== 
``` 

**Hint**: If you have your KeyVault config in a `.env` file and not globally available you can use it like so:
```
env $(cat .env | grep -v ^# | xargs) akec encrypt myvalue 
env $(cat .env | grep -v ^# | xargs) akec decrypt Yyvoh0WE1r8ZXoRNijgv8fghJGQrAEAQ3YWJJ149SJSgT81VToX4LJmfHHof3d6I0Jl3vaf3Qb6uY5VuIDqsvS12llOMfjjp3/vCkeADF+vkVuElLPBQ4QyrVpcoqWJOv/NnQnNAC1Vn2k0U5fd7e9y4KdYmDVco026WqoAeuK2uTmVXHfkOKf3qqhZLwyWhDz07wXGiBh8eRpp3ql2aFselcGiI6QFyVr5vaEUS0juHRlfdDoexed89c3ItCFC8bAVixtJFWj1VDT0LT6IvuFPHmM5XS+9H2e7tQLRVnsLHYxkOqKFzRMBXpWJSpghJ1qhx0qrzHXMksSQoGsBvHQ== 
``` 
