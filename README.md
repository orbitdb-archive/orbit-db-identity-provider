# orbit-db-identity-provider

> Default identity provider for orbitdb

### Use
```
const Keystore = require('orbit-db-keystore')
const keystore = Keystore.create('keysPath')
const identity = await IdentityProvider.createIdentity(keystore, 'peerid')
```

## License

[MIT](LICENSE) © 2018 Haja Networks Oy
