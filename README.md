# orbit-db-identity-provider

> Default identity provider for orbitdb

### Use
```js
const Keystore = require('orbit-db-keystore')
const keystore = Keystore.create('keysPath')
const identity = await IdentityProvider.createIdentity(keystore, 'peerid')

console.log(identity.toJSON())
<!-- { id: 'peerid',
  publicKey: '0453895b939459e222a72003fd1f2cf6a242d4e8c00406fee36382655cbca66110965a839b91b9f9486f8f29f4547b7e0c0f32938899a0f43a59d7d803e333cc49',
  signatures:
   { id: '3044022046fab6d5370792bb3575bdcca87f0a23d372f02231445c74f0b5d52375e9d10d02207b9267396bcdb33fdf543f19afcbef5d68ee767f985dc9865dc353a68ccdd66f',
     publicKey: '3045022100863765c299cf75a992db5cd4e2bd67e4cacf6de37b10451d8cb799eb73b6801502207d18b9c31d19921d62783d23c92a2297d17d21afbfb12063906620e9e6be9e4f' },
  type: 'orbitdb' } -->

```

## License

[MIT](LICENSE) © 2018 Haja Networks Oy
