'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const IdentityProviders = require('../src/identity-provider')
const Identity = require('../src/identity')
const savedKeysPath = path.resolve('./test/fixtures/keys')
const keypath = path.resolve('./test/keys')
let keystore

const type = 'orbitdb'

describe('Identity Provider', function () {
  before(async () => {
    rmrf.sync(keypath)
    keystore = Keystore.create(keypath)
  })

  after(async () => {
    // Remove stored keys
    rmrf.sync(keypath)
  })

  describe('create an identity', () => {
    describe('create a new identity', () => {
      let id = 'A'
      let identity, externalPublicKey

      before(async () => {
        identity = await IdentityProviders.createIdentity({ id, keystore })
        let key = await keystore.getKey(id)
        externalPublicKey = key.getPublic('hex')
      })

      it('has the correct id', async () => {
        assert.strict.equal(identity.id, externalPublicKey)
      })

      it('created a key for id in keystore', async () => {
        const key = await identity.provider._keystore.getKey(id)
        assert.notStrictEqual(key, undefined)
      })

      it('has the correct public key', async () => {
        const signingKey = keystore.getKey(externalPublicKey)
        assert.notStrictEqual(signingKey, undefined)
        assert.strict.equal(identity.publicKey, signingKey.getPublic('hex'))
      })

      it('has a signature for the id', async () => {
        const signingKey = await keystore.getKey(externalPublicKey)
        const idSignature = await keystore.sign(signingKey, externalPublicKey)
        const publicKey = signingKey.getPublic('hex')
        const verifies = await keystore.verify(idSignature, publicKey, externalPublicKey)
        assert.strict.equal(verifies, true)
        assert.strict.equal(identity.signatures.id, idSignature)
      })

      it('has a signature for the publicKey', async () => {
        const signingKey = await keystore.getKey(externalPublicKey)
        const idSignature = await keystore.sign(signingKey, externalPublicKey)
        const externalKey = await keystore.getKey(id)
        const publicKeyAndIdSignature = await keystore.sign(externalKey, identity.publicKey + idSignature)
        assert.strict.equal(identity.signatures.publicKey, publicKeyAndIdSignature)
      })

      it('defaults to Keystore.sign as default identity signer', async () => {
        let savedKeysKeystore = Keystore.create(savedKeysPath)
        let id = 'QmPhnEjVkYE1Ym7F5MkRUfkD6NtuSptE7ugu1Ggr149W2X'

        const expectedPublicKey = '04f5b75ff7ca624fd0bf68e7aa94f59477407bf20c769c6cd4cd10c2662b5fa34adfe5e85636c9789bc9c25146ed3eaef1ef7c40da661f68b19909c3116863beec'
        const expectedPkSignature = '304402201b17da87ce27f4f4a5541c1af1f25bb748fac16890d2dc5c44c3011902007e9d022024292230343221b8745323d2c80fac3c52a69ef7af31dae7284bf2daab0e1a19'
        const expectedSignature = '3044022015b33469bdd666d435c8578652d0c8ab3c92fa7cf4bc8e1e2ff383a3ea49972a022056f6b0bc3662e78f35e770cc3ae867d7ed253a2fee9a3754ff7938386221c447'

        identity = await IdentityProviders.createIdentity({ id, keystore: savedKeysKeystore })
        let key = await savedKeysKeystore.getKey(id)
        assert.strict.equal(identity.id, key.getPublic('hex'))
        assert.strict.equal(identity.publicKey, expectedPublicKey)
        assert.strict.equal(identity.signatures.id, expectedPkSignature)
        assert.strict.equal(identity.signatures.publicKey, expectedSignature)
      })
    })

    describe('create an identity with saved keys', () => {
      const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'

      let savedKeysKeystore
      let identity
      before(async () => {
        savedKeysKeystore = Keystore.create(savedKeysPath)
        identity = await IdentityProviders.createIdentity({ id, keystore: savedKeysKeystore })
      })

      it('has the correct id', async () => {
        let key = await savedKeysKeystore.getKey(id)
        assert.strict.equal(identity.id, key.getPublic('hex'))
      })

      it('has the correct public key', async () => {
        const signingKey = await savedKeysKeystore.getKey(identity.id)
        assert.strict.equal(identity.publicKey, signingKey.getPublic('hex'))
      })

      it('has the correct identity type', async () => {
        assert.strict.equal(identity.type, type)
      })

      it('has the correct idSignature', async () => {
        const signingKey = await savedKeysKeystore.getKey(identity.id)
        const idSignature = await savedKeysKeystore.sign(signingKey, identity.id)
        assert.strict.equal(idSignature, identity.signatures.id)
      })

      it('has a pubKeyIdSignature for the publicKey', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        const pubKeyIdSignature = await savedKeysKeystore.sign(signingKey, identity.publicKey + identity.signatures.id)
        assert.strict.equal(identity.signatures.publicKey, pubKeyIdSignature)
      })

      it('has the correct signatures', async () => {
        const internalSigningKey = await savedKeysKeystore.getKey(identity.id)
        const externalSigningKey = await savedKeysKeystore.getKey(id)
        const idSignature = await savedKeysKeystore.sign(internalSigningKey, identity.id)
        const pubKeyIdSignature = await savedKeysKeystore.sign(externalSigningKey, identity.publicKey + idSignature)
        const expectedSignature = { id: idSignature, publicKey: pubKeyIdSignature }
        assert.deepStrictEqual(identity.signatures, expectedSignature)
      })
    })
  })

  describe('verify identity\'s signature', () => {
    const id = 'QmFoo'
    let identity

    it('identity pkSignature verifies', async () => {
      identity = await IdentityProviders.createIdentity({ id, type })
      const verified = await keystore.verify(identity.signatures.id, identity.publicKey, identity.id)
      assert.strict.equal(verified, true)
    })

    it('identity signature verifies', async () => {
      identity = await IdentityProviders.createIdentity({ id, type, keystore })
      const verified = await keystore.verify(identity.signatures.publicKey, identity.id, identity.publicKey + identity.signatures.id)
      assert.strict.equal(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      class IP {
        async getPublicKey () { return 'pubKey' }
        async signPubKeySignature (data) { return `false signature '${data}'` }
        static async verifyIdentity (data) { return false }
        static get type () { return 'fake' }
      }

      IdentityProviders.addIdentityProvider(IP)
      identity = await IdentityProviders.createIdentity({ type: IP.type, keystore })
      const verified = await IdentityProviders.verifyIdentity(identity)
      assert.strict.equal(verified, false)
    })
  })

  describe('verify identity', () => {
    const id = 'QmFoo'
    let identity

    it('identity verifies', async () => {
      identity = await IdentityProviders.createIdentity({ id, type, keystore })
      const verified = await identity.provider.verifyIdentity(identity)
      assert.strict.equal(verified, true)
    })
  })

  describe('sign data with an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity

    before(async () => {
      identity = await IdentityProviders.createIdentity({ id, keystore })
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(identity.id)
      const expectedSignature = await keystore.sign(signingKey, data)
      const signature = await identity.provider.sign(identity, data, keystore)
      assert.strict.equal(signature, expectedSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signatures, identity.type, identity.provider)
      let signature
      let err
      try {
        signature = await identity.provider.sign(modifiedIdentity, data, keystore)
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(signature, undefined)
      assert.strict.equal(err, `Error: Private signing key not found from Keystore`)
    })
  })

  describe('verify data signed by an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity
    let signature

    beforeEach(async () => {
      identity = await IdentityProviders.createIdentity({ id, type, keystore })
      signature = await identity.provider.sign(identity, data, keystore)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identity.provider.verify(signature, identity.publicKey, data)
      assert.strict.equal(verified, true)
    })

    it('doesn\'t verify invalid signature', async () => {
      const verified = await identity.provider.verify('invalid', identity.publicKey, data)
      assert.strict.equal(verified, false)
    })
  })
})
