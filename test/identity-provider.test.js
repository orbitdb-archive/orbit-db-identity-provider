const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const mkdirp = require('mkdirp')
const LocalStorage = require('node-localstorage').LocalStorage
const Keystore = require('orbit-db-keystore')
const IdentityProvider = require('../src/identity-provider')
const Identity = require('../src/identity')

const savedKeysPath = path.resolve('./test/fixtures/keys')
const testKeysPath = path.resolve('./test/keys')
let keystore

describe('Identity Provider', function() {
  keystore = Keystore.create(testKeysPath)
  const identitySignerFn = async (id, data) => {
    const key = await keystore.getKey(id)
    return await keystore.sign(key, data)
  }

  before(() => {
    // Make sure we don't use previous test keys
    rmrf.sync(testKeysPath)
    keystore = Keystore.create(testKeysPath)
  })

  after(() => {
    // Remove stored keys
    rmrf.sync(testKeysPath)
  })

  describe('create an identity', () => {
    describe('create a new identity', () => {
      const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
      let identity

      before(async () => {
        identity = await IdentityProvider.createIdentity(keystore, id, identitySignerFn)
      })

      it('has the correct id', async () => {
        assert.equal(identity.id, id)
      })

      it('created a key for id in keystore', async () => {
        const key = await keystore.getKey(id)
        assert.notEqual(key, undefined)
      })

      it('has the correct public key', async () => {
        const signingKey = await keystore.getKey(id)
        assert.notEqual(signingKey, undefined)
        assert.equal(identity.publicKey, signingKey.getPublic('hex'))
      })

      it('has a signature for the id', async () => {
        const signingKey = await keystore.getKey(id)
        const idSignature = await keystore.sign(signingKey, id)
        const verifies = await keystore.verify(idSignature, signingKey.getPublic('hex'), id)
        assert.equal(verifies, true)
        assert.equal(identity.pkSignature, idSignature)
      })

      it('has a signature for the publicKey', async () => {
        const signingKey = await keystore.getKey(id)
        const idSignature = await keystore.sign(signingKey, id)
        const signature = await keystore.sign(signingKey, identity.publicKey + idSignature)
        assert.equal(identity.signature, signature)
      })
    })

    describe('create an identity with saved keys', () => {
      const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
      const expectedPublicKey = '0474eee0310cd3ea85528c0305e7ab39f410437eebaf794bddbac97869d82f0abbfc7089c6a41a3ed7e3343831c264b18003454042788e5af7aca5684ff225f78c'

      let savedKeysKeystore
      let identity

      before(async () => {
        savedKeysKeystore = Keystore.create(savedKeysPath)
        const identitySignerFn = async (id, data) => {
          const key = await savedKeysKeystore.getKey(id)
          return await savedKeysKeystore.sign(key, data)
        }
        identity = await IdentityProvider.createIdentity(savedKeysKeystore, id, identitySignerFn)
      })

      it('has the correct id', async () => {
        assert.equal(identity.id, id)
      })

      it('has the correct public key', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        assert.equal(identity.publicKey, expectedPublicKey)
      })

      it('has a signature for the publicKey', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        const signature = await savedKeysKeystore.sign(signingKey, identity.publicKey + identity.pkSignature)
        assert.equal(identity.signature, signature)
      })
    })
  })

  describe('verify identity\'s signature', () => {
    const id = 'QmFoo'
    let identity

    it('identity signature verifies', async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, identitySignerFn)
      const data = identity.publicKey + identity.pkSignature
      const verified = await keystore.verify(identity.signature, identity.publicKey, data)
      assert.equal(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      const signer = {
        sign: (key, data) => `false signature '${data}'`
      }
      identity = await IdentityProvider.createIdentity(keystore, id, signer.sign)
      const data = identity.publicKey + identity.pkSignature
      const verified = await keystore.verify(identity.signature, identity.publicKey, data)
      assert.equal(verified, false)
    })
  })

  describe('sign data with an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity

    beforeEach(async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, identitySignerFn)
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(id)
      const expectedSignature = await keystore.sign(signingKey, data)
      const signature = await identity.provider.sign(identity, data, keystore)
      assert.equal(signature, expectedSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signature, identity.provider)

      let err
      try {
        const signature = await identity.provider.sign(modifiedIdentity, data, keystore)
      } catch (e) {
        err = e
      }
      assert.equal(err, `Error: Private signing key not found from Keystore`)
    })
  })

  describe('verify a signature', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity
    let signature
    let signingKey
    let expectedSignature

    beforeEach(async () => {
      signingKey = await keystore.getKey(id)
      expectedSignature = await keystore.sign(signingKey, data)

      identity = await IdentityProvider.createIdentity(keystore, id, identitySignerFn)
      signature = await identity.provider.sign(identity, data, keystore)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identity.provider.verify(signature, identity.publicKey, data, keystore)
      assert.equal(verified, true)
    })

    it('doesn\'t verify invalid signature', async () => {
      const verified = await identity.provider.verify('invalid', identity.publicKey, data, keystore)
      assert.equal(verified, false)
    })
  })
})