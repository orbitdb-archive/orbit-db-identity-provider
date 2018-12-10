'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const mkdirp = require('mkdirp')
const LocalStorage = require('node-localstorage').LocalStorage
const Keystore = require('orbit-db-keystore')
const IdentityProviders = require('../src/identity-provider')
const Identity = require('../src/identity')
const savedKeysPath = path.resolve('./test/fixtures/keys')
const keypath = path.resolve('./test/keys')
let keystore

const type = 'orbitdb'

describe('Identity Provider', function() {

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
      let identity, pubKey

      before(async () => {
        identity = await IdentityProviders.createIdentity({ id, keystore })
      })

      it('has the correct id', async () => {
        assert.equal(identity.id, id)
      })

      it('created a key for id in keystore', async () => {
        const key = await identity.provider._odbip._keystore.getKey(id)
        assert.notEqual(key, undefined)
      })

      it('has the correct public key', async () => {
        const signingKey = keystore.getKey(id)
        assert.notEqual(signingKey, undefined)
        assert.equal(identity.publicKey, signingKey.getPublic('hex'))
      })

      it('defaults to Keystore.sign as default identity signer', async () => {
        let keystore = Keystore.create(keypath)
        identity = await IdentityProviders.createIdentity({ id, keystore })
        let key = await keystore.getKey(id)
        assert.equal(identity.id, id)
        assert.equal(identity.publicKey, key.getPublic('hex'))
      })
    })

    describe('create an identity with saved keys', () => {
      const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
      const expectedPublicKey = '04c709aa3c50b4c70ff545f42fc029ceb5b3e86fbda2c4c6a37cbc32b128cc954180f1d95663aad04beb8a59af7b01ade59b5be8008abe91b465bc1f40c08eebf2'

      let savedKeysKeystore
      let identity
      before(async () => {
        savedKeysKeystore = Keystore.create(savedKeysPath)
        identity = await IdentityProviders.createIdentity({ id, keystore: savedKeysKeystore })
      })

      it('has the correct id', async () => {
        assert.equal(identity.id, id)
      })

      it('has the correct public key', async () => {
        const key = await savedKeysKeystore.getKey(id)
        assert.equal(identity.publicKey, key.getPublic('hex'))
      })

      it('has the correct identity type', async () => {
        assert.equal(identity.type, type)
      })
    })
  })

  describe('verify identity\'s signature', () => {
    const id = 'QmFoo'
    let identity, keystore

    class IP {
      constructor() {}
      getPublicKey(options) {
        const key = options.keystore.getKey(options.id) || options.keystore.createKey(options.id)
        return key.getPublic('hex')
      }
      async signPubKeySignature(data, options) {
        const key = options.keystore.getKey(options.id)
        return await options.keystore.sign(key, data)
      }
      static async verifyIdentity(identity, options) {
        return await options.keystore.verify(identity.signatures.publicKey, identity.id, identity.publicKey + identity.signatures.id)
      }
      static get type () { return 'sometype' }
    }

    IdentityProviders.addIdentityProvider(IP)

    before(async () => {
      keystore = Keystore.create(keypath)
      identity = await IdentityProviders.createIdentity({ id, type: IP.type, keystore })
    })

    it('has the correct idSignature', async () => {
      const signingKey = await keystore.getKey(identity.id)
      const idSignature = await keystore.sign(signingKey, identity.id)
      assert.equal(idSignature, identity.signatures.id)
    })

    it('has a pubKeyIdSignature for the publicKey', async () => {
      const signingKey = await keystore.getKey(id)
      const pubKeyIdSignature = await keystore.sign(signingKey, identity.publicKey + identity.signatures.id)
      assert.equal(identity.signatures.publicKey, pubKeyIdSignature)
    })

    it('has the correct signatures', async () => {
      const internalSigningKey = await keystore.getKey(identity.id)
      const idSignature = await keystore.sign(internalSigningKey, identity.id)

      const externalSigningKey = await keystore.getKey(id)
      const pubKeyIdSignature = await keystore.sign(externalSigningKey, identity.publicKey + idSignature)

      assert.deepEqual(identity.signatures, { id: idSignature, publicKey: pubKeyIdSignature })
    })

    it('identity pkSignature verifies', async () => {
      const verified = await keystore.verify(identity.signatures.publicKey, identity.id, identity.publicKey)
      assert.equal(verified, true)
    })

    it('identity signature verifies', async () => {
      const verified = await keystore.verify(identity.signatures.id, identity.publicKey, identity.id)
      assert.equal(verified, true)
    })

    it('identity verifies', async () => {
      const verified = await identity.provider.verifyIdentity(identity, { keystore })
      assert.equal(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      class FAKEIP {
        constructor() {}
        async getPublicKey() { return 'pubKey' }
        async signPubKeySignature(data) { return `false signature '${data}'` }
        static async verifyIdentity(data) { return false }
        static get type () { return 'fake' }
      }

      IdentityProviders.addIdentityProvider(FAKEIP)
      identity = await IdentityProviders.createIdentity({ type: FAKEIP.type, keystore })
      const data = identity.publicKey + identity.pkSignature
      const verified = await IdentityProviders.verifyIdentity(identity)
      assert.equal(verified, false)
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
      assert.equal(signature, expectedSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, identity.type, identity.provider, '<sig>', identity.signatures)

      let err
      try {
        const signature = await identity.provider.sign(modifiedIdentity, data, keystore)
      } catch (e) {
        err = e
      }
      assert.equal(err, `Error: Private signing key not found from Keystore`)
    })
  })

  describe('verify data signed by an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity
    let signature
    let signingKey
    let expectedSignature

    beforeEach(async () => {
      signingKey = await keystore.getKey(id)
      expectedSignature = await keystore.sign(signingKey, data)

      identity = await IdentityProviders.createIdentity({ id, type, keystore })
      signature = await identity.provider.sign(identity, data, keystore)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identity.provider.verify(signature, identity.publicKey, data)
      assert.equal(verified, true)
    })

    it('doesn\'t verify invalid signature', async () => {
      const verified = await identity.provider.verify('invalid', identity.publicKey, data)
      assert.equal(verified, false)
    })
  })
})
