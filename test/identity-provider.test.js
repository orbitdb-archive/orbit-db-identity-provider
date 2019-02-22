'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const Identities = require('../src/identities')
const Identity = require('../src/identity')
const savedKeysPath = path.resolve('./test/fixtures/keys')
const signingKeysPath = path.resolve('./test/signingKeys')
const identityKeysPath = path.resolve('./test/identityKeys')
let keystore, identityKeystore

const type = 'orbitdb'

describe('Identity Provider', function () {
  before(async () => {
    rmrf.sync(signingKeysPath)
    rmrf.sync(identityKeysPath)
    identityKeystore = Keystore.create(identityKeysPath)
  })

  after(async () => {
    // Remove stored keys
    rmrf.sync(signingKeysPath)
    rmrf.sync(identityKeysPath)
  })

  describe('create an identity', () => {
    describe('create a new identity', () => {
      let id = 'A'
      let identity, externalId

      before(async () => {
        identity = await Identities.createIdentity({ id, signingKeysPath, identityKeysPath })
        keystore = identity.provider._keystore
        let key = await identityKeystore.getKey(id)
        externalId = key.public.marshal().toString('hex')
      })

      it('has the correct id', async () => {
        assert.strictEqual(identity.id, externalId)
      })

      it('created a key for id in identity-keystore', async () => {
        const key = await identityKeystore.getKey(id)
        assert.notStrictEqual(key, undefined)
      })

      it('has the correct public key', async () => {
        const signingKey = await keystore.getKey(externalId)
        assert.notStrictEqual(signingKey, undefined)
        assert.strictEqual(identity.publicKey, signingKey.public.marshal().toString('hex'))
      })

      it('has a signature for the id', async () => {
        const signingKey = await keystore.getKey(externalId)
        const idSignature = await keystore.sign(signingKey, externalId)
        const publicKey = signingKey.public.marshal().toString('hex')
        const verifies = await Keystore.verify(idSignature, publicKey, externalId)
        assert.strictEqual(verifies, true)
        assert.strictEqual(identity.signatures.id, idSignature)
      })

      it('has a signature for the publicKey', async () => {
        const signingKey = await keystore.getKey(externalId)
        const idSignature = await keystore.sign(signingKey, externalId)
        const externalKey = await identityKeystore.getKey(id)
        const publicKeyAndIdSignature = await keystore.sign(externalKey, identity.publicKey + idSignature)
        assert.strictEqual(identity.signatures.publicKey, publicKeyAndIdSignature)
      })
    })

    describe('create an identity with saved keys', () => {
      let savedKeysKeystore, identity
      let id = 'QmPhnEjVkYE1Ym7F5MkRUfkD6NtuSptE7ugu1Ggr149W2X'

      const expectedPublicKey = '024f8502e981273322b4e500e97f80343b9370bc36ceddfa5f13d40b0b1ff64c76'
      const expectedIdSignature = '3045022100e51a3e11ba10bf5019a38c24f4c22e8cde0c6caa1059c9deacda30e7b8dc40bb02206ccfa7d8422ed206b72287a76285537d4bb27cc4c73ca058c944bf8eaa53b270'
      const expectedPkIdSignature = '3045022100844a34c852240a8731f51406a780c3b9756e700530ff14136fd7f9563188f6340220592116cedc868908317323dc9a973e91c62224face22727e58c48ecea505dfb8'

      before(async () => {
        savedKeysKeystore = Keystore.create(savedKeysPath)
        identity = await Identities.createIdentity({ id, keystore: savedKeysKeystore, identityKeysPath: savedKeysPath })
      })

      it('has the correct id', async () => {
        let key = await savedKeysKeystore.getKey(id)
        assert.strictEqual(identity.id, key.public.marshal().toString('hex'))
      })

      it('has the correct public key', async () => {
        assert.strictEqual(identity.publicKey, expectedPublicKey)
      })

      it('has the correct identity type', async () => {
        assert.strictEqual(identity.type, type)
      })

      it('has the correct idSignature', async () => {

        assert.strictEqual(identity.signatures.id, expectedIdSignature)
      })

      it('has a pubKeyIdSignature for the publicKey', async () => {
        assert.strictEqual(identity.signatures.publicKey, expectedPkIdSignature)
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
      identity = await Identities.createIdentity({ id, type })
      const verified = await Keystore.verify(identity.signatures.id, identity.publicKey, identity.id)
      assert.strictEqual(verified, true)
    })

    it('identity signature verifies', async () => {
      identity = await Identities.createIdentity({ id, type, keystore })
      const verified = await Keystore.verify(identity.signatures.publicKey, identity.id, identity.publicKey + identity.signatures.id)
      assert.strictEqual(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      class IP {
        async getId () { return 'pubKey' }
        async signIdentity (data) { return `false signature '${data}'` }
        static async verifyIdentity (data) { return false }
        static get type () { return 'fake' }
      }

      Identities.addIdentityProvider(IP)
      identity = await Identities.createIdentity({ type: IP.type, keystore })
      const verified = await Identities.verifyIdentity(identity)
      assert.strictEqual(verified, false)
    })
  })

  describe('verify identity', () => {
    const id = 'QmFoo'
    let identity

    it('identity verifies', async () => {
      identity = await Identities.createIdentity({ id, type, keystore })
      const verified = await identity.provider.verifyIdentity(identity)
      assert.strictEqual(verified, true)
    })
  })

  describe('sign data with an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity

    before(async () => {
      identity = await Identities.createIdentity({ id, keystore })
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(identity.id)
      const expectedSignature = await keystore.sign(signingKey, data)
      const signature = await identity.provider.sign(identity, data, keystore)
      assert.strictEqual(signature, expectedSignature)
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
      assert.strictEqual(signature, undefined)
      assert.strictEqual(err, `Error: Private signing key not found from Keystore`)
    })
  })

  describe('verify data signed by an identity', () => {
    const id = '03602a3da3eb35f1148e8028f141ec415ef7f6d4103443edbfec2a0711d716f53f'
    const data = 'hello friend'
    let identity
    let signature

    beforeEach(async () => {
      identity = await Identities.createIdentity({ id, type, keystore })
      signature = await identity.provider.sign(identity, data, keystore)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identity.provider.verify(signature, identity.publicKey, data)
      assert.strictEqual(verified, true)
    })

    it('doesn\'t verify invalid signature', async () => {
      const verified = await identity.provider.verify('invalid', identity.publicKey, data)
      assert.strictEqual(verified, false)
    })
  })
})
