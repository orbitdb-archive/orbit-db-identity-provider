'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const Identities = require('../src/identities')
const Identity = require('../src/identity')
const fixturesPath = path.resolve('./test/fixtures/keys')
const savedKeysPath = path.resolve('./test/fixtures/savedKeys')
const signingKeysPath = path.resolve('./test/signingKeys')
const identityKeysPath = path.resolve('./test/identityKeys')
const migrate = require('localstorage-level-migration')
const fs = require('fs-extra')

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
    await identityKeystore.close()
    rmrf.sync(signingKeysPath)
    rmrf.sync(identityKeysPath)
  })

  describe('create an identity', () => {
    describe('create a new identity', () => {
      let id = 'A'
      let identity, externalId

      before(async () => {
        identity = await Identities.createIdentity({ id, signingKeysPath, keystore: identityKeystore })
        keystore = identity.provider._keystore
        let key = await identityKeystore.getKey(id)
        externalId = key.public.marshal().toString('hex')
      })

      after(async () => {
        await keystore.close()
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
        assert.strictEqual(identity.publicKey, keystore.getPublic(signingKey))
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

      const expectedPublicKey = '040d78ff62afb656ac62db1aae3b1536a614991e28bb4d721498898b7d4194339640cd18c37b259e2c77738de0d6f9a5d52e0b936611de6b6ba78891a8b2a38317'
      const expectedIdSignature = '30450221009de7b91952d73f577e85962aa6301350865212e3956862f80f4ebb626ffc126b022027d57415fb145b7e06cf06320fbfa63ea98a958b065726fe86eaab809a6bf607'
      const expectedPkIdSignature = '304402202806e7c2406ca1f35961d38adc3997c179e142d54e1ca838ace373fae27124fd02200d6ca3aea6e1341bf5e4e0b84b559bbeefecfade34115de266a69d04d924905e'

      before(async () => {
        await fs.copy(fixturesPath, savedKeysPath)
        savedKeysKeystore = Keystore.create(savedKeysPath)
        identity = await Identities.createIdentity({ id, keystore: savedKeysKeystore, identityKeysPath: savedKeysPath })
      })

      after(async () => {
        rmrf.sync(savedKeysPath)
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
      identity = await Identities.createIdentity({ id, type, keystore:  identityKeystore })
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

  describe('create identity from existing keys', () => {
    let source = fixturesPath + '/QmPhnEjVkYE1Ym7F5MkRUfkD6NtuSptE7ugu1Ggr149W2X'
    let publicKey = '045756c20f03ec494d07e8dd8456f67d6bd97ca175e6c4882435fe364392f131406db3a37eebe1d634b105a57b55e4f17247c1ec8ffe04d6a95d1e0ee8bed7cfbd'
    let identity

    before(async () => {
      identity = await Identities.createIdentity({ id: 'A', migrate: migrate(source) })
    })

    it('creates identity with correct public key', async () => {
      assert.equal(identity.publicKey, publicKey)
    })

    it('verifies signatures signed by existing key', async () => {
      const sig = '3045022067aa0eacf268ed8a94f07a1f352f8e4e03f2168e75896aaa18709bc759cd8f41022100e9f9b281a0873efb86d52aef647d8dedc6e3e4e383c8a82258a9e1da78bf2057'
      const ver = await identity.provider.verify(sig, identity.publicKey, 'signme', 'v0')
      assert.equal(ver, true)
    })
  })
})
