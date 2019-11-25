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

const { defaultStorage } = require('orbit-db-test-utils')

const storage = defaultStorage

const type = 'orbitdb'

describe('Identity Provider', function () {
  before(async () => {
    rmrf.sync(signingKeysPath)
    rmrf.sync(identityKeysPath)
  })

  after(async () => {
    rmrf.sync(signingKeysPath)
    rmrf.sync(identityKeysPath)
  })

  describe('Creating Identities', () => {
    const id = 'A'
    let identities, identity, keystore, signingKeystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      keystore = new Keystore(identityStore)
      const signingStore = await storage.createStore(signingKeysPath)
      signingKeystore = new Keystore(signingStore)
      identities = new Identities({ keystore })
    })

    it('identityKeysPath only - has the correct id', async () => {
      identity = await identities.createIdentity({ id })
      const key = await identities.keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      assert.strictEqual(identity.id, externalId)
    })

    it('identityKeysPath and signingKeysPath - has a different id', async () => {
      identity = await identities.createIdentity({ id, signingKeystore })
      const key = await identities.keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      assert.notStrictEqual(identity.id, externalId)
    })

    after(async () => {
      await keystore.close()
      await signingKeystore.close()
    })
  })

  describe('Passing in custom keystore', async () => {
    const id = 'B'
    let identities, identity
    let keystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      keystore = new Keystore(identityStore)
    })

    it('has the correct id', async () => {
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id })
      const key = await keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      assert.strictEqual(identity.id, externalId)
    })

    it('created a key for id in identity-keystore', async () => {
      const key = await keystore.getKey(id)
      assert.notStrictEqual(key, undefined)
    })

    it('has the correct public key', async () => {
      const key = await keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      const signingKey = await keystore.getKey(externalId)
      assert.notStrictEqual(signingKey, undefined)
      assert.strictEqual(identity.publicKey, keystore.getPublic(signingKey))
    })

    it('has a signature for the id', async () => {
      const key = await keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      const signingKey = await keystore.getKey(externalId)
      const idSignature = await keystore.sign(signingKey, externalId)
      const publicKey = signingKey.public.marshal().toString('hex')
      const verifies = await Keystore.verify(idSignature, publicKey, externalId)
      assert.strictEqual(verifies, true)
      assert.strictEqual(identity.signatures.id, idSignature)
    })

    it('has a signature for the publicKey', async () => {
      const key = await keystore.getKey(id)
      const externalId = key.public.marshal().toString('hex')
      const signingKey = await keystore.getKey(externalId)
      const idSignature = await keystore.sign(signingKey, externalId)
      const externalKey = await keystore.getKey(id)
      const publicKeyAndIdSignature = await keystore.sign(externalKey, identity.publicKey + idSignature)
      assert.strictEqual(identity.signatures.publicKey, publicKeyAndIdSignature)
    })

    after(async () => {
      await keystore.close()
    })
  })

  describe('create an identity with saved keys', () => {
    let savedKeysKeystore, identities, identity
    const id = 'QmPhnEjVkYE1Ym7F5MkRUfkD6NtuSptE7ugu1Ggr149W2X'

    const expectedPublicKey = '040d78ff62afb656ac62db1aae3b1536a614991e28bb4d721498898b7d4194339640cd18c37b259e2c77738de0d6f9a5d52e0b936611de6b6ba78891a8b2a38317'
    const expectedIdSignature = '30450221009de7b91952d73f577e85962aa6301350865212e3956862f80f4ebb626ffc126b022027d57415fb145b7e06cf06320fbfa63ea98a958b065726fe86eaab809a6bf607'
    const expectedPkIdSignature = '304402202806e7c2406ca1f35961d38adc3997c179e142d54e1ca838ace373fae27124fd02200d6ca3aea6e1341bf5e4e0b84b559bbeefecfade34115de266a69d04d924905e'

    before(async () => {
      await fs.copy(fixturesPath, savedKeysPath)
      const savedKeysStore = await storage.createStore(savedKeysPath)
      savedKeysKeystore = new Keystore(savedKeysStore)
      identities = new Identities({ keystore: savedKeysKeystore })
      identity = await identities.createIdentity({ id })
    })

    after(async () => {
      rmrf.sync(savedKeysPath)
    })

    it('has the correct id', async () => {
      const key = await savedKeysKeystore.getKey(id)
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

    after(async () => {
      await savedKeysKeystore.close()
    })
  })

  describe('verify identity\'s signature', () => {
    const id = 'QmFoo'
    let identities, identity, keystore, signingKeystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      const signingStore = await storage.createStore(signingKeysPath)
      keystore = new Keystore(identityStore)
      signingKeystore = new Keystore(signingStore)
    })

    it('identity pkSignature verifies', async () => {
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, type, signingKeystore })
      const verified = await Keystore.verify(identity.signatures.id, identity.publicKey, identity.id)
      assert.strictEqual(verified, true)
    })

    it('identity signature verifies', async () => {
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, type, signingKeystore })
      const verified = await Keystore.verify(identity.signatures.publicKey, identity.id, identity.publicKey + identity.signatures.id)
      assert.strictEqual(verified, true)
    })

    it('identity provider verifies identity', async () => {
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, type, signingKeystore })
      const verified = await identities.verifyIdentity(identity)
      assert.strictEqual(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      identity = await identities.createIdentity({ id: 'A' })
      identity.signatures.publicKey = 'fake'
      const verified = await identities.verifyIdentity(identity)
      assert.strictEqual(verified, false)
    })

    after(async () => {
      await keystore.close()
      await signingKeystore.close()
    })
  })

  describe('verify identity', () => {
    const id = 'QmFoo'
    let identities, identity, keystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      keystore = new Keystore(identityStore)
    })

    it('identity verifies', async () => {
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, type })
      const verified = await identities.verifyIdentity(identity)
      assert.strictEqual(verified, true)
    })

    after(async () => {
      await keystore.close()
    })
  })

  describe('sign data with identities', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identities, identity, keystore, signingKeystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      const signingStore = await storage.createStore(signingKeysPath)
      keystore = new Keystore(identityStore)
      signingKeystore = new Keystore(signingStore)
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, signingKeystore })
    })

    it('sign data', async () => {
      const expectedIdSignature = await identities.sign(identity, identity.id)

      const pkSigningKey = await signingKeystore.getKey(id)
      const expectedPkSignature = await signingKeystore.sign(pkSigningKey, identity.publicKey + expectedIdSignature)
      assert.strictEqual(identity.signatures.id, expectedIdSignature)
      assert.strictEqual(identity.signatures.publicKey, expectedPkSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signatures, identity.type)
      let signature
      let err
      try {
        signature = await identities.sign(modifiedIdentity, data)
      } catch (e) {
        err = e.toString()
      }
      assert.strictEqual(signature, undefined)
      assert.strictEqual(err, `Error: Private signing key not found from Keystore`)
    })

    after(async () => {
      await keystore.close()
      await signingKeystore.close()
    })
  })

  describe('verify data with identities', () => {
    const id = '03602a3da3eb35f1148e8028f141ec415ef7f6d4103443edbfec2a0711d716f53f'
    const data = 'hello friend'
    let identities, identity, keystore
    let signature

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      keystore = new Keystore(identityStore)
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id, type })
      signature = await identities.sign(identity, data)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identities.verify(signature, identity.publicKey, data)
      assert.strictEqual(verified, true)
    })

    it('doesn not verify invalid signature', async () => {
      const verified = await identities.verify(signature, identity.publicKey, 'bad data')
      assert.strictEqual(verified, false)
    })

    after(async () => {
      await identities.close()
    })
  })

  describe('create identity from existing keys', () => {
    const source = fixturesPath + '/existing'
    const publicKey = '045756c20f03ec494d07e8dd8456f67d6bd97ca175e6c4882435fe364392f131406db3a37eebe1d634b105a57b55e4f17247c1ec8ffe04d6a95d1e0ee8bed7cfbd'
    let identities, identity, keystore

    before(async () => {
      const identityStore = await storage.createStore(identityKeysPath)
      keystore = new Keystore(identityStore)
      identities = new Identities({ keystore })
      identity = await identities.createIdentity({ id: 'A', migrate: migrate(source) })
    })

    it('creates identity with correct public key', async () => {
      assert.strictEqual(identity.publicKey, publicKey)
    })

    it('verifies signatures signed by existing key', async () => {
      const sig = '3045022067aa0eacf268ed8a94f07a1f352f8e4e03f2168e75896aaa18709bc759cd8f41022100e9f9b281a0873efb86d52aef647d8dedc6e3e4e383c8a82258a9e1da78bf2057'
      const ver = await identities.verify(sig, identity.publicKey, 'signme', 'v0')
      assert.strictEqual(ver, true)
    })

    after(async () => {
      await identities.close()
    })
  })
})
