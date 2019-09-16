'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const Identities = require('../src/identities')
const EthIdentityProvider = require('../src/ethereum-identity-provider')
const Identity = require('../src/identity')
const keypath = path.resolve('./test/keys')

const implementations = require('orbit-db-test-utils/implementations')

const properLevelModule = implementations.filter(i => i.key.indexOf('level') > -1).map(i => i.module)[0]
const storage = require('orbit-db-storage-adapter')(properLevelModule)

let keystore, store

const type = EthIdentityProvider.type
describe('Ethereum Identity Provider', function () {
  before(async () => {
    rmrf.sync(keypath)
    Identities.addIdentityProvider(EthIdentityProvider)
    store = await storage.createStore(keypath)
    keystore = new Keystore(store)
  })

  after(async () => {
    await keystore.close()
    rmrf.sync(keypath)
  })

  describe('create an ethereum identity', () => {
    let identityProvider, identity
    let wallet

    before(async () => {
      const ethIdentityProvider = new EthIdentityProvider()
      wallet = await ethIdentityProvider._createWallet()
      identityProvider = new Identities()
      identity = await identityProvider.createIdentity(keystore, { type, wallet })
    })

    it('has the correct id', async () => {
      assert.strictEqual(identity.id, wallet.address)
    })

    it('created a key for id in keystore', async () => {
      const key = await keystore.getKey(wallet.address)
      assert.notStrictEqual(key, undefined)
    })

    it('has the correct public key', async () => {
      const signingKey = await keystore.getKey(wallet.address)
      assert.notStrictEqual(signingKey, undefined)
      assert.strictEqual(identity.publicKey, keystore.getPublic(signingKey))
    })

    it('has a signature for the id', async () => {
      const signingKey = await keystore.getKey(wallet.address)
      const idSignature = await keystore.sign(signingKey, wallet.address)
      const verifies = await Keystore.verify(idSignature, signingKey.public.marshal().toString('hex'), wallet.address)
      assert.strictEqual(verifies, true)
      assert.strictEqual(identity.signatures.id, idSignature)
    })

    it('has a signature for the publicKey', async () => {
      const signingKey = await keystore.getKey(wallet.address)
      const idSignature = await keystore.sign(signingKey, wallet.address)
      const publicKeyAndIdSignature = await wallet.signMessage(identity.publicKey + idSignature)
      assert.strictEqual(identity.signatures.publicKey, publicKeyAndIdSignature)
    })
  })

  describe('verify identity', () => {
    let identityProvider, identity

    before(async () => {
      identityProvider = new Identities()
      identity = await identityProvider.createIdentity(keystore, { type })
    })

    it('ethereum identity verifies', async () => {
      const verified = await Identities.verifyIdentity(identity, keystore)
      assert.strictEqual(verified, true)
    })

    it('ethereum identity with incorrect id does not verify', async () => {
      const identity2 = new Identity('NotAnId', identity.publicKey, identity.signatures.id, identity.signatures.publicKey, identity.type)
      const verified = await Identities.verifyIdentity(identity2, keystore)
      assert.strictEqual(verified, false)
    })
  })

  describe('sign data with an identity', () => {
    let identityProvider, identity
    const data = 'hello friend'

    before(async () => {
      identityProvider = new Identities()
      identity = await identityProvider.createIdentity(keystore, { type })
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(identity.id)
      const expectedSignature = await keystore.sign(signingKey, data)
      const signature = await identityProvider.sign(identity, data, keystore)
      assert.strictEqual(signature, expectedSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signatures, identity.type)
      let signature
      let err
      try {
        signature = await identityProvider.sign(modifiedIdentity, data, keystore)
      } catch (e) {
        err = e.toString()
      }
      assert.strictEqual(signature, undefined)
      assert.strictEqual(err, `Error: Private signing key not found from Keystore`)
    })

    describe('verify data signed by an identity', () => {
      const data = 'hello friend'
      let identityProvider, identity
      let signature

      before(async () => {
        identityProvider = new Identities()
        identity = await identityProvider.createIdentity(keystore, { type })
        signature = await identityProvider.sign(identity, data, keystore)
      })

      it('verifies that the signature is valid', async () => {
        const verified = await keystore.verify(signature, identity.publicKey, data)
        assert.strictEqual(verified, true)
      })
    })
  })
})
