'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const IdentityProvider = require('../src/identity-provider')
const EthIdentityProvider = require('../src/ethereum-identity-provider')
const Identity = require('../src/identity')
const keypath = path.resolve('./test/keys')
let keystore

const type = EthIdentityProvider.type
describe('Ethereum Identity Provider', function () {
  before(async () => {
    rmrf.sync(keypath)
    IdentityProvider.addIdentityProvider(EthIdentityProvider)
    keystore = Keystore.create(keypath)
  })

  describe('create an ethereum identity', () => {
    let identity
    let wallet, id

    before(async () => {
      wallet = await EthIdentityProvider.createWallet()
      id = wallet.address
      identity = await IdentityProvider.createIdentity({ type, keystore, wallet })
    })

    it('has the correct id', async () => {
      assert.strict.equal(identity.id, wallet.address)
    })

    it('created a key for id in keystore', async () => {
      const key = await keystore.getKey(id)
      assert.notStrictEqual(key, undefined)
    })

    it('has the correct public key', async () => {
      const signingKey = await keystore.getKey(id)
      assert.notStrictEqual(signingKey, undefined)
      assert.strict.equal(identity.publicKey, signingKey.getPublic('hex'))
    })

    it('has a signature for the id', async () => {
      const signingKey = await keystore.getKey(id)
      const idSignature = await keystore.sign(signingKey, id)
      const verifies = await keystore.verify(idSignature, signingKey.getPublic('hex'), id)
      assert.strict.equal(verifies, true)
      assert.strict.equal(identity.signatures.id, idSignature)
    })

    it('has a signature for the publicKey', async () => {
      const signingKey = await keystore.getKey(id)
      const idSignature = await keystore.sign(signingKey, id)
      const publicKeyAndIdSignature = await wallet.signMessage(identity.publicKey + idSignature)
      assert.strict.equal(identity.signatures.publicKey, publicKeyAndIdSignature)
    })
  })

  describe('verify identity', () => {
    let identity
    let wallet

    before(async () => {
      wallet = await EthIdentityProvider.createWallet()
      identity = await IdentityProvider.createIdentity({ keystore, type, wallet })
    })

    it('ethereum identity verifies', async () => {
      const verified = await IdentityProvider.verifyIdentity(identity, { wallet })
      assert.strict.equal(verified, true)
    })

    it('ethereum identity with incorrect id does not verify', async () => {
      let identity2 = new Identity('NotAnId', identity.publicKey, identity.signatures.id, identity.signatures.publicKey, identity.type, identity.provider)
      const verified = await IdentityProvider.verifyIdentity(identity2, { wallet })
      assert.strict.equal(verified, false)
    })
  })

  describe('sign data with an identity', () => {
    let identity
    let wallet
    const data = 'hello friend'

    before(async () => {
      wallet = await EthIdentityProvider.createWallet()
      identity = await IdentityProvider.createIdentity({ keystore, type, wallet })
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(wallet.address)
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

    describe('verify data signed by an identity', () => {
      const data = 'hello friend'
      let identity
      let signature

      before(async () => {
        identity = await IdentityProvider.createIdentity({ type, wallet, keystore })
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
})
