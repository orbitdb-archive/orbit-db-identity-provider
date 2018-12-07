/* eslint-disable no-unused-vars */
'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const mkdirp = require('mkdirp')
const LocalStorage = require('node-localstorage').LocalStorage
const Keystore = require('orbit-db-keystore')
const IdentityProvider = require('../src/identity-provider')
const Identity = require('../src/identity')
const { Wallet } = require('ethers')
const savedKeysPath = path.resolve('./test/fixtures/keys')
const testKeysPath = path.resolve('./test/keys')
let keystore

describe('Identity Provider', function () {
  const type = 'orbitdb'
  const identitySignerFn = async (id, data) => {
    const key = await keystore.getKey(id)
    return keystore.sign(key, data)
  }

  const identityVerifierFn = async (identity) => {
    return keystore.verify(identity.signatures.publicKey, identity.publicKey, identity.publicKey + identity.signatures.id)
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

  describe('constructor', () => {
    it('throws an error if keystore is not given as a constructor argument', async () => {
      let err
      try {
        identity = new IdentityProvider() // eslint-disable-line
      } catch (e) {
        err = e
      }
      assert.strictEqual(err.message, 'Keystore is required')
    })
  })

  describe('create an identity', () => {
    describe('create a new identity', () => {
      const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
      let identity

      before(async () => {
        identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
      })

      it('has the correct id', async () => {
        assert.strictEqual(identity.id, id)
      })

      it('created a key for id in keystore', async () => {
        const key = await keystore.getKey(id)
        assert.notStrictEqual(key, undefined)
      })

      it('has the correct public key', async () => {
        const signingKey = await keystore.getKey(id)
        assert.notStrictEqual(signingKey, undefined)
        assert.strictEqual(identity.publicKey, signingKey.getPublic('hex'))
      })

      it('has a signature for the id', async () => {
        const signingKey = await keystore.getKey(id)
        const idSignature = await keystore.sign(signingKey, id)
        const verifies = await keystore.verify(idSignature, signingKey.getPublic('hex'), id)
        assert.strictEqual(verifies, true)
        assert.strictEqual(identity.signatures.id, idSignature)
      })

      it('has a signature for the publicKey', async () => {
        const signingKey = await keystore.getKey(id)
        const idSignature = await keystore.sign(signingKey, id)
        const publicKeyAndIdSignature = await keystore.sign(signingKey, identity.publicKey + idSignature)
        assert.strictEqual(identity.signatures.publicKey, publicKeyAndIdSignature)
      })

      it('defaults to Keystore.sign as default identity signer', async () => {
        let savedKeysKeystore = Keystore.create(savedKeysPath)

        const expectedPublicKey = '0474eee0310cd3ea85528c0305e7ab39f410437eebaf794bddbac97869d82f0abbfc7089c6a41a3ed7e3343831c264b18003454042788e5af7aca5684ff225f78c'
        const expectedPkSignature = '3045022100b76e40b9aaf005eedc76703ad5a22753f0bfe244f4b4c63fd0082141cf69b11d0220328ac530ef665cf2619e85e5e39c15f8e8c7856b2f56c7a10863fc09407e7919'
        const expectedSignature = '3046022100f07c401bf4f598f41042bb34b45f311b942cafe46890a753eee27dcd5e85d565022100f0755c52cfcfc94a97858768ba07de71bbc4637e02ef886db9843f3aba80b610'
        const identitySignerFn = (key, data) => {
          return expectedSignature
        }

        identity = await IdentityProvider.createIdentity(savedKeysKeystore, id)
        assert.strictEqual(identity.id, id)
        assert.strictEqual(identity.publicKey, expectedPublicKey)
        assert.strictEqual(identity.signatures.id, expectedPkSignature)
        assert.strictEqual(identity.signatures.publicKey, expectedSignature)
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
          return savedKeysKeystore.sign(key, data)
        }
        identity = await IdentityProvider.createIdentity(savedKeysKeystore, id, { type, identitySignerFn })
      })

      it('has the correct id', async () => {
        assert.strictEqual(identity.id, id)
      })

      it('has the correct public key', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        assert.strictEqual(identity.publicKey, expectedPublicKey)
      })

      it('has the correct public key', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        assert.strictEqual(identity.publicKey, expectedPublicKey)
      })

      it('has the correct identity type', async () => {
        assert.strictEqual(identity.type, type)
      })

      it('has the correct idSignature', async () => {
        const expectedIdSignature = '3045022100b76e40b9aaf005eedc76703ad5a22753f0bfe244f4b4c63fd0082141cf69b11d0220328ac530ef665cf2619e85e5e39c15f8e8c7856b2f56c7a10863fc09407e7919'
        const signingKey = await savedKeysKeystore.getKey(id)
        const idSignature = await savedKeysKeystore.sign(signingKey, id)
        assert.strictEqual(idSignature, expectedIdSignature)
      })

      it('has a pubKeyIdSignature for the publicKey', async () => {
        const signingKey = await savedKeysKeystore.getKey(id)
        const pubKeyIdSignature = await savedKeysKeystore.sign(signingKey, identity.publicKey + identity.signatures.id)
        assert.strictEqual(identity.signatures.publicKey, pubKeyIdSignature)
      })

      it('has the correct signatures', async () => {
        const expectedSignature = {
          id: '3045022100b76e40b9aaf005eedc76703ad5a22753f0bfe244f4b4c63fd0082141cf69b11d0220328ac530ef665cf2619e85e5e39c15f8e8c7856b2f56c7a10863fc09407e7919',
          publicKey: '3046022100f07c401bf4f598f41042bb34b45f311b942cafe46890a753eee27dcd5e85d565022100f0755c52cfcfc94a97858768ba07de71bbc4637e02ef886db9843f3aba80b610'
        }
        const signingKey = await savedKeysKeystore.getKey(id)
        const idSignature = await savedKeysKeystore.sign(signingKey, id)
        const pubKeyIdSignature = await savedKeysKeystore.sign(signingKey, signingKey.getPublic('hex') + idSignature)
        assert.deepStrictEqual(identity.signatures, expectedSignature)
      })
    })
  })

  describe('verify identity\'s signature', () => {
    const id = 'QmFoo'
    let identity

    it('identity pkSignature verifies', async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
      const verified = await keystore.verify(identity.signatures.id, identity.publicKey, id)
      assert.strictEqual(verified, true)
    })

    it('identity signature verifies', async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
      const data = identity.publicKey + identity.signatures.id
      const verified = await keystore.verify(identity.signatures.publicKey, identity.publicKey, data)
      assert.strictEqual(verified, true)
    })

    it('false signature doesn\'t verify', async () => {
      const signer = {
        sign: (key, data) => `false signature '${data}'`
      }
      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn: signer.sign })
      const data = identity.publicKey + identity.pkSignature
      const verified = await keystore.verify(identity.signatures, identity.publicKey, data)
      assert.strictEqual(verified, false)
    })
  })

  describe('verify identity', () => {
    const id = 'QmFoo'
    let identity

    it('identity verifies', async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
      const verified = await IdentityProvider.verifyIdentity(identity, identityVerifierFn)
      assert.strictEqual(verified, true)
    })
  })

  describe('sign data with an identity', () => {
    const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
    const data = 'hello friend'
    let identity

    beforeEach(async () => {
      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
    })

    it('sign data', async () => {
      const signingKey = await keystore.getKey(id)
      const expectedSignature = await keystore.sign(signingKey, data)
      const signature = await identity.provider.sign(identity, data, keystore)
      assert.strictEqual(signature, expectedSignature)
    })

    it('throws an error if private key is not found from keystore', async () => {
      // Remove the key from the keystore (we're using a mock storage in these tests)
      const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signatures, identity.type, identity.provider)

      let err
      try {
        const signature = await identity.provider.sign(modifiedIdentity, data, keystore)
      } catch (e) {
        err = e
      }
      assert.strictEqual(err.message, `Private signing key not found from Keystore`)
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

      identity = await IdentityProvider.createIdentity(keystore, id, { type, identitySignerFn })
      signature = await identity.provider.sign(identity, data, keystore)
    })

    it('verifies that the signature is valid', async () => {
      const verified = await identity.provider.verify(signature, identity.publicKey, data, keystore)
      assert.strictEqual(verified, true)
    })

    it('doesn\'t verify invalid signature', async () => {
      const verified = await identity.provider.verify('invalid', identity.publicKey, data, keystore)
      assert.strictEqual(verified, false)
    })
  })

  describe('verify identity created with ethers wallet', () => {
    let identity
    let wallet
    let privKey = '0x3141592653589793238462643383279502884197169399375105820974944592'

    const identitySignerFn = async (id, data) => {
      return wallet.signMessage(data)
    }

    const identityVerifierFn = async (identity) => {
      const signerAddress = Wallet.verifyMessage(identity.publicKey + identity.signatures.id, identity.signatures.publicKey)
      return (signerAddress === identity.id)
    }

    before(async () => {
      wallet = new Wallet(privKey)
      identity = await IdentityProvider.createIdentity(keystore, wallet.address, { type: 'ethers', identitySignerFn })
    })

    it('ethers identity verifies', async () => {
      const verified = await IdentityProvider.verifyIdentity(identity, identityVerifierFn)
      assert.strictEqual(verified, true)
    })

    it('ethers identity with incorrect id does not verify', async () => {
      let identity2 = await IdentityProvider.createIdentity(keystore, 'NotWalletAddress', { type: 'ethers', identitySignerFn })
      const verified = await IdentityProvider.verifyIdentity(identity2, identityVerifierFn)
      assert.strictEqual(verified, false)
    })
  })
})
