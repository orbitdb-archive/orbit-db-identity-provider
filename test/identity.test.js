'use strict'

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
let keystore, key

describe('Identity', function() {
  before(() => {
  })

  after(() => {
  })

  const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
  const publicKey = '<pubkey>'
  const pkSignature = 'signature for <id>'
  const signature = 'signature for <pkSignature + publicKey>'
  const type = 'odb'
  const provider = 'IdentityProviderInstance'

  let identity

  before(async () => {
    identity = new Identity(id, publicKey, pkSignature, signature, type, provider)
  })

  it('has the correct id', async () => {
    assert.equal(identity.id, id)
  })

  it('has the correct publicKey', async () => {
    assert.equal(identity.publicKey, publicKey)
  })

  it('has the correct pkSignature', async () => {
    assert.equal(identity.pkSignature, pkSignature)
  })

  it('has the correct signature', async () => {
    assert.equal(identity.signature, signature)
  })

  it('has the correct provider', async () => {
    assert.deepEqual(identity.provider, provider)
  })

  it('converts identity to a JSON object', async () => {
    const expected = {
      id: id,
      publicKey: publicKey,
      pkSignature: pkSignature,
      signature: signature,
      type: type
    }
    assert.deepEqual(identity.toJSON(), expected)
  })

  describe('Constructor inputs', () => {
    it('throws and error if id was not given in constructor', async () => {
      let err
      try {
        identity = new Identity()
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Identity id is required")
    })

    it('throws and error if publicKey was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc')
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Invalid public key")
    })

    it('throws and error if identity signature was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Signature of the id (pkSignature) is required")
    })

    it('throws and error if identity signature was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, pkSignature)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Signature is required")
    })

    it('throws and error if identity provider was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, pkSignature, signature, type)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Identity provider is required")
    })

    it('throws and error if identity type was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, pkSignature, signature, null, provider)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Identity type is required")
    })
  })
})
