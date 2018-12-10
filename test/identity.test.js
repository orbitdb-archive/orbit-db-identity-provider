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
  const idSignature = 'signature for <id>'
  const publicKeyAndIdSignature = 'signature for <publicKey + idSignature>'
  const type = 'orbitdb'
  const provider = 'IdentityProviderInstance'

  let identity

  before(async () => {
    identity = new Identity(id, publicKey, type, provider, idSignature, publicKeyAndIdSignature)
  })

  it('has the correct id', async () => {
    assert.equal(identity.id, id)
  })

  it('has the correct publicKey', async () => {
    assert.equal(identity.publicKey, publicKey)
  })

  it('has the correct idSignature', async () => {
    assert.equal(identity.signatures.id, idSignature)
  })

  it('has the correct publicKeyAndIdSignature', async () => {
    assert.equal(identity.signatures.publicKey, publicKeyAndIdSignature)
  })

  it('has the correct provider', async () => {
    assert.deepEqual(identity.provider, provider)
  })

  it('converts identity to a JSON object', async () => {
    const expected = {
      id: id,
      publicKey: publicKey,
      type: type,
      signatures: { id: idSignature, publicKey: publicKeyAndIdSignature }
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

    it('throws and error if identity provider was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, type)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Identity provider is required")
    })

    it('throws and error if identity type was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, null, provider)
      } catch (e) {
        err = e
      }
      assert.equal(err, "Error: Identity type is required")
    })
  })
})
