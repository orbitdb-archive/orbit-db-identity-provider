'use strict'

const assert = require('assert')
const Identity = require('../src/identity')

describe('Identity', function () {
  const id = '0x01234567890abcdefghijklmnopqrstuvwxyz'
  const publicKey = '<pubkey>'
  const idSignature = 'signature for <id>'
  const publicKeyAndIdSignature = 'signature for <publicKey + idSignature>'
  const type = 'orbitdb'
  const provider = 'IdentityProviderInstance'

  let identity

  before(async () => {
    identity = new Identity(id, publicKey, idSignature, publicKeyAndIdSignature, type, provider)
  })

  it('has the correct id', async () => {
    assert.strict.equal(identity.id, id)
  })

  it('has the correct publicKey', async () => {
    assert.strict.equal(identity.publicKey, publicKey)
  })

  it('has the correct idSignature', async () => {
    assert.strict.equal(identity.signatures.id, idSignature)
  })

  it('has the correct publicKeyAndIdSignature', async () => {
    assert.strict.equal(identity.signatures.publicKey, publicKeyAndIdSignature)
  })

  it('has the correct provider', async () => {
    assert.deepStrictEqual(identity.provider, provider)
  })

  it('converts identity to a JSON object', async () => {
    const expected = {
      id: id,
      publicKey: publicKey,
      signatures: { id: idSignature, publicKey: publicKeyAndIdSignature },
      type: type
    }
    assert.deepStrictEqual(identity.toJSON(), expected)
  })

  describe('Constructor inputs', () => {
    it('throws and error if id was not given in constructor', async () => {
      let err
      try {
        identity = new Identity()
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Identity id is required')
    })

    it('throws and error if publicKey was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc')
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Invalid public key')
    })

    it('throws and error if identity signature was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey)
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Signature of the id (idSignature) is required')
    })

    it('throws and error if identity signature was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, idSignature)
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Signature of (publicKey + idSignature) is required')
    })

    it('throws and error if identity provider was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, idSignature, publicKeyAndIdSignature, type)
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Identity provider is required')
    })

    it('throws and error if identity type was not given in constructor', async () => {
      let err
      try {
        identity = new Identity('abc', publicKey, idSignature, publicKeyAndIdSignature, null, provider)
      } catch (e) {
        err = e.toString()
      }
      assert.strict.equal(err, 'Error: Identity type is required')
    })
  })
})
