'use strict'
const IdentityProviderInterface = require('./identity-provider-interface')
const Keystore = require('orbit-db-keystore')
const keypath = './orbitdb/identity/keys'
const type = 'orbitdb'

class OrbitDBIdentityProvider extends IdentityProviderInterface {
  constructor (options = {}) {
    super()
    this._keystore = options.keystore || Keystore.create(options.keypath || keypath)
  }

  // Returns the type of the identity provider
  static get type () { return type }

  async getId (options = {}) {
    const id = options.id
    if (!id) {
      throw new Error('id is required')
    }

    const keystore = this._keystore
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    return key.getPublic('hex')
  }

  async signIdentity (pubKeyIdSig, options = {}) {
    const id = options.id
    if (!id) {
      throw new Error('id is required')
    }
    const keystore = this._keystore
    const key = await keystore.getKey(id)
    if (!key) {
      throw new Error(`Signing key for '${id}' not found`)
    }
    return keystore.sign(key, pubKeyIdSig)
  }

  static async verifyIdentity (identity, options = {}) {
    // Verify that identity was signed by the ID
    const keystore = options.keystore || options.provider._keystore
    const verified = await keystore.verify(
      identity.signatures.publicKey,
      identity.id,
      identity.publicKey + identity.signatures.id
    )
    return verified
  }
}

module.exports = OrbitDBIdentityProvider
