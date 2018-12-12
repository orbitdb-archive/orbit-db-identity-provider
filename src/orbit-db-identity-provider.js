'use strict'
const IdentityProvider = require('./identity-provider')
const Keystore = require('orbit-db-keystore')
const keypath = './orbitdb/identity/keys'
const type = 'orbitdb'

class OrbitDBIdentityProvider extends IdentityProvider {
  constructor (options = {}) {
    super()
    this._keystore = Keystore.create(options.keypath || keypath)
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

  static async verifyIdentity (identity) {
    // Verify that identity was signed by the ID
    return Keystore.verify(
      identity.signatures.publicKey,
      identity.id,
      identity.publicKey + identity.signatures.id
    )
  }
}

module.exports = OrbitDBIdentityProvider
