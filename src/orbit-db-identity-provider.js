'use strict'
const IdentityProvider = require('./identity-provider')
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'

class OrbitDBIdentityProvider extends IdentityProvider {
  constructor(options = {}) {
    super()
    this._keystore = options.keystore || Keystore.create(options.keypath || './orbitdb/identity/keys')
  }

  // Returns the type of the identity provider
  static get type () { return type }

  async createId(options = {}) {
    const ipfs = options.ipfs
    if (!ipfs)
      throw new Error('ipfs instance required')

    const keystore = options.keystore || this._keystore
    const { id } = await ipfs.id()
    this.id = id
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    return key.getPublic('hex')
  }

  async signIdentity(pubKeyIdSig, options = {}) {
    const keystore = options.keystore || this._keystore
    const id = this.id
    const key = await keystore.getKey(id)
    if(!key)
      throw new Error(`Signing key for '${id}' not found`)
    return await keystore.sign(key, pubKeyIdSig)
  }

  static async verifyIdentity (identity, options = {}) {
    // Verify that identity was signed by the ID
    const keystore = options.keystore || identity.provider._keystore
    const verified = await keystore.verify(
      identity.signatures.publicKey,
      identity.id,
      identity.publicKey + identity.signatures.id
    )
    return verified
  }
}

module.exports = OrbitDBIdentityProvider
