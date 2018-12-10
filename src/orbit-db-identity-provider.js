'use strict'
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'

class OrbitDBIdentityProvider {
  constructor(options = {}) {
    this._keystore = options.keystore || Keystore.create(options.keypath || './orbitdb/identity/keys')
  }

  // Returns the type of the identity provider
  static get type () { return type }

  async sign (id, data) {
    const signingKey = await this._keystore.getKey(id)
    if (!signingKey)
      throw new Error(`Private signing key not found from Keystore`)

    const signature = await this._keystore.sign(signingKey, data)
    return signature
  }

  verify (signature, publicKey, data) {
    return this._keystore.verify(signature, publicKey, data)
  }

  getPublicKey(options = {}) {
    const id = options.id
    if (!id)
      throw new Error('id is required')

    const keystore = options.keystore || this._keystore
    const key = keystore.getKey(id) || keystore.createKey(id)
    return key.getPublic('hex')
  }

  async signPublicKey(id, options = {}) {
    const keystore = this._keystore
    const key = keystore.getKey(id) || keystore.createKey(id)
    const publicKey = key.getPublic('hex')
    const idSignature = await keystore.sign(key, id)
    return { publicKey, idSignature }
  }

  async signPubKeySignature(pubKeyIdSig, options = {}) {
    const keystore = options.keystore || this._keystore
    const id = options.id
    const key = keystore.getKey(id)
    if(!key)
      throw new Error(`Signing key for '${id}' not found`)
    return keystore.sign(key, pubKeyIdSig)
  }

  async verifyIdentity (identity) {
    // Verify that identity.id was signed by this publicKey
    const verified = this._keystore.verify(
      identity.signatures.id,
      identity.publicKey,
      identity.id
    )
    return verified
  }
}

module.exports = OrbitDBIdentityProvider
