'use strict'
const isDefined = require('./is-defined')
const Identity = require('./identity')

class IdentityProvider {
  constructor (keystore) {
    if (!isDefined(keystore)) {
      throw new Error('Signing function is invalid')
    }
    this._keystore = keystore
  }

  async createIdentity(id, signingFunction) {
    const key = await this._keystore.getKey(id)
      || await this._keystore.createKey(id)

    const pkSignature = await this._keystore.sign(key, id) // sign the id with the signing key we're going to use
    const publicKey = key.getPublic('hex')
    const signature = await signingFunction(publicKey + pkSignature) // sign both the key and the signature created with that key

    return new Identity(id, publicKey, pkSignature, signature, this)
  }

  static async verifyIdentity (identity, verifierFunction) {
    return verifierFunction(identity.publicKey + identity.pkSignature, identity.signature) === identity.id
  }

  async sign (identity, data) {
    const signingKey = await this._keystore.getKey(identity.id)

    if (!signingKey)
      throw new Error(`Private signing key not found from Keystore`)

    const signature = await this._keystore.sign(signingKey, data)
    return signature
  }

  async verify (signature, publicKey, data) {
    return this._keystore.verify(signature, publicKey, data)
  }
}

module.exports = IdentityProvider
