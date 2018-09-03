'use strict'
const isDefined = require('./is-defined')
const Identity = require('./identity')
const defaultType = 'orbitdb'

class IdentityProvider {
  constructor (keystore) {
    if (!isDefined(keystore)) {
      throw new Error('Keystore is required')
    }
    this._keystore = keystore
  }

  async createIdentity(id, identitySignerFn, type) {
    // Get the key for id from the keystore or create one
    // if it doesn't exist
    const key = await this._keystore.getKey(id) ||
      await this._keystore.createKey(id)
    // Sign with the key for the id
    const selfSigningFn = async (id, data) => await this._keystore.sign(key, data)
    // If signing function was not passed, use keystore as the identity signer
    identitySignerFn = isDefined(identitySignerFn) ? identitySignerFn : selfSigningFn
    // If no type was indicated, set to default
    type = isDefined(type) ? type : defaultType
    // Sign the id with the signing key we're going to use
    const idSignature = await this._keystore.sign(key, id)
    // Get the hex string of the public key
    const publicKey = key.getPublic('hex')
    // Sign both the key and the signature created with that key
    const pubKeyIdSignature = await identitySignerFn(id, publicKey + idSignature)
    return new Identity(id, publicKey, idSignature, pubKeyIdSignature, type, this)
  }

  static async createIdentity (keystore, id, identitySignerFn, type) {
    const identityProvider = new IdentityProvider(keystore)
    return await identityProvider.createIdentity(id, identitySignerFn, type)
  }

  static async verifyIdentity (identity, verifierFunction) {
    return verifierFunction(identity)
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
