'use strict'
const Identity = require('./identity')
const OrbitDBIdentityProvider = require('./orbit-db-identity-provider')
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'
const keypath = './orbitdb/identity/keys'
let supportedTypes = {
  'orbitdb': OrbitDBIdentityProvider
}

const getHandlerFor = (type) => {
  if (!IdentityProvider.isSupported(type)) {
    throw new Error(`IdentityProvider type '${type}' is not supported`)
  }
  return supportedTypes[type]
}

class IdentityProvider {
  constructor (options = {}) {
    this._keystore = options.keystore || Keystore.create(options.keypath || keypath)
  }

  async sign (identity, data) {
    const signingKey = await this._keystore.getKey(identity.id)
    if (!signingKey) {
      throw new Error(`Private signing key not found from Keystore`)
    }

    return this._keystore.sign(signingKey, data)
  }

  async verify (signature, publicKey, data) {
    return this._keystore.verify(signature, publicKey, data)
  }

  async createIdentity (options = {}) {
    const IdentityProvider = getHandlerFor(options.type)
    const identityProvider = new IdentityProvider(options)
    const id = await identityProvider.getPublicKey(options)
    const { publicKey, idSignature } = await this.signPublicKey(id)
    const pubKeyIdSignature = await identityProvider.signPubKeySignature(publicKey + idSignature, options)
    return new Identity(id, publicKey, idSignature, pubKeyIdSignature, IdentityProvider.type, this)
  }

  async signPublicKey (id) {
    const keystore = this._keystore
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const publicKey = await key.getPublic('hex')
    const idSignature = await keystore.sign(key, id)
    return { publicKey, idSignature }
  }

  async verifyIdentity (identity, options = {}) {
    const verified = await this._keystore.verify(
      identity.signatures.id,
      identity.publicKey,
      identity.id
    )
    options = Object.assign({}, options, { provider: this })
    return verified && IdentityProvider.verifyIdentity(identity, options)
  }

  static async verifyIdentity (identity, options = {}) {
    const IdentityProvider = getHandlerFor(identity.type)
    return IdentityProvider.verifyIdentity(identity, options)
  }

  static async createIdentity (options = {}) {
    options = Object.assign({}, { type }, options)
    const identityProvider = new IdentityProvider(options)
    return identityProvider.createIdentity(options)
  }

  static isSupported (type) {
    return Object.keys(supportedTypes).includes(type)
  }

  static addIdentityProvider (IdentityProvider) {
    if (!IdentityProvider) {
      throw new Error('IdentityProvider class needs to be given as an option')
    }

    if (!IdentityProvider.type ||
      typeof IdentityProvider.type !== 'string') {
      throw new Error('Given IdentityProvider class needs to implement: static get type() { /* return a string */}.')
    }

    supportedTypes[IdentityProvider.type] = IdentityProvider
  }

  static removeIdentityProvider (type) {
    delete supportedTypes[type]
  }
}

module.exports = IdentityProvider
