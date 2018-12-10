'use strict'
const Identity = require('./identity')
const OrbitDBIdentityProvider = require('./orbit-db-identity-provider')
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'
let supportedTypes = {
  'orbitdb': OrbitDBIdentityProvider,
}

const getHandlerFor = (type) => {
  if (!IdentityProvider.isSupported(type)) {
    throw new Error(`IdentityProvider type '${type}' is not supported`)
  }
  return supportedTypes[type]
}

class IdentityProvider {
  constructor(options = {}) {
    this._odbip = options.odbip || new OrbitDBIdentityProvider(options)
  }

  async sign (identity, data) {
    return this._odbip.sign(identity.id, data)
  }

  async verify (signature, publicKey, data) {
    return this._odbip.verify(signature, publicKey, data)
  }

  async createIdentity(options = {}) {
    if (options.type === 'orbitdb') {
      const id = options.id
      const publicKey = await this._odbip.getPublicKey({ id })
      return new Identity(id, publicKey, options.type, this)
    }

    const IdentityProvider = getHandlerFor(options.type)
    const identityProvider = new IdentityProvider(options)
    const externalPublicKey = await identityProvider.getPublicKey(options)
    const { publicKey, idSignature } = await this._odbip.signPublicKey(externalPublicKey, options)
    const pubKeyIdSignature = await identityProvider.signPubKeySignature(publicKey + idSignature, options)
    return new Identity(externalPublicKey, publicKey, options.type, this, idSignature, pubKeyIdSignature)
  }

  async verifyIdentity (identity, options = {}) {
    if (options.type === 'orbitdb') {
      console.warn(`No external identity to verify`)
      return true
    }
    const verified = await this._odbip.verifyIdentity(identity) // verify odbip signed signature
    return verified && await IdentityProvider.verifyIdentity(identity, options) // verify externally signed signature
  }

  static async verifyIdentity(identity, options = {}) {
    const IdentityProvider = getHandlerFor(identity.type)
    return IdentityProvider.verifyIdentity(identity, options)
  }

  static async createIdentity (options = {}) {
    options = Object.assign({}, { type }, options )
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
