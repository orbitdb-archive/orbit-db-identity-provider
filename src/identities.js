'use strict'
const Identity = require('./identity')
const OrbitDBIdentityProvider = require('./orbit-db-identity-provider')
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'
const identityKeysPath = './orbitdb/identity/identitykeys'
const supportedTypes = {
  orbitdb: OrbitDBIdentityProvider
}

const getHandlerFor = (type) => {
  if (!Identities.isSupported(type)) {
    throw new Error(`IdentityProvider type '${type}' is not supported`)
  }
  return supportedTypes[type]
}

class Identities {
  constructor (options) {
    this._keystore = options.keystore
    this._signingKeystore = options.signingKeystore || this._keystore
  }

  get keystore () { return this._keystore }

  get signingKeystore () { return this._signingKeystore }

  async sign (identity, data) {
    const signingKey = await this._keystore.getKey(identity.id)
    if (!signingKey) {
      throw new Error(`Private signing key not found from Keystore`)
    }
    const sig = await this._keystore.sign(signingKey, data)
    return sig
  }

  async verify (signature, publicKey, data, verifier = 'v1') {
    return this._keystore.verify(signature, publicKey, data, verifier)
  }

  async createIdentity (options = {}) {
    const IdentityProvider = getHandlerFor(options.type)
    const identityProvider = new IdentityProvider(options)
    const id = await identityProvider.getId(options)

    if (options.migrate) {
      await options.migrate({ targetStore: this._keystore._store, targetId: id })
    }
    const { publicKey, idSignature } = await this.signId(id)
    const pubKeyIdSignature = await identityProvider.signIdentity(publicKey + idSignature, options)
    return new Identity(id, publicKey, idSignature, pubKeyIdSignature, IdentityProvider.type, this)
  }

  async signId (id) {
    const keystore = this._keystore
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const publicKey = keystore.getPublic(key)
    const idSignature = await keystore.sign(key, id)
    return { publicKey, idSignature }
  }

  async verifyIdentity (identity) {
    const verified = await this._keystore.verify(
      identity.signatures.id,
      identity.publicKey,
      identity.id
    )
    return verified && Identities.verifyIdentity(identity)
  }

  static async verifyIdentity (identity) {
    const IdentityProvider = getHandlerFor(identity.type)
    return IdentityProvider.verifyIdentity(identity)
  }

  static async createIdentity (options = {}) {
    if (!options.keystore) {
      options.keystore = new Keystore(options.identityKeysPath || identityKeysPath)
    }
    if (!options.signingKeystore) {
      if (options.signingKeysPath) {
        options.signingKeystore = new Keystore(options.signingKeysPath)
      } else {
        options.signingKeystore = options.keystore
      }
    }
    options = Object.assign({}, { type }, options)
    const identities = new Identities(options)
    return identities.createIdentity(options)
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

module.exports = Identities
