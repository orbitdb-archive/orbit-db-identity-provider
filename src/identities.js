'use strict'
const Identity = require('./identity')
const OrbitDBIdentityProvider = require('./orbit-db-identity-provider')
const Keystore = require('orbit-db-keystore')
const type = 'orbitdb'
const identityKeysPath = './orbitdb/identity/identitykeys'
let supportedTypes = {
  'orbitdb': OrbitDBIdentityProvider
}

const getHandlerFor = (type) => {
  if (!Identities.isSupported(type)) {
    throw new Error(`IdentityProvider type '${type}' is not supported`)
  }
  return supportedTypes[type]
}

class Identities {
  constructor (keystore) {
    this._keystore = keystore
  }

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
      await options.migrate({ targetPath: this._keystore.path, targetId: id })
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
    const keystore = options.keystore || Keystore.create(options.identityKeysPath || identityKeysPath)
    options = Object.assign({}, { type }, options)
    const identities = new Identities(keystore)
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
