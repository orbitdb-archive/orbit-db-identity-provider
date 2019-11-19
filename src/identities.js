'use strict'
const Identity = require('./identity')
const IdentityProvider = require('./identity-provider-interface.js')
const OrbitDBIdentityProvider = require('./orbit-db-identity-provider')
const Keystore = require('orbit-db-keystore')
const LRU = require('lru')
const path = require('path')

const identityKeysPath = path.join('./orbitdb', 'identity', 'identitykeys')
const defaultType = 'orbitdb'
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
  constructor (options = {}) {
    this._keystore = options.keystore || new Keystore(options.identityKeysPath || identityKeysPath)
    this._knownIdentities = options.cache || new LRU(options.cacheSize || 1000)
  }

  static get IdentityProvider () { return IdentityProvider }

  get keystore () { return this._keystore }

  async sign (identity, data) {
    const keystore = this.keystore
    const signingKey = await keystore.getKey(identity.id)
    if (!signingKey) {
      throw new Error(`Private signing key not found from Keystore`)
    }
    return keystore.sign(signingKey, data)
  }

  async createIdentity (options = {}) {
    const keystore = options.keystore || this.keystore
    const type = options.type || defaultType
    const identityProvider = type === defaultType ? new OrbitDBIdentityProvider(options.signingKeystore || keystore) : new (getHandlerFor(type))(options)
    const id = await identityProvider.getId(options)
    if (options.migrate) {
      await options.migrate({ targetStore: keystore._store, targetId: id })
    }
    const { publicKey, idSignature } = await this.signId(id, keystore)
    const pubKeyIdSignature = await identityProvider.signIdentity(publicKey + idSignature, options)
    return new Identity(id, publicKey, idSignature, pubKeyIdSignature, type)
  }

  async signId (id, keystore) {
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const publicKey = keystore.getPublic(key)
    const idSignature = await keystore.sign(key, id)
    return { publicKey, idSignature }
  }

  async verifyIdentity (identity) {
    const knownID = this._knownIdentities.get(identity.signatures.id)
    if (knownID) {
      return identity.id === knownID.id &&
             identity.publicKey === knownID.publicKey &&
             identity.signatures.id === knownID.signatures.id &&
             identity.signatures.publicKey === knownID.signatures.publicKey
    }
    const verified = await Identities.verifyIdentity(identity, this.keystore)
    if (verified) {
      this._knownIdentities.set(identity.signatures.id, identity)
    }
    return verified
  }

  static async verifyIdentity (identity, keystore) {
    const verifyId = await keystore.verify(
      identity.signatures.id,
      identity.publicKey,
      identity.id
    )
    const IdentityProvider = getHandlerFor(identity.type)
    return verifyId && IdentityProvider.verifyIdentity(identity)
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
