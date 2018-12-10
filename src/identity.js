'use strict'
const isDefined = require('./is-defined')

class Identity {
  constructor (id, publicKey, type, provider, idSignature, pubKeyIdSignature) {
    if (!isDefined(id)) {
      throw new Error('Identity id is required')
    }

    if (!isDefined(publicKey)) {
      throw new Error('Invalid public key')
    }

    if (!isDefined(type)) {
      throw new Error('Identity type is required')
    }

    if (!isDefined(provider)) {
      throw new Error('Identity provider is required')
    }

    this._id = id
    this._publicKey = publicKey
    this._type = type
    if (idSignature && pubKeyIdSignature) {
      this._signatures = Object.assign({}, { id: idSignature }, { publicKey: pubKeyIdSignature } )
    }
    this._provider = provider
  }

  /**
  * This is only used as a fallback to the clock id when necessary
  * @return {string} public key hex encoded
  */
  get id () {
    return this._id
  }

  get publicKey () {
    return this._publicKey
  }

  get signatures() {
    if (this._signatures) {
      return this._signatures
    }
    console.warn(`Identity does not have any signatures`)
  }

  get type() {
    return this._type
  }

  get provider() {
    return this._provider
  }

  toJSON () {
    return Object.assign({}, {
      id: this._id,
      publicKey: this._publicKey,
      type: this._type
    }, this._signatures ? { signatures: this._signatures } : {} )
  }
}

module.exports = Identity
