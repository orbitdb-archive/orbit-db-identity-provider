'use strict'
const isDefined = require('./is-defined')

class Identity {
  constructor (id, publicKey, pkSignature, signature, provider) {
    if (!isDefined(id)) {
      throw new Error('Identity id is required')
    }

    if (!isDefined(publicKey)) {
      throw new Error('Invalid public key')
    }

    if (!isDefined(pkSignature)) {
      throw new Error('Signature of the id (pkSignature) is required')
    }

    if (!isDefined(signature)) {
      throw new Error('Signature is required')
    }

    if (!isDefined(provider)) {
      throw new Error('Identity provider is required')
    }

    this._id = id
    this._publicKey = publicKey
    this._pkSignature = pkSignature
    this._signature = signature
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

  get pkSignature() {
    return this._pkSignature
  }

  get signature() {
    return this._signature
  }

  get provider() {
    return this._provider
  }

  toJSON () {
    return {
      id: this._id,
      publicKey: this._publicKey,
      pkSignature: this._pkSignature,
      signature: this._signature
    }
  }
}

module.exports = Identity
