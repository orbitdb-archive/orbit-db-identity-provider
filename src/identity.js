'use strict'
const isDefined = require('./is-defined')

class Identity {
  constructor (id, publicKey, idSignature, pubKeyIdSignature, type) {
    if (!isDefined(id)) {
      throw new Error('Identity id is required')
    }

    if (!isDefined(publicKey)) {
      throw new Error('Invalid public key')
    }

    if (!isDefined(idSignature)) {
      throw new Error('Signature of the id (idSignature) is required')
    }

    if (!isDefined(pubKeyIdSignature)) {
      throw new Error('Signature of (publicKey + idSignature) is required')
    }

    if (!isDefined(type)) {
      throw new Error('Identity type is required')
    }

    this._id = id
    this._publicKey = publicKey
    this._signatures = Object.assign({}, { id: idSignature }, { publicKey: pubKeyIdSignature })
    this._type = type
  }

  static isIdentity (identity) {
    return identity.id !== undefined &&
           identity.publicKey !== undefined &&
           identity.signatures.id !== undefined &&
           identity.signatures.publicKey !== undefined &&
           identity.type !== undefined
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

  get signatures () {
    return this._signatures
  }

  get type () {
    return this._type
  }

  toJSON () {
    return {
      id: this._id,
      publicKey: this._publicKey,
      signatures: this._signatures,
      type: this._type
    }
  }
}

module.exports = Identity
