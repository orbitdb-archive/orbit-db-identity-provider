'use strict'
class IdentityProvider {
  constructor() {}

  /* Return publicKey of identity */
  async createId(options) {}

  /* Return signature of OrbitDB public key signature */
  async signIdentity(pubKeySignature, identity) {}

  /* Verify a signature of OrbitDB public key signature */
  static async verifyIdentity (identity, identityProvider, options) {}

  /* Return the type for this identity provider */
  static get type () {
    throw new Error(`'static get type ()' needs to be defined in the inheriting class`)
  }

  get type () {
    return this.constructor.type
  }
}

module.exports = IdentityProvider
