'use strict'
class IdentityProvider {
  /* Return id of identity (to be signed by orbit-db public key)*/
  async getId (options) {}

  /* Return signature of OrbitDB public key signature */
  async signIdentity (data, options) {}

  /* Verify a signature of OrbitDB public key signature */
  static async verifyIdentity (identity, options) {}

  /* Return the type for this identity provider */
  static get type () {
    throw new Error(`'static get type ()' needs to be defined in the inheriting class`)
  }

  get type () {
    return this.constructor.type
  }
}

module.exports = IdentityProvider
