'use strict'
class IdentityProvider {
  static async signIdentity(id, identity) {}

  static async verifyIdentity (identity) {}

    /* Return the type for this identity provider */
  static get type () {
    throw new Error(`'static get type ()' needs to be defined in the inheriting class`)
  }

  get type () {
    return this.constructor.type
  }
}

module.exports = IdentityProvider
