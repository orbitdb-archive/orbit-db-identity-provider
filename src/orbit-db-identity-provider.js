'use strict'
const IdentityProvider = require('./identity-provider')
const type = 'orbitdb'

class OrbitDBIdentityProvider extends IdentityProvider {
  // Returns the type of the identity provider
  static get type () { return type }

  static async verifyIdentity (identity, options = {}) {
    // Verify that identity was signed by the ID
    const keystore = options.keystore || identity.provider._keystore
    const verified = await keystore.verify(
      identity.signatures.publicKey,
      identity.publicKey,
      identity.publicKey + identity.signatures.publicKey
    )
    return verified
  }
}

module.exports = OrbitDBIdentityProvider
