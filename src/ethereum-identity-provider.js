'use strict'
const IdentityProvider = require('./identity-provider')
const { Wallet } = require('ethers')
const type = 'ethereum'

class EthIdentityProvider extends IdentityProvider {

  // Returns the type of the identity provider
  static get type () { return type }

  static async createWallet(options = {}) {
    return await Wallet.createRandom()
  }

  static async signIdentity(id, options = {}) {
    const wallet = options.wallet
    return await wallet.signMessage(id)
  }

  static async verifyIdentity (identity) {
    // Verify that identity was signed by the id
    const signerAddress = Wallet.verifyMessage(identity.publicKey + identity.signatures.id, identity.signatures.publicKey)
    return (signerAddress === identity.id)
  }
}

module.exports = EthIdentityProvider
