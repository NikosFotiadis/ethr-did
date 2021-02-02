const HttpProvider =require( 'ethjs-provider-http')
const Eth = require ('ethjs-query')
const EthContract = require( 'ethjs-contract')
const DidRegistryContract = require( 'ethr-did-resolver/contracts/ethr-did-registry.json')
const { createJWT, verifyJWT, SimpleSigner, toEthereumAddress } =require( 'did-jwt')
const { Buffer } = require( 'buffer')
const { REGISTRY, stringToBytes32, delegateTypes } =require( 'ethr-did-resolver')
const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')
const { Secp256k1VerificationKey2018 } = delegateTypes
const Web3 = require('web3')
const EthereumTx = require('ethereumjs-tx').Transaction
const Common = require('ethereumjs-common')

function configureProvider (conf = {}) {
  if (conf.provider) {
    return conf.provider
  } else if (conf.web3) {
    return conf.web3.currentProvider
  } else {
    return new HttpProvider(conf.rpcUrl || 'https://mainnet.infura.io/ethr-did')
  }
}

function attributeToHex (key, value) {
  if (Buffer.isBuffer(value)) {
    return `0x${value.toString('hex')}`
  }
  const match = key.match(/^did\/(pub|auth|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/)
  if (match) {
    const encoding = match[6]
    // TODO add support for base58
    if (encoding === 'base64') {
      return `0x${Buffer.from(value, 'base64').toString('hex')}`
    }
  }
  if (value.match(/^0x[0-9a-fA-F]*$/)) {
    return value
  }
  return `0x${Buffer.from(value).toString('hex')}`
}

class EthrDID {
  constructor (conf = {}) {
    const provider = configureProvider(conf)
    const eth = new Eth(provider)
    const registryAddress = conf.registry || REGISTRY
    const DidReg = new EthContract(eth)(DidRegistryContract)
    this.registry = DidReg.at(registryAddress)
    this.address = conf.address
    this.registryAddress = registryAddress

    this.web3Provider = new Web3.providers.HttpProvider(conf.providerUrl)
    this.web3 = new Web3(this.web3Provider)
    this.privateKey = conf.privateKey
    this.chainId = conf.chainId
    this.networkId = conf.networkId
    this.registryInstance = new this.web3.eth.Contract(
      DidRegistryContract,
      registryAddress
    )

    if (!this.address) throw new Error('No address is set for EthrDid')
    this.did = `did:ethr:${this.address}`
    if (conf.signer) {
      this.signer = conf.signer
    } else if (conf.privateKey) {
      this.signer = SimpleSigner(conf.privateKey)
    }
  }

  async createKeyPair () {
    const kp = secp256k1.genKeyPair()
    const publicKey = kp.getPublic('hex')
    const privateKey = kp.getPrivate('hex')
    const address = toEthereumAddress(publicKey)
    return { address, privateKey }
  }

  async getAccountNonce (address) {
    return await this.web3.eth.getTransactionCount(address)
  }

  async estimateGas (method, from, ...params) {
    return await method(...params).estimateGas({ from })
  }

  async getGasPrice () {
    return await this.web3.eth.getGasPrice()
  }

  async toHex (value) {
    return this.web3.utils.toHex(value)
  }

  async getData (method, ...params) {
    return method(...params).encodeABI()
  }

  async sendRawTransaction (transaction) {
    return this.web3.eth.sendSignedTransaction(`${transaction.toString('hex')}`);
  }

  async signTransaction (nonce, to, value, data, gasLimit, gasPrice) {
    const privateKey = Buffer.from(this.privateKey, 'hex')
    const txParams = {
      nonce: await this.toHex(nonce),
      gasPrice: await this.toHex(gasPrice),
      gasLimit: await this.toHex(gasLimit),
      to,
      value: await this.toHex(value),
      data
    }

    const customCommon = Common.default.forCustomChain(
      'mainnet',
      {
        name: 'my-network',
        networkId: Number(this.networkId),
        chainId: Number(this.chainId)
      },
      'petersburg'
    )

    const tx = new EthereumTx(txParams, { common: customCommon })
    tx.sign(privateKey)

    return tx.serialize()
  }

  async signAndSendTxRoot (from, contractAddress, method, value, ...args) {
    const gasPrice = await this.getGasPrice()
    const gasLimit = await this.estimateGas(method, from, ...args)
    const inputData = await this.getData(method, ...args)
    const nonce = await this.getAccountNonce(from)
    const methodRawTransaction = await this.signTransaction(
      nonce,
      contractAddress,
      value,
      inputData,
      gasLimit,
      gasPrice
    )

    return await this.sendRawTransaction(methodRawTransaction)
  }

  async lookupOwner (cache = true) {
    if (cache && this.owner) return this.owner
    return await this.registryInstance.methods.identityOwner(this.address).call()
  }

  async changeOwner (newOwner) {
    const owner = await this.lookupOwner()
    const txHash = await this.registry.changeOwner(this.address, newOwner, {
      from: owner
    })
    this.owner = newOwner
    return txHash
  }

  async addDelegate (delegate, options = {}) {
    const delegateType = options.delegateType || Secp256k1VerificationKey2018
    const expiresIn = options.expiresIn || 86400
    const from = await this.lookupOwner()
    const method = this.registryInstance.methods.addDelegate
    const to = this.registryAddress

    return await this.signAndSendTxRoot(
      from,
      to,
      method,
      0x0,
      this.address,
      delegateType,
      delegate,
      expiresIn
    )
  }

  async revokeDelegate (delegate, delegateType = Secp256k1VerificationKey2018) {
    const owner = await this.lookupOwner()
    return this.registry.revokeDelegate(this.address, delegateType, delegate, {
      from: owner
    })
  }


  async setAttribute(key, value, expiresIn = 86400, gasLimit) {
    const from = await this.lookupOwner();
    const method = this.registryInstance.methods.setAttribute;
    const to = this.registryAddress;

    return await this.signAndSendTxRoot(
      from,
      to,
      method,
      0x0,
      this.address,
      stringToBytes32(key),
      attributeToHex(key, value),
      expiresIn,
    );
  }

  async revokeAttribute (key, value, gasLimit) {
    const owner = await this.lookupOwner()
    return this.registry.revokeAttribute(
      this.address,
      stringToBytes32(key),
      attributeToHex(key, value),
      {
        from: owner,
        gas: gasLimit
      }
    )
  }

  // Create a temporary signing delegate able to sign JWT on behalf of identity
  async createSigningDelegate (
    delegateType = Secp256k1VerificationKey2018,
    expiresIn = 86400
  ) {
    const kp = EthrDID.createKeyPair()
    this.signer = SimpleSigner(kp.privateKey)
    const txHash = await this.addDelegate(kp.address, {
      delegateType,
      expiresIn
    })
    return { kp, txHash }
  }

  async signJWT (payload, expiresIn) {
    if (typeof this.signer !== 'function') {
      throw new Error('No signer configured')
    }
    const options = { signer: this.signer, alg: 'ES256K-R', issuer: this.did }
    if (expiresIn) options.expiresIn = expiresIn
    return createJWT(payload, options)
  }

  async verifyJWT (jwt, resolver, audience = this.did) {
    return verifyJWT(jwt, { resolver, audience })
  }
}

module.exports = EthrDID