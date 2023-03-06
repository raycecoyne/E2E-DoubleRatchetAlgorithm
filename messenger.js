'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')
//REMOVE THIS LATER
const { subtle } = require('node:crypto').webcrypto

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate

  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    //throw ('not implemented!')
    this.EGKeyPair = await generateEG()

    const certificate = {
      username: username,
      pub: this.EGKeyPair.pub
    }

    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    //throw ('not implemented!')
  
    const certString = JSON.stringify(certificate)
    const verification = await verifyWithECDSA(this.caPublicKey, certString, signature)

    if (verification) {
      this.certs[certificate.username] = certificate.pub
      //initialize connection chains with counterparty's public key 
      const initialPair = {pub: certificate.pub, sec: this.EGKeyPair.sec}
      this.conns[certificate.username] = {
        SKs:this.EGKeyPair.sec, 
        PKs:this.EGKeyPair.pub, 
        PKr:certificate.pub, 
        sendChain:[], 
        recChain:[], 
        oldPairs:[]
      }
    }
    else{
      throw('Invalid certificate')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    //throw ('not implemented!')
    this.conns[name].recChain = []

    let kdfInput
    if (this.conns[name].sendChain.length===0){
      //cache old pairs for delivery failsafes
      this.conns[name].oldPairs.push({sec: this.conns[name].SKs, pub: this.conns[name].PKs})

      //Generate new diffie helman pair for ratchet
      const newKeyPair = await generateEG()
      this.conns[name].SKs = newKeyPair.sec
      this.conns[name].PKs = newKeyPair.pub

      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const dhSecret = await computeDH(secKey,pubKey)
      kdfInput = dhSecret
    }
    else{
      kdfInput=this.conns[name].sendChain[this.conns[name].sendChain.length-1][0]
    }
    const flatKey = await subtle.exportKey("raw", this.conns[name].PKr)
    const hkdfSalt = await HMACtoHMACKey(kdfInput, flatKey)
    let derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
    this.conns[name].sendChain.push(derivedKeyPair)

    let derivedKey = derivedKeyPair[1]
    derivedKey = await HMACtoAESKey(derivedKey,"AESKeyGen")
    const salt = await genRandomSalt()

    //Encrypt derivedKey for government decryption
    let govKey = await computeDH(this.EGKeyPair.sec,this.govPublicKey)
    govKey = await HMACtoAESKey(govKey,govEncryptionDataStr)
    const saltGov = await genRandomSalt()
    const plaintextGov = await subtle.exportKey("raw", derivedKey)
    const ciphertextGov = await encryptWithGCM(govKey,plaintextGov,saltGov)
    
    //Return header/ciphertext for use by correspondent and government
    const header = {
      newPubKey: this.conns[name].PKs,
      receiverIV: salt, 
      vGov:this.EGKeyPair.pub,  
      cGov:ciphertextGov, ivGov:saltGov, 
      sendChainIndex: this.conns[name].sendChain.length
    }
    const ciphertext = await encryptWithGCM(derivedKey,plaintext,salt, JSON.stringify(header))
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    //throw ('not implemented!')
    if(header.newPubKey != this.conns[name].PKr){
      this.conns[name].PKr = header.newPubKey
      this.conns[name].recChain = []
    }
    this.conns[name].sendChain = []

    //For starting new chains or backfilling missed messages
    let derivedKeyPair
    let hkdfSalt 

    let flatKey = await subtle.exportKey("raw", this.conns[name].PKs)

    if (this.conns[name].recChain.length===0){
      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const rootKey = await computeDH(secKey,pubKey)
      hkdfSalt = await HMACtoHMACKey(rootKey, flatKey)

      derivedKeyPair = await HKDF(rootKey,hkdfSalt,"ratchet-str")
      derivedKeyPair.push("UNREAD")
      this.conns[name].recChain.push(derivedKeyPair)
    }

    if(header.sendChainIndex > this.conns[name].recChain.length){
      for(let i=this.conns[name].recChain.length-1; i<header.sendChainIndex-1; i++){
        let kdfInput = this.conns[name].recChain[i][0]
        hkdfSalt = await HMACtoHMACKey(kdfInput, flatKey)
        derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
        derivedKeyPair.push("UNREAD")
        this.conns[name].recChain.push(derivedKeyPair)
      }
    }

    if(this.conns[name].recChain[header.sendChainIndex-1][2]== "READ"){
      throw "REPLAY ATTACK"
    }

    let derivedKey = this.conns[name].recChain[header.sendChainIndex-1][1]
    derivedKey = await HMACtoAESKey(derivedKey,"AESKeyGen")
    let plaintext
    try{
       plaintext = await decryptWithGCM(derivedKey,ciphertext,header.receiverIV, JSON.stringify(header))
    }
    catch{
      //Attempt message recovery using old keys cache
      for(let i=0; i<this.conns[name].oldPairs.length; i++){
        let pubKeyTest = header.newPubKey
        let secKeyTest = this.conns[name].oldPairs[i].sec
        let flatKeyTest = await subtle.exportKey("raw", this.conns[name].oldPairs[i].pub)
        let rootKeyTest = await computeDH(secKeyTest,pubKeyTest)
        let hkdfSaltTest = await HMACtoHMACKey(rootKeyTest, flatKeyTest)

        derivedKeyPair = await HKDF(rootKeyTest,hkdfSaltTest,"ratchet-str")
        derivedKeyPair.push("UNREAD")
        let recChainTest = []
        recChainTest.push(derivedKeyPair)  

        for(let i=recChainTest.length-1; i<header.sendChainIndex-1; i++){
          let kdfInputTest = recChainTest[i][0]
          hkdfSaltTest = await HMACtoHMACKey(kdfInputTest, flatKeyTest)
          derivedKeyPair = await HKDF(kdfInputTest,hkdfSaltTest,"ratchet-str")
          derivedKeyPair.push("UNREAD")
          recChainTest.push(derivedKeyPair)
        }

        let derivedKeyTest = recChainTest[header.sendChainIndex-1][1]
        derivedKeyTest = await HMACtoAESKey(derivedKeyTest,"AESKeyGen")
        let plaintextTest
        try{
          plaintextTest = await decryptWithGCM(derivedKeyTest,ciphertext,header.receiverIV, JSON.stringify(header))
          return byteArrayToString(plaintextTest)
       }
       catch{
        //Test Unsuccessful
      }
      }
      throw "FAILED DECRYPTION"
    }
    this.conns[name].recChain[header.sendChainIndex-1][2] = "READ"
    return byteArrayToString(plaintext)
  }
};

module.exports = {
  MessengerClient
}
