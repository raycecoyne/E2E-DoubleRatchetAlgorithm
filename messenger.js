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
      this.conns[certificate.username] = {SKs:this.EGKeyPair.sec, PKs:this.EGKeyPair.pub, PKr:certificate.pub, PKsOld:this.EGKeyPair.pub, sendChain:[], recChain:[]}
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

    //Generate unique message keypair for sent messages
    const newKeyPair = await generateEG()
    this.conns[name].SKs = newKeyPair.sec
    this.conns[name].PKs = newKeyPair.pub

    const secKey = this.conns[name].SKs
    const pubKey = this.conns[name].PKr
    const dhSecret = await computeDH(secKey,pubKey)
    const dhSecretFlat = await subtle.exportKey("raw", dhSecret)

    let kdfInput
    if (this.conns[name].sendChain.length===0){
      kdfInput = dhSecret
    }
    else{
      kdfInput=this.conns[name].sendChain[this.conns[name].sendChain.length-1][0]
      console.log("FOUND OLD CHAIN")
    }
    console.log(await cryptoKeyToJSON(kdfInput))
    console.log(dhSecretFlat)
    const hkdfSalt = await HMACtoHMACKey(kdfInput, dhSecretFlat)
    let derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
    derivedKeyPair.push("UNREAD")
    this.conns[name].sendChain.push(derivedKeyPair)

    console.log("SEND CHAIN TO", name)
    await MessengerClient.printKeyList(this.conns[name].sendChain)

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
    console.log("INDEX " , this.conns[name].sendChain.length)
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
    this.conns[name].PKr = header.newPubKey
    this.conns[name].sendChain = []
    //For starting new chains or backfilling missed messages
    let derivedKeyPair
    let hkdfSalt 
    console.log("Send Chain Index", header.sendChainIndex)
    if (this.conns[name].recChain.length===0){
      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const dhSecret = await computeDH(secKey,pubKey)
      const dhSecretFlat = await subtle.exportKey("raw", dhSecret)
  
      const rootKey = await computeDH(secKey,pubKey)
      hkdfSalt = await HMACtoHMACKey(rootKey, dhSecretFlat)

      derivedKeyPair = await HKDF(rootKey,hkdfSalt,"ratchet-str")
      derivedKeyPair.push("UNREAD")
      this.conns[name].recChain.push(derivedKeyPair)
    }

    if(header.sendChainIndex > this.conns[name].recChain.length){
      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const dhSecret = await computeDH(secKey,pubKey)
      const dhSecretFlat = await subtle.exportKey("raw", dhSecret)

      for(let i=this.conns[name].recChain.length-1; i<header.sendChainIndex-1; i++){
        console.log("Run",i)
        let kdfInput = this.conns[name].recChain[i][0]
        console.log(await cryptoKeyToJSON(kdfInput))
        console.log(dhSecretFlat)
        hkdfSalt = await HMACtoHMACKey(kdfInput, dhSecretFlat)
        derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
        derivedKeyPair.push("UNREAD")
        this.conns[name].recChain.push(derivedKeyPair)
      }
    }


    console.log("RECEIVE CHAIN from ", name)
    await MessengerClient.printKeyList(this.conns[name].recChain)
    console.log("END")

    if(this.conns[name].recChain[header.sendChainIndex-1][2]== "READ"){
      throw "REPLAY ATTACK"
    }

    let derivedKey = this.conns[name].recChain[header.sendChainIndex-1][1]
    derivedKey = await HMACtoAESKey(derivedKey,"AESKeyGen")
    const plaintext = await decryptWithGCM(derivedKey,ciphertext,header.receiverIV, JSON.stringify(header))
    this.conns[name].recChain[header.sendChainIndex-1][2] = "READ"
    return byteArrayToString(plaintext)
  }

  static async printKeyList(list){
    for (const x of list) {
      for (const y of x){ 
        try{
          let z = await cryptoKeyToJSON(y)
          console.log("      ", z.k)
        }
        catch{
          console.log("      ", y)
        }
      } 
      console.log("---------");
    }
  }

};

module.exports = {
  MessengerClient
}
