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
    // ElGamal keypair will be used to derive initial root keys for new communication sessions.
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
      //const initialPair = {pub: certificate.pub, sec: this.EGKeyPair.sec}
      this.conns[certificate.username] = {
        SKs:this.EGKeyPair.sec, 
        PKs:this.EGKeyPair.pub, 
        PKr:certificate.pub, 
        sendChain:[], 
        recChain:[], 
        oldPairs:[],
        SKsLast:this.EGKeyPair.sec,
        PKrFirst:certificate.pub
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

    //Compute first Diffie Hellman from existing secret+public combo
    const dhSecret1 = await computeDH(this.conns[name].SKs, this.conns[name].PKr) 

    let kdfInput
    if (this.conns[name].sendChain.length===0){
      //cache old pairs for delivery failsafes
      this.conns[name].oldPairs.push({sec: this.conns[name].SKs, secLast:this.conns[name].SKsLast})
      while(this.conns[name].oldPairs.length > 5){
        // The memory cost of key storage for your algorithm should always be O(1) - 5 records long in this case
        const removedItem = this.conns[name].oldPairs.shift()
      }

      //Generate ElGamal key pairs for the Diffie-Hellman key exchange
      const newKeyPair = await generateEG()
      this.conns[name].SKsLast = this.conns[name].SKs
      this.conns[name].SKs = newKeyPair.sec
      this.conns[name].PKs = newKeyPair.pub

      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const dhSecret2 = await computeDH(secKey,pubKey)
      kdfInput = dhSecret2
    }
    else{
      kdfInput=this.conns[name].sendChain[this.conns[name].sendChain.length-1][0]
    }

    //Ratchet to produce message and kdf key pair
    const hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC")
    let derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
    this.conns[name].sendChain.push(derivedKeyPair)

    let derivedKey = derivedKeyPair[1]
    let derivedKeyAES = await HMACtoAESKey(derivedKey,"AESKeyGen")
    //Generate a new random iv every time we encrypt with AES-GCM
    const salt = await genRandomSalt()

    //console.log("SEND CHAIN to ", name)
    //await MessengerClient.printKeyList(this.conns[name].sendChain)
    //console.log("END")


    //Encrypt derivedKey for government decryption
    let govKey = await computeDH(this.EGKeyPair.sec,this.govPublicKey)
    govKey = await HMACtoAESKey(govKey,govEncryptionDataStr)
    const saltGov = await genRandomSalt()
    const plaintextGov = await HMACtoAESKey(derivedKey,"AESKeyGen",true)
    const ciphertextGov = await encryptWithGCM(govKey,plaintextGov,saltGov)
    
    //Return header/ciphertext for use by correspondent and government
    const header = {
      newPubKey: this.conns[name].PKs,
      receiverIV: salt, 
      vGov:this.EGKeyPair.pub,  
      cGov:ciphertextGov, ivGov:saltGov, 
      sendChainIndex: this.conns[name].sendChain.length
    }

    const ciphertext = await encryptWithGCM(derivedKeyAES,plaintext,salt, JSON.stringify(header))
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
    /*
      No verification since we assume that there is some trusted central party, 
      and that this central party can securely receive certificates generated by clients
    */

    //Compute first Diffie Hellman from existing secret+public combo
    const dhSecret1 = await computeDH(this.conns[name].SKs, this.conns[name].PKr) 
    if(header.newPubKey != this.conns[name].PKr){
      this.conns[name].PKr = header.newPubKey
      this.conns[name].recChain = []
    }
    this.conns[name].sendChain = []

    //For starting new chains or backfilling missed messages
    let derivedKeyPair
    let hkdfSalt 

    if (this.conns[name].recChain.length===0){
      const secKey = this.conns[name].SKs
      const pubKey = this.conns[name].PKr
      const dhSecret2 = await computeDH(secKey,pubKey)

      hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC")

      derivedKeyPair = await HKDF(dhSecret2,hkdfSalt,"ratchet-str")
      derivedKeyPair.push("UNREAD")
      this.conns[name].recChain.push(derivedKeyPair)
    }

    if(header.sendChainIndex > this.conns[name].recChain.length){
      for(let i=this.conns[name].recChain.length-1; i<header.sendChainIndex-1; i++){
        let kdfInput = this.conns[name].recChain[i][0]
        hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC")
        derivedKeyPair = await HKDF(kdfInput,hkdfSalt,"ratchet-str")
        derivedKeyPair.push("UNREAD")
        this.conns[name].recChain.push(derivedKeyPair)
      }
    }

    if(this.conns[name].recChain[header.sendChainIndex-1][2]== "READ"){
      throw "REPLAY ATTACK"
    }

    /*
    console.log("REC CHAIN to ", name)
    await MessengerClient.printKeyList(this.conns[name].recChain)
    console.log("END")
    */

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
        let secKeyLastTest = this.conns[name].oldPairs[i].secLast

        let dhSecret1Test = await computeDH(secKeyLastTest,this.conns[name].PKrFirst)
        let dhSecret2Test = await computeDH(secKeyTest,pubKeyTest)
        let hkdfSaltTest = await HMACtoHMACKey(dhSecret1Test, "HMAC") 
        
        derivedKeyPair = await HKDF(dhSecret2Test,hkdfSaltTest,"ratchet-str")
        derivedKeyPair.push("UNREAD")
        let recChainTest = []
        recChainTest.push(derivedKeyPair)  
        
        let kdfInputTest
        for(let i=recChainTest.length-1; i<header.sendChainIndex-1; i++){
          dhSecret1Test = dhSecret2Test

          kdfInputTest = recChainTest[i][0]
          hkdfSaltTest = await HMACtoHMACKey(dhSecret1Test, "HMAC")
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
  /*
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
  */
};

module.exports = {
  MessengerClient
}
