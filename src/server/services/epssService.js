const forge = require('node-forge')
const fs = require('fs')
const path = require('path')

module.exports.sign = async function (dataString, keyString) {
  try {
    const dataBuffer = Buffer.isBuffer(dataString) ? dataString : Buffer.from(dataString, 'utf8')
    const privateKey = forge.pki.privateKeyFromPem(keyString)

    const md = forge.md.sha256.create()
    md.update(dataBuffer)
    const signature = privateKey.sign(md)
    const signatureBase64 = forge.util.encode64(signature)
    return signatureBase64
  } catch (error) {
    console.error('Error executing sign command:', error.message)
    return false
  }
}

module.exports.deSign = async function (dataString, signatureString, publicKeyString) {
  try {
    const dataBuffer = Buffer.isBuffer(dataString) ? dataString : Buffer.from(dataString, 'utf8')
    const publicKey = forge.pki.publicKeyFromPem(publicKeyString)
    const signature = forge.util.decode64(signatureString)
    const md = forge.md.sha256.create()
    md.update(dataBuffer)
    const verified = publicKey.verify(md.digest().getBytes(), signature)
    return verified
  } catch (error) {
    console.error('Error executing deSign command:', error.message)
    return false
  }
}
