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

module.exports.deSign = async function (dataString, keyString) {
  try {
    const p7 = forge.pkcs7.messageFromPem(dataString)

    const certificates = p7.certificates

    if (certificates.length > 0) {
      const subjectAttributes = certificates[0].subject.attributes

      const subject = subjectAttributes.reduce((result, attr) => {
        result[attr.name] = attr.value
        return result
      }, {})

      return subject
    } else {
      throw new Error('No certificates found')
    }
  } catch (error) {
    console.error('Error executing deSign command:', error.message)
    return false
  }
}