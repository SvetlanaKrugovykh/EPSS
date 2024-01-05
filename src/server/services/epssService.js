const forge = require('node-forge')
const fs = require('fs')
const path = require('path')

module.exports.signFile = async function (FileName, KeyFiles) {
  try {
    const data = fs.readFileSync(FileName, 'utf8')
    const keys = forge.pki.rsa.generateKeyPair(2048)
    const publicKeyPEM = forge.pki.publicKeyToPem(keys.publicKey)
    const privateKeyPEM = forge.pki.privateKeyToPem(keys.privateKey)
    fs.writeFileSync(KeyFiles[0], privateKeyPEM)
    const publicKeyFileName = KeyFiles[0].replace('PrivatKey', 'PublicKey')
    fs.writeFileSync(publicKeyFileName, publicKeyPEM)


    for (const keyFile of KeyFiles) {
      const keyPEM = await readKeyFileWithTags(keyFile, 'PRIVATE')
      const privateKey = forge.pki.privateKeyFromPem(keyPEM)

      const md = forge.md.sha256.create()
      md.update(data, 'utf8')
      const signature = privateKey.sign(md)
      const signatureHex = forge.util.bytesToHex(signature)

      const signedFileName = `${FileName}._signed_`
      fs.writeFileSync(signedFileName, signatureHex)
      console.log(`Signed file: ${signedFileName}`)
    }

    return true
  } catch (error) {
    console.error('Error executing signFile command:', error.message)
    return false
  }
}

module.exports.deSign = async function (FileName, SignatureFile, PublicKeyFiles) {
  try {
    const verificationResult = await verifySignature(FileName, SignatureFile, PublicKeyFiles)
    if (verificationResult) {
      console.log('Signature verification succeeded:', verificationResult)
      return true
    } else {
      console.log('Signature verification failed.')
      return false
    }
  } catch (error) {
    console.error('Error executing deSign command:', error.message)
    return false
  }
}

async function verifySignature(FileName, SignatureFile, PublicKeyFiles) {
  try {
    const data = fs.readFileSync(FileName, 'utf8')
    const ssignatureHex = fs.readFileSync(SignatureFile, 'utf8')
    const signature = forge.util.hexToBytes(ssignatureHex)

    const keys = []
    for (const keyFile of PublicKeyFiles) {
      const publicKey = await readKeyFileWithTags(keyFile, 'PUBLIC')
      keys.push(publicKey)
    }

    const md = forge.md.sha256.create()
    md.update(data, 'utf8')

    for (const key of keys) {
      const verified = key.verify(md.digest().bytes(), signature)
      console.log(`Signature verified: ${verified}`)
    }

    return true
  } catch (error) {
    console.error('Error verifying signature:', error.message)
    return false
  }
}

async function readKeyFileWithTags(keyFile, keyType) {
  try {
    let keyBuffer = fs.readFileSync(keyFile, 'utf8')
    const beginTag = `-----BEGIN ${keyType} KEY-----`
    const endTag = `-----END ${keyType} KEY-----`

    if (!keyBuffer.includes(`-----BEGIN`)) {
      const keyBase64 = keyBuffer.toString('base64')
      keyBuffer = `${beginTag}\n${keyBase64}\n${endTag}`
    }

    if (keyType === 'PUBLIC') {
      if (keyBuffer.includes('-----BEGIN CERTIFICATE-----')) {
        const certificate = forge.pki.certificateFromPem(keyBuffer)
        return certificate.publicKey
      } else {
        const publicKey = forge.pki.publicKeyFromPem(keyBuffer)
        return publicKey
      }
    }
    return keyBuffer
  } catch (error) {
    console.error('Error reading key file:', error.message)
    return false
  }
}