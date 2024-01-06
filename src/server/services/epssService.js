const forge = require('node-forge')
const fs = require('fs')
const path = require('path')

module.exports.signFile = async function (FileName, KeyFiles, genegateKeys = false) {
  try {
    const data = fs.readFileSync(FileName, 'utf8')
    if (genegateKeys) keysGeneration(KeyFiles)

    for (const keyFile of KeyFiles) {
      const keyPEM = await readKeyFileWithTags(keyFile, 'PRIVATE')
      const privateKey = forge.pki.privateKeyFromPem(keyPEM)

      const md = forge.md.sha256.create()
      md.update(data, 'utf8')
      const signature = privateKey.sign(md)
      const signatureHex = forge.util.bytesToHex(signature)

      const signedFileName = `${FileName}._signed_.${KeyFiles.indexOf(keyFile)}`
      fs.writeFileSync(signedFileName, signatureHex)
      console.log(`Signed file: ${signedFileName}`)
    }

    return true
  } catch (error) {
    console.error('Error executing signFile command:', error.message)
    return false
  }
}

module.exports.deSign = async function (FileName, PublicKeyFiles) {
  try {
    const verificationResult = await verifySignature(FileName, PublicKeyFiles)
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

async function keysGeneration(KeyFiles) {
  try {
    for (const keyFile of KeyFiles) {
      const keys = forge.pki.rsa.generateKeyPair(2048)
      const publicKeyPEM = forge.pki.publicKeyToPem(keys.publicKey)
      const privateKeyPEM = forge.pki.privateKeyToPem(keys.privateKey)
      fs.writeFileSync(keyFile, privateKeyPEM)
      const publicKeyFileName = keyFile.replace('PrivatKey', 'PublicKey')
      fs.writeFileSync(publicKeyFileName, publicKeyPEM)
      console.log(`Generated keys: ${keyFile} and ${publicKeyFileName}`)
    }
    return true
  } catch (error) {
    console.error('Error executing keysGeneration command:', error.message)
    return false
  }
}

async function verifySignature(FileName, PublicKeyFiles) {
  try {
    const data = fs.readFileSync(FileName, 'utf8')

    for (const keyFile of PublicKeyFiles) {
      const key = await readKeyFileWithTags(keyFile, 'PUBLIC')
      const SignatureFile = `${FileName}._signed_.${PublicKeyFiles.indexOf(keyFile)}`
      const ssignatureHex = fs.readFileSync(SignatureFile, 'utf8')
      const signature = forge.util.hexToBytes(ssignatureHex)

      const md = forge.md.sha256.create()
      md.update(data, 'utf8')

      const verified = key.verify(md.digest().bytes(), signature)
      console.log(`Signature ${PublicKeyFiles.indexOf(keyFile)} verified: ${verified}`)
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