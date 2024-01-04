const forge = require('node-forge')
const fs = require('fs').promises
const path = require('path')

module.exports.signFile = async function (FileName, KeyFiles) {
  try {
    const dataBuffer = await fs.readFile(FileName)
    const fileContent = dataBuffer.toString('utf8')

    for (const keyFile of KeyFiles) {
      const keyBuffer = await readKeyFileWithTags(keyFile, 'PRIVATE')
      const privateKey = forge.pki.privateKeyFromPem(keyBuffer)

      const md = forge.md.sha256.create()
      md.update(fileContent)
      const signature = privateKey.sign(md)
      const signatureBase64 = forge.util.encode64(signature)

      const signedFileName = `${FileName}._signed_`
      await fs.writeFile(signedFileName, signatureBase64, 'utf8')
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
    const dataBuffer = await fs.readFile(FileName)
    const signatureBase64 = await fs.readFile(SignatureFile, 'utf8')
    const signatureBinary = forge.util.decode64(signatureBase64)

    const keys = []
    for (const keyFile of PublicKeyFiles) {
      const publicKeyPem = await readKeyFileWithTags(keyFile, 'PUBLIC')
      const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
      keys.push(publicKey)
    }

    const md = forge.md.sha256.create()
    md.update(dataBuffer.toString('utf8'), 'utf8')

    for (const key of keys) {
      const isSignatureValid = key.verify(md.digest().getBytes(), signatureBinary)
      if (!isSignatureValid) {
        return false
      }
    }

    return true
  } catch (error) {
    console.error('Error verifying signature:', error.message)
    return false
  }
}
async function readKeyFileWithTags(keyFile, keyType) {
  try {
    let keyBuffer = await fs.readFile(keyFile, 'utf8')
    const beginTag = `-----BEGIN ${keyType} KEY-----`
    const endTag = `-----END ${keyType} KEY-----`

    if (!keyBuffer.includes(`-----BEGIN`)) {
      const keyBase64 = keyBuffer.toString('base64')
      keyBuffer = `${beginTag}\n${keyBase64}\n${endTag}`
    }

    if (keyType === 'PUBLIC') {
      if (keyBuffer.includes('-----BEGIN CERTIFICATE-----')) {
        const certificate = forge.pki.certificateFromPem(keyBuffer);
        return forge.pki.publicKeyToPem(certificate.publicKey);
      }
    }

    return keyBuffer
  } catch (error) {
    console.error('Error reading key file:', error.message)
    return false
  }
}