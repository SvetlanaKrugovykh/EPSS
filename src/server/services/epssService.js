const forge = require('node-forge')
const fs = require('fs')

module.exports.signFile = async function (FileName, KeyFiles, genegateKeys = false) {
  try {
    const data = fs.readFileSync(FileName, 'utf8')
    if (genegateKeys) keysGeneration(KeyFiles)

    for (const keyFile of KeyFiles) {
      const rawData = fs.readFileSync(keyFile, 'utf8')
      const dataType = detectKeyOrCert(rawData)
      let key
      if (dataType === 'private_key') {
        key = forge.pki.privateKeyFromPem(rawData)
      } else if (dataType === 'unknown') {
        key = binaryToPEM(rawData, 'PRIVATE KEY')
      }

      const md = forge.md.sha256.create()
      md.update(data, 'utf8')
      const signature = key.sign(md)
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

module.exports.checkKeys = async function (KeyFiles) {
  try {
    for (const keyFile of KeyFiles) {
      const rawData = fs.readFileSync(keyFile, 'utf8')
      const dataType = detectKeyOrCert(rawData)

      if (dataType === 'private_key' || dataType === 'public_key' || dataType === 'certificate') {
        console.log(`Detected data type: ${dataType}`)

        if (dataType !== 'private_key' && dataType !== 'public_key' && dataType !== 'certificate') {
          const pemData = binaryToPEM(dataBuffer, dataType)
          if (pemData) {
            console.log('PEM format:')
            console.log(pemData)
          } else {
            console.error('Failed to convert to PEM format')
          }
        }
      } else {
        console.error('Unknown data type')
      }
    }
    return true
  } catch (error) {
    console.error('Error executing checkKeys command:', error.message)
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
      const rawData = fs.readFileSync(keyFile, 'utf8')
      const dataType = detectKeyOrCert(rawData)
      let key
      if (dataType === 'public_key') {
        key = forge.pki.publicKeyFromPem(rawData)
      } else if (dataType === 'certificate') {
        const certificate = forge.pki.certificateFromPem(rawData)
        key = certificate.publicKey
      } else if (dataType === 'unknown') {
        const pemData = binaryToPEM(rawData, 'PUBLIC KEY')
        if (pemData) {
          key = forge.pki.publicKeyFromPem(pemData)
        }
      }
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

function detectKeyOrCert(data) {
  const pemHandlers = [
    { handler: forge.pki.privateKeyFromPem, type: 'private_key' },
    { handler: forge.pki.publicKeyFromPem, type: 'public_key' },
    { handler: forge.pki.certificateFromPem, type: 'certificate' }
  ]

  const derHandlers = [
    { handler: forge.pki.privateKeyFromAsn1, type: 'private_key' },
    { handler: forge.pki.publicKeyFromAsn1, type: 'public_key' },
    { handler: forge.pki.certificateFromAsn1, type: 'certificate' }
  ]

  for (const { handler, type } of pemHandlers) {
    try {
      const key = handler(data)
      console.log(key)
      return type
    } catch (err) { }
  }

  try {
    const derBuffer = Buffer.from(data, 'binary')
    const asn1 = forge.asn1.fromDer(derBuffer.toString('binary'))

    for (const { handler, type } of derHandlers) {
      try {
        const key = handler(asn1)
        console.log(key)
        return type
      } catch (err) { }
    }
  } catch (err) { }

  return 'unknown'
}

function binaryToPEM(binaryData, type) {
  if (type === 'private_key') {
    return forge.pki.privateKeyToPem(forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(binaryData)))
  } else if (type === 'certificate') {
    return forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(binaryData)))
  } else {
    return null
  }
}

