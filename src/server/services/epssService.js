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

module.exports.deSign = async function (FileName, KeyFiles) {
  try {
    const dataBuffer = await fs.readFile(FileName)

    const keys = []
    for (const keyFile of KeyFiles) {
      const key = await fs.readFile(keyFile, 'utf8')
      keys.push(key)
      const keyType = identifyPublicKeyType(key)
      console.log(`Key type: ${keyType}`)
    }

    const derData = dataBuffer.toString('binary')

    const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(derData))

    const certificates = p7.certificates

    if (certificates.length > 0) {
      const subjectAttributes = certificates[0].subject.attributes

      const subject = subjectAttributes.reduce((result, attr) => {
        result[attr.name] = attr.value
        return result
      }, {})

      return { subject, keys }
    } else {
      throw new Error('No certificates found')
    }
  } catch (error) {
    console.error('Error executing deSign command:', error.message)
    return false
  }
}

function identifyPublicKeyType(keyString) {
  try {
    const rsaPublicKey = forge.pki.publicKeyFromPem(keyString)
    if (rsaPublicKey) {
      return 'RSA'
    }
  } catch (error) {
  }

  return 'Unknown'
}

async function readKeyFileWithTags(keyFile, keyType) {
  try {
    let keyBuffer = await fs.readFile(keyFile, 'utf8')
    const beginTag = `-----BEGIN ${keyType} KEY-----`
    const endTag = `-----END ${keyType} KEY-----`

    if (!keyBuffer.includes(beginTag) || !keyBuffer.includes(endTag)) {
      keyBuffer = `${beginTag}\n${keyBuffer}\n${endTag}`
    }
    return keyBuffer
  } catch (error) {
    console.error('Error reading key file:', error.message)
    return false
  }
}