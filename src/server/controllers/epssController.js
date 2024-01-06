const HttpError = require('http-errors')
const epssService = require('../services/epssService')
const addTag = process.env.PLATFORM !== 'freebsd' ? '( Test mode )' : ''

module.exports.epssSign = async function (request, _reply) {
  const { FileName, KeyFiles } = request.body
  const message = await epssService.signFile(FileName, KeyFiles)

  if (!message) {
    throw new HttpError[501]('Command execution failed')
  }

  return {
    message: `Sign on ${message}`
  }
}

module.exports.epssDeSign = async function (request, _reply) {
  const { FileName, KeyFiles } = request.body
  const message = await epssService.deSign(FileName, KeyFiles)

  return {
    message: `DeSign off ${message}`
  }
}

module.exports.checkKeys = async function (request, _reply) {
  const { KeyFiles } = request.body
  const message = await epssService.checkKeys(KeyFiles)

  return {
    message: `Check Key ${message}`
  }

}