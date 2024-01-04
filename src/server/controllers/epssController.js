const HttpError = require('http-errors')
const epssService = require('../services/epssService')
const addTag = process.env.PLATFORM !== 'freebsd' ? '( Test mode )' : ''

module.exports.epssSign = async function (request, _reply) {
  const { dataString, keyString } = request.body
  const message = await epssService.sign(dataString, keyString)

  if (!message) {
    throw new HttpError[501]('Command execution failed')
  }

  return {
    message: `Sign on ${message}`
  }
}


module.exports.epssDeSign = async function (request, _reply) {
  const { dataString, keyString } = request.body
  const message = await epssService.deSign(dataString, keyString)

  if (!message) {
    throw new HttpError[501]('Command execution failed')
  }

  return {
    message: `DeSign off ${message}`
  }
}