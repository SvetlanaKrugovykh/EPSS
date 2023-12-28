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
    message: `Abonent switched off ${addTag}`
  }
}


module.exports.epssDeSign = async function (request, _reply) {
  const { dataString } = request.body
  const message = await epssService.deSign(dataString)

  if (!message) {
    throw new HttpError[501]('Command execution failed')
  }

  return {
    message: `Abonent forwarded on ${addTag}`
  }
}