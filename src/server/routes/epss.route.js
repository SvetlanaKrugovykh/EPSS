const epssController = require('../controllers/epssController')
const isAuthorizedGuard = require('../guards/is-authorized.guard')
const epssSignSchema = require('../schemas/epss-sign.schema')
module.exports = (fastify, _opts, done) => {

  fastify.route({
    method: 'POST',
    url: '/epss/sign/',
    handler: epssController.epssSign,
    preHandler: [
      isAuthorizedGuard
    ],
    schema: epssSignSchema
  })

  fastify.route({
    method: 'POST',
    url: '/epss/de-sign/',
    handler: epssController.epssDeSign,
    preHandler: [
      isAuthorizedGuard
    ],
    schema: epssSignSchema
  })

  done()
}

