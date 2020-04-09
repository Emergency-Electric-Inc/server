// @ts-check

// Apollo dependencies
const { AuthenticationError } = require('apollo-server')
const jwt = require('jsonwebtoken')

const { promisify } = require('util')

const JwksClient = require('jwks-rsa')

const winston = require('winston')
const { prisma } = require('../generated/prisma-client')

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.splat(), winston.format.simple()),
  transports: [new winston.transports.Console()]
})

console.log('Logging level: %s', logger.level)

/**
 *  The context passed to the resolvers
 *  @typedef {Object} ApolloContext
 *  @property {import('../generated/prisma-client).Prisma} prisma The generated Prisma client
 *  @property {User} user the currently authenticated user
 *  @proopery {import('winston').Logger} logger A logger
 */

/**
 *  @constructor
 *  @param {string} id
 *  @param {string} name
 *  @param {string} email
 *  @param {[string]} groups
 */

function User (id, name, email) {
  this.id = id
  this.name = name
  this.email = email
}

/**
 *  Options used for verifying the JWT
 *  @type jwt.VerifyOptions
 */

const jwtVerifyOptions = {
  audience: process.env.JWT_AUDIENCE,
  issuer: process.env.JWT_ISSUER,
  algorithms: ['RS256']
}

const { JWKS_URI } = process.env
const jwksClient = JwksClient({
  jwksUri: JWKS_URI
})

/**
 *  @param {import('jsonwebtoken').JwtHeader} header
 *  @returns {Promise<string>} key
 */

const getKey = async header => {
  const getSigningKey = promisify(jwksClient.getSigningKey)

  let key
  try {
    key = await getSigningKey(header.kid)
  } catch (err) {
    logger.error('Error while retrieving signing key (%O) from %O',
      header.kid,
      JWKS_URI
    )
    throw new AuthenticationError('Not Authorized')
  }

  logger.debug('Retrieved public key from (%O) with kid (%O): %O', JWKS_URI, header.kid, key)

  return key.rsaPublicKey
}

/**
 *  Async factory for the context
 *
 *  @param { {req: import('Express').Request} } req
 *  @return { Promise<ApolloContext> } context
 */

const context = async ({ req }) => {
  const authorizationHeader = req.header('Authorization')
  if (typeof authorizationHeader !== 'string' || authorizationHeader === 'null' || authorizationHeader === '') {
    logger.error('Authorization token missing from request headers: %O', req.headers)
    throw new AuthenticationError('Not authorized')
  }

  const token = authorizationHeader.replace(/^Bearer\s/, '')

  logger.debug('Decoding token: %s', token)
  let tokenHeader
  try {
    tokenHeader = jwt.decode(token, { compolete: true }).header
  } catch (err) {
    logger.error('Error while decoding token: %O', token, err)
    throw new AuthenticationError('Not Authorized')
  }
  logger.debug('Retrieving public key used for JWT validation')
  const pubKey = await getKey(tokenHeader)

  logger.debug('Verifying and decoding JWT')
  let decodeJWT
  try {
    decodeJWT = jwt.verify(token, pubKey, jwtVerifyOptions)
  } catch (err) {
    logger.error('Error while verifying token: %O\n%O', token, err)
    throw new AuthenticationError('Not Authorized')
  }

  logger.debug('Creating User using decoded JWT: %O', decodeJWT)
  const user = new User(decodeJWT.sub, decodeJWT.name, decodeJWT.email)

  if (typeof user === 'undefined' || user == null) {
    logger.error('Unable to authenticate user: %O', req.header)
    throw new AuthenticationError('Not Authorized')
  }

  logger.debug('Current user: %O', user)

  return { user, prisma, logger }
}

module.exports = context
