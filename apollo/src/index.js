// @ts-check

const { importSchema } = require('graphql-import')
const { ApolloServer, gql } = require('apollo-server')

const PORT = process.env.PORT || 8000

const checkEnvironment = () => {
  const requiredEnvironmentalVariables = ['JWT_ISSUER', 'JWKS_URI', 'PRISMA_ENDPOINT', 'PRISMA_SECRET']

  let environmentReady = true
  for (const variableName of requiredEnvironmentalVariables) {
    if (!(variableName in process.env)) {
      console.error('Server cannot be started with environment variable %s', variableName)
      environmentReady = false
    }
  }
  if (!environmentReady) {
    throw new Error('Missing one or more required environment variables')
  }
}

const resolvers = require('./resolvers')
const context = require('./context')

const typeDefs = gql(importSchema('schema/apollo.graphql'))

const main = async () => {
  checkEnvironment()

  const server = new ApolloServer({
    resolvers,
    typeDefs,
    context,
    cors: true,
    forMatError: err => {
      console.log('%O', err)
      console.log('%O', err.extensions)

      return err
    }
  })

  const { url } = await server.listen(PORT)
  console.log(`Server running on ${url}`)
}

main()
