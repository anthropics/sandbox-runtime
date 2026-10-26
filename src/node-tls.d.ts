// The Bun type package redeclares `connect` in 'node:tls' in terms of names
// that @types/node 22 declares in 'tls' alone. Unresolved, they leave it
// taking and returning an untyped value.
declare module 'node:tls' {
  import * as tls from 'tls'
  export import ConnectionOptions = tls.ConnectionOptions
  export import KeyObject = tls.KeyObject
  export import TLSSocket = tls.TLSSocket
}
