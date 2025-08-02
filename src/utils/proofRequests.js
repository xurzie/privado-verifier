function generateProofRequest(requestId, host) {
  return {
    id: requestId,
    typ: 'application/iden3comm-plain-json',
    type: 'https://iden3-communication.io/authorization/1.0/request',
    body: {
      reason: 'Login with PrivadoID',
      callbackUrl: `${host}/api/callback?requestId=${requestId}`,
      scope: [
        {
          id: requestId,
          circuitId: 'credentialAtomicQuerySigV2',
          query: {
            allowedIssuers: ['*'],
            context: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
            credentialSubject: {
              birthday: { $lt: 20070714 }
            },
            type: 'KYCAgeCredential'
          }
        }
      ]
    }
  };
}

module.exports = { generateProofRequest };
