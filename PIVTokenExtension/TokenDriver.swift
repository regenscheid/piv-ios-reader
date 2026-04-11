//
//  TokenDriver.swift
//  PIVTokenExtension
//

import CryptoTokenKit

class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        return Token(tokenDriver: self, instanceID: configuration.instanceID)
    }
}
