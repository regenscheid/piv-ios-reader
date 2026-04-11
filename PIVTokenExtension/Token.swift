//
//  Token.swift
//  PIVTokenExtension
//

import CryptoTokenKit

class Token: TKToken, TKTokenDelegate {
    func createSession(_ token: TKToken) throws -> TKTokenSession {
        return TokenSession(token: self)
    }
}
