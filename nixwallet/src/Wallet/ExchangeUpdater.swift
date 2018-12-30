//
//  ExchangeUpdater.swift
//  breadwallet
//
//  Created by Adrian Corscadden on 2017-01-27.
//  Copyright © 2017 breadwallet LLC. All rights reserved.
//

import Foundation

class ExchangeUpdater : Subscriber {

    //MARK: - Public
    init(store: Store, walletManager: WalletManager) {
        self.store = store
        self.walletManager = walletManager
        store.subscribe(self,
                        selector: { $0.defaultCurrencyCode != $1.defaultCurrencyCode },
                        callback: { state in
                            guard let currentRate = state.rates.first( where: { $0.code == state.defaultCurrencyCode }) else { return }
                            self.store.perform(action: ExchangeRates.setRate(currentRate))
        })
    }

    /*
    func refresh(completion: @escaping () -> Void) {
        walletManager.apiClient?.exchangeRates { rates, error in
            guard let currentRate = rates.first( where: { $0.code == self.store.state.defaultCurrencyCode }) else { completion(); return }
            self.store.perform(action: ExchangeRates.setRates(currentRate: currentRate, rates: rates))
            completion()
        }
    }
    */
    
    func refresh(completion: @escaping () -> Void) {
        
        walletManager.apiClient?.nixMultiplier{multiplier, error in
            guard let ratio_to_btc : Double = multiplier else { completion(); return }
            self.walletManager.apiClient?.exchangeRatesNix(code: "NIX", isFallback: false, ratio_to_btc, { rates,
                ratio_to_btc, error in
                
                guard let currentRate = rates.first( where: { $0.code == self.store.state.defaultCurrencyCode }) else { completion(); return }
                let aRate = Rate(code: currentRate.code, name: currentRate.name, rate: currentRate.rate * ratio_to_btc)
                
                self.store.perform(action: ExchangeRates.setRates(currentRate: aRate, rates: rates))

                completion()
            })
        }
    }
 
    
    //MARK: - Private
    let store: Store
    let walletManager: WalletManager
}
