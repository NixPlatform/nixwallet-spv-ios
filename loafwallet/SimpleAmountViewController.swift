//
//  SimpleAmountViewController.swift
//  loafwallet
//
//  Created by Kerry Washington on 10/19/18.
//  Copyright © 2018 Litecoin Foundation. All rights reserved.
//

import Foundation
import UIKit

class SimpleAmountViewController: UIViewController {
  
  var walletAddress = ""
  var partnerCode = ""
  var amountTextField = UITextField()

  init(walletAddress: String, partnerCode: String) {
    
    super.init(nibName: nil, bundle: nil)
    configureViews()
    layoutCustomViews()
  }
  
  required init?(coder aDecoder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }
  
//  - (BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string
//  {
//  NSString *newString = [textField.text stringByReplacingCharactersInRange:range withString:string];
//  NSArray  *arrayOfString = [newString componentsSeparatedByString:@"."];
//
//  if ([arrayOfString count] > 2 )
//  return NO;
//
//  return YES;
//  }
  
  private func configureViews() {
    self.view.backgroundColor = #colorLiteral(red: 0.9529411765, green: 0.9529411765, blue: 0.9529411765, alpha: 1)
    let backButton = UIBarButtonItem(image: #imageLiteral(resourceName: "Close"), style: .plain, target: self, action:#selector(SimpleAmountViewController.dismissWebView))
    self.navigationItem.leftBarButtonItem = backButton 
    UIBarButtonItem.appearance().setTitleTextAttributes([NSAttributedStringKey.foregroundColor: UIColor.red], for: .normal)

    self.title = "Coinbase: Set Amount"
    self.view.addSubview(amountTextField)
      
    amountTextField.translatesAutoresizingMaskIntoConstraints = false
    amountTextField.font = UIFont.customBody(size: 18)
    amountTextField.textColor = UIColor.black
    amountTextField.textAlignment = .left
    amountTextField.borderStyle = .none
    amountTextField.placeholder = "$100"
    amountTextField.keyboardType = .numberPad
    amountTextField.keyboardAppearance = .light
    amountTextField.becomeFirstResponder()
 
  }
    
  private func layoutCustomViews() {
 
      amountTextField.constrain([
        amountTextField.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
        amountTextField.centerYAnchor.constraint(equalTo: self.view.centerYAnchor, constant: -100),
        amountTextField.widthAnchor.constraint(equalToConstant: 120.0),
        amountTextField.heightAnchor.constraint(equalToConstant: 40.0)
        ])
  }
  
  private func presentBrowserViewController(urlString:String) {
    
//    guard let url = Bundle.main.url(forResource: "coinbase_index", withExtension: "html") else {return}
//    coinbaseBrowserVC.load(URLRequest(url:url))
//
//    self.present(coinbaseBrowserVC, animated: true, completion: nil)
//    registerLogEvent(name:"OPEN_COINBASE_STORE")
    
  }
  
  @objc func dismissWebView() {
    dismiss(animated: false) {
      //
    }
  }
  
  func validateDecimalPlaces(text:String) {
    self.amountTextField.text = text
  }
  
}
