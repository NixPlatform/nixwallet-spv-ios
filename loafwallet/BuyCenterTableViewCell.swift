//
//  BuyCenterTableViewCell.swift
//  breadwallet
//
//  Created by Kerry Washington on 9/30/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

import Foundation
import UIKit

protocol BuyCenterTableViewCellDelegate : class {
  func didClickPartnerCell(partner: String, fiatAmount:Double)
}

class BuyCenterTableViewCell : UITableViewCell {
  
  private let colorFrameView = UIView()
  private let selectImage = UIImageView()
  private var cellButton = UIButton()
  private var swipeView = UIView()

  var logoImageView = UIImageView()
  var partnerLabel = UILabel()
  var financialDetailsLabel = UILabel()
  var frameView = UIView()
  var priceControl : CircleSliderControl?
  var startPoint = CGPoint()
  weak var delegate : BuyCenterTableViewCellDelegate?
  
  init(style: UITableViewCellStyle, reuseIdentifier: String?, shouldShowPC:Bool?) {
    super.init(style: style, reuseIdentifier: reuseIdentifier)
    self.selectionStyle = .none
    self.backgroundColor = UIColor.clear
    
    configureViews()
    layoutCustomViews()
  }
  
  override init(style: UITableViewCellStyle, reuseIdentifier: String?) {
    super.init(style: style, reuseIdentifier: reuseIdentifier)
    self.selectionStyle = .none
    self.backgroundColor = UIColor.clear
    
    configureViews()
    layoutCustomViews()
  }
  
  required init?(coder aDecoder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }
  
  func configureViews() {
    
    self.addSubview(frameView)
    frameView.addSubview(colorFrameView)
    colorFrameView.addSubview(logoImageView)
    frameView.addSubview(partnerLabel)
    frameView.addSubview(financialDetailsLabel)
    frameView.addSubview(selectImage)
    frameView.addSubview(cellButton)
    
    frameView.translatesAutoresizingMaskIntoConstraints = false
    frameView.layer.cornerRadius = 5
    frameView.clipsToBounds = true
    
    colorFrameView.backgroundColor = UIColor.white
    
    logoImageView.translatesAutoresizingMaskIntoConstraints = false
    logoImageView.contentMode = .scaleAspectFit
    
    partnerLabel.translatesAutoresizingMaskIntoConstraints = false
    partnerLabel.font = UIFont.customBold(size: 20)
    partnerLabel.textColor = UIColor.white
    
    financialDetailsLabel.translatesAutoresizingMaskIntoConstraints = false
    financialDetailsLabel.font = UIFont.customBody(size: 14)
    financialDetailsLabel.textColor = UIColor.white
    financialDetailsLabel.textAlignment = .left
    financialDetailsLabel.numberOfLines = 0
    financialDetailsLabel.lineBreakMode = .byWordWrapping
   
    selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
    selectImage.contentMode = .scaleAspectFit
    
    cellButton.setTitle(" ", for: .normal)
    shouldActivateCellButton(activate: true)
    
  }
  
  func turnOnPriceControl(partner:String) {
    
    if partner == "Coinbase" {
      selectImage.image = nil
      self.isUserInteractionEnabled = true
      shouldActivateCellButton(activate: false)
      priceControl = CircleSliderControl(frame: CGRect.zero)
      priceControl?.translatesAutoresizingMaskIntoConstraints = false
      frameView.addSubview(priceControl!)
      priceControl?.constrain([
        priceControl?.trailingAnchor.constraint(equalTo: frameView.trailingAnchor, constant:-30),
        priceControl?.widthAnchor.constraint(equalToConstant: 50),
        priceControl?.heightAnchor.constraint(equalToConstant: 50),
        priceControl?.topAnchor.constraint(equalTo: frameView.topAnchor, constant:4)
        ])
      
      swipeView = UIView(frame: CGRect.zero)
      swipeView.translatesAutoresizingMaskIntoConstraints = false
      //swipeView.backgroundColor = UIColor(red: 0.3, green: 0.3, blue: 0.3, alpha: 0.3)
      frameView.addSubview(swipeView)
      swipeView.constrain([
        swipeView.trailingAnchor.constraint(equalTo: frameView.trailingAnchor, constant:-35),
        swipeView.leadingAnchor.constraint(equalTo: frameView.leadingAnchor),
        swipeView.topAnchor.constraint(equalTo: frameView.topAnchor),
        swipeView.bottomAnchor.constraint(equalTo: frameView.bottomAnchor)
        ])

      let tap = UITapGestureRecognizer(target: self, action: #selector(BuyCenterTableViewCell.handleTap(recognizer:)))
      tap.numberOfTapsRequired = 1
      tap.numberOfTouchesRequired = 1
      swipeView.addGestureRecognizer(tap)
      
      let pan = UIPanGestureRecognizer(target: self, action:#selector(BuyCenterTableViewCell.handlePan(recognizer:)))
      swipeView.addGestureRecognizer(pan)
    }
  }
  
  
  func shouldActivateCellButton(activate: Bool) {
    if activate {
     cellButton.addTarget(self, action: #selector(cellButtonPressed), for: .touchUpInside)
     cellButton.addTarget(self, action: #selector(cellButtonImageChanged), for: .touchDown)
     cellButton.addTarget(self, action: #selector(cellButtonImageChanged), for: .touchUpOutside)
    } else {
     cellButton.removeTarget(self, action: #selector(cellButtonPressed), for: .touchUpInside)
     cellButton.removeTarget(self, action: #selector(cellButtonImageChanged), for: .touchDown)
     cellButton.removeTarget(self, action: #selector(cellButtonImageChanged), for: .touchUpOutside)
    }
  }
  
  func layoutCustomViews() {
    let margins = self.layoutMarginsGuide
    
    frameView.constrain([
      frameView.leadingAnchor.constraint(equalTo: margins.leadingAnchor, constant: -3),
      frameView.trailingAnchor.constraint(equalTo: margins.trailingAnchor, constant: 3),
      frameView.topAnchor.constraint(equalTo: margins.topAnchor, constant: 10),
      frameView.bottomAnchor.constraint(equalTo: margins.bottomAnchor, constant: 10)
      ])
    
    colorFrameView.constrain([
      colorFrameView.leadingAnchor.constraint(equalTo: frameView.leadingAnchor),
      colorFrameView.widthAnchor.constraint(equalToConstant: 80),
      colorFrameView.topAnchor.constraint(equalTo: frameView.topAnchor),
      colorFrameView.bottomAnchor.constraint(equalTo: frameView.bottomAnchor)
      ])
    
    logoImageView.constrain([
      logoImageView.leadingAnchor.constraint(equalTo: frameView.leadingAnchor, constant: 8),
      logoImageView.trailingAnchor.constraint(equalTo: colorFrameView.trailingAnchor, constant: -8),
      logoImageView.bottomAnchor.constraint(equalTo: frameView.bottomAnchor),
      logoImageView.centerYAnchor.constraint(equalTo: frameView.centerYAnchor)
      ])
    
    partnerLabel.constrain([
      partnerLabel.leadingAnchor.constraint(equalTo: colorFrameView.trailingAnchor, constant: 10),
      partnerLabel.widthAnchor.constraint(equalToConstant: 160),
      partnerLabel.topAnchor.constraint(equalTo: frameView.topAnchor, constant: 10),
      partnerLabel.heightAnchor.constraint(equalToConstant: 24)
      ])
    
    financialDetailsLabel.constrain([
      financialDetailsLabel.leadingAnchor.constraint(equalTo: colorFrameView.trailingAnchor, constant: 10),
      financialDetailsLabel.trailingAnchor.constraint(equalTo: frameView.trailingAnchor),
      financialDetailsLabel.topAnchor.constraint(equalTo: partnerLabel.bottomAnchor),
      financialDetailsLabel.heightAnchor.constraint(equalToConstant: 80)
      ])
    
    selectImage.constrain([
      selectImage.widthAnchor.constraint(equalToConstant: 18),
      selectImage.trailingAnchor.constraint(equalTo: frameView.trailingAnchor, constant:-3),
      selectImage.heightAnchor.constraint(equalToConstant: 18),
      selectImage.centerYAnchor.constraint(equalTo: frameView.centerYAnchor)
      ])
    
    cellButton.constrain([
      cellButton.widthAnchor.constraint(equalTo: frameView.widthAnchor),
      cellButton.trailingAnchor.constraint(equalTo: frameView.trailingAnchor),
      cellButton.topAnchor.constraint(equalTo: frameView.topAnchor),
      cellButton.bottomAnchor.constraint(equalTo: frameView.bottomAnchor)
      ])
  }
  
  @objc func handlePan(recognizer:UIPanGestureRecognizer) {
    
    if recognizer.state == .began {
      startPoint = recognizer.location(in: swipeView)
      print(startPoint)
    } else if recognizer.state == .changed {
      let changed = recognizer.location(in: swipeView)
      let dx = changed.x - startPoint.x
      let dy = changed.y - startPoint.y
      
      var dist = CGFloat(0.0)

      if dx > 0 {
        dist = CGFloat(sqrt(dx*dx + dy*dy))
      } else {
        dist = -1.0 * CGFloat(sqrt(dx*dx + dy*dy))
      }
      
      if (priceControl?.fiatValue)! > 0 {
        priceControl?.fiatValue =  (priceControl?.fiatValue)! + Int(dist/10)
        print("Val: \(priceControl?.fiatValue)  :  number \(dist/1000)")
        let val = String(format: "$%d", (priceControl?.fiatValue)!)
        priceControl?.valueLabel.text = "\(val)"
        priceControl?.updateArcLayerPath(incr:dist/1000)
        shouldActivateCellButton(activate: true)
         selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
      } else {
        priceControl?.resetValues()
        selectImage.image = nil
        shouldActivateCellButton(activate: false)
      }
      
    } else if recognizer.state == .ended {
      startPoint = CGPoint()
    }

  }
  
  
  
  @objc func handleTap(recognizer:UITapGestureRecognizer) {
    
    let location = recognizer.location(in: swipeView)
    
    if location.x > 250 && location.y < 60 { //RESET
      priceControl?.resetValues()
      selectImage.image = nil
      shouldActivateCellButton(activate: false)
    } else {
      priceControl?.fiatValue += 1
      let val = String(format: "$%d", (priceControl?.fiatValue)!)
      priceControl?.valueLabel.text = "\(val)"
      let fl = CGFloat((priceControl?.fiatValue)!) * 0.001
      priceControl?.updateArcLayerPath(incr:fl)
    }
  }
  
  @objc func cellButtonPressed(selector: UIButton) {
    selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
    if let partnerName = partnerLabel.text {
      delegate?.didClickPartnerCell(partner: partnerName, fiatAmount: Double((priceControl?.fiatValue)!))
    }
  }
  
  @objc func cellButtonImageChanged(selector: UIButton) {
    if let partner = partnerLabel.text {
      switch partner {
       case "Simplex":
        selectImage.image = #imageLiteral(resourceName: "simplexRightArrow")
       case "Bitrefill":
        selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
       case "Changelly":
        selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
       case "Coinbase":
        selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
       default:
        selectImage.image = #imageLiteral(resourceName: "whiteRightArrow")
      }
    } 
  }
  
  
  
}

