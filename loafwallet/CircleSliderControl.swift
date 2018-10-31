//
//  CircleSliderControl.swift
//  loafwallet
//
//  Created by Kerry Washington on 10/21/18.
//  Copyright © 2018 Litecoin Foundation. All rights reserved.
//

import Foundation
import UIKit
let resetSide = 15

let minValueAngle = CGFloat(-5*π/4)
let maxValueAngle = CGFloat(-7*π/4)

class CircleSliderControl : UIControl {
  
  var valueLabel = UILabel()
  var resetLabel = UILabel()
  private var arcLayer = CAShapeLayer()
  var fiatValue = 5
  var fiatAmount = CGFloat(4.6) //4.6 - 0.1
  
  override init(frame: CGRect) {
    super.init(frame: frame)
    configureViews()
    layoutCustomViews()
  }
  
  required init?(coder decoder: NSCoder) {
    super.init(coder: decoder)
  }
  
  func configureViews() {
    self.addSubview(valueLabel)
    self.addSubview(resetLabel)

    valueLabel.translatesAutoresizingMaskIntoConstraints = false
    valueLabel.font = UIFont.customBold(size: 16)
    valueLabel.textColor = .white//#colorLiteral(red: 0.1137254902, green: 0.4274509804, blue: 0.7921568627, alpha: 1)
    valueLabel.text = "$\(fiatValue)" //kcw-grunt: Hard coding to USD until better fiat agreement
    valueLabel.textAlignment = .center
    valueLabel.adjustsFontSizeToFitWidth = true
    
    resetLabel.translatesAutoresizingMaskIntoConstraints = false
    resetLabel.backgroundColor = .red
    resetLabel.layer.cornerRadius = 5
    resetLabel.clipsToBounds = true
    resetLabel.textColor = .white
    resetLabel.text = "X"
    resetLabel.textAlignment = .center
    resetLabel.font = UIFont.customBold(size: 8)
    resetLabel.alpha = 0.0
  }
  
  func layoutCustomViews() {
    
    valueLabel.constrain([
      valueLabel.centerXAnchor.constraint(equalTo: self.centerXAnchor),
      valueLabel.centerYAnchor.constraint(equalTo: self.centerYAnchor),
      valueLabel.widthAnchor.constraint(equalToConstant: 40),
      valueLabel.heightAnchor.constraint(equalToConstant: 60)
      ])
    
    resetLabel.constrain([
      resetLabel.centerXAnchor.constraint(equalTo: valueLabel.centerXAnchor),
      resetLabel.centerYAnchor.constraint(equalTo: valueLabel.centerYAnchor , constant:22),
      resetLabel.heightAnchor.constraint(equalToConstant:10),
      resetLabel.widthAnchor.constraint(equalToConstant:10)
      ])
    
    let trackLayer = CAShapeLayer()
    trackLayer.path = UIBezierPath(arcCenter:CGPoint(x: 25, y: 25), radius: 23, startAngle: minValueAngle, endAngle: maxValueAngle, clockwise: true).cgPath
    trackLayer.fillColor = nil
    trackLayer.strokeColor = UIColor.white.cgColor // #colorLiteral(red: 0.7215686275, green: 0.7725490196, blue: 0.8392156863, alpha: 1)
    trackLayer.lineWidth = 2.0
    trackLayer.lineCap = "round" //.bevel
    self.layer.addSublayer(trackLayer)
    
    arcLayer.path = UIBezierPath(arcCenter:CGPoint(x: 25, y: 25), radius: 23, startAngle: minValueAngle, endAngle: maxValueAngle - fiatAmount, clockwise: true).cgPath
    arcLayer.fillColor = nil
    arcLayer.strokeColor = #colorLiteral(red: 0.137254902, green: 0.8078431373, blue: 0.4196078431, alpha: 1)
    arcLayer.lineWidth = 3.0
    arcLayer.lineCap = "round" //.bevel
    self.layer.addSublayer(arcLayer)
  }
  
  
  @objc func updateArcLayerPath(incr:CGFloat) {
    
    if resetLabel.alpha == CGFloat(0.0) {
      resetLabel.alpha = CGFloat(1.0)
    }

    fiatAmount = fiatAmount - incr
    if fiatAmount >= 0.01 && fiatAmount <= 4.6 {
     arcLayer.path = UIBezierPath(arcCenter:CGPoint(x: 25, y: 25), radius: 23, startAngle: CGFloat(-5*π/4), endAngle: maxValueAngle - fiatAmount, clockwise: true).cgPath
    }
  }
  
  @objc func resetValues() {
    resetLabel.alpha = CGFloat(0.0)
    
    print("didTap")
    fiatValue = 5
    fiatAmount = CGFloat(4.6)
    valueLabel.text = "$\(fiatValue)" //kcw-grunt: Hard coding to USD until better fiat agreement
    arcLayer.path = UIBezierPath(arcCenter:CGPoint(x: 25, y: 25), radius: 23, startAngle: minValueAngle, endAngle: maxValueAngle - fiatAmount, clockwise: true).cgPath
  }

}
