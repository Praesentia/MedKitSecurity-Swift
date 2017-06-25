/*
 -----------------------------------------------------------------------------
 This source file is part of Clock.
 
 Copyright 2017 Jon Griffeth.  All rights reserved.
 -----------------------------------------------------------------------------
 */


import Foundation


extension DateFormatter {
    
    convenience init(dateFormat: String)
    {
        self.init()
        self.dateFormat = dateFormat
    }
    
}


// End of File
