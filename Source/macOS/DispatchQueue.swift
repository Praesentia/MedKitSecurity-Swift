/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017-2018 Jon Griffeth
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -----------------------------------------------------------------------------
 */

import Foundation


extension DispatchQueue {
    
    private static let queueIdentifier = "SecurityKitAOS"
    
    /**
     Main module dispatch queue.
     
     - Remark:
        Apparently, the macOS security API is not entirely thread-safe.  Hence,
        the use of a serialized queue.
     */
    static let module = DispatchQueue(label: queueIdentifier)
    
}


// End of File
