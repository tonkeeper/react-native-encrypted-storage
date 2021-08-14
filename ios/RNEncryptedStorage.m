//
//  RNEncryptedStorage.m
//  Starter
//
//  Created by Yanick Bélanger on 2020-02-09.
//  Copyright © 2020 Facebook. All rights reserved.
//

#import "RNEncryptedStorage.h"
#import <Security/Security.h>
#import <React/RCTLog.h>

void rejectPromise(NSString *message, NSError *error, RCTPromiseRejectBlock rejecter)
{
    NSString* errorCode = [NSString stringWithFormat:@"%ld", error.code];
    NSString* errorMessage = [NSString stringWithFormat:@"RNEncryptedStorageError: %@", message];

    rejecter(errorCode, errorMessage, error);
}

@implementation RNEncryptedStorage

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(isDeviceProtected:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL apiAvailable = (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly != NULL);

    if (!apiAvailable) {
        resolve(@NO);
        return;
    }

    OSStatus status;

    // delete the item to resolve some entitlements and security issues when running from Xcode debugger
    {
        NSDictionary *query = @{
                                (__bridge id)kSecClass:  (__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecAttrService: @"LocalDeviceServices",
                                (__bridge id)kSecAttrAccount: @"ProbeAccount"
                                };

        status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status == errSecSuccess || status == errSecItemNotFound) {
            // okay: we either had no probe as expected, or cleaned up a leftover from the previous check
        } else {
            NSError* error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:status userInfo: nil];
            rejectPromise(@"Unexpected error occured while removing the probe keychain item", error, reject);
            return;
        }
    }

    NSData* probeValue = [@"ProbeValue" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *attributes = @{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: @"LocalDeviceServices",
                                 (__bridge id)kSecAttrAccount: @"ProbeAccount",
                                 (__bridge id)kSecValueData: probeValue,
                                 (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                                 };

    status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    if (status == errSecSuccess) { // item added okay, passcode has been set
        NSDictionary *query = @{
                                (__bridge id)kSecClass:  (__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecAttrService: @"LocalDeviceServices",
                                (__bridge id)kSecAttrAccount: @"ProbeAccount"
                                };
        
        status = SecItemDelete((__bridge CFDictionaryRef)query);

        if (status != errSecSuccess) {
            NSError* error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:status userInfo: nil];
            rejectPromise(@"Unexpected error occured while removing the probe keychain item", error, reject);
            return;
        }
        resolve(@YES);
    } else {
        resolve(@NO);
    }
}

RCT_EXPORT_METHOD(setItem:(NSString *)key withValue:(NSString *)value resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData* dataFromValue = [value dataUsingEncoding:NSUTF8StringEncoding];
    
    if (dataFromValue == nil) {
        NSError* error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:0 userInfo: nil];
        rejectPromise(@"An error occured while parsing value", error, reject);
        return;
    }

    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(
        // default allocator
        NULL,

        // We don't use "WhenPasscodeSet" for two reasons:
        // 1) in case the user does not have passcode set we'd need to use "when unlocked this device only" anyway.
        // 2) if we use "when passcode set" flag when the passcode is set,
        //    then the wallet will unexpectedly stop working (item will be erased)
        //    if the user turns the passcode off and on.
        // "ThisDeviceOnly" is set in order to prevent unexpected backups
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,

        // Requires any biometrics OR device passcode to read the item.
        // Biometry may be re-enrolled and the item will still be accessible.
        kSecAccessControlUserPresence,

        // No error out reference — this call never fails for these parameters.
        NULL);
    
    // Prepares the insert query structure
    NSDictionary* storeQuery = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecValueData : dataFromValue,
        (__bridge id)kSecAttrAccessControl: (__bridge id)accessControlRef
    };
    
    // Deletes the existing item prior to inserting the new one
    SecItemDelete((__bridge CFDictionaryRef)storeQuery);
    
    OSStatus insertStatus = SecItemAdd((__bridge CFDictionaryRef)storeQuery, nil);
    
    if (insertStatus == noErr) {
        resolve(value);
    }
    
    else {
        NSError* error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:insertStatus userInfo: nil];
        rejectPromise(@"An error occured while saving value", error, reject);   
    }
}

RCT_EXPORT_METHOD(getItem:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary* getQuery = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
    };
    
    CFTypeRef dataRef = NULL;
    OSStatus getStatus = SecItemCopyMatching((__bridge CFDictionaryRef)getQuery, &dataRef);
    
    if (getStatus == errSecSuccess) {
        NSString* storedValue = [[NSString alloc] initWithData: (__bridge NSData*)dataRef encoding: NSUTF8StringEncoding];
        resolve(storedValue);
    }

    else if (getStatus == errSecItemNotFound) {
        resolve(nil);
    }
    
    else {
        NSError* error = [NSError errorWithDomain: [[NSBundle mainBundle] bundleIdentifier] code:getStatus userInfo:nil];
        rejectPromise(@"An error occured while retrieving value", error, reject);
    }
}

RCT_EXPORT_METHOD(removeItem:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary* removeQuery = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue
    };
    
    OSStatus removeStatus = SecItemDelete((__bridge CFDictionaryRef)removeQuery);
    
    if (removeStatus == noErr) {
        resolve(key);
    }
    
    else {
        NSError* error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:removeStatus userInfo: nil];
        rejectPromise(@"An error occured while removing value", error, reject);
    }
}

RCT_EXPORT_METHOD(clear:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    
    // Maps through all Keychain classes and deletes all items that match
    for (id secItemClass in secItemClasses) {
        NSDictionary *spec = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)spec);
    }
    
    resolve(nil);
}
@end