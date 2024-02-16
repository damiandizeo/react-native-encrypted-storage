//
//  RNEncryptedStorage.m
//  SATO
//
//  Created by Damian Di Zeo on 2024-02-16.
//  Copyright © 2020 SATO Technoloiges Corp. All rights reserved.
//

#import "RNEncryptedStorage.h"
#import <Security/Security.h>
#import <React/RCTLog.h>

void rejectPromise(NSString *message, NSError *error, RCTPromiseRejectBlock rejecter) {
    NSString *errorCode = [NSString stringWithFormat:@"%ld", error.code];
    NSString *errorMessage = [NSString stringWithFormat:@"RNEncryptedStorageError: %@", message];
    rejecter(errorCode, errorMessage, error);
}

@implementation RNEncryptedStorage

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

CFStringRef getKeychainAccessibility(NSDictionary *options) {
    id keychainAccessibility = options[@"keychainAccessibility"];
    if( keychainAccessibility == nil ) {
        return kSecAttrAccessibleAfterFirstUnlock;
    }
    NSDictionary *valueMap = @{
        @"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        @"kSecAttrAccessibleWhenUnlockedThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        @"kSecAttrAccessibleWhenUnlocked": (__bridge NSString *)kSecAttrAccessibleWhenUnlocked,
        @"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        @"kSecAttrAccessibleAfterFirstUnlock": (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlock,
    };
    NSString *value = valueMap[keychainAccessibility];
    return (__bridge CFStringRef)value;
}

NSString *getKeychainAccessGroup(NSDictionary *options) {
    id keychainAccessGroup = options[@"keychainAccessGroup"];
    return keychainAccessGroup;
}

NSString *getKeychainService(NSDictionary *options) {
    id keychainService = options[@"storageName"];
    if( keychainService == nil ) {
        return [[NSBundle mainBundle] bundleIdentifier];
    }
    return keychainService;
}


RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(setItem:(NSString *)key withValue:(NSString *)value withOptions:(NSDictionary *) options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *dataFromValue = [value dataUsingEncoding:NSUTF8StringEncoding];
    
    if( dataFromValue == nil ) {
        NSError *error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:0 userInfo: nil];
        rejectPromise(@"An error occured while parsing value", error, reject);
        return;
    }
    
    // Prepares the insert query structure
    CFStringRef keychainAccessibility = getKeychainAccessibility(options);
    NSString *keychainService = getKeychainService(options);
    NSMutableDictionary *storeQuery = [NSMutableDictionary dictionaryWithDictionary: @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecValueData : dataFromValue,
        (__bridge id)kSecAttrAccessible: (__bridge id)keychainAccessibility,
        (__bridge id)kSecAttrService: keychainService
    }];
    NSString *keychainAccessGroup = getKeychainAccessGroup(options);
    if( keychainAccessGroup != nil ) {
        [storeQuery setValue:keychainAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    }
    
    // Deletes the existing item prior to inserting the new one
    SecItemDelete((__bridge CFDictionaryRef)storeQuery);
    
    OSStatus insertStatus = SecItemAdd((__bridge CFDictionaryRef)storeQuery, nil);
    
    if( insertStatus == noErr ) {
        resolve(value);
    } else {
        NSError *error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:insertStatus userInfo: nil];
        rejectPromise(@"An error occured while saving value", error, reject);
    }
}

RCT_EXPORT_METHOD(getItem:(NSString *)key withOptions:(NSDictionary *) options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *keychainService = getKeychainService(options);

    NSMutableDictionary *getQuery = [NSMutableDictionary dictionaryWithDictionary: @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecAttrService: keychainService,
        (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
    }];
    NSString *keychainAccessGroup = getKeychainAccessGroup(options);
    if( keychainAccessGroup != nil ) {
        [getQuery setValue:keychainAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    }
    
    CFTypeRef dataRef = NULL;
    OSStatus getStatus = SecItemCopyMatching((__bridge CFDictionaryRef)getQuery, &dataRef);
    
    if( getStatus == errSecSuccess ) {
        NSString *storedValue = [[NSString alloc] initWithData: (__bridge NSData*)dataRef encoding: NSUTF8StringEncoding];
        resolve(storedValue);
    } else if( getStatus == errSecItemNotFound ) {
        resolve(nil);
    } else {
        NSError *error = [NSError errorWithDomain: [[NSBundle mainBundle] bundleIdentifier] code:getStatus userInfo:nil];
        rejectPromise(@"An error occured while retrieving value", error, reject);
    }
}

RCT_EXPORT_METHOD(removeItem:(NSString *)key withOptions:(NSDictionary *) options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    CFStringRef keychainAccessibility = getKeychainAccessibility(options);
    NSString *keychainService = getKeychainService(options);
    NSMutableDictionary *removeQuery = [NSMutableDictionary dictionaryWithDictionary: @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : key,
        (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecAttrAccessible: (__bridge id)keychainAccessibility,
        (__bridge id)kSecAttrService: keychainService
    }];
    NSString *keychainAccessGroup = getKeychainAccessGroup(options);
    if( keychainAccessGroup != nil ) {
        [removeQuery setValue:keychainAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    }
    
    OSStatus removeStatus = SecItemDelete((__bridge CFDictionaryRef)removeQuery);
    
    if( removeStatus == noErr ) {
        resolve(key);
    } else {
        NSError *error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier] code:removeStatus userInfo: nil];
        rejectPromise(@"An error occured while removing value", error, reject);
    }
}

RCT_EXPORT_METHOD(clear:(NSDictionary *) options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    
    NSString *keychainService = getKeychainService(options);
    NSString *keychainAccessGroup = getKeychainAccessGroup(options);
    
    // Maps through all Keychain classes and deletes all items that match
    for (id secItemClass in secItemClasses) {
        NSMutableDictionary *spec = [NSMutableDictionary dictionaryWithDictionary: @{
            (__bridge id)kSecClass: secItemClass,
            (__bridge id)kSecAttrService: keychainService
        }];
        if( keychainAccessGroup != nil ) {
            [spec setValue:keychainAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
        }
        SecItemDelete((__bridge CFDictionaryRef)spec);
    }
    
    resolve(nil);
}

@end
