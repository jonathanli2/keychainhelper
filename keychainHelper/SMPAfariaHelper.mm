//
//  AfariaHelper.m
//
//  Created by Marcus Pridham on 12-10-02.
//  Copyright 2012 Sybase. All rights reserved.
//
#import <CommonCrypto/CommonDigest.h>
#import "SMPAfariaHelper.h"


@implementation SMPAfariaHelper

+(void)log:(NSString*) message output:(NSMutableString*) outputContainer{
    if (outputContainer != nil ){
        if (outputContainer.length > 0){
            [outputContainer appendString:@"\r\n"];
        }
        [outputContainer appendString:message];
    }
    
    NSLog(@"%@", message);
}

/******************************************************************************
 *    Name       :  getIdentityBasedOnLabel:
 *    Desc       :  retrieves a SecIdentityRef from the keychain which matches
                    kSecAttrLabel's value, the first matched one will be returned
                    Caller needs to free the identity reference object
 *    Return Val :  See header file for description of errors
 ******************************************************************************/
+ (OSStatus) getIdentityBasedOnLabel:(NSString *)label identity:(SecIdentityRef*)pidentityRef output:(NSMutableString*)output {
   [SMPAfariaHelper _dumpCredentials:@"Before getIdentityBasedOnCommonName" labelAttribute:label output:output];
   *pidentityRef = nil;
   
   // Common name is stored in label attribute,
   NSDictionary* queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                                  label,                   kSecAttrLabel,
                                  (__bridge id)kSecClassIdentity,  kSecClass,
                                  kCFBooleanTrue,         kSecReturnRef,
                                  kCFBooleanTrue,         kSecReturnAttributes,
                                  kSecMatchLimitAll,      kSecMatchLimit,
                                  nil];
   
   // Get a new identity from the keychain
   // This works because the private key will automatically be associated with the certificate in the keychain
   CFArrayRef result;
   
   OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryIdentity, (CFTypeRef*)&result);
   
   if (err == errSecItemNotFound)
   {
      *pidentityRef = nil;
   }
   else if (err == noErr && result != nil )
   {
      CFIndex resultCount = CFArrayGetCount(result);
      NSLog(@"Matched identity count: %i", (int)resultCount);
      // somehow two identities are returned with the same certificate, one with public key, one with private key,
      // the one with public key is invalid identity, need to return the one with the private key
      for (int resultIndex = 0; resultIndex < resultCount; resultIndex++)
      {
         NSDictionary* thisResult = (NSDictionary*) CFArrayGetValueAtIndex(result, resultIndex);
         
         CFTypeRef keyClass = (__bridge CFTypeRef) [thisResult objectForKey:(__bridge id)kSecAttrKeyClass];
         if (keyClass != nil )
         {
            if ([[(__bridge id)keyClass description] isEqual:(__bridge id)kSecAttrKeyClassPrivate])
            {
               *pidentityRef = (__bridge SecIdentityRef)[thisResult objectForKey:(__bridge NSString*)kSecValueRef];
               CFRetain(*pidentityRef);
            }
         }
      }
      CFRelease(result);
   }
   else
   {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"error: %d", (int)err] output:output];
   }
   return err;
}


#pragma mark -
#pragma mark Private Methods


/******************************************************************************
 *    Name       :  resetIdentities
 *    Desc       :  Delete identities for application
 *    Note       :  identities are not deleted when deleting the application.
 *                  All identities whose kSecAttrLabel matches the name parameter will be deleted. nil is invalid parameter
 *    Return Val :  error code
 ******************************************************************************/
+ (OSStatus)resetIdentities:(NSMutableString*)output{
   
   [SMPAfariaHelper _dumpCredentials:@"Before reset identities" output:output];
   
	OSStatus sanityCheck = noErr;
   NSDictionary *queryIdentity;
   
   queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                    (__bridge id)kSecClassIdentity, kSecClass,
                    nil];
   
	// Delete the private key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryIdentity);
   if (sanityCheck != noErr && sanityCheck != errSecItemNotFound ){
      NSLog(@"delete identity failed: %i", (int)sanityCheck);
   }
   
   [SMPAfariaHelper _dumpCredentials:@"After reset identities" output:output];
   
   return sanityCheck;
}


/******************************************************************************
 *    Name       :  deleteIdentities
 *    Desc       :  Delete identities for application
 *    Note       :  identities are not deleted when deleting the application.
 *                  All identities whose kSecAttrLabel matches the name parameter will be deleted. nil is invalid parameter
 *    Return Val :  error code
 ******************************************************************************/
+ (OSStatus)deleteIdentities:(NSString*)name output:(NSMutableString*)output{
   NSString *log;
   if (name == nil )
      return errSecParam;
   
   log = [@"Before delete identities: " stringByAppendingString:name];

   [SMPAfariaHelper _dumpCredentials:log output:output];
  
	OSStatus sanityCheck = noErr;
   NSDictionary *queryIdentity;

   queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                          name, kSecAttrLabel,
                          (__bridge id)kSecClassIdentity, kSecClass,
                          nil];

	// Delete the private key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryIdentity);
   if (sanityCheck != noErr && sanityCheck != errSecItemNotFound ){
      NSLog(@"delete identity failed: %i", (int)sanityCheck);
   }
   
   [SMPAfariaHelper _dumpCredentials:@"After delete identities" output:output];
   
   return sanityCheck;
}

/******************************************************************************
 *    Name       :  DeleteCertificates
 *    Desc       :  Delete certificates for application
 *    Note       :  Certificates are not deleted when deleting the application.
 *                  All certificates whose kSecAttrLabel matches the name parameter will be deleted. 
 *    Param      :  nil is not valid name
 *    Return Val :  error code
 ******************************************************************************/
+ (OSStatus)deleteCertificates:(NSString*)name output:(NSMutableString*)output{
   NSString *log;
   if (name == nil )
      return errSecParam;
   
   log = [@"Before delete certificate: " stringByAppendingString:name];
   
   [SMPAfariaHelper _dumpCredentials:log output:output];
   
   OSStatus sanityCheck = noErr;
   NSDictionary *queryCertificate;

   queryCertificate = [NSDictionary dictionaryWithObjectsAndKeys:
                                     name, kSecAttrLabel,
                                     (__bridge id)kSecClassCertificate, kSecClass,
                                     nil];

   // Delete the certificate.
   sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryCertificate);
   if (sanityCheck != noErr && sanityCheck != errSecItemNotFound ){
      NSLog(@"delete certificate failed: %i", (int)sanityCheck);
      
   }
   
   [SMPAfariaHelper _dumpCredentials:@"After delete certificate" output:output];
   
   return sanityCheck;
}

/******************************************************************************
 *    Name       :  DeleteKeys
 *    Desc       :  Delete keys for application
 *    Note       :  Keys are not deleted when deleting the application.
 *                  All keys whose kSecAttrLabel matches the name parameter will be deleted. nil is invalid parameter
 *    Return Val :  error code
 ******************************************************************************/
+ (OSStatus)deleteKeys:(NSString*)name output:(NSMutableString*)output {
   
   if (name == nil )
      return errSecParam;
   
	OSStatus sanityCheck = noErr;
 
   NSDictionary * queryKey = [NSDictionary dictionaryWithObjectsAndKeys:
                          name, kSecAttrLabel,
                          (__bridge id)kSecClassKey, kSecClass,
                          nil];
   
	// Delete the key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryKey);
   if (sanityCheck != noErr && sanityCheck != errSecItemNotFound ){
      [SMPAfariaHelper log:[NSString stringWithFormat:@"delete key failed: %i", (int)sanityCheck] output:output];
   }
   
   return sanityCheck;
}




#pragma mark Helper Log method

+ (void)_printCertificate:(SecCertificateRef)certificate attributes:(NSDictionary *)attrs indent:(int)indent output:(NSMutableString*)output
// Prints a certificate for debugging purposes.  The indent parameter is necessary to
// allow different indents depending on whether the key is part of an identity or not.
{
   CFStringRef         summary;
   NSString *          label;
   
   assert(certificate != NULL);
   assert(attrs != nil);
   
   summary = SecCertificateCopySubjectSummary(certificate);
   assert(summary != NULL);
   
   label = [attrs objectForKey:(__bridge id)kSecAttrLabel];
   if (label != nil) {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%*slabel   = '%s'\n", indent, "", [label UTF8String]] output:output];
   }
   [SMPAfariaHelper log:[NSString stringWithFormat:@"%*ssummary = '%s'\n", indent, "", [(__bridge NSString *)summary UTF8String]] output:output];
   
   CFRelease(summary);
}

+ (void)_printKey:(SecKeyRef)key attributes:(NSDictionary *)attrs attrName:(CFTypeRef)attrName flagValues:(const char *)flagValues output:(NSMutableString*)output
// Prints a flag within a key.
{
#pragma unused(key)
   id  flag;
   
   // assert(key != NULL);
   assert(attrs != nil);
   assert(attrName != NULL);
   assert(flagValues != NULL);
   assert(strlen(flagValues) == 2);
   
   flag = [attrs objectForKey:(__bridge id)attrName];
   if (flag == nil) {
      [SMPAfariaHelper log:@"-" output:output];
   } else if ([flag boolValue]) {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%c", flagValues[0]] output:output];
   } else {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%c", flagValues[1]] output:output];
   }
}

+ (void)_printKey:(SecKeyRef)key attributes:(NSDictionary *)attrs indent:(int)indent output:(NSMutableString*)output
// Prints a key for debugging purposes.  The indent parameter is necessary to allow
// different indents depending on whether the key is part of an identity or not.
{
#pragma unused(key)
   id          label;
   CFTypeRef   keyClass;
   
   //assert(key != NULL);
   assert(attrs != nil);
   
   label = [attrs objectForKey:(__bridge id)kSecAttrLabel];
   if (label != nil) {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%*slabel     = '%s'", indent, "", [label UTF8String]] output:output];
   }
   label = [attrs objectForKey:(__bridge id)kSecAttrApplicationLabel];
   if (label != nil) {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%*sapp label = %s", indent, "", [[label description] UTF8String]] output:output];
   }
   label = [attrs objectForKey:(__bridge id)kSecAttrApplicationTag];
   if (label != nil) {
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%*sapp tag   = %s", indent, "", [[label description] UTF8String]] output:output];
   }
   [SMPAfariaHelper log:[NSString stringWithFormat:@"%*sflags     = ", indent, ""] output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanEncrypt flagValues:"Ee" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanDecrypt flagValues:"Dd" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanDerive  flagValues:"Rr" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanSign    flagValues:"Ss" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanVerify  flagValues:"Vv" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanWrap    flagValues:"Ww" output:output];
   [self _printKey:key attributes:attrs attrName:kSecAttrCanUnwrap  flagValues:"Uu" output:output];
   [SMPAfariaHelper log:@"\n" output:output];
   
   keyClass = (__bridge CFTypeRef) [attrs objectForKey:(__bridge id)kSecAttrKeyClass];
   if (keyClass != nil) {
      const char *    keyClassStr;
      
      // keyClass is a CFNumber whereas kSecAttrKeyClassPublic (and so on)
      // are CFStrings.  Gosh, that makes things hard <rdar://problem/6914637>.
      // So I compare their descriptions.  Yuck!
      
      if ( [[(__bridge id)keyClass description] isEqual:(__bridge id)kSecAttrKeyClassPublic] ) {
         keyClassStr = "kSecAttrKeyClassPublic";
      } else if ( [[(__bridge id)keyClass description] isEqual:(__bridge id)kSecAttrKeyClassPrivate] ) {
         keyClassStr = "kSecAttrKeyClassPrivate";
      } else if ( [[(__bridge id)keyClass description] isEqual:(__bridge id)kSecAttrKeyClassSymmetric] ) {
         keyClassStr = "kSecAttrKeyClassSymmetric";
      } else {
         keyClassStr = "?";
      }
      [SMPAfariaHelper log:[NSString stringWithFormat:@"%*skey class = %s\n", indent, "", keyClassStr] output:output];
   }
}

+ (void)_printIdentity:(SecIdentityRef)identity attributes:(NSDictionary *)attrs output:(NSMutableString*)output
// Prints an identity for debugging purposes.
{
   OSStatus            err;
   SecCertificateRef   certificate;
   
   assert(identity != NULL);
   assert(attrs != nil);
   
   err = SecIdentityCopyCertificate(identity, &certificate);
   assert(err == noErr);
   [SMPAfariaHelper log:@"    certificate" output:output];
   [SMPAfariaHelper _printCertificate:certificate attributes:attrs indent:6 output:output];
 
   SecKeyRef           key;
   err = SecIdentityCopyPrivateKey(identity, &key);
   assert(err == noErr);
   [SMPAfariaHelper log:@"    key" output:output];
   [SMPAfariaHelper _printKey:key attributes:attrs indent:6 output:output];
   CFRelease(key);
   
   CFRelease(certificate);
}

+ (void)_printCertificate:(SecCertificateRef)certificate attributes:(NSDictionary *)attrs output:(NSMutableString*)output
// Prints a certificate for debugging purposes.  The real work is done
// by a helper routine that's shared with -_printIdentity:attributes:.
{
   assert(certificate != NULL);
   assert(attrs != nil);
   [SMPAfariaHelper _printCertificate:certificate attributes:attrs indent:4 output:output];
}

+ (void)_printKey:(SecKeyRef)key attributes:(NSDictionary *)attrs output:(NSMutableString*)output
// Prints a certificate for debugging purposes.  The real work is done
// by a helper routine that's shared with -_printIdentity:attributes:.
{
   // assert(key != NULL);
   assert(attrs != nil);
   [SMPAfariaHelper _printKey:key attributes:attrs indent:4 output:output];
}



+ (void)_dumpCredentialsOfSecClass:(CFTypeRef)secClass labelAttribute:(NSString*)name output:(NSMutableString*)output
// Iterates through all of the credentials of a particular class
// (identity, key, certificate, Internet, generic) and calls the selector on each.
{
   OSStatus    err;
   CFArrayRef  result;
   CFIndex     resultCount;
   CFIndex     resultIndex;
   
   assert(secClass != NULL);
    
   result = NULL;
   if (name == nil){
         
      err = SecItemCopyMatching(
              (__bridge CFDictionaryRef) [NSDictionary dictionaryWithObjectsAndKeys:
                                 (__bridge id)secClass,           kSecClass,
                                 kSecMatchLimitAll,      kSecMatchLimit,
                                 kCFBooleanTrue,         kSecReturnRef,
                                 kCFBooleanTrue,         kSecReturnAttributes,
                                 nil
                                 ],
              (CFTypeRef *) &result
              );
   }
   else{
     // NSData * appTag = [commonName dataUsingEncoding:NSUTF8StringEncoding];
      err = SecItemCopyMatching(
              (__bridge CFDictionaryRef) [NSDictionary dictionaryWithObjectsAndKeys:
                                 name, kSecAttrLabel,
                                 (__bridge id)secClass,           kSecClass,
                                 kSecMatchLimitAll,      kSecMatchLimit,
                                 kCFBooleanTrue,         kSecReturnRef,
                                 kCFBooleanTrue,         kSecReturnAttributes,
                                 nil
                                 ],
              (CFTypeRef *) &result
              );

   }
   if (err == errSecItemNotFound){
      [SMPAfariaHelper log:[NSString stringWithFormat:@"item count: %i", 0] output:output];
   }
   else if (err == noErr){
      assert( result != NULL );
      if (result != NULL) {
         assert( CFGetTypeID(result) == CFArrayGetTypeID() );
         
         resultCount = CFArrayGetCount(result);
         [SMPAfariaHelper log:[NSString stringWithFormat:@"item count: %i", (int)resultCount] output:output];
         
         for (resultIndex = 0; resultIndex < resultCount; resultIndex++) {
            NSDictionary *  thisResult;
            
            [SMPAfariaHelper log:[NSString stringWithFormat:@"Item No. %zd\n", (ssize_t) resultIndex] output:output];
            thisResult = (NSDictionary *) CFArrayGetValueAtIndex(result, resultIndex);
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            if (secClass == kSecClassIdentity){
               [SMPAfariaHelper _printIdentity:(SecIdentityRef)[thisResult objectForKey:(__bridge NSString *)kSecValueRef] attributes:thisResult output:output];
            }
            else if (secClass == kSecClassCertificate){
                [SMPAfariaHelper _printCertificate:(SecCertificateRef)[thisResult objectForKey:(__bridge NSString *)kSecValueRef] attributes:thisResult output:output];
           
            }
            else if (secClass == kSecClassKey){
                [SMPAfariaHelper _printKey:(SecKeyRef)[thisResult objectForKey:(__bridge NSString *)kSecValueRef] attributes:thisResult output:output];
        
            }
            #pragma clang diagnostic pop
         }
         
         CFRelease(result);
      }
   }
   else{
      [SMPAfariaHelper log:[NSString stringWithFormat:@"error: %d", (int)err] output:output];
      
   }
}

+ (void)_dumpCredentials:(NSString*)description output:(NSMutableString*)outputString {
   [SMPAfariaHelper _dumpCredentials:description labelAttribute:nil output:outputString];

}

//pass commonName to nil to match all common name
+ (void)_dumpCredentials:(NSString*)description labelAttribute:(NSString*)name output:(NSMutableString*) output
{
   [SMPAfariaHelper log:[NSString stringWithFormat:@"%@\n", description] output:output];
   
   [SMPAfariaHelper log:@"------ identities --------:" output:output];
   [SMPAfariaHelper _dumpCredentialsOfSecClass:kSecClassIdentity labelAttribute:name output:(NSMutableString*)output];
   
   [SMPAfariaHelper log:@"\n------ certificates --------" output:output];
   [SMPAfariaHelper _dumpCredentialsOfSecClass:kSecClassCertificate  labelAttribute:name output:(NSMutableString*)output];

   //do not print key information for security reason
   [SMPAfariaHelper log:@"\n------ keys --------" output:output];
   [SMPAfariaHelper _dumpCredentialsOfSecClass:kSecClassKey labelAttribute:name output:(NSMutableString*)output];
   
}


@end
