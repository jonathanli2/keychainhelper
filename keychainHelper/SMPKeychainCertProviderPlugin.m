//  Copyright © 2017 SAP. All rights reserved.

#import "SMPKeychainCertProviderPlugin.h"

//do not localize the below string constant
static NSString* const kEmailCertificateLabel = @"emailCertificateLabel";

@interface SMPKeychainCertProviderPlugin ()
@property (nonatomic, strong) NSURL* url;
@property (retain, nonatomic) NSBundle* localizationBundle;

- (void) deleteFileAtURL:(NSURL *)url;
@end

@implementation SMPKeychainCertProviderPlugin


- (NSString*) getLocalizedResource:(NSString*)resourceID{
    NSString* str = [self.localizationBundle localizedStringForKey:resourceID value:nil table:nil];
    if (str == nil){
        str = resourceID;
    }
    return str;
}

- (void)applicationLaunchedWithUrl:(NSURL*)url {
   
    self.url = url;
    
    //check the preference for the certificate label
    NSString* certLabel = nil;
    id emailcertlabel = nil;
    if (emailcertlabel == nil ){
        certLabel = self.url.lastPathComponent;
    }
    else {
        certLabel = emailcertlabel;
    }
    
    [self showPasswordPrompt: NO label:certLabel];
    
}

- (void)showPasswordPrompt:(BOOL)isForRetry label:(NSString*)certLabel {
    NSString* message;
    if (isForRetry){
        message = [self getLocalizedResource:@"incorrect_password"];
    }
    else{
        message = [self getLocalizedResource:@"please_input"];
    }
    
    
    UIAlertController* passwordPrompt = [UIAlertController alertControllerWithTitle:[self getLocalizedResource:@"import_certificate"] message:message preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction* ok = [UIAlertAction
                         actionWithTitle:[self getLocalizedResource:@"ok"]
                         style:UIAlertActionStyleDefault
                         handler:^(UIAlertAction * action)
                         {
                         UITextField *password = passwordPrompt.textFields[0];
                       
                         NSError* error = nil;
                         NSData *p12data = [NSData dataWithContentsOfURL:self.url];
                         [SMPKeychainCertProviderPlugin parsePKCS12FileAndAddToKeychain:p12data withPassword:password.text label:certLabel error:&error];
                         if (error == nil){
                           
                            [self deleteFileAtURL:self.url];
                             
                         }
                         else{
                             //if the password is wrong, ask user to retry with new password
                             if (error.code == ERR_Authentication_Failed){
                                 [self showPasswordPrompt:YES label:certLabel];
                             }
                             else{
                                
                                 [self deleteFileAtURL:self.url];
                                 //Fail to import certificate file (wrong file format, invalid keychain sharing setting, prompt user and cancel the operation
                                 int statusCode = 0;
                                 
                                 id status = [[error userInfo] objectForKey:@"status"];
                                 if (status != nil){
                                     statusCode = [status intValue];
                                 }
                                 
                                 NSString *errMsg = [NSString stringWithFormat:[self getLocalizedResource:@"fail_to_import"], statusCode];
                                 UIAlertController* importFailedDialog = [UIAlertController alertControllerWithTitle:[self getLocalizedResource:@"error"] message:errMsg preferredStyle:UIAlertControllerStyleAlert];
                                 [importFailedDialog addAction:[UIAlertAction actionWithTitle:[self getLocalizedResource:@"ok"] style:UIAlertActionStyleDefault handler:nil]];
                                 [SMPKeychainCertProviderPlugin getTopViewController:importFailedDialog];
                             }
                         }
                         }];
    
    UIAlertAction* cancel = [UIAlertAction actionWithTitle:[self getLocalizedResource:@"cancel"] style:UIAlertActionStyleCancel
                                                   handler:^(UIAlertAction * action){
                                                       //delete cert file
                                                       [self deleteFileAtURL:self.url];
                                                       [passwordPrompt dismissViewControllerAnimated:YES completion:nil];
                                                   }];
    
    [passwordPrompt addAction:ok];
    [passwordPrompt addAction:cancel];
    
    [passwordPrompt addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = [self getLocalizedResource:@"password"];
        textField.secureTextEntry = YES;
    }];
    
    [SMPKeychainCertProviderPlugin getTopViewController:passwordPrompt];
}


+ (void) parsePKCS12FileAndAddToKeychain:(NSData*)data withPassword:(NSString *)password label:(NSString*)certLabel error:(NSError**)error {
    NSError* err = nil;
    
    CFArrayRef items = NULL;
    
    CFDataRef inP12data = (__bridge CFDataRef)data;
    
    NSDictionary* options = [NSDictionary dictionaryWithObjectsAndKeys:
                             password, kSecImportExportPassphrase, nil];
    
    OSStatus status = SecPKCS12Import(inP12data, (__bridge CFDictionaryRef)options, &items);
    
    if (status == noErr) {
        //password is valid, delete existing cert if existing
        [SMPKeychainCertProviderPlugin deleteStoredCertificateWithError:certLabel error:&err];
        if (err == nil){
            
            CFDictionaryRef identityAndTrust = CFArrayGetValueAtIndex(items, 0);
            const void *tempIdentity = NULL;
            tempIdentity = CFDictionaryGetValue(identityAndTrust, kSecImportItemIdentity);
            
            NSDictionary *queryCertificate  = [NSDictionary dictionaryWithObjectsAndKeys:
                    certLabel, kSecAttrLabel,
                    (__bridge id)tempIdentity, kSecValueRef,
                    nil];
            
            status = SecItemAdd((__bridge CFDictionaryRef) queryCertificate, nil);
            
            if (status != noErr ){
                NSLog(@"Fail to save certificate to keychain %@ status:%d.", certLabel, status);
                err = [SMPKeychainCertProviderPlugin getErrorObject:ERR_Save_Certificate_To_KeyChain_Failed message:@"Save certificate to keychain failed." status:status];
            }
            else {
                NSLog(@"Success, the certificate has been added to the keychain. status: %d", status);
            }
        }
    }
    else {
        if (status == errSecAuthFailed ){
            err = [SMPKeychainCertProviderPlugin getErrorObject:ERR_Authentication_Failed message:@"Certificate password invalid." status:status];
        }
        else{
            err = [SMPKeychainCertProviderPlugin getErrorObject:ERR_Load_Certificate_From_File_Failed message:@"Fail to load certificate from file." status:status];
        }
    }
    
    if (error != nil){
        *error = err;
    }
}

//only applicable for the email and webserver imported certificates, cannot delete a file in the project's directory (ex. certificate in resources folder)
- (void) deleteFileAtURL:(NSURL *)url {
    NSError* error = nil;
    BOOL success = [[NSFileManager defaultManager] removeItemAtURL:url error:&error];
    if (success) {
        NSLog(@"File deletion was a success.");
    }
    else {
        NSLog(@"Error: %@ %@, file could not be deleted.", error, [error userInfo]);
    }
}


//method to synchronously get a certificate from saved local copy.
//if saved certicate exists, return true and also set the identityref parameter to the certificate
//If no saved certificate exists, return true and also setting identityRef parameter to nil.
//if error happens during getting the saved certificate, return false with related error, also setting identityRef parameter to nil
+ (BOOL) getStoredCertificate:(SecIdentityRef *)pidentityRef label:certLabel error:(NSError**)anError{
    // retrieves a SecIdentityRef from the cached object in memory. If no cached object exists, then get it from keychain for matched
    // kSecAttrLabel's value, the first matched one will be returned
    // Return Val :  the matched identity object
    *pidentityRef = nil;
    NSError* error = nil;
    
    //check current identity object if available
    NSDictionary* queryIdentity;
    
    if (certLabel != nil ){
        queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                                   certLabel,                   kSecAttrLabel,
                                   (__bridge id)kSecClassIdentity,  kSecClass,
                                   kCFBooleanTrue,         kSecReturnRef,
                                   kCFBooleanTrue,         kSecReturnAttributes,
                                   kSecMatchLimitAll,      kSecMatchLimit,
                                   nil];
    }
    else{
        queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                                   (__bridge id)kSecClassIdentity,  kSecClass,
                                   kCFBooleanTrue,         kSecReturnRef,
                                   kCFBooleanTrue,         kSecReturnAttributes,
                                   kSecMatchLimitAll,      kSecMatchLimit,
                                   nil];
    }
    // Get a new identity from the keychain
    // This works because the private key will automatically be associated with the certificate in the keychain
    CFArrayRef result = nil;
    
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
                    //get hold of the new identity object
                    CFRetain(*pidentityRef);
                    
                    }
                }
            }
        }
    else
        {
        error = [self getErrorObject:ERR_Read_KeyChain_Item_Failed message:@"Fail to load certificate from keychain" status:err];
        }
    
    if (result != nil){
        CFRelease(result);
    }
    
    return error == nil;
}

// If a certificate exists in the keychain, this method is called before Initialize unless the certificate was already validated (used for a registration that was successful)
//method to delete the saved local copy
//if not saved certificate exists, do nothing and return true,
//if saved certificate is deleted, return true
//if saved certificate exists and fails to delete, reture false with error
+ (BOOL) deleteStoredCertificateWithError: (NSString*)certLabel error:(NSError**)anError{
    NSError* error = nil;
    OSStatus sanityCheck = noErr;
    NSDictionary *queryIdentity;
    
    if (certLabel != nil){
    queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                     certLabel, kSecAttrLabel,
                     (__bridge id)kSecClassIdentity, kSecClass,
                     nil];
    }
    else{
        queryIdentity = [NSDictionary dictionaryWithObjectsAndKeys:
                    (__bridge id)kSecClassIdentity, kSecClass,
                     nil];
    }
    // Delete the private key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryIdentity);
    if (sanityCheck != noErr && sanityCheck != errSecItemNotFound ){
        error = [SMPKeychainCertProviderPlugin getErrorObject:ERR_Delete_Saved_Certificate_Failed message:@"Fail to delete the saved certificate" status:sanityCheck];
    }
    
    if (anError != nil){
        *anError = error;
    }
    
    return error == nil;
}

+(NSError*)getErrorObject:(int)errorCode message:(NSString*)errorMessage status:(int)status {
    NSDictionary *userInfo;
    if (status == 0){
        userInfo = @{ NSLocalizedDescriptionKey : errorMessage };
    }
    else{
        userInfo = @{ NSLocalizedDescriptionKey : errorMessage, @"status": [NSNumber numberWithInt:status] };
    }
    NSError *error = [NSError errorWithDomain:Certificate_Provider_Error_Domain
                                         code:errorCode
                                     userInfo:userInfo];
    return error;
}

//The base view controller may be presenting other view. If alertview is presented, then dismiss it automatically
+ (void) getTopViewController:(UIViewController*) vc{
    UIViewController* presentingViewController = [UIApplication.sharedApplication.keyWindow rootViewController];
    while ([presentingViewController presentedViewController] != nil ){
        UIViewController * presented = [presentingViewController presentedViewController];
        if ([presented isKindOfClass:[UIAlertController class]] || [presented isKindOfClass:[UIAlertView class]]){
            dispatch_async(dispatch_get_main_queue(),^{
                [presentingViewController dismissViewControllerAnimated:NO completion:^{
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [presentingViewController presentViewController:vc animated:YES completion:nil];
                    });
                }];
            });
            //completion callback will present the new controller
            return;
        }
        else{
            presentingViewController = [presentingViewController presentedViewController];
        }
    }
    
    dispatch_async(dispatch_get_main_queue(),^{
        [presentingViewController presentViewController:vc animated:YES completion:nil];
    });
}

@end
