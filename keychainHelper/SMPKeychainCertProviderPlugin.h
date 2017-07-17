//  Copyright © 2017 SAP. All rights reserved.


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#define Certificate_Provider_Error_Domain @"ERR_Keychain_Certificate_Provider"

#define ERR_Set_Parameters_Failed                    -1
#define ERR_Certificate_File_Not_Exist               -2
#define ERR_Load_Certificate_From_File_Failed        -3
#define ERR_Save_Certificate_To_KeyChain_Failed      -4
#define ERR_Read_KeyChain_Item_Failed                -5
#define ERR_Delete_Saved_Certificate_Failed          -6
#define ERR_Authentication_Failed                    -7
#define ERR_KeyChainShareAccessGroup_Error           -8
#define ERR_MissingParameter_Error                   -9
#define ERR_User_Cancel_Error                        -10

@interface SMPKeychainCertProviderPlugin : NSObject <UIAlertViewDelegate>

- (NSString*) getLocalizedResource:(NSString*)resourceID;

+ (BOOL) getStoredCertificate:(SecIdentityRef *)pidentityRef label:certLabel error:(NSError**)anError;
+ (BOOL) deleteStoredCertificateWithError: (NSString*)certLabel error:(NSError**)anError;
+ (NSError*) getErrorObject:(int)errorCode message:(NSString*)errorMessage status:(int)status;
+ (void) parsePKCS12FileAndAddToKeychain:(NSData*)data withPassword:(NSString *)password label:(NSString*)certLabel error:(NSError**)error;
+ (void) getTopViewController:(UIViewController*)vc;
- (void)applicationLaunchedWithUrl:(NSURL*)url;

@end
