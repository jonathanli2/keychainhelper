//
//  ViewController.m
//  keychainHelper
//
//  Created by Li, Jonathan on 12/2/14.
//  Copyright (c) 2014 SAP Kapsel. All rights reserved.
//

#import "ViewController.h"
#import "SMPAfariaHelper.h"

NSString *const SERVICE = @"MyService";

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *certLabel;
@property (weak, nonatomic) IBOutlet UITextView *txtOutput;
@property (weak, nonatomic) IBOutlet UISwitch *accessGroupEnabled;
@property (weak, nonatomic) IBOutlet UITextField *KeyOrCertFileName;
@property (weak, nonatomic) IBOutlet UITextField *accessGroupName;
@property (weak, nonatomic) IBOutlet UITextField *ValueOrCertFilePassword;
@property (strong, nonatomic) NSString *bundleSeedID;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
 
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (__bridge NSString *)kSecClassGenericPassword, (__bridge NSString *)kSecClass,
                           @"bundleSeedID", kSecAttrAccount,
                           @"", kSecAttrService,
                           (id)kCFBooleanTrue, kSecReturnAttributes,
                           nil];
    CFDictionaryRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound)
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);

    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge NSString *)kSecAttrAccessGroup];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    self.bundleSeedID = [[components objectEnumerator] nextObject];
    CFRelease(result);
    
    self.accessGroupName.text = [NSString stringWithFormat:@"%@.%@", self.bundleSeedID, [[NSBundle mainBundle] bundleIdentifier]];
  
}


-(NSMutableDictionary*) prepareDict:(NSString *) key accessGroup:(NSString*)accessGroup
{
 
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    [dict setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
 
    NSData *encodedKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    [dict setObject:encodedKey forKey:(__bridge id)kSecAttrGeneric];
    [dict setObject:encodedKey forKey:(__bridge id)kSecAttrAccount];
    [dict setObject:SERVICE forKey:(__bridge id)kSecAttrService];
    [dict setObject:key forKey:(__bridge id)kSecAttrLabel];
    [dict setObject:(__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];
 
    //This is for sharing data across apps
    if(accessGroup != nil)
        [dict setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
 
    return  dict;
 
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)onUpdate:(id)sender {
    
    NSString* key = self.KeyOrCertFileName.text;
    NSMutableDictionary * dictKey =[self prepareDict:key accessGroup:[self getAccessGroup]];
 
    NSMutableDictionary * dictUpdate =[[NSMutableDictionary alloc] init];
    
    NSString *value = self.ValueOrCertFilePassword.text;
    
    NSData * data = [value dataUsingEncoding:NSUTF8StringEncoding];

    [dictUpdate setObject:data forKey:(__bridge id)kSecValueData];
 
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)dictKey, (__bridge CFDictionaryRef)dictUpdate);

    if( status != errSecSuccess) {
         self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nUnable to update item for key %@ with error:%d",self.txtOutput.text , key,(int)status];
    }
    else{
         self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nUpdate item succeeded",self.txtOutput.text];
    }
    
}

- (IBAction)onDelete:(id)sender {
    
    NSString* key = self.KeyOrCertFileName.text;
   
    NSMutableDictionary *dict = [self prepareDict:key accessGroup:[self getAccessGroup]];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)dict);
    if( status != errSecSuccess) {
         self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nUnable to remove item for key %@ with error:%d",self.txtOutput.text , key,(int)status];
    }
    else{
         self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nDelete item succeeded",self.txtOutput.text];
    }

}

- (IBAction)onAdd:(id)sender {
    
    NSString* key = self.KeyOrCertFileName.text;
    NSString *value = self.ValueOrCertFilePassword.text;
    
    NSData * data = [value dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableDictionary * dict =[self prepareDict:key accessGroup:[self getAccessGroup]];
    [dict setObject:data forKey:(__bridge id)kSecValueData];
 
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dict, NULL);
    if(errSecSuccess != status) {
        self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nUnable add item with key =%@ error:%d",self.txtOutput.text , key,(int)status];
    }
    else{
         self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nAdd item succeeded",self.txtOutput.text];
    }
}

-(NSString*) getAccessGroup {
    bool bAccess = self.accessGroupEnabled.isOn;
 
    NSString* accessGroup = nil;
    if (bAccess)
    {
        accessGroup = self.accessGroupName.text;
    }
    return accessGroup;

}


- (IBAction)onRead:(id)sender {
     NSString* key = self.KeyOrCertFileName.text;

    NSMutableDictionary *dict = [self prepareDict:key accessGroup:[self getAccessGroup]];
    [dict setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
    [dict setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)dict,&result);
 
   if(errSecSuccess != status) {
        self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nUnable read item with key =%@ error:%d",self.txtOutput.text , key,(int)status];
    }
    else{
        self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nAdd item succeeded",self.txtOutput.text];
        NSString* date = [[NSString alloc] initWithData:(__bridge NSData *)result encoding:NSUTF8StringEncoding];
        self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nRead succeeded. Datat is: %@",self.txtOutput.text, date];

    }
}

- (IBAction)onDumpAll:(id)sender {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
        (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
        (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
        nil];
    NSArray *secItemClasses = [NSArray arrayWithObjects:
                           (__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecClassInternetPassword,
                           (__bridge id)kSecClassCertificate,
                           (__bridge id)kSecClassKey,
                           (__bridge id)kSecClassIdentity,
                           nil];
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];

        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        self.txtOutput.text = [NSString stringWithFormat:@"%@ \r\nItems in class: %@, %@ ",self.txtOutput.text, secItemClass, result];

        if (result != NULL) {
            CFRelease(result);
        }
    }
}

- (IBAction)onDumpCerts:(id)sender {

    NSMutableString* strOutput = [[NSMutableString alloc] init];
    [SMPAfariaHelper _dumpCredentials:@"dump client identity" output:strOutput];
    self.txtOutput.text = [strOutput description];
}

- (IBAction)onClearLog:(id)sender {
    self.txtOutput.text = nil;
}

- (IBAction)onResetAllItems:(id)sender {
    NSArray *secItemClasses = @[(__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecClassInternetPassword,
                           (__bridge id)kSecClassCertificate,
                           (__bridge id)kSecClassKey,
                           (__bridge id)kSecClassIdentity];
    for (id secItemClass in secItemClasses) {
        NSDictionary *spec = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)spec);
    }
    self.txtOutput.text = @"All keychain items are deleted";

}

- (IBAction)onResetCerts:(id)sender {
    NSMutableString* strOutput = [[NSMutableString alloc] init];

    if ([self.certLabel.text isEqualToString:@""]){
        [SMPAfariaHelper resetIdentities:strOutput];
    }
    else{
        [SMPAfariaHelper deleteIdentities:self.certLabel.text output:strOutput];
    }
}
- (IBAction)onImportCert:(id)sender {
}

@end
