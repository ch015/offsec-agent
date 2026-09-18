#import <Foundation/Foundation.h>
#import "Bridge.h"

@implementation Bridge

- (id)signIn:(NSDictionary *)payload error:(NSError **)error {
  NSString *url = [payload objectForKey:@"url"];
  [self openOAuth:payload error:error];
  return [self dispatch:url];
}

- (void)openOAuth:(NSDictionary *)payload error:(NSError **)error {
  NSURL *u = [NSURL URLWithString:@"https://example.com"];
  logEvent("oauth");
}

+ (void)initialize {
  [Bridge setup];
}

@end

static int helper(int x) {
  return x + 1;
}
