
#import "PogoprotosNetworkingEnvelopes.pbobjc.h"

@class CLLocation;

@interface RequestEnvelope (Helper)

+ (instancetype)buildWithRequests:(NSArray<Request *> *)requests location:(CLLocation *)location authInfo:(RequestEnvelope_AuthInfo *)authInfo;

@end
