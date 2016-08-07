
#import "RequestEnvelope+Helper.h"
#import "RpcApiClient.h"
#import "xxhash.h"
#import "encrypt.h"
#import <CoreLocation/CoreLocation.h>

const uint32_t HashSeed = 0x1B845238;

@implementation RequestEnvelope (Helper)

+ (instancetype)buildWithRequests:(NSArray<Request *> *)requests location:(CLLocation *)location authInfo:(RequestEnvelope_AuthInfo *)authInfo {
    RequestEnvelope *requestEnvelope = [RequestEnvelope message];
    requestEnvelope.statusCode = 2;
    requestEnvelope.requestId = [[NSDate date] timeIntervalSince1970] * 1000;
    if (location) {
        requestEnvelope.latitude = location.coordinate.latitude;
        requestEnvelope.longitude = location.coordinate.longitude;
        requestEnvelope.altitude = 8;   // fix altitude to 8
    }
    [requestEnvelope.requestsArray addObjectsFromArray:requests];
    requestEnvelope.authTicket = [self buildAuthTicket];
    
    // if authentication ticket has already existed
    if ([RpcApiClient sharedClient].lastAuthTicket) {
        [requestEnvelope.unknown6Array addObject:[requestEnvelope buildUnknown6]];
    } else {
        requestEnvelope.authInfo = authInfo;
    }
    
    requestEnvelope.unknown12 = 989;
    
    return requestEnvelope;
}

- (Unknown6 *)buildUnknown6 {
    Unknown6 *unknown6 = [Unknown6 new];
    unknown6.requestType = 6;
    
    Unknown6_Unknown2 *unknown6Unknown2 = [Unknown6_Unknown2 new];
    unknown6Unknown2.encryptedSignature = [self generateSignatureData:[self buildSignature]];
    unknown6.unknown2 = unknown6Unknown2;
    
    return unknown6;
}

+ (AuthTicket *)buildAuthTicket {
    AuthTicket *lastTicket = [RpcApiClient sharedClient].lastAuthTicket;
    if (lastTicket) {
        AuthTicket *authTicket = [AuthTicket new];
        authTicket.start = lastTicket.start;
        authTicket.expireTimestampMs = lastTicket.expireTimestampMs;
        authTicket.end = lastTicket.end;
        return authTicket;
    }
    return lastTicket;
}

#pragma mark - Unknown6 Signature Generation

- (Signature *)buildSignature {
    double latitude = self.latitude;
    double longitude = self.longitude;
    double altitude = self.altitude;
    
    Signature *signature = [Signature new];
    signature.locationHash1 = [self generateLocation1:self.authTicket latitude:latitude longitude:longitude altitude:altitude];
    signature.locationHash2 = [self generateLocation2:latitude longitude:longitude altitude:altitude];
    
    for (Request *request in self.requestsArray) {
        [signature.requestHashArray addValue:[self generateRequestHash:request authTicket:self.authTicket]];
    }
    
    signature.unk22 = [self uRandom:32];
    signature.timestamp = [[NSDate date] timeIntervalSince1970] * 1000;
    signature.timestampSinceStart = [[NSDate date] timeIntervalSince1970] * 1000 - [RpcApiClient sharedClient].startTime;
    
    return signature;
}

- (uint32_t)generateLocation1:(AuthTicket *)authTicket latitude:(double)latitude longitude:(double)longitude altitude:(double)altitude {
    // need to serialize authentication ticket for calculating location hash 1
    uint32_t firstHash = XXH32(authTicket.data.bytes, authTicket.data.length, HashSeed);
    
    NSData *latitudeHexData = [self doubleToHexData:latitude];
    NSData *longitudeHexData = [self doubleToHexData:longitude];
    NSData *altitudeHexData = [self doubleToHexData:altitude];
    
    NSMutableData *locationBytesData = [NSMutableData data];
    [locationBytesData appendData:latitudeHexData];
    [locationBytesData appendData:longitudeHexData];
    [locationBytesData appendData:altitudeHexData];
    
    uint32_t result = XXH32(locationBytesData.bytes, locationBytesData.length, firstHash);
    return result;
}

- (uint32_t)generateLocation2:(double)latitude longitude:(double)longitude altitude:(double)altitude {
    NSData *latitudeHexData = [self doubleToHexData:latitude];
    NSData *longitudeHexData = [self doubleToHexData:longitude];
    NSData *altitudeHexData = [self doubleToHexData:altitude];
    
    NSMutableData *locationBytesData = [NSMutableData data];
    [locationBytesData appendData:latitudeHexData];
    [locationBytesData appendData:longitudeHexData];
    [locationBytesData appendData:altitudeHexData];
    
    uint32_t result = XXH32(locationBytesData.bytes, locationBytesData.length, HashSeed);
    return result;
}

- (uint64_t)generateRequestHash:(Request *)request authTicket:(AuthTicket *)authTicket {
    NSData *authTicketData = authTicket.data;
    NSData *requestData = request.data;
    uint64_t firstHash = XXH64(authTicketData.bytes, authTicketData.length, HashSeed);
    uint64_t result = XXH64(requestData.bytes, requestData.length, firstHash);
    return result;
}

- (NSData *)generateSignatureData:(Signature *)signature {
    NSData *signatureData = signature.data;
    NSData *ivData = [self uRandom:32];
    
    // get output size
    size_t outputSize;
    int result = unknown6_encrypt(signatureData.bytes, signatureData.length, ivData.bytes, ivData.length, NULL, &outputSize);
    // create output buffer
    unsigned char output[outputSize];
    memset(output, 0, outputSize);
    
    result = unknown6_encrypt(signatureData.bytes, signatureData.length, ivData.bytes, ivData.length, output, &outputSize);
    
    NSData *outputData = [NSData dataWithBytes:output length:outputSize];
    return outputData;
}

#pragma mark - Helpers

- (NSData *)uRandom:(NSInteger)bytes {
    int error = 0;
    NSMutableData* data = [NSMutableData dataWithLength:bytes];
    error = SecRandomCopyBytes(kSecRandomDefault, bytes, [data mutableBytes]);
    if (error) {
        NSLog(@"Generate random bytes failed");
        return nil;
    }
    return data;
}

// https://github.com/Grover-c13/PokeGOAPI-Java/commit/e1d2d15320f363da89ae09b411fce0e7ba672066
- (NSData *)doubleToHexData:(double)value {
    uint64_t valueBits;
    memcpy(&valueBits, &value, sizeof(valueBits));
    unsigned char bytes[] = {
        (unsigned char) (valueBits >> 56),
        (unsigned char) (valueBits >> 48),
        (unsigned char) (valueBits >> 40),
        (unsigned char) (valueBits >> 32),
        (unsigned char) (valueBits >> 24),
        (unsigned char) (valueBits >> 16),
        (unsigned char) (valueBits >> 8),
        (unsigned char) valueBits
    };
    NSData *hexData = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    return hexData;
}

@end
