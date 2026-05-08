// tutorial_daemon.m — planted-bug XPC daemon for station tutorial.
// Three deliberate vulnerabilities. See docs/tutorial/first-pass-planted.md.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Private API used by real daemons to get the audit token from a connection.
@interface NSXPCConnection (AuditToken)
@property (readonly) audit_token_t auditToken;
@end

// --- Protocol definitions ---

@protocol PrivilegedOps <NSObject>
- (void)installConfigAtPath:(NSString *)path
                   contents:(NSData *)data
                  withReply:(void (^)(BOOL success, NSError *error))reply;
- (void)restartServiceWithID:(NSString *)serviceID
                   withReply:(void (^)(BOOL success, NSError *error))reply;
@end

@protocol InternalOps <NSObject>
- (void)writeAuditLog:(NSString *)message
            withReply:(void (^)(BOOL success))reply;
- (void)resetCacheAtPath:(NSString *)path
               withReply:(void (^)(BOOL success, NSError *error))reply;
@end

// --- Exported object for the privileged service ---

@interface PrivilegedHandler : NSObject <PrivilegedOps>
@property (nonatomic, strong) NSXPCConnection *currentConnection;
@end

@implementation PrivilegedHandler

- (void)installConfigAtPath:(NSString *)path
                   contents:(NSData *)data
                  withReply:(void (^)(BOOL, NSError *))reply {
    // BUG 2: Audit token is captured here but authorization is deferred
    // to -authorizeMethodID:connection: which has a bypass.
    if (![self authorizeMethodID:1 connection:self.currentConnection]) {
        reply(NO, [NSError errorWithDomain:@"com.tutorial.daemon"
                                      code:403
                                  userInfo:@{NSLocalizedDescriptionKey: @"unauthorized"}]);
        return;
    }
    [data writeToFile:path atomically:YES];
    reply(YES, nil);
}

- (void)restartServiceWithID:(NSString *)serviceID
                   withReply:(void (^)(BOOL, NSError *))reply {
    if (![self authorizeMethodID:2 connection:self.currentConnection]) {
        reply(NO, [NSError errorWithDomain:@"com.tutorial.daemon"
                                      code:403
                                  userInfo:@{NSLocalizedDescriptionKey: @"unauthorized"}]);
        return;
    }
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/launchctl"];
    [task setArguments:@[@"kickstart", @"-k",
                         [NSString stringWithFormat:@"system/%@", serviceID]]];
    [task launch];
    [task waitUntilExit];
    reply(task.terminationStatus == 0, nil);
}

// BUG 2 detail: methodID 0 is "internal reset" — it always returns YES,
// bypassing audit-token verification. An attacker who can reach this
// through the privileged listener can skip authorization entirely by
// calling any method that internally routes through methodID 0.
- (BOOL)authorizeMethodID:(int)methodID connection:(NSXPCConnection *)conn {
    if (methodID == 0) {
        return YES;
    }
    audit_token_t token = conn.auditToken;
    SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, token);
    if (!task) return NO;

    CFErrorRef error = NULL;
    CFStringRef value = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.tutorial.daemon.admin"), &error);
    CFRelease(task);
    if (error) {
        if (value) CFRelease(value);
        return NO;
    }
    BOOL authorized = (value != NULL);
    if (value) CFRelease(value);
    return authorized;
}

@end

// --- Exported object for the internal service ---

@interface InternalHandler : NSObject <InternalOps>
@end

@implementation InternalHandler

// BUG 3: This "internal" service is un-gated — any process can connect
// and call writeAuditLog: to write arbitrary content to a privileged path.
- (void)writeAuditLog:(NSString *)message
            withReply:(void (^)(BOOL))reply {
    NSString *logPath = @"/var/log/tutorial-daemon-audit.log";
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    }
    [fh seekToEndOfFile];
    NSString *line = [NSString stringWithFormat:@"%@: %@\n",
                      [NSDate date], message];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
    reply(YES);
}

- (void)resetCacheAtPath:(NSString *)path
               withReply:(void (^)(BOOL, NSError *))reply {
    NSError *err = nil;
    [[NSFileManager defaultManager] removeItemAtPath:path error:&err];
    reply(err == nil, err);
}

@end

// --- Delegate ---

@interface DaemonDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation DaemonDelegate

// BUG 1: shouldAcceptNewConnection does NOT branch by listener identity.
// Both the privileged and internal listeners share this single delegate.
// Any client connecting to either MachService gets accepted with the same
// exported interface — the "internal" service hands out PrivilegedHandler
// if an attacker connects to the privileged port name, and vice versa.
// In practice, the InternalHandler is the danger: it's un-gated and
// exposes file-write primitives.
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)newConnection {

    // No listener identity check — this is the bug.
    // A correct implementation would compare listener to each known
    // listener and set the appropriate interface + exported object.

    newConnection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(InternalOps)];
    newConnection.exportedObject = [[InternalHandler alloc] init];
    [newConnection resume];
    return YES;
}

@end

// --- main ---

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        DaemonDelegate *delegate = [[DaemonDelegate alloc] init];

        // Two MachServices registered in the launchd plist.
        NSXPCListener *privilegedListener =
            [[NSXPCListener alloc]
                initWithMachServiceName:@"com.tutorial.daemon.privileged"];
        privilegedListener.delegate = delegate;

        NSXPCListener *internalListener =
            [[NSXPCListener alloc]
                initWithMachServiceName:@"com.tutorial.daemon.internal"];
        internalListener.delegate = delegate;

        [privilegedListener resume];
        [internalListener resume];

        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
