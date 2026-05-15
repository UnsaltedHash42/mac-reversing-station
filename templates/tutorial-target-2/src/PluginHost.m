// PluginHost.m — host binary for tutorial-target-2 bundle.
// One deliberate vulnerability across the host/helper boundary.
// See docs/tutorial/first-pass-bundle.md.
#import <Foundation/Foundation.h>

// --- Protocol shared with PluginHelper ---

@protocol PluginHelperProtocol <NSObject>
- (void)loadPluginAtPath:(NSString *)path
                withReply:(void (^)(BOOL ok, NSError *error))reply;
- (void)listLoadedPluginsWithReply:(void (^)(NSArray<NSString *> *paths))reply;
@end

// Public protocol the host exposes to its own clients (apps that want
// to ask the host to load a plugin on their behalf).
@protocol HostFrontendProtocol <NSObject>
- (void)requestPluginLoad:(NSString *)pluginName
                withReply:(void (^)(BOOL ok, NSError *error))reply;
@end

// --- Frontend object exposed to host clients ---

@interface FrontendHandler : NSObject <HostFrontendProtocol>
@property (nonatomic, strong) NSXPCConnection *helperConnection;
@end

@implementation FrontendHandler

- (NSXPCConnection *)helperConnection {
    if (_helperConnection) return _helperConnection;

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *helperServiceName = @"com.tutorial.pluginhost.helper";
    _helperConnection = [[NSXPCConnection alloc]
        initWithServiceName:helperServiceName];
    _helperConnection.remoteObjectInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(PluginHelperProtocol)];
    [_helperConnection resume];
    (void)bundle;
    return _helperConnection;
}

- (void)requestPluginLoad:(NSString *)pluginName
                withReply:(void (^)(BOOL, NSError *))reply {
    // BUG 1 (host wrong-door): the host accepts pluginName from any client
    // and forwards it to the helper without checking that the caller is
    // entitled to load plugins, and without normalizing the path. The host
    // joins the resource directory as a STRING prefix instead of resolving
    // the bundle path — so a pluginName like "../../../../tmp/evil.dylib"
    // ends up at the helper as a real filesystem path outside the bundle.
    NSString *pluginsDir = [[[NSBundle mainBundle] resourcePath]
        stringByAppendingPathComponent:@"plugins"];
    NSString *resolvedPath =
        [pluginsDir stringByAppendingPathComponent:pluginName];

    id<PluginHelperProtocol> proxy =
        [[self helperConnection] remoteObjectProxyWithErrorHandler:^(NSError *e) {
        reply(NO, e);
    }];
    [proxy loadPluginAtPath:resolvedPath withReply:reply];
}

@end

// --- Listener delegate (NO acceptance gate) ---

@interface HostDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation HostDelegate

- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    // BUG 1 detail: no peer validation. Any process on the system that
    // can find the host's Mach service (com.tutorial.pluginhost.frontend)
    // can call requestPluginLoad: and traverse out of the plugin directory.
    newConnection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(HostFrontendProtocol)];
    newConnection.exportedObject = [FrontendHandler new];
    [newConnection resume];
    return YES;
}

@end

// --- main ---

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        static HostDelegate *gDelegate;
        gDelegate = [HostDelegate new];
        NSXPCListener *listener = [[NSXPCListener alloc]
            initWithMachServiceName:@"com.tutorial.pluginhost.frontend"];
        listener.delegate = gDelegate;
        [listener resume];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
