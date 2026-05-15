// PluginHelper.m — bundled XPC helper for tutorial-target-2.
// Two deliberate vulnerabilities (the dlopen ones).
// See docs/tutorial/first-pass-bundle.md.
#import <Foundation/Foundation.h>
#import <dlfcn.h>

// --- Protocol exposed over XPC ---

@protocol PluginHelperProtocol <NSObject>
- (void)loadPluginAtPath:(NSString *)path
                withReply:(void (^)(BOOL ok, NSError *error))reply;
- (void)listLoadedPluginsWithReply:(void (^)(NSArray<NSString *> *paths))reply;
@end

// --- Loaded-plugin registry (in-process) ---

static NSMutableArray<NSString *> *gLoadedPluginPaths;
static dispatch_queue_t gRegistryQueue;

static void EnsureRegistry(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gLoadedPluginPaths = [NSMutableArray array];
        gRegistryQueue = dispatch_queue_create(
            "com.tutorial.pluginhost.helper.registry", DISPATCH_QUEUE_SERIAL);
    });
}

// --- Path allowlist check (the broken one) ---

// BUG 2 detail: the allowlist is a STRING SUFFIX on the filename and a
// substring check on the directory part. It should resolve the path with
// realpath() and verify the resolved path is inside the bundle's
// Resources/plugins directory. Instead it accepts anything that:
//   1. ends in ".dylib"
//   2. has the substring "/plugins/" anywhere in its path
// Both are trivially satisfied by paths that escape the bundle (e.g.
// "/tmp/evil/plugins/x.dylib" or "/path/to/Resources/plugins/../../../tmp/x.dylib").
static BOOL PathLooksLikeAllowlistedPlugin(NSString *path) {
    if (![path hasSuffix:@".dylib"]) return NO;
    if ([path rangeOfString:@"/plugins/"].location == NSNotFound) return NO;
    return YES;
}

// --- Exported object ---

@interface PluginHandler : NSObject <PluginHelperProtocol>
@end

@implementation PluginHandler

- (void)loadPluginAtPath:(NSString *)path
                withReply:(void (^)(BOOL, NSError *))reply {
    EnsureRegistry();

    // BUG 2: trivially-bypassed allowlist (see PathLooksLikeAllowlistedPlugin).
    // A correct implementation would resolve `path` with realpath() and
    // confirm the resolved path is a prefix-equal child of the bundle's
    // Resources/plugins directory.
    if (!PathLooksLikeAllowlistedPlugin(path)) {
        NSError *err = [NSError errorWithDomain:@"com.tutorial.pluginhost.helper"
                                           code:400
                                       userInfo:@{NSLocalizedDescriptionKey:
                                                  @"path failed allowlist check"}];
        reply(NO, err);
        return;
    }

    // BUG 3: even if the path ALLOWLIST were correct, the helper does not
    // verify the dylib's signature, team id, or hardened-runtime status
    // before loading it into its own process. A correct implementation
    // would call SecStaticCodeCreateWithPath + SecStaticCodeCheckValidity
    // with a designated-requirement string before dlopen, or use
    // SecCodeCopySigningInformation to read the team id and gate on it.
    void *handle = dlopen([path UTF8String], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        NSString *msg = [NSString stringWithFormat:@"dlopen failed: %s",
                                                   dlerror()];
        NSError *err = [NSError errorWithDomain:@"com.tutorial.pluginhost.helper"
                                           code:500
                                       userInfo:@{NSLocalizedDescriptionKey: msg}];
        reply(NO, err);
        return;
    }

    // Real plugins implement an entry point; if it's there, call it.
    typedef int (*plugin_init_t)(void);
    plugin_init_t init = (plugin_init_t)dlsym(handle, "plugin_initialize");
    int rc = init ? init() : 0;

    dispatch_sync(gRegistryQueue, ^{
        [gLoadedPluginPaths addObject:path];
    });

    reply(rc == 0, nil);
}

- (void)listLoadedPluginsWithReply:(void (^)(NSArray<NSString *> *))reply {
    EnsureRegistry();
    __block NSArray<NSString *> *snapshot;
    dispatch_sync(gRegistryQueue, ^{
        snapshot = [gLoadedPluginPaths copy];
    });
    reply(snapshot ?: @[]);
}

@end

// --- Listener delegate ---

@interface HelperDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation HelperDelegate

- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    // The helper is reachable as a bundled XPC service (the host is its
    // intended client), so the system grants the connection per-bundle.
    // No additional gate is needed on the helper side IF the host
    // validates its inputs. The host does not — see PluginHost.m BUG 1.
    newConnection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(PluginHelperProtocol)];
    newConnection.exportedObject = [PluginHandler new];
    [newConnection resume];
    return YES;
}

@end

// --- main ---

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        static HelperDelegate *gDelegate;
        gDelegate = [HelperDelegate new];
        NSXPCListener *listener = [NSXPCListener serviceListener];
        listener.delegate = gDelegate;
        [listener resume];
    }
    return 0;
}
