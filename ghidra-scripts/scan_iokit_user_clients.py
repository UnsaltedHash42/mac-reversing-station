# Ghidra script: scan one loaded program for IOKit user-client surface.
#
# IOKit user clients are a major attack surface, especially in EDR /
# AV / driver-helper binaries that talk to a kernel driver via
# IOConnectCallMethod. The selector + scalar/struct payloads passed
# through these calls are exactly what fuzzes turn up bugs in.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   ioservice_open_callsite             callsite (IOService handle is dynamic)
#   ioconnect_call_method_callsite      selector (arg 1, uint32_t)
#   ioconnect_call_scalar_callsite      selector (arg 1)
#   ioconnect_call_struct_callsite      selector (arg 1)
#   ioconnect_call_async_method         selector (arg 1)
#   ioservice_matching_callsite         service class name (arg 0, char*)
#   ioservice_name_matching_callsite    service name (arg 0, char*)
#   io_connect_map_memory_callsite      memory type (arg 1, const)
#
# Recovering the *selector* (an integer) for each IOConnectCallMethod
# turns "this binary opens an IOConnect" into "this binary calls user
# client method 0x05 / 0x12 / 0x21" -- which is exactly the call-table
# index the kernel driver dispatches on.
#
# Tier B (function-name match):
#   user_client_handler_impl    *userClient* / *externalMethod / *getTargetAndMethodForIndex
#   ioservice_open_impl         *openClient / *connectToService
#
# Tier C (string heuristic):
#   io_service_class_string     IOService / IOUserClient / com.apple.driver.* class names
#   io_kit_string               IOKit / IOConnect / IOService / IOUserClient
#
# @category Mach-O.IOKit
# @runtime Jython

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("IOServiceOpen", arg_index=0, recover_kind="none",
            anchor_kind="ioservice_open_callsite"),
    APISpec("IOServiceMatching", arg_index=0, recover_kind="string",
            anchor_kind="ioservice_matching_callsite", evidence_label="class"),
    APISpec("IOServiceNameMatching", arg_index=0, recover_kind="string",
            anchor_kind="ioservice_name_matching_callsite", evidence_label="name"),
    APISpec("IOConnectCallMethod", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_call_method_callsite", evidence_label="selector"),
    APISpec("IOConnectCallScalarMethod", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_call_scalar_callsite", evidence_label="selector"),
    APISpec("IOConnectCallStructMethod", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_call_struct_callsite", evidence_label="selector"),
    APISpec("IOConnectCallAsyncMethod", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_call_async_callsite", evidence_label="selector"),
    APISpec("IOConnectCallAsyncScalarMethod", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_call_async_scalar_callsite", evidence_label="selector"),
    APISpec("IOConnectMapMemory", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_map_memory_callsite", evidence_label="memory_type"),
    APISpec("IOConnectMapMemory64", arg_index=1, recover_kind="const",
            anchor_kind="ioconnect_map_memory_callsite", evidence_label="memory_type"),
    APISpec("IORegistryEntryFromPath", arg_index=1, recover_kind="string",
            anchor_kind="ioregistry_entry_from_path_callsite", evidence_label="path"),
]


run_string_scan(
    scan_name="scan_iokit_user_clients",
    rules=[
        StringRule("C", "io_service_class_string",
                   r"(IOService|IOUserClient|IOSurface|IOHID|IOUSBHost|IOAccelerator|com\.apple\.driver\.[A-Za-z0-9_.-]+)",
                   max_anchors=24, evidence_label="class"),
        StringRule("C", "io_kit_string",
                   r"(IOKit|IOConnect|IORegistry|IOServiceMatching|IOServiceOpen)",
                   max_anchors=16, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "user_client_handler_impl",
                   r"(userClient|externalMethod|getTargetAndMethodFor|clientMemoryForType|clientClose|registerNotificationPort)",
                   max_anchors=16, evidence_label="function"),
        StringRule("B", "ioservice_open_impl",
                   r"(openClient|connectToService|matchingService|openIOConnect)",
                   max_anchors=12, evidence_label="function"),
    ],
    api_specs=API_SPECS,
)
