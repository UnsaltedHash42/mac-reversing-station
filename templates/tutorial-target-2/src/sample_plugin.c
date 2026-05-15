// sample_plugin.c — legitimate plugin that ships in PluginHost.app/Contents/Resources/plugins/.
// Loaded by PluginHelper for the happy-path demo.

#include <os/log.h>

int plugin_initialize(void) {
    os_log(OS_LOG_DEFAULT, "tutorial-target-2 sample_plugin loaded");
    return 0;
}
