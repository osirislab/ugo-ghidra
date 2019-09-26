package ugo;

import com.google.inject.AbstractModule;
import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.PluginTool;

public class UgoModule extends AbstractModule {
    private UgoPlugin ugoPlugin;
    private PluginTool pluginTool;

    public UgoModule(UgoPlugin ugoPlugin, PluginTool pluginTool) {
        this.ugoPlugin = ugoPlugin;
        this.pluginTool = pluginTool;
    }

    protected void configure() {
        bind(UgoPlugin.class).toInstance(ugoPlugin);
        bind(PluginTool.class).toInstance(pluginTool);
    }
}
