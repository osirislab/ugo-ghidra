package ugo.actions;

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.util.HelpLocation;
import resources.ResourceManager;
import ugo.UgoDecompilerController;
import ugo.UgoDecompilerProvider;

import javax.swing.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

public class UgoCloneDecompilerAction extends UgoAbstractDecompilerAction {

    private final UgoDecompilerProvider provider;
    private UgoDecompilerController controller;

    public UgoCloneDecompilerAction(UgoDecompilerProvider provider, UgoDecompilerController controller) {
        super("Decompile Clone");
        this.provider = provider;
        this.controller = controller;
        ImageIcon image = ResourceManager.loadImage("images/camera-photo.png");
        setToolBarData(new ToolBarData(image, "ZZZ"));
        setDescription("Create a snapshot (disconnected) copy of this Decompiler window ");
        setHelpLocation(new HelpLocation("Snapshots", "Snapshots_Start"));
        setKeyBindingData(new KeyBindingData(KeyEvent.VK_T,
                InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
    }

    @Override
    protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
        return controller.getFunction() != null;
    }

    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        provider.cloneWindow();
    }
}
