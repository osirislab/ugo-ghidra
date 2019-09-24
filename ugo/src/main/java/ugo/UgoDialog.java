package ugo;

import docking.DialogComponentProvider;

import javax.swing.*;
import java.awt.*;

public class UgoDialog extends DialogComponentProvider {
    private static final String DIALOG_TITLE = "UGO_DIALOG";

    public UgoDialog() {
        super(DIALOG_TITLE);
        addWorkPanel(new JPanel(new GridBagLayout()));
    }
}
