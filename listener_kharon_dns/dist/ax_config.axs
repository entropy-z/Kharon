/// Kharon DNS listener

function ListenerUI(mode_create)
{
    let spacer1 = form.create_vspacer();

    let labelHost = form.create_label("Host & Port (Bind):");
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create);
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }
    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535);
    spinPortBind.setValue(53);
    spinPortBind.setEnabled(mode_create);

    let labelDomain = form.create_label("Authoritative Domain(s):");
    let textDomain = form.create_textline("");
    textDomain.setPlaceholder("ns1.c2.com,ns2.backup.com");

    let labelPktSize = form.create_label("Max Payload (bytes):");
    let spinPktSize = form.create_spin();
    spinPktSize.setRange(512, 65535);
    spinPktSize.setValue(4096);

    let labelTTL = form.create_label("DNS TTL (seconds):");
    let spinTTL = form.create_spin();
    spinTTL.setRange(1, 3600);
    spinTTL.setValue(5);

    let checkBurstEnabled = form.create_check("Enable Burst Mode");
    checkBurstEnabled.setChecked(false);

    let labelBurstSleep = form.create_label("Burst Sleep (ms):");
    let spinBurstSleep = form.create_spin();
    spinBurstSleep.setRange(10, 1000);
    spinBurstSleep.setValue(50);
    spinBurstSleep.setEnabled(false);

    let labelBurstJitter = form.create_label("Burst Jitter (%):");
    let spinBurstJitter = form.create_spin();
    spinBurstJitter.setRange(0, 90);
    spinBurstJitter.setValue(0);
    spinBurstJitter.setEnabled(false);

    form.connect(checkBurstEnabled, "stateChanged", function() {
        if(spinBurstSleep.getEnabled()) {
            spinBurstSleep.setEnabled(false);
            spinBurstJitter.setEnabled(false);
        } else {
            spinBurstSleep.setEnabled(true);
            spinBurstJitter.setEnabled(true);
        }
    });

    let spacer2 = form.create_vspacer();

    let layout = form.create_gridlayout();
    layout.addWidget(spacer1,            0, 0, 1, 3);
    layout.addWidget(labelHost,          1, 0, 1, 1);
    layout.addWidget(comboHostBind,      1, 1, 1, 1);
    layout.addWidget(spinPortBind,       1, 2, 1, 1);
    layout.addWidget(labelDomain,        2, 0, 1, 1);
    layout.addWidget(textDomain,         2, 1, 1, 2);
    layout.addWidget(labelPktSize,       3, 0, 1, 1);
    layout.addWidget(spinPktSize,        3, 1, 1, 2);
    layout.addWidget(labelTTL,           4, 0, 1, 1);
    layout.addWidget(spinTTL,            4, 1, 1, 2);
    layout.addWidget(checkBurstEnabled,  5, 0, 1, 3);
    layout.addWidget(labelBurstSleep,    6, 0, 1, 1);
    layout.addWidget(spinBurstSleep,     6, 1, 1, 2);
    layout.addWidget(labelBurstJitter,   7, 0, 1, 1);
    layout.addWidget(spinBurstJitter,    7, 1, 1, 2);
    layout.addWidget(spacer2,            8, 0, 1, 3);

    let container = form.create_container();
    container.put("host_bind",     comboHostBind);
    container.put("port_bind",     spinPortBind);
    container.put("domain",        textDomain);
    container.put("pkt_size",      spinPktSize);
    container.put("ttl",           spinTTL);
    container.put("burst_enabled", checkBurstEnabled);
    container.put("burst_sleep",   spinBurstSleep);
    container.put("burst_jitter",  spinBurstJitter);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 360,
        ui_width: 500
    }
}
