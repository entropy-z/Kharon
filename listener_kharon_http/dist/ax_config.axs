function ListenerUI(mode_create)
{
    // ============================================
    // === MAIN SETTINGS ===
    // ============================================
    let labelHost = form.create_label("Host & port (Bind):");        
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create);
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }

    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535);
    spinPortBind.setValue(443);
    spinPortBind.setEnabled(mode_create);

    // === BLOCK USER AGENTS ===
    let labelBlockUserAgents = form.create_label("Block User Agents:");
    let blockUserAgentsText = form.create_textmulti();
    blockUserAgentsText.setPlaceholder("curl*\nwget*");

    // === DOMAIN ROTATION ===
    let labelDomainRotation = form.create_label("Domain Rotation:");
    let domainRotationCombo = form.create_combo();
    domainRotationCombo.addItem("Random");
    domainRotationCombo.addItem("Round Robin");
    domainRotationCombo.addItem("Failover");
    domainRotationCombo.setCurrentIndex(0);

    // === FILE UPLOAD SECTION ===
    let labelUploadProfile = form.create_label("Upload Profile:");
    
    let fileSelector = form.create_selector_file();
    fileSelector.setPlaceholder("Select a profile file");
    
    // Opcional: campo para mostrar o nome do arquivo selecionado
    let uploadedFileText = form.create_textline();
    uploadedFileText.setReadOnly(true);
    uploadedFileText.setPlaceholder("No file selected");
    
    // form.connect(fileSelector, "selection_changed", function() {
    //    let selectedFile = fileSelector.getSelection();
    //    if (selectedFile) {
    //        uploadedFileText.setValue(selectedFile);
    //    } else {
    //        uploadedFileText.setValue("");
    //    }
    //  });

    // === PROXY SETTINGS ===
    let proxy_group = form.create_groupbox("Proxy Settings", true);  

    let label_proxy_url = form.create_label("Proxy URL:");
    let proxy_url_text  = form.create_textline();
    proxy_url_text.setPlaceholder("http://127.0.0.1:8080");

    let label_proxy_user = form.create_label("Username:");
    let proxy_user_text  = form.create_textline();

    let label_proxy_pass = form.create_label("Password:");
    let proxy_pass_text  = form.create_textline();

    let proxy_layout_group = form.create_gridlayout();
    proxy_layout_group.addWidget(label_proxy_url,  0, 0, 1, 1);      
    proxy_layout_group.addWidget(proxy_url_text,   0, 1, 1, 2);      
    proxy_layout_group.addWidget(label_proxy_user, 1, 0, 1, 1);      
    proxy_layout_group.addWidget(proxy_user_text,  1, 1, 1, 2);      
    proxy_layout_group.addWidget(label_proxy_pass, 2, 0, 1, 1);      
    proxy_layout_group.addWidget(proxy_pass_text,  2, 1, 1, 2);      

    let proxy_panel_group = form.create_panel();
    proxy_panel_group.setLayout(proxy_layout_group);

    proxy_group.setPanel(proxy_panel_group);
    proxy_group.setChecked(false);

    // === SSL SETTINGS ===
    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("SSL certificate");

    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("SSL key");

    let ssl_layout = form.create_gridlayout();
    ssl_layout.addWidget(certSelector, 0, 0, 1, 3);
    ssl_layout.addWidget(keySelector,  1, 0, 1, 3);

    let ssl_panel = form.create_panel();
    ssl_panel.setLayout(ssl_layout);

    let ssl_group = form.create_groupbox("Use SSL (HTTPS)", true);   
    ssl_group.setPanel(ssl_panel);
    ssl_group.setChecked(false);

    // === MAIN LAYOUT ===
    let layoutMain = form.create_gridlayout();
    layoutMain.addWidget(labelHost,     0, 0, 1, 1);
    layoutMain.addWidget(comboHostBind, 0, 1, 1, 1);
    layoutMain.addWidget(spinPortBind,  0, 2, 1, 1);

    layoutMain.addWidget(labelBlockUserAgents, 1, 0, 1, 3);
    layoutMain.addWidget(blockUserAgentsText,  2, 0, 1, 3);

    layoutMain.addWidget(labelDomainRotation, 3, 0, 1, 1);
    layoutMain.addWidget(domainRotationCombo, 3, 1, 1, 2);

    layoutMain.addWidget(labelUploadProfile,  4, 0, 1, 1);
    layoutMain.addWidget(fileSelector,        4, 1, 1, 2);
    // layoutMain.addWidget(uploadedFileText,    5, 0, 1, 3);

    layoutMain.addWidget(proxy_group,        5, 0, 1, 3);
    layoutMain.addWidget(ssl_group,          6, 0, 1, 3);

    let panelMain = form.create_panel();
    panelMain.setLayout(layoutMain);

    // ============================================
    // === CONTAINER ===
    // ============================================
    let container = form.create_container();

    // Main settings
    container.put("host_bind", comboHostBind);
    container.put("port_bind", spinPortBind);
    container.put("block_user_agents", blockUserAgentsText);
    
    // File selector - armazena o seletor completo
    container.put("uploaded_file", fileSelector);
    
    // Domain Rotation
    container.put("domain_rotation_strategy", domainRotationCombo);
    
    // Proxy settings
    container.put("proxy_url", proxy_url_text);
    container.put("proxy_user", proxy_user_text);
    container.put("proxy_pass", proxy_pass_text);
    
    // SSL settings
    container.put("ssl", ssl_group);
    container.put("ssl_cert", certSelector);
    container.put("ssl_key", keySelector);

    let layout = form.create_hlayout();
    layout.addWidget(panelMain);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container
    }
}