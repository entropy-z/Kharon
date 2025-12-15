function ListenerUI(mode_create)
{
    // === MAIN SETTINGS ===
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

    // === HTTP METHODS ===
    let labelMethods = form.create_label("HTTP Methods:");
    let methodsMultiChoice = form.create_combo();
    methodsMultiChoice.addItem("GET");
    methodsMultiChoice.addItem("POST");
    methodsMultiChoice.setEnabled(mode_create)

    // === CALLBACK SETTINGS ===
    let labelCallbackHost = form.create_label("Callback Hosts:");
    let callback_txtmulti = form.create_textmulti();
    callback_txtmulti.setPlaceholder("192.168.1.1:4444\nserver2.com:5555");

    // === URI SETTINGS ===
    let labelUri = form.create_label("URI:");
    let textlineUri = form.create_textmulti();
    textlineUri.setPlaceholder("/kh_route_1\n/kh_route_2");

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

    // === HEADERS SETTINGS ===
    let labelUserAgent = form.create_label("User Agent:");
    let userAgentText = form.create_textline();
    userAgentText.setPlaceholder("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

    // Request Headers
    let requestHeadersGroup = form.create_groupbox("Request Headers", true);

    let labelRequestHeaders = form.create_label("Custom Request Headers:");
    let requestHeadersText = form.create_textmulti();
    requestHeadersText.setPlaceholder("X-Forwarded-For: 192.168.1.1\nX-Custom-Header: value\nAccept: application/json\nAuthorization: Bearer token");

    let requestHeadersLayout = form.create_gridlayout();
    requestHeadersLayout.addWidget(labelRequestHeaders, 0, 0, 1, 3);
    requestHeadersLayout.addWidget(requestHeadersText, 1, 0, 1, 3);

    let requestHeadersPanel = form.create_panel();
    requestHeadersPanel.setLayout(requestHeadersLayout);
    requestHeadersGroup.setPanel(requestHeadersPanel);
    requestHeadersGroup.setChecked(false);

    // Server Headers
    let serverHeadersGroup = form.create_groupbox("Server Headers", true);

    let labelServerHeaders = form.create_label("Custom Server Response Headers:");
    let serverHeadersText = form.create_textmulti();
    serverHeadersText.setPlaceholder("Server: Apache/2.4.41\nX-Powered-By: PHP/7.4\nX-Content-Type-Options: nosniff\nCache-Control: no-cache");

    let serverHeadersLayout = form.create_gridlayout();
    serverHeadersLayout.addWidget(labelServerHeaders, 0, 0, 1, 3);
    serverHeadersLayout.addWidget(serverHeadersText, 1, 0, 1, 3);

    let serverHeadersPanel = form.create_panel();
    serverHeadersPanel.setLayout(serverHeadersLayout);
    serverHeadersGroup.setPanel(serverHeadersPanel);
    serverHeadersGroup.setChecked(false);

    let headers_layout = form.create_gridlayout();
    headers_layout.addWidget(labelUserAgent, 0, 0, 1, 1);
    headers_layout.addWidget(userAgentText, 0, 1, 1, 2);
    headers_layout.addWidget(requestHeadersGroup, 1, 0, 1, 3);
    headers_layout.addWidget(serverHeadersGroup, 2, 0, 1, 3);

    let headers_panel = form.create_panel();
    headers_panel.setLayout(headers_layout);

    // === MAIN LAYOUT ===
    let layoutMain = form.create_gridlayout();
    layoutMain.addWidget(labelHost,     0, 0, 1, 1);
    layoutMain.addWidget(comboHostBind, 0, 1, 1, 1);
    layoutMain.addWidget(spinPortBind,  0, 2, 1, 1);

    layoutMain.addWidget(labelMethods,       1, 0, 1, 1);
    layoutMain.addWidget(methodsMultiChoice, 1, 1, 1, 2);

    layoutMain.addWidget(labelCallbackHost, 2, 0, 1, 1);
    layoutMain.addWidget(callback_txtmulti,  2, 1, 1, 2);

    layoutMain.addWidget(labelUri,      3, 0, 1, 1);
    layoutMain.addWidget(textlineUri,   3, 1, 1, 2);

    layoutMain.addWidget(proxy_group,    4, 0, 1, 3);
    layoutMain.addWidget(ssl_group,      5, 0, 1, 3);

    let panelMain = form.create_panel();
    panelMain.setLayout(layoutMain);

    // Malleable 
    let layoutMalleable = form.create_gridlayout();

    let panelMalleable = form.create_panel();
    panelMalleable.setLayout(layoutMalleable);

    // === TABS ===
    let tabs = form.create_tabs();
    tabs.addTab(panelMain, "Main settings");
    tabs.addTab(headers_panel, "HTTP Headers");
    tabs.addTab(panelMalleable, "Malleable Profile");

    let layout = form.create_hlayout();
    layout.addWidget(tabs);

    // === CONTAINER ===
    let container = form.create_container();
    container.put("host_bind", comboHostBind);
    container.put("port_bind", spinPortBind);
    container.put("http_method", methodsMultiChoice);
    container.put("uri", textlineUri);
    container.put("callback_addresses", callback_txtmulti);
    container.put("ssl", ssl_group);
    container.put("ssl_cert", certSelector);
    container.put("ssl_key", keySelector);
    container.put("proxy_url", proxy_url_text);
    container.put("proxy_user", proxy_user_text);
    container.put("proxy_pass", proxy_pass_text);
    container.put("user_agent", userAgentText);
    container.put("request_headers", requestHeadersText);
    container.put("server_headers", serverHeadersText);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container
    }
}
