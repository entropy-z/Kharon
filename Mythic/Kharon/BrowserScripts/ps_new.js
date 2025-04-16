function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { 'plaintext': combined };
    } else if (responses.length > 0) {
        try {
            let data = [];
            for (let i = 0; i < responses.length; i++) {
                try {
                    data = data.concat(JSON.parse(responses[i]));
                } catch (error) {
                    console.log(error);
                    const combined = responses.reduce((prev, cur) => prev + cur, "");
                    return {'plaintext': combined};
                }
            }

            const systemProcesses = ["System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", 
                                   "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", 
                                   "dwm.exe", "explorer.exe", "Memory Compression"];
            const securityProcesses = ["MsMpEng.exe", "NisSrv.exe", "MpDefenderCoreService.exe", 
                                     "SecurityHealthService.exe", "MBAMService", "CylanceSvc"];
            const adminTools = ["ProcessHacker.exe", "pestudio.exe", "x64dbg.exe", "powershell.exe", 
                              "cmd.exe", "mmc.exe", "regedit.exe", "Taskmgr.exe", "procexp.exe"];

            const headers = [
                { "plaintext": "Image Name", "type": "string", "width": 450, "headerStyle": baseHeaderStyle() },
                { "plaintext": "PID", "type": "number", "width": 100, "headerStyle": baseHeaderStyle() },
                { "plaintext": "PPID", "type": "number", "width": 100, "headerStyle": baseHeaderStyle() },
                { "plaintext": "Arch", "type": "string", "width": 70, "headerStyle": baseHeaderStyle() },
                { "plaintext": "Session", "type": "number", "width": 120, "headerStyle": baseHeaderStyle() },
                { "plaintext": "User", "type": "string", "width": 300, "headerStyle": baseHeaderStyle() },
                { "plaintext": "Actions", "type": "button", "width": 10, "headerStyle": baseHeaderStyle(), "disableSort": true }
            ];

            function baseHeaderStyle() {
                return {
                    "backgroundColor": "#2a3e50",
                    "border": "1px solid #3d4a56",
                    "borderBottom": "2px solid #4b5a6b"
                };
            }

            const rows = data.map(process => {
                let rowStyle = {
                    "borderBottom": "1px solid #3d4a56"
                };
                let processName = process["Image Name"];
                let isSystem = systemProcesses.includes(processName) || process["Session ID"] === 0;
                let isSecurity = securityProcesses.includes(processName);
                let isAdminTool = adminTools.includes(processName);
                
                if (isSecurity) {
                    Object.assign(rowStyle, {
                        "backgroundColor": "rgba(220, 20, 60, 0.2)",
                        // "borderLeft": "4px solid crimson"
                    });
                } else if (isAdminTool) {
                    Object.assign(rowStyle, {
                        "backgroundColor": "rgba(30, 144, 255, 0.2)",
                        // "borderLeft": "4px solid dodgerblue"
                    });
                } else if (isSystem) {
                    Object.assign(rowStyle, {
                        "backgroundColor": "rgba(100, 149, 237, 0.2)",
                        // "borderLeft": "4px solid cornflowerblue"
                    });
                }

                const actionMenu = {
                    "name": "More...",
                    "type": "menu",
                    "value": [
                        {
                            "name": "Process Details",
                            "type": "dictionary",
                            "value": {
                                "Image Path": process["Image Path"] || "N/A",
                                "Command Line": process["Command Line"] || "N/A",
                                "Threads": process["Threads Quantity"] || 0,
                                "Handles": process["Handle Count"] || 0,
                                "Session": process["Session ID"] || 0,
                                "User": process["User Token"] || "N/A"
                            },
                            "leftColumnTitle": "Property",
                            "rightColumnTitle": "Value",
                            "title": `${process["Image Name"]} (PID: ${process["Process ID"]})`
                        },
                        {
                            "name": "Kill Process",
                            "type": "task",
                            "ui_feature": "proc -action kill -pid",
                            "parameters": process["Process ID"],
                            "startIcon": "skull",
                            "style": {"color": "#ff6b6b"}
                        }
                    ],
                    "style": {
                        "backgroundColor": "#2d3436",
                        "border": "1px solid #4b5a6b",
                        "color": "#74b9ff",
                        "borderRadius": "4px",
                        "padding": "4px"
                    }
                };

                return {
                    "rowStyle": rowStyle,
                    "Image Name": {
                        "plaintext": process["Image Name"],
                        "cellStyle": {
                            "fontWeight": isSystem ? "bold" : "normal",
                            "color": isSecurity ? "#dc143c" : (isAdminTool ? "#1e90ff" : "#ffffff")
                        }
                    },
                    "PID": {
                        "plaintext": process["Process ID"],
                        "cellStyle": {
                            "color": isSecurity ? "#dc143c" : "#74b9ff",
                            "fontWeight": "bold"
                        },
                        "copyIcon": true
                    },
                    "PPID": {
                        "plaintext": process["Parent ID"],
                        "cellStyle": {
                            "color": isSecurity ? "#dc143c" : "#74b9ff"
                        },
                        "copyIcon": true
                    },
                    "Arch": {
                        "plaintext": process["Architecture"],
                        "cellStyle": {
                            "color": process["Architecture"] === "x64" ? "#a29bfe" : "#fd79a8"
                        }
                    },
                    "Session": {
                        "plaintext": process["Session ID"],
                        "cellStyle": {
                            "color": process["Session ID"] === 0 ? "#ffeaa7" : "#dfe6e9"
                        }
                    },
                    "User": {
                        "plaintext": process["User Token"] || "SYSTEM",
                        "cellStyle": {
                            "color": process["User Token"] === "SYSTEM" ? "#ff6b6b" : "#55efc4"
                        }
                    },
                    "Actions": {
                        "button": actionMenu,
                        "cellStyle": {
                            "textAlign": "left"
                        }
                    }
                };
            });

            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "backgroundColor": "#1e272e",
                    "border": "1px solid #3d4a56",
                    "cellStyle": {
                        "borderBottom": "1px solid #3d4a56"
                    }
                }]
            };
        } catch (e) {
            return { 
                'plaintext': "Error processing response: " + e.toString(),
                'cellStyle': {
                    'color': '#ff7675',
                    'border': '1px solid #ff7675',
                    'padding': '8px',
                    'backgroundColor': '#1e272e'
                }
            };
        }
    } else {
        return { 
            "plaintext": "No response yet from agent...",
            "cellStyle": {
                "color": "#b2bec3",
                "fontStyle": "italic",
                "border": "1px dashed #3d4a56",
                "padding": "8px",
                "backgroundColor": "#1e272e"
            }
        };
    }
}
