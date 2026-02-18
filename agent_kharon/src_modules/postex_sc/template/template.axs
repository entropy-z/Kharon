
let cmd_dotnet_inline = ax.create_command("template-inline", "", "", "Task: execute template postex");
cmd_dotnet_inline.addArgFlagFile("--args", "", true, "");
cmd_dotnet_inline.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dotnet_version = parsed_json["dotnet_version"] || "";

    let mod_params = ax.bof_pack("bytes,wstr,wstr,wstr", [dotnet_file]);
    let mod_path = ax.script_dir() + "dist/template." + ax.arch(id) + ".bin";

    ax.execute_alias(id, cmdline, `execute postex --file ${mod_path} --args ${mod_params}`, message);
});

let cmd_dotnet_fork = ax.create_command("template-fork", "", "", "Task: execute template postex");
cmd_dotnet_fork.addArgFlagString("--method", "method", false, "Method to use fork, choice 'explicit' need use fork_pid or 'spawn'");
cmd_dotnet_fork.addArgFlagString("--pid", "", false, "");
cmd_dotnet_fork.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let args = parsed_json["args"] || "";

    let mod_params = ax.bof_pack("wstr", [dotnet_file, args, app_domain, dotnet_version]);
    let mod_path = ax.script_dir() + "dist/template." + ax.arch(id) + ".bin";

    ax.execute_alias(id, cmdline, `execute postex --method ${method} --pid ${fork_pid} --file ${mod_path} --args ${mod_params}`, message);
});
