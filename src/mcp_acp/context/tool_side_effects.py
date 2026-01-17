"""Tool side effects mapping for policy decisions.

Manual mapping of known tool side effects. This allows writing policies
like "deny all tools with CODE_EXEC".

Side effect values match SideEffect enum in context/resource.py:
- Filesystem: fs_read, fs_write
- Database: db_read, db_write
- Network: network_egress, network_ingress
- Execution: code_exec, process_spawn, sudo_elevate
- Secrets: secrets_read, env_read, keychain_read
- System: clipboard_read, clipboard_write, browser_open
- Sensitive: screen_capture, audio_capture, camera_capture
- Cloud: cloud_api, container_exec
- Communication: email_send

Note: Unknown tools have no side effects listed (empty set).
This is conservative - unknown tools won't match side_effect rules.
"""

__all__ = ["TOOL_SIDE_EFFECTS"]

TOOL_SIDE_EFFECTS: dict[str, frozenset[str]] = {
    # Shell/code execution - most dangerous
    "bash": frozenset({"code_exec", "fs_write", "fs_read", "network_egress", "process_spawn"}),
    "shell": frozenset({"code_exec", "fs_write", "fs_read", "network_egress", "process_spawn"}),
    "execute": frozenset({"code_exec"}),
    "run_command": frozenset({"code_exec", "fs_write", "fs_read", "process_spawn"}),
    "exec": frozenset({"code_exec"}),
    "eval": frozenset({"code_exec"}),
    "spawn": frozenset({"process_spawn"}),
    "fork": frozenset({"process_spawn"}),
    "subprocess": frozenset({"process_spawn", "code_exec"}),
    # Privilege escalation
    "sudo": frozenset({"sudo_elevate", "code_exec"}),
    "run_as_admin": frozenset({"sudo_elevate", "code_exec"}),
    "elevate": frozenset({"sudo_elevate"}),
    # File system - read
    "read_file": frozenset({"fs_read"}),
    "get_file": frozenset({"fs_read"}),
    "cat": frozenset({"fs_read"}),
    "head": frozenset({"fs_read"}),
    "tail": frozenset({"fs_read"}),
    "list_directory": frozenset({"fs_read"}),
    "list_files": frozenset({"fs_read"}),
    "ls": frozenset({"fs_read"}),
    "find_files": frozenset({"fs_read"}),
    "search_files": frozenset({"fs_read"}),
    "glob": frozenset({"fs_read"}),
    # File system - write
    "write_file": frozenset({"fs_write"}),
    "create_file": frozenset({"fs_write"}),
    "edit_file": frozenset({"fs_read", "fs_write"}),
    "update_file": frozenset({"fs_read", "fs_write"}),
    "append_file": frozenset({"fs_write"}),
    "delete_file": frozenset({"fs_write"}),
    "remove_file": frozenset({"fs_write"}),
    "mkdir": frozenset({"fs_write"}),
    "rmdir": frozenset({"fs_write"}),
    "move_file": frozenset({"fs_read", "fs_write"}),
    "copy_file": frozenset({"fs_read", "fs_write"}),
    "rename_file": frozenset({"fs_write"}),
    # Network - outbound
    "fetch_url": frozenset({"network_egress"}),
    "http_request": frozenset({"network_egress"}),
    "http_get": frozenset({"network_egress"}),
    "http_post": frozenset({"network_egress"}),
    "curl": frozenset({"network_egress"}),
    "wget": frozenset({"network_egress"}),
    "download": frozenset({"network_egress", "fs_write"}),
    "upload": frozenset({"network_egress", "fs_read"}),
    # Network - inbound (servers)
    "start_server": frozenset({"network_ingress"}),
    "listen": frozenset({"network_ingress"}),
    "bind_port": frozenset({"network_ingress"}),
    # Database
    "query_db": frozenset({"db_read"}),
    "query_database": frozenset({"db_read"}),
    "sql_query": frozenset({"db_read"}),
    "select": frozenset({"db_read"}),
    "execute_sql": frozenset({"db_read", "db_write"}),
    "insert": frozenset({"db_write"}),
    "update": frozenset({"db_write"}),
    "delete": frozenset({"db_write"}),
    # Secrets and credentials
    "get_secret": frozenset({"secrets_read"}),
    "read_secret": frozenset({"secrets_read"}),
    "get_credential": frozenset({"secrets_read"}),
    # Environment variables
    "get_env": frozenset({"env_read"}),
    "read_env": frozenset({"env_read"}),
    "getenv": frozenset({"env_read"}),
    "environ": frozenset({"env_read"}),
    # Keychain/keyring
    "get_keychain": frozenset({"keychain_read"}),
    "read_keychain": frozenset({"keychain_read"}),
    "get_keyring": frozenset({"keychain_read"}),
    "get_password": frozenset({"keychain_read", "secrets_read"}),
    # Clipboard
    "get_clipboard": frozenset({"clipboard_read"}),
    "read_clipboard": frozenset({"clipboard_read"}),
    "pbpaste": frozenset({"clipboard_read"}),
    "set_clipboard": frozenset({"clipboard_write"}),
    "write_clipboard": frozenset({"clipboard_write"}),
    "pbcopy": frozenset({"clipboard_write"}),
    "copy_to_clipboard": frozenset({"clipboard_write"}),
    # Browser
    "open_url": frozenset({"browser_open"}),
    "open_browser": frozenset({"browser_open"}),
    "browse": frozenset({"browser_open"}),
    "webbrowser": frozenset({"browser_open"}),
    # Screen/audio/camera capture
    "screenshot": frozenset({"screen_capture"}),
    "screen_capture": frozenset({"screen_capture"}),
    "record_screen": frozenset({"screen_capture"}),
    "record_audio": frozenset({"audio_capture"}),
    "microphone": frozenset({"audio_capture"}),
    "record_video": frozenset({"camera_capture"}),
    "camera": frozenset({"camera_capture"}),
    "webcam": frozenset({"camera_capture"}),
    # Cloud APIs
    "aws": frozenset({"cloud_api", "network_egress"}),
    "gcloud": frozenset({"cloud_api", "network_egress"}),
    "azure": frozenset({"cloud_api", "network_egress"}),
    "s3": frozenset({"cloud_api", "network_egress"}),
    "boto3": frozenset({"cloud_api", "network_egress"}),
    # Containers
    "docker_exec": frozenset({"container_exec", "code_exec"}),
    "kubectl_exec": frozenset({"container_exec", "code_exec"}),
    "docker_run": frozenset({"container_exec", "code_exec", "process_spawn"}),
    # Email
    "send_email": frozenset({"email_send", "network_egress"}),
    "send_mail": frozenset({"email_send", "network_egress"}),
    "smtp_send": frozenset({"email_send", "network_egress"}),
}
