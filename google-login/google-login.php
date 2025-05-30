<?php
/**
 * Plugin Name: Google prijava za WordPress
 * Plugin URI: https://valentincic.eu
 * Description: Plugin za enostavno prijavo v WordPress preko Google računa. Omogoča prijavo z Google računom in blokira privzeto WordPress prijavo.
 * Version: 2.1.0
 * Author: Tjaž Valentinčič
 * Text Domain: google-login-wp
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

//DISABLE ADMIN BAR FOR SUBSCRIBERS

add_action('after_setup_theme', function() {
    if (current_user_can('subscriber')) {
        show_admin_bar(false);
    }
});

class GoogleLoginWP {
    // Store plugin options
    private $options;
    
    // Constructor
    public function __construct() {
        // Initialize the plugin
        add_action('plugins_loaded', array($this, 'init'));
        add_action('wp_logout', array($this, 'end_session'));
    }
    private function start_secure_session() {
    // Only start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            $secure = is_ssl();
            $httponly = true;
            
            session_set_cookie_params([
                'lifetime' => 0,                  
                'path' => COOKIEPATH,           
                'domain' => COOKIE_DOMAIN,    
                'secure' => $secure,
                'httponly' => $httponly,
                'samesite' => 'Lax'
            ]);
            session_start();
        }
    }
    public function end_session() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }
    
    public function init() {

        $this->options = get_option('google_login_wp_options', array(
            'client_id' => '',
            'client_secret' => '',
            'authorized_domains' => '',
            'redirect_after_login' => '/interno-gradivo/',
            'login_page' => '/login',
        ));
        
        add_action('admin_init', array($this, 'register_settings'));
        
        add_action('admin_menu', array($this, 'add_settings_page'));
        
        add_action('init', array($this, 'block_wp_login'));
        
        add_action('init', array($this, 'handle_google_login'));
        
        add_shortcode('google_login_button', array($this, 'login_button_shortcode'));
    }
    
    public function add_settings_page() {
        add_options_page(
            __('Google Login Settings', 'google-login-wp'),
            __('Google Login', 'google-login-wp'),
            'manage_options',
            'google-login-wp',
            array($this, 'settings_page_content')
        );
    }
    
    public function register_settings() {
        register_setting(
            'google_login_wp_options_group',
            'google_login_wp_options',
            array($this, 'sanitize_options')
        );
        
        add_settings_section(
            'google_login_wp_main_section',
            __('Google API Settings', 'google-login-wp'),
            array($this, 'settings_section_callback'),
            'google-login-wp'
        );
        
        add_settings_field(
            'client_id',
            __('Google Client ID', 'google-login-wp'),
            array($this, 'client_id_callback'),
            'google-login-wp',
            'google_login_wp_main_section'
        );
        
        add_settings_field(
            'client_secret',
            __('Google Client Secret', 'google-login-wp'),
            array($this, 'client_secret_callback'),
            'google-login-wp',
            'google_login_wp_main_section'
        );
        
        add_settings_field(
            'authorized_domains',
            __('Authorized Domains', 'google-login-wp'),
            array($this, 'authorized_domains_callback'),
            'google-login-wp',
            'google_login_wp_main_section'
        );
        
        add_settings_field(
            'login_page',
            __('Login Page URL', 'google-login-wp'),
            array($this, 'login_page_callback'),
            'google-login-wp',
            'google_login_wp_main_section'
        );
        
        add_settings_field(
            'redirect_after_login',
            __('Redirect After Login', 'google-login-wp'),
            array($this, 'redirect_after_login_callback'),
            'google-login-wp',
            'google_login_wp_main_section'
        );
    }
    
    // Sanitize options
    public function sanitize_options($input) {
        $new_input = array();
        $old_options = get_option('google_login_wp_options', array());

        if (isset($input['client_id'])) {
            $new_input['client_id'] = sanitize_text_field($input['client_id']);
        }

        if (isset($input['client_secret']) && !empty($input['client_secret'])) {
            $new_input['client_secret'] = sanitize_text_field($input['client_secret']);
        } elseif (isset($old_options['client_secret'])) {
            $new_input['client_secret'] = $old_options['client_secret'];
        }

        if (isset($input['authorized_domains'])) {
            $new_input['authorized_domains'] = sanitize_text_field($input['authorized_domains']);
        }

        if (isset($input['login_page'])) {
            $new_input['login_page'] = sanitize_text_field($input['login_page']);
            if (substr($new_input['login_page'], 0, 1) !== '/') {
                $new_input['login_page'] = '/' . $new_input['login_page'];
            }
        }

        if (isset($input['redirect_after_login'])) {
            $new_input['redirect_after_login'] = sanitize_text_field($input['redirect_after_login']);
            if (substr($new_input['redirect_after_login'], 0, 1) !== '/') {
                $new_input['redirect_after_login'] = '/' . $new_input['redirect_after_login'];
            }
        }

        return $new_input;
    }
    
    // Settings section callback
    public function settings_section_callback() {
        echo '<p>' . __('Configure your Google API credentials and settings.', 'google-login-wp') . '</p>';
        echo '<p>' . __('You need to create a project in the Google Developer Console and obtain OAuth 2.0 credentials.', 'google-login-wp') . '</p>';
        echo '<p>' . sprintf(__('Visit %s to create your credentials.', 'google-login-wp'), '<a href="https://console.developers.google.com/" target="_blank">Google Developer Console</a>') . '</p>';
        echo '<p>' . __('Required settings in Google Console:', 'google-login-wp') . '</p>';
        echo '<ul>';
        echo '<li>' . sprintf(__('Authorized JavaScript origins: %s', 'google-login-wp'), '<code>' . home_url() . '</code>') . '</li>';
        echo '<li>' . sprintf(__('Authorized redirect URIs: %s', 'google-login-wp'), '<code>' . home_url('google-login-callback') . '</code>') . '</li>';
        echo '</ul>';
    }
    
    // Client ID field callback
    public function client_id_callback() {
        printf(
            '<input type="text" id="client_id" name="google_login_wp_options[client_id]" value="%s" class="regular-text" required />',
            isset($this->options['client_id']) ? esc_attr($this->options['client_id']) : ''
        );
    }
    
    // Client Secret field callback
    public function client_secret_callback() {
        if (!empty($this->options['client_secret'])) {
            echo '<input type="password" id="client_secret" name="google_login_wp_options[client_secret]" value="" class="regular-text" autocomplete="new-password" />';
            echo '<p class="description">' . __('TO UPDATE CLIENT SECRET PASTE NEW TO THE FIELD', 'google-login-wp') . '</p>';
        } else {
            echo '<input type="password" id="client_secret" name="google_login_wp_options[client_secret]" value="" class="regular-text" required autocomplete="new-password" />';
        }
    }
    
    // Authorized domains field callback
    public function authorized_domains_callback() {
        printf(
            '<input type="text" id="authorized_domains" name="google_login_wp_options[authorized_domains]" value="%s" class="regular-text" />',
            isset($this->options['authorized_domains']) ? esc_attr($this->options['authorized_domains']) : ''
        );
        echo '<p class="description">' . __('Comma-separated list of email domains that are allowed to log in (e.g., "example.com,company.org").', 'google-login-wp') . '</p>';
    }
    
    // Login page field callback
    public function login_page_callback() {
        printf(
            '<input type="text" id="login_page" name="google_login_wp_options[login_page]" value="%s" class="regular-text" />',
            isset($this->options['login_page']) ? esc_attr($this->options['login_page']) : '/login'
        );
        echo '<p class="description">' . __('URL path to your custom login page where you\'ll place the Google login button.', 'google-login-wp') . '</p>';
    }
    
    // Redirect after login field callback
    public function redirect_after_login_callback() {
        printf(
            '<input type="text" id="redirect_after_login" name="google_login_wp_options[redirect_after_login]" value="%s" class="regular-text" />',
            isset($this->options['redirect_after_login']) ? esc_attr($this->options['redirect_after_login']) : '/interno-gradivo/'
        );
    }
    
    // Settings page content
    public function settings_page_content() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields('google_login_wp_options_group');
                do_settings_sections('google-login-wp');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
    
    // Block WordPress default login
    public function block_wp_login() {
        global $pagenow;
        
        if ($pagenow == 'wp-login.php' && !is_user_logged_in()) {
            // Allow access to logout action
            $allowed_actions = array('logout');
            $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';
            
            if (in_array($action, $allowed_actions)) {
                return;
            }
            
            // Redirect to custom login page
            $login_page = isset($this->options['login_page']) ? $this->options['login_page'] : '/login';
            wp_redirect(home_url($login_page));
            exit;
        }
    }
    
    // Google login button shortcode
    public function login_button_shortcode($atts) {
        // Start session if not already started
        $this->start_secure_session();

        // Show error if set by handle_google_login
        $error_html = '';
        if (!empty($_SESSION['google_login_error'])) {
            $error_html = '<div class="google-login-error">' . esc_html($_SESSION['google_login_error']) . '</div>';
            unset($_SESSION['google_login_error']);
        }

        // Check if user is already logged in
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            $logout_url = wp_logout_url(home_url('/'));
            
            // Custom greeting for specific users
            $custom_greeting = '';

            $logout_html = '
            <div class="google-login-container logged-in">
                ' . $custom_greeting . '
                <div class="user-info">
                    <span class="user-avatar">' . get_avatar($current_user->ID, 40) . '</span>
                    <span class="user-name">Prijavljeni ste kot: <strong>' . esc_html($current_user->display_name) . '</strong></span>
                </div>
                <a href="' . esc_url($logout_url) . '" class="google-logout-button">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                    ' . __('Odjava', 'google-login-wp') . '
                </a>
            </div>
            <style>
                .google-login-container.logged-in {
                    border-radius: 6px;
                    padding: 15px;
                    margin: 20px auto;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.07);
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    max-width: 350px;
                }
                .user-info {
                    display: flex;
                    align-items: center;
                    margin-bottom: 15px;
                    justify-content: center;
                }
                .user-avatar {
                    margin-right: 10px;
                }
                .user-avatar img {
                    border-radius: 50%;
                }
                .user-name {
                    font-size: 16px;
                    color: var(--e-global-color-primary, #333);
                }
                .google-logout-button {
                    display: inline-flex;
                    align-items: center;
                    color: var(--e-global-color-onprimary, #fff);
                    border-radius: 4px;
                    padding: 8px 15px;
                    font-size: 14px;
                    font-weight: 500;
                    box-shadow: 0 2px 4px 0 rgba(0,0,0,.15);
                    transition: all .2s ease;
                    text-decoration: none;
                    border: none;
                }
                .google-logout-button:hover {
                    background-color: var(--e-global-color-primary, #1565c0);
                    box-shadow: 0 0 3px 3px rgba(25,118,210,.12);
                    color: #ffffff !important;
                }
                .google-logout-button svg {
                    margin-right: 10px;
                }
                .google-login-greeting {
                    font-weight: bold;
                    color: var(--e-global-color-primary, #fff);
                    font-size: 16px;
                }
            </style>';

            return $error_html . $logout_html;
        }

        // If not logged in, show the login button
        $client_id = isset($this->options['client_id']) ? $this->options['client_id'] : '';

        if (empty($client_id)) {
            return $error_html . '<div class="google-login-error">' . __('Google Login is not properly configured.', 'google-login-wp') . '</div>';
        }

        // Get current URL for state parameter to prevent CSRF
        $state = wp_create_nonce('google_login_state');

        // Store state in session
        $_SESSION['google_login_state'] = $state;

        // Generate login URL
        $login_url = $this->get_google_login_url($state);

        // Button HTML
        $button_html = '
        <div class="google-login-container">
            <a href="' . esc_url($login_url) . '" class="google-login-button">
                <svg width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">
                    <path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"/>
                    <path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z"/>
                    <path fill="#FBBC05" d="M11.69 28.18C11.25 26.86 11 25.45 11 24s.25-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24c0 3.55.85 6.91 2.34 9.88l7.35-5.7z"/>
                    <path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z"/>
                </svg>
                ' . __('Prijava z Google računom', 'google-login-wp') . '
            </a>
        </div>
        <style>
            .google-login-container {
                margin: 20px 0;
                text-align: center;
            }
            .google-login-button {
                display: inline-flex;
                align-items: center;
                background-color: #fff;
                color: #757575;
                border-radius: 4px;
                padding: 10px 15px;
                font-size: 14px;
                font-weight: 500;
                box-shadow: 0 2px 4px 0 rgba(0,0,0,.25);
                transition: all .2s ease;
                text-decoration: none;
            }
            .google-login-button:hover {
                box-shadow: 0 0 3px 3px rgba(66,133,244,.3);
                background-color: #f8f8f8;
            }
            .google-login-button svg {
                margin-right: 10px;
            }
            .google-login-error {
                color: #d94f4f;
                padding: 10px;
                background-color: #ffebee;
                border-radius: 4px;
                text-align: center;
            }
        </style>';

        return $error_html . $button_html;
    }
    
    // Get Google login URL
    private function get_google_login_url($state) {
        $client_id = isset($this->options['client_id']) ? $this->options['client_id'] : '';
        
        $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth';
        $redirect_uri = home_url('google-login-callback');
        
        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'email profile',
            'state' => $state,
            'prompt' => 'select_account',
        );
        
        return $auth_url . '?' . http_build_query($params);
    }
    
    // Handle Google login callback
    public function handle_google_login() {
        if (!isset($_GET['code']) || !isset($_SERVER['REQUEST_URI'])) {
            return;
        }
        
        if (strpos($_SERVER['REQUEST_URI'], 'google-login-callback') === false) {
            return;
        }
        
        // Verify state to prevent CSRF
        if (!session_id()) {
            session_start();
        }
        // Error handling: collect errors to display on /login page via shortcode
        $error = '';

        if (!isset($_GET['state']) || !isset($_SESSION['google_login_state']) || $_GET['state'] !== $_SESSION['google_login_state']) {
            $error = __('Invalid login attempt. Please try again.', 'google-login-wp');
        }

        // Clear session state
        unset($_SESSION['google_login_state']);

        if (empty($error)) {
            // Exchange code for access token
            $token_data = $this->get_google_token($_GET['code']);

            if (!$token_data || isset($token_data['error'])) {
            $error = __('Error connecting to Google. Please try again later.', 'google-login-wp');
            }
        }

        if (empty($error)) {
            // Get user info using access token
            $user_data = $this->get_google_user_data($token_data['access_token']);

            if (!$user_data || isset($user_data['error'])) {
            $error = __('Error retrieving user information from Google.', 'google-login-wp');
            }
        }

        if (empty($error)) {
            // Check if user's email domain is allowed
            if (!$this->is_domain_allowed($user_data['email'])) {
            $error = __('Your email domain is not authorized to log in.', 'google-login-wp');
            }
        }

        if (empty($error)) {
            // Process user login or registration
            $user_id = $this->process_user($user_data);

            if (is_wp_error($user_id)) {
            $error = $user_id->get_error_message();
            }
        }

        if (!empty($error)) {
            // Store error in session and redirect to login page
            $_SESSION['google_login_error'] = $error;
            $login_page = isset($this->options['login_page']) ? $this->options['login_page'] : '/login';
            wp_redirect(home_url($login_page));
            exit;
        }
        
        // Log the user in
        wp_set_auth_cookie($user_id, true);
        
        // Redirect after login
        $redirect_url = isset($this->options['redirect_after_login']) ? $this->options['redirect_after_login'] : '/interno-gradivo/';
        wp_redirect(home_url($redirect_url));
        exit;
    }
    
    // Get token from Google using auth code
    private function get_google_token($code) {
        $client_id = isset($this->options['client_id']) ? $this->options['client_id'] : '';
        $client_secret = isset($this->options['client_secret']) ? $this->options['client_secret'] : '';
        
        $token_url = 'https://oauth2.googleapis.com/token';
        $redirect_uri = home_url('google-login-callback');
        
        $body = array(
            'code' => $code,
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'redirect_uri' => $redirect_uri,
            'grant_type' => 'authorization_code',
        );
        
        $response = wp_remote_post($token_url, array(
            'body' => $body,
            'timeout' => 15,
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        return json_decode(wp_remote_retrieve_body($response), true);
    }
    
    // Get user data from Google
    private function get_google_user_data($access_token) {
        $user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
        
        $response = wp_remote_get($user_info_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
            ),
            'timeout' => 15,
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        return json_decode(wp_remote_retrieve_body($response), true);
    }
    
    // Check if email domain is allowed
    private function is_domain_allowed($email) {
        $authorized_domains = isset($this->options['authorized_domains']) ? $this->options['authorized_domains'] : '';
        
        if (empty($authorized_domains)) {
            return true;
        }
        
        $email_parts = explode('@', $email);
        if (count($email_parts) !== 2) {
            return false;
        }
        
        $user_domain = $email_parts[1];
        $allowed_domains = array_map('trim', explode(',', $authorized_domains));
        
        return in_array($user_domain, $allowed_domains);
    }
    
    // Process user login/registration
    private function process_user($user_data) {
        if (!isset($user_data['email']) || empty($user_data['email'])) {
            return new WP_Error('missing_email', __('Email address is required from Google login.', 'google-login-wp'));
        }
        
        // Check if user exists
        $user = get_user_by('email', $user_data['email']);
        
        if ($user) {
            // User exists, update their name if needed
            $user_id = $user->ID;
            
            $update_data = array(
                'ID' => $user_id,
            );
            
            if (isset($user_data['given_name']) && isset($user_data['family_name'])) {
                $update_data['first_name'] = $user_data['given_name'];
                $update_data['last_name'] = $user_data['family_name'];
                $update_data['display_name'] = $user_data['given_name'] . ' ' . $user_data['family_name'];
            }
            
            if (count($update_data) > 1) {
                wp_update_user($update_data);
            }
            
            return $user_id;
        } else {
            // Create new user
            $email_parts = explode('@', $user_data['email']);
            $username = $email_parts[0];
            
            // Make sure username is unique
            $username = $this->generate_unique_username($username);
            
            // Create user data
            $user_data_arr = array(
                'user_login' => $username,
                'user_email' => $user_data['email'],
                'user_pass' => wp_generate_password(),
                'role' => 'subscriber',
            );
            
            // Add name info if available
            if (isset($user_data['given_name'])) {
                $user_data_arr['first_name'] = $user_data['given_name'];
            }
            
            if (isset($user_data['family_name'])) {
                $user_data_arr['last_name'] = $user_data['family_name'];
            }
            
            if (isset($user_data['given_name']) && isset($user_data['family_name'])) {
                $user_data_arr['display_name'] = $user_data['given_name'] . ' ' . $user_data['family_name'];
            }
            
            // Insert user
            $user_id = wp_insert_user($user_data_arr);
            
            if (is_wp_error($user_id)) {
                return $user_id;
            }
            
            // Store Google profile data in user meta
            update_user_meta($user_id, 'google_login_id', sanitize_text_field($user_data['sub']));
            
            return $user_id;
        }
    }
    
    // Generate unique username
    private function generate_unique_username($username) {
        $original_username = $username;
        $count = 1;
        
        while (username_exists($username)) {
            $username = $original_username . $count;
            $count++;
        }
        
        return $username;
    }
}



// Initialize the plugin
$google_login_wp = new GoogleLoginWP();

// Add rewrite rule for the login callback
function google_login_wp_add_rewrite_rules() {
    add_rewrite_rule('^google-login-callback/?', 'index.php?google_login_callback=1', 'top');
}
add_action('init', 'google_login_wp_add_rewrite_rules');

// Add query var for the login callback
function google_login_wp_query_vars($vars) {
    $vars[] = 'google_login_callback';
    return $vars;
}
add_filter('query_vars', 'google_login_wp_query_vars');




/**
 * Additional setup required:
 * 
 * 1. Create a WordPress page at /login where you'll place the shortcode [google_login_button]
 * 2. Set up your Google OAuth credentials at https://console.developers.google.com/
 * 3. Configure the plugin settings with your Client ID and Client Secret
 * 4. Set the authorized redirect URI to yourdomain.com/google-login-callback in Google Console
 * 5. After activating the plugin, go to Settings > Permalinks and click Save to flush rewrite rules
 */