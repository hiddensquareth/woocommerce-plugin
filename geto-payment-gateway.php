<?php
/*
Plugin Name: WooCommerce GETO Gateway
Plugin URI: https://geto.app
Description: Extends WooCommerce with a GETO payment gateway.
Version: 1.0
Author: GETO
Author URI: https://geto.app
Text Domain: geto-payment-gateway
Domain Path: /languages
Requires at least: 5.0
Requires PHP: 7.2
WC requires at least: 3.0
WC tested up to: 8.0
License: GNU General Public License v3.0
License URI: http://www.gnu.org/licenses/gpl-3.0.html
*/

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('GETO_PAYMENT_VERSION', '1.0.0');
define('GETO_PAYMENT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('GETO_PAYMENT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('GETO_PAYMENT_TEXT_DOMAIN', 'geto-payment-gateway');

// Check if WooCommerce is active
function geto_payment_woocommerce_missing_notice() {
    echo '<div class="error"><p><strong>' . 
        sprintf(
            __('GETO Payment Gateway requires WooCommerce to be installed and active. You can download %s here.', 'geto-payment-gateway'),
            '<a href="https://woocommerce.com/" target="_blank">WooCommerce</a>'
        ) . 
        '</strong></p></div>';
}

// Initialize the gateway
add_action('plugins_loaded', 'geto_init', 0);
function geto_init() {
    // Check if WooCommerce is active
    if (!class_exists('WC_Payment_Gateway')) {
        add_action('admin_notices', 'geto_payment_woocommerce_missing_notice');
        return;
    }
    
    include_once('geto-client.php');
    include_once('geto-callback.php');

    // Load plugin text domain
    load_plugin_textdomain('geto-payment-gateway', false, dirname(plugin_basename(__FILE__)) . '/languages');
    
    // Add the gateway to WooCommerce
    function woocommerce_add_geto_gateway($methods) {
        $methods[] = 'Geto_Client';
        return $methods;
    }
    
    add_filter('woocommerce_payment_gateways', 'woocommerce_add_geto_gateway');
    add_action('template_redirect', 'callback_handler');

}

// Register activation hook
register_activation_hook(__FILE__, 'geto_payment_activation_check');
function geto_payment_activation_check() {
    if (!class_exists('WooCommerce')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(__('Sorry, but this plugin requires WooCommerce to be installed and active.', 'geto-payment-gateway'));
    }
}
