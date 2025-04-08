<?php
/**
 * GETO Payment Gateway
 *
 * Provides a GETO Payment Gateway for WooCommerce.
 *
 * @class    Geto_Client
 * @package  WooCommerce/Classes/Payment
 * @version  1.0.
 */

defined('ABSPATH') || exit;

class Geto_Client extends WC_Payment_Gateway {

	private $logger;
	function __construct() {
		// global ID
		$this->id = 'geto_payment';
		$this->icon = apply_filters('woocommerce_geto_icon', '');
		$this->has_fields = true;
		$this->method_title = __( "GETO", 'geto-payment-gateway' );

		// Show Description
		$this->method_description = __( "GETO Payment Gateway Plug-in for WooCommerce", 'geto-payment-gateway' );

		// vertical tab title
		$this->title = __( "GETO", 'geto-payment-gateway' );

		$this->supports = array( 'products' );
		// setting defines
		$this->init_form_fields();

		// load time variable setting
		$this->init_settings();
		
		// Turn these settings into variables we can use
		foreach ( $this->settings as $setting_key => $value ) {
			$this->$setting_key = $value;
		}
		
		// further check of SSL if you want
		add_action( 'admin_notices', array( $this,	'do_ssl_check' ) );
		
		// Save settings
		if ( is_admin() ) {
			add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
		}

        // Register webhook handler
        add_action('woocommerce_api_geto_webhook', array($this, 'webhook_handler'));

        // Register callack handler
        add_action('template_redirect', array($this, 'callback_handler'));
        
        // Initialize logger and log initialization
        $this->logger = wc_get_logger();
        $this->log_message('GETO Payment Gateway initialized');
	} // End __construct()

	/**
	 * Log message to WooCommerce log if debug is enabled
	 *
	 * @param string $message
	 */
	private function log_message($message) {
        $message = '[GETO LOG] ' . $message;
        if (empty($this->logger)) {
            $this->logger = wc_get_logger();
        }
        $this->logger->debug($message, array('source' => 'geto-payment'));

         // Also output to terminal
        error_log($message); // <- This shows up in terminal with php -S
	}
    
    /**
     * Process admin options and sanitize inputs
     */
    public function process_admin_options() {
        // Check the nonce
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'woocommerce-settings')) {
            wp_die(__('Security check failed. Please refresh the page and try again.', 'geto-payment-gateway'));
        }

        // Sanitize all input fields
        if (isset($_POST[$this->get_field_key('account_key')])) {
            $_POST[$this->get_field_key('account_key')] = sanitize_text_field($_POST[$this->get_field_key('account_key')]);
        }
        if (isset($_POST[$this->get_field_key('account_key_test')])) {
            $_POST[$this->get_field_key('account_key_test')] = sanitize_text_field($_POST[$this->get_field_key('account_key_test')]);
        }
        if (isset($_POST[$this->get_field_key('api_key')])) {
            $_POST[$this->get_field_key('api_key')] = sanitize_text_field($_POST[$this->get_field_key('api_key')]);
        }
        if (isset($_POST[$this->get_field_key('api_key_test')])) {
            $_POST[$this->get_field_key('api_key_test')] = sanitize_text_field($_POST[$this->get_field_key('api_key_test')]);
        }

        $result = parent::process_admin_options();

        $v = $this->validate_field_required('title', 'Title');
        $v = $this->validate_field_required('description', 'Description') && $v;
        $v = $this->validate_field_required('currency', 'Currency') && $v;
        $v = $this->validate_field_required('account_key', 'Account Key') && $v;
        $v = $this->validate_field_required('api_key', 'API Key') && $v;
        $v = $this->validate_field_required('webhook_secret', 'Webhook Secret') && $v;
        $v = $this->validate_field_required('webhook_url', 'Webhook URL') && $v;

        if (!$v) {
            return false;
        }

        foreach ( $this->settings as $setting_key => $value ) {
			$this->$setting_key = $value;
		}

        $api_key = $this->get_option('api_key');

        // After saving settings, register webhook if enabled
        if ('yes' === $this->get_option('enabled')) {
            $this->log_message('Registering webhook after saving settings');
            $this->register_webhook();
        }

        return $result;
	}

    private function validate_field_required($field, $field_desc) {
        $value = $this->get_option($field);
        if (empty($value)) {
            WC_Admin_Settings::add_error("{$field_desc} is required.");
            return false;
        }
        return true;
    }

	/**
	 * Administration fields for specific Gateway
	 */
	public function init_form_fields() {
		$this->form_fields = array(
			'enabled' => array(
				'title'		=> __( 'Enable / Disable', 'geto-payment-gateway' ),
				'label'		=> __( 'Enable this payment gateway', 'geto-payment-gateway' ),
				'type'		=> 'checkbox',
				'default'	=> 'no',
			),
            'test_mode' => array(
				'title'		=> __( 'GETO Test Mode', 'geto-payment-gateway' ),
				'label'		=> __( 'Enable Test Mode', 'geto-payment-gateway' ),
				'type'		=> 'checkbox',
				'description' => __( 'This is the test mode of gateway.', 'geto-payment-gateway' ),
				'default'	=> 'no',
			),
			'title' => array(
				'title'		=> __( 'Title', 'geto-payment-gateway' ),
				'type'		=> 'text',
				'desc_tip'	=> __( 'Payment title of checkout process.', 'geto-payment-gateway' ),
				'default'	=> __( 'GETO', 'geto-payment-gateway' ),
			),
			'description' => array(
				'title'		=> __( 'Description', 'geto-payment-gateway' ),
				'type'		=> 'textarea',
				'desc_tip'	=> __( 'Payment title of checkout process.', 'geto-payment-gateway' ),
				'default'	=> __( 'Proceed with GETO.', 'geto-payment-gateway' ),
				'css'		=> 'max-width:450px;'
			),
            'currency' => array(
                'title'     => __( 'Currency Code', 'geto-payment-gateway' ),
                'type'      => 'select',
                'desc_tip'  => __( 'Choose the currency for this gateway.', 'geto-payment-gateway' ),
                'options'   => get_woocommerce_currencies(), // Built-in WooCommerce currency list
                'default'   => get_woocommerce_currency(),   // Use store default
            ),
            'account_key' => array(
				'title'		=> __( 'Account Key', 'geto-payment-gateway' ),
				'type'		=> 'text',
				'desc_tip'	=> __( 'Account Key from GETO Account', 'geto-payment-gateway' ),
			),
            'api_key' => array(
				'title'		=> __( 'API Key', 'geto-payment-gateway' ),
				'type'		=> 'text',
				'desc_tip'	=> __( 'API Key from GETO Account', 'geto-payment-gateway' ),
			),
            'webhook_secret' => array(
                'title'     => __( 'Webhook Secret', 'geto-payment-gateway' ),
                'type'      => 'text',
                'desc_tip'  => __( 'Secret key for verifying webhook signatures. Keep this secret!', 'geto-payment-gateway' ),
                'description' => __( 'Generate a random string and enter it here. This will be used to verify webhook signatures.', 'geto-payment-gateway' ),
                'default' => wp_generate_uuid4() 
            ),
            'webhook_url' => array(
                'title'     => __( 'Webhook URL', 'geto-payment-gateway' ),
                'type'      => 'text',
                'desc_tip'  => __( 'URL to provide to GETO for webhook notifications.', 'geto-payment-gateway' ),
                'default'   => home_url( '?wc-api=geto_webhook' ),
                // 'custom_attributes' => array('readonly' => 'readonly'),
            ),
            'webhook_registration_status' => [
                'title'       => __('Webhook Status', 'geto-payment-gateway'),
                'type'        => 'textarea',
                'description' => __('The current status of the webhook registration.'),
                'default'     => '{ "message": "Not Registered" }',
                'custom_attributes' => [
                    'readonly' => 'readonly',
                    'rows'     => 5
                ]
            ]
		);		
	}
	
	// Response handled for payment gateway
	public function process_payment( $order_id ) {
		global $woocommerce;

		$customer_order = new WC_Order( $order_id );
		
		$is_test_mode = ($this->test_mode == "yes");

        if ($is_test_mode) {
            $base_url = "https://test-api.geto.app";
        } else {
            $base_url = "https://api.geto.app";
        }
        $api_key = $this->api_key;
        $account_key = $this->account_key;

		// Log payment attempt
		$this->log_message('Processing payment for order ' . $order_id);

		// Prepare payment payload with sanitized data
		$payload = array(
            'amount' => $customer_order->get_total() * 100,
            'currency' => sanitize_text_field($this->currency),
            'accountKey' => sanitize_text_field($account_key),
            'paymentDescription' => sanitize_text_field($this->get_payment_description($customer_order)),
            'customer'=> array(
                'id'=> intval($customer_order->get_user_id()),
                'email'=> sanitize_email($customer_order->get_billing_email()),
                'name'=> sanitize_text_field($customer_order->get_billing_first_name() . ' ' . $customer_order->get_billing_last_name()),
                'phone'=> sanitize_text_field($customer_order->get_billing_phone()),
            ),
            'merchantRef'=> sanitize_text_field($customer_order->get_order_number()),
            'returnUrl'=> esc_url_raw($customer_order->get_checkout_order_received_url()),
            'metadata'=> array(
                'ipAddress' => sanitize_text_field($_SERVER['REMOTE_ADDR']),
                'WooCommerceGetoPluginVersion' => GETO_PAYMENT_VERSION
            )
		);

        try {
            // Get access token for API authentication
            $access_token = $this->get_access_token(
                $base_url, 
                $api_key, 
                $account_key
            );

            if (empty($access_token)) {
                $this->log_message('Failed to get access token for order ' . $order_id);
                throw new Exception(__('Authentication with payment gateway failed. Please try again or contact site administrator.', 'geto-payment-gateway'));
            }
	
            // Log the API request
            $this->log_message('Sending payment request to GETO API: ' . wp_json_encode($payload));

            // Send this payload to GETO API for processing
            $response = wp_remote_post( "$base_url/v2/payments/init", array(
                'headers'   => array(
                    'Content-Type' => 'application/json',
                    'Accept'  => 'application/json',
                    'Authorization' => "Bearer $access_token",
                ),
                'body'      => wp_json_encode($payload),
                'timeout'   => 90,
                'sslverify' => true,
            ));

            // Check for WP error
            if (is_wp_error($response)) {
                $error_message = $response->get_error_message();
                $this->log_message('WP Error during payment init: ' . $error_message);
                throw new Exception(__('Connection to payment gateway failed: ', 'geto-payment-gateway') . $error_message);
            }

            // Check HTTP response code
            $http_code = wp_remote_retrieve_response_code($response);
            if ($http_code !== 200) {
                $this->log_message('HTTP Error during payment init. Code: ' . $http_code);
                throw new Exception(__('Payment gateway returned an error: HTTP ', 'geto-payment-gateway') . $http_code);
            }

            // Check for empty response
            $response_body = wp_remote_retrieve_body($response);
            if (empty($response_body)) {
                $this->log_message('Empty response from payment gateway');
                throw new Exception(__('Empty response from payment gateway.', 'geto-payment-gateway'));
            }

            // Decode JSON response
            $data = json_decode($response_body, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->log_message('Invalid JSON response: ' . json_last_error_msg());
                throw new Exception(__('Invalid response from payment gateway.', 'geto-payment-gateway'));
            }

            
            // Validate response data
            if (!isset($data['payment']['paymentKey']) || !isset($data['url'])) {
                $this->log_message('Missing required fields in API response: ' . wp_json_encode($data));
                throw new Exception(__('Invalid response from payment gateway: missing required data.', 'geto-payment-gateway'));
            }

            $payment_key = $data['payment']['paymentKey'];
            $return_url = $data['url'];

            // Update order meta with paymentKey for future reference
            $customer_order->update_meta_data('_geto_payment_key',$payment_key);
            $customer_order->save();

            // Add order note
            $customer_order->add_order_note(
                sprintf(__('GETO Payment initiated. Payment Key: %s', 'geto-payment-gateway'), 
                $payment_key)
            );

            // Mark as pending
            $customer_order->update_status('pending', __('Awaiting GETO payment', 'geto-payment-gateway'));

            // Empty cart
            $woocommerce->cart->empty_cart();

            // Log success
            $this->log_message('Payment initialization successful. Redirecting to: ' . $return_url);

            // Return success with redirect URL
            return array(
                'result'   => 'success',
                'redirect' => $return_url,
            );

        } catch (Exception $e) {
            // Log the error
            $this->log_message('Error in process_payment: ' . $e->getMessage());
            
            // Mark order as failed
            $customer_order->update_status('failed', $e->getMessage());
            
            // Display error to customer
            wc_add_notice(__('Payment error:', 'geto-payment-gateway') . ' ' . $e->getMessage(), 'error');
            
            return array(
                'result' => 'failure',
                'redirect' => '',
            );
        }

	}

    private function get_payment_description($order) {
        $items = $order->get_items();
        $item_count = count( $items );
        
        if ( $item_count > 0 ) {
            $first_item = reset( $items );
            $product = $first_item->get_product();
            $product_name = $product ? $product->get_name() : '-';
        
            if ( $item_count === 1 ) {
                $message = "$product_name";
            } else {
                $message = "$product_name and more...";
            }
        } else {
            $message = "-";
        }
        
        return $message;
    }
	
	// Validate fields
	public function validate_fields() {
		return true;
	}

    /**
     * Display payment fields on checkout
     * Display payment fields on checkout
     */
    public function payment_fields() {
        // Show description if set
        if ($this->description) {
            echo wpautop(wptexturize($this->description));
        }
        
        // Add payment fields
        if ($this->supports('default_credit_card_form')) {
            $this->credit_card_form();
        }
    }
	public function do_ssl_check() {
		if( $this->enabled == "yes" ) {
			if( get_option( 'woocommerce_force_ssl_checkout' ) == "no" ) {
				echo "<div class=\"error\"><p>". sprintf( __( "<strong>%s</strong> is enabled and WooCommerce is not forcing the SSL certificate on your checkout page. Please ensure that you have a valid SSL certificate and that you are <a href=\"%s\">forcing the checkout pages to be secured.</a>" ), $this->method_title, admin_url( 'admin.php?page=wc-settings&tab=checkout' ) ) ."</p></div>";	
			}
		}		
	}

    /**
     * Get access token from GETO API
     *
     * @param string $base_url API base URL
     * @param string $api_key API key
     * @param string $account_key Account key
     * @return string Access token
     * @throws Exception If authentication fails
     */
    public function get_access_token( $base_url, $api_key, $account_key ) {
        // Log token request
        $this->log_message('Requesting access token from GETO API');
        
        // Format request body properly as JSON
        $request_body = array(
            'accountKey' => sanitize_text_field($account_key)
        );
        
        $response = wp_remote_post( "$base_url/v2/accounts/token", array(
            'method'    => 'POST',
            'headers'   => array(
                'Content-Type'  => 'application/json',
                'Accept'  => 'application/json',
                'api-key' => sanitize_text_field($api_key),
            ),
            'body'      => wp_json_encode($request_body),
            'timeout'   => 90,
            'sslverify' => true,
        ));

        // Check for WP errors
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            $this->log_message('WP Error during token request: ' . $error_message);
            throw new Exception(__('Connection to payment gateway failed: ', 'geto-payment-gateway') . $error_message);
        }

        // Check HTTP response code
        $http_code = wp_remote_retrieve_response_code($response);
        if ($http_code !== 200) {
            $this->log_message('HTTP Error during token request. Code: ' . $http_code);
            throw new Exception(__('Authentication failed: HTTP ', 'geto-payment-gateway') . $http_code);
        }

        // Check for empty response
        $response_body = wp_remote_retrieve_body($response);
        if (empty($response_body)) {
            $this->log_message('Empty response from token endpoint');
            throw new Exception(__('Empty response from payment gateway during authentication.', 'geto-payment-gateway'));
        }

        // Decode JSON response
        $data = json_decode($response_body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->log_message('Invalid JSON in token response: ' . json_last_error_msg());
            throw new Exception(__('Invalid response from payment gateway during authentication.', 'geto-payment-gateway'));
        }

        // Validate token in response
        if (!isset($data['token']) || empty($data['token'])) {
            $this->log_message('Token missing from response: ' . wp_json_encode($data));
            throw new Exception(__('Authentication failed: Token not provided by gateway.', 'geto-payment-gateway'));
        }

        $this->log_message('Successfully obtained access token');
        return $data['token'];
    }

    /**
     * Register webhook with GETO API
     */
    public function register_webhook() {
        // Don't register if plugin is not enabled
        if ($this->enabled !== 'yes') {
            return;
        }

        // Don't register if url and secret are not set
        if (empty($this->webhook_url) || empty($this->webhook_secret)) {
            $this->log_message('Skipped webhook registration due to missing webhook_url or webhook_secret');
            return;
        }

        // Get API credentials based on mode
        $is_test_mode = ($this->test_mode == "yes");
        
        if ($is_test_mode) {
            $base_url = "https://test-api.geto.app";
        } else {
            $base_url = "https://api.geto.app";
        }

        $api_key = $this->api_key;
        $account_key = $this->account_key;

        // Skip if credentials are missing
        if (empty($api_key) || empty($account_key)) {
            $this->log_message('Cannot register webhook - missing API credentials');
            return;
        }

        try {
            // Get access token
            $access_token = $this->get_access_token($base_url, $api_key, $account_key);
            
            // Prepare webhook data
            $webhook_data = array(
                'accountKey' => $account_key,
                'url' => $this->webhook_url,
                'secret' => $this->webhook_secret,
            );

            // Register webhook with GETO API
            $response = wp_remote_post("$base_url/v2/accounts/webhook", array(
                'method' => 'POST',
                'headers' => array(
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'Authorization' => "Bearer $access_token"
                ),
                'body' => wp_json_encode($webhook_data),
                'timeout' => 30,
                'sslverify' => true
            ));

            // Check for errors
            if (is_wp_error($response)) {
                $this->log_message('Error registering webhook: ' . $response->get_error_message());
                $this->settings['webhook_registration_status'] = json_encode(array('message' => $response->get_error_message()));
                update_option( $this->get_option_key(), $this->settings );
                return;
            }

            $http_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            // Log response
            if ($http_code >= 200 && $http_code < 300) {
                $this->log_message('Webhook registered successfully');
                $this->settings['webhook_registration_status'] = $response_body;
            } else {
                $this->log_message('Failed to register webhook. Response: ' . $response_body);
                $this->settings['webhook_registration_status'] = $response_body;
            }

            update_option( $this->get_option_key(), $this->settings );

        } catch (Exception $e) {
            $this->log_message('Exception while registering webhook: ' . $e->getMessage());
            $this->settings['webhook_registration_status'] = json_encode(array('message' => $e->getMessage()));
            update_option( $this->get_option_key(), $this->settings );
        }
    }

    /**
     * Verify webhook signature
     *
     * @param string $payload The raw webhook payload
     * @param string $signature The signature header from the request
     * @return bool Whether the signature is valid
     */
    private function verify_webhook_signature($payload, $secret) {
        // If no webhook secret is set, skip verification
        if (empty($this->webhook_secret)) {
            $this->log_message('Warning: Webhook secret not configured - skipping signature verification');
            return true;
        }

        return $this->webhook_secret == $secret;

        // // Calculate expected signature
        // $expected_signature = hash_hmac('sha256', $payload, $this->webhook_secret);

        // // Compare signatures using hash_equals to prevent timing attacks
        // return hash_equals($expected_signature, $signature);
    }

    /**
     * Process webhook notifications from GETO
     * 
     * Handles callbacks from the payment gateway for asynchronous payment notifications
     */
    public function webhook_handler() {
        // Verify the request
        $request_body = file_get_contents('php://input');
        $secret = isset($_SERVER['HTTP_X_NOTIFY_SECRET']) ? $_SERVER['HTTP_X_NOTIFY_SECRET'] : '';

        if (empty($request_body)) {
            $this->log_message('Invalid webhook: Missing payload');
            status_header(400);
            exit('Invalid webhook - missing payload');
        }
        
        // Log the incoming webhook
        $this->log_message('Webhook received: ' . $request_body);
        
        if (!$this->verify_webhook_signature($request_body, $secret)) {
            $this->log_message('Invalid webhook: Secret verification failed');
            status_header(401);
            exit('Invalid signature');
        }
        
        // Parse the JSON payload
        $data = json_decode($request_body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->log_message('Invalid webhook: Invalid JSON payload');
            status_header(400);
            exit('Invalid JSON');
        }
        
        // Verify required fields
        if (!isset($data['paymentKey']) || !isset($data['status'])) {
            $this->log_message('Invalid webhook: Missing required fields');
            status_header(400);
            exit('Missing required fields');
        }
        
        // Find the order by payment key
        $orders = wc_get_orders(array(
            'meta_key' => '_geto_payment_key',
            'meta_value' => $data['paymentKey'],
            'limit' => 1,
        ));
        
        if (empty($orders)) {
            $this->log_message('Webhook: Order not found for payment key ' . $data['paymentKey']);
            status_header(404);
            exit('Order not found');
        }
        
        $order = reset($orders);
        
        // Process based on status
        switch ($data['status']) {
            case 'complete':
                // Payment successful
                if ($order->needs_payment()) {
                    $order->payment_complete($data['paymentKey']);
                    $order->add_order_note(__('Payment completed via GETO webhook', 'geto-payment-gateway'));
                    $this->log_message('Payment completed for order #' . $order->get_id());
                } else {
                    $this->log_message('Order #' . $order->get_id() . ' already paid or completed');
                }
                
                // Return success response
                status_header(200);
                echo json_encode(array('success' => true, 'message' => 'Payment completed'));
                exit;
                
            case 'pending_customer':
                // Payment is pending
                if ($order->has_status('failed')) {
                    // If the order was previously failed, move it back to pending
                    $order->update_status('pending', __('Payment pending via GETO webhook', 'geto-payment-gateway'));
                } else if (!$order->has_status('pending')) {
                    // Only update if not already pending
                    $order->update_status('pending', __('Payment pending via GETO webhook', 'geto-payment-gateway'));
                }
                
                $this->log_message('Payment pending for order #' . $order->get_id());
                
                // Return success response
                status_header(200);
                echo json_encode(array('success' => true, 'message' => 'Payment pending'));
                exit;
                
            case 'cancelled':
                // Payment was cancelled
                if (!$order->has_status('cancelled')) {
                    $order->update_status('cancelled', __('Payment cancelled via GETO webhook', 'geto-payment-gateway'));
                    $this->log_message('Payment cancelled for order #' . $order->get_id());
                    
                    // Optional: Handle inventory, increase stock, etc.
                    // wc_increase_stock_levels($order_id);
                }
                
                // Return success response
                status_header(200);
                echo json_encode(array('success' => true, 'message' => 'Payment cancellation recorded'));
                exit;

            default:
                // Payment failed
                if (!$order->has_status('failed')) {
                    $order->update_status('failed', __('Payment failed via GETO webhook', 'geto-payment-gateway'));
                    
                    // Add details about the failure if available
                    if (isset($data['failureReason'])) {
                        $order->add_order_note(sprintf(
                            __('Payment failed reason: %s', 'geto-payment-gateway'),
                            sanitize_text_field($data['failureReason'])
                        ));
                    }
                    
                    $this->log_message('Payment failed for order #' . $order->get_id());
                    
                    // If this was a customer-initiated failure, possibly notify the customer
                    if (isset($data['failureType']) && $data['failureType'] === 'customer_initiated') {
                        // Optional: Send email notification to customer
                        // WC()->mailer()->get_emails()['WC_Email_Failed_Order']->trigger($order->get_id());
                    }
                }
                
                // Return success response
                status_header(200);
                echo json_encode(array('success' => true, 'message' => 'Payment failure recorded'));
                exit;
                
            // default:
            //     // Unknown status
            //     $this->log_message('Received unknown payment status: ' . $data['status'] . ' for order #' . $order->get_id());
            //     $order->add_order_note(sprintf(
            //         __('Received unknown payment status from GETO: %s', 'geto-payment-gateway'),
            //         sanitize_text_field($data['status'])
            //     ));
                
            //     // Return error response
            //     status_header(400);
            //     echo json_encode(array('success' => false, 'message' => 'Unknown payment status'));
            //     exit;
        }
        
        // This code should never be reached but is here as a fallback
        status_header(500);
        $this->log_message('Unexpected error in webhook handler for order #' . $order->get_id());
        echo json_encode(array('success' => false, 'message' => 'Unexpected error in webhook processing'));
        exit;
    }

    public function callback_handler() {
        error_log('In callback_handler');
        $this->log_message('In callback_handler');
        // Only run on the "order received" (thank you) page
        if (!is_order_received_page()) {
            return;
        }
    
        $order_id = absint(get_query_var('order-received'));
    
        if (!$order_id) {
            return;
        }
    
        $order = wc_get_order($order_id);
    
        if (!$order || $order->get_payment_method() !== 'geto') {
            return;
        }
    
        // Skip if already paid
        if ($order->is_paid()) {
            return;
        }
    
        // 💡 Optional: retrieve payment key from GET or session
        $payment_key = isset($_GET['paymentKey']) ? sanitize_text_field($_GET['paymentKey']) : null;
    
        if (!$payment_key) {
            $order->add_order_note('GETO return: missing paymentKey');
            return;
        }
    
        // 🎯 Verify payment again with your GETO API
        $response = wp_remote_get('https://your-api-endpoint/check-status?paymentKey=' . $payment_key);
    
        if (is_wp_error($response)) {
            $order->add_order_note('GETO return: API error - ' . $response->get_error_message());
            return;
        }
    
        $body = json_decode(wp_remote_retrieve_body($response), true);
    
        if (!empty($body['status']) && $body['status'] === 'PAID') {
            $order->payment_complete($payment_key);
            $order->add_order_note('GETO payment completed via callback (order received page)');
        } else {
            $order->add_order_note('GETO return: payment not confirmed (status = ' . ($body['status'] ?? 'unknown') . ')');
        }
    }
    

}
