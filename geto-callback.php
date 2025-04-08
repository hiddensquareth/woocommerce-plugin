<?php

function callback_handler() {
    if (!isset($_GET['paymentKey'])) return;

    error_log('GETO callback received: ' . print_r($_GET, true));

    $order_id = wc_get_order_id_by_order_key($_GET['key']);
    $order = wc_get_order($order_id);

    if ($order && $order->has_status('pending')) {
        $order->payment_complete($_GET['paymentKey']);
        $order->add_order_note(__('Payment completed via GETO return callback', 'geto-payment-gateway'));
    }
}
