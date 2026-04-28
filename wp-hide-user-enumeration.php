<?php
/*
Plugin Name: WP Hide User Enumeration & Security
Description: Blockiert gängige WordPress-Pfade zur Benutzer-Aufzählung, sichert die REST API, deaktiviert Benutzer-Sitemaps und schützt vor XML-RPC Angriffen.
Version: 1.2.0
Author: behrmedia
*/

if (!defined('ABSPATH')) {
    exit;
}

// 1. Blockierung der Autoren-Scans (mit nativen WP-Funktionen & 404-Fehler)
function wp_hue_block_author_enum() {
    if (is_admin()) {
        return;
    }

    // is_author() deckt automatisch ?author=1 UND /author/name/ ab
    if (is_author()) {
        global $wp_query;
        $wp_query->set_404();
        status_header(404);
        nocache_headers();
        
        // Lade das echte 404-Template des aktiven Themes
        $template_404 = get_query_template('404');
        if ($template_404) {
            include($template_404);
        }
        exit;
    }
}
add_action('template_redirect', 'wp_hue_block_author_enum', 1);

// 2. Absicherung der REST API (mit dynamischem Präfix)
function wp_hue_restrict_rest_users($result) {
    if (!empty($result)) {
        return $result;
    }

    // Erlaubt Administratoren / befugten Nutzern weiterhin den Zugriff
    if (is_user_logged_in() && current_user_can('list_users')) {
        return $result;
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    // Holt den dynamischen REST-Präfix
    $rest_prefix = trailingslashit(rest_get_url_prefix()); 

    // Dynamische Prüfung auf den /users Endpunkt
    if (strpos($uri, '/' . $rest_prefix . 'wp/v2/users') !== false) {
        return new WP_Error(
            'rest_forbidden', 
            __('REST endpoint unavailable.', 'wp-hue'), 
            array('status' => 403)
        );
    }

    return $result;
}
add_filter('rest_authentication_errors', 'wp_hue_restrict_rest_users');

// 3. Verstecken der Links im Frontend
function wp_hue_hide_author_links($link) {
    return home_url('/');
}
add_filter('author_link', 'wp_hue_hide_author_links');

// 4. NEU: Deaktivierung der nativen WP-Benutzer-Sitemap
add_filter('wp_sitemaps_add_provider', function($provider, $name) {
    if ('users' === $name) {
        return false; // Schließt die Benutzer-Sitemap aus
    }
    return $provider;
}, 10, 2);

// 5. NEU: Deaktivierung von XML-RPC (Schutz vor Brute-Force via system.multicall)
add_filter('xmlrpc_enabled', '__return_false');

// --- GitHub Update Checker Integration ---
require 'plugin-update-checker/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/barti-mcfly/wp-hide-user-enumeration/',
    __FILE__,
    'wp-hide-user-enumeration'
);

// Weist PUC an, im Hauptzweig (main) nach Updates zu suchen
$myUpdateChecker->setBranch('main');