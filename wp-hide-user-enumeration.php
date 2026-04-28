<?php
/*
Plugin Name: WP Hide User Enumeration & Security
Description: Blockiert gängige WordPress-Pfade zur Benutzer-Aufzählung, sichert die REST API, deaktiviert Benutzer-Sitemaps und schützt vor XML-RPC Angriffen. Inklusive GitHub-Updates.
Version: 1.0.0
Author: behrmedia
*/

if (!defined('ABSPATH')) {
    exit;
}

// ==============================================================================
// 0. GitHub Plugin Update Checker (PUC)
// ==============================================================================
require 'plugin-update-checker/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/DEIN_GITHUB_BENUTZERNAME/wp-hide-user-enumeration/',
    __FILE__,
    'wp-hide-user-enumeration'
);

// Weist PUC an, im Hauptzweig (main) nach Updates zu suchen
$myUpdateChecker->setBranch('main');


// ==============================================================================
// 1. Blockierung der Autoren-Scans (Parameter & Permalinks)
// ==============================================================================
function wp_hue_block_author_enum() {
    if (is_admin()) {
        return;
    }

    if (is_author()) {
        global $wp_query;
        $wp_query->set_404();
        status_header(404);
        nocache_headers();
        
        $template_404 = get_query_template('404');
        if ($template_404) {
            include($template_404);
        }
        exit;
    }
}
add_action('template_redirect', 'wp_hue_block_author_enum', 1);


// ==============================================================================
// 2. Absicherung der REST API (/wp-json/wp/v2/users)
// ==============================================================================
function wp_hue_restrict_rest_users($result) {
    if (!empty($result)) {
        return $result;
    }

    // Erlaubt Administratoren / befugten Nutzern weiterhin den Zugriff (Wichtig für Page Builder)
    if (is_user_logged_in() && current_user_can('list_users')) {
        return $result;
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $rest_prefix = trailingslashit(rest_get_url_prefix()); 

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


// ==============================================================================
// 3. Verstecken der Frontend-Links
// ==============================================================================
function wp_hue_hide_author_links($link) {
    return home_url('/');
}
add_filter('author_link', 'wp_hue_hide_author_links');


// ==============================================================================
// 4. Deaktivierung der nativen WP-Benutzer-Sitemap
// ==============================================================================
add_filter('wp_sitemaps_add_provider', function($provider, $name) {
    if ('users' === $name) {
        return false;
    }
    return $provider;
}, 10, 2);


// ==============================================================================
// 5. Deaktivierung von XML-RPC (Basis-Schutz, falls .htaccess nicht greift)
// ==============================================================================
add_filter('xmlrpc_enabled', '__return_false');

?>
