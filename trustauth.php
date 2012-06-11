<?php
/*
Plugin Name: TrustAuth
Plugin URI: http://trustauth.com
Description: This plugin adds TrustAuth authentication to a WordPress blog.
Version: 1.0.0
Author: Dan Fox
Author URI: http://romaimperator.com
License: GPL2
*/
/*  Copyright 2012  Dan Fox  (email : romaimperator@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

global $wpdb;
define("TRUSTAUTH_TABLE_NAME", $wpdb->prefix . "trustauth");
define("TRUSTAUTH_COOKIE_NAME", "trustauth-wordpress");
define("TRUSTAUTH_COOKIE_EXPIRATION", 30);
define("TRUSTAUTH_SALT_OPTION_NAME", "trustauth_salt");
define("TRUSTAUTH_DB_VERSION_OPTION_NAME", "trustauth_db_version");

set_include_path(get_include_path() . PATH_SEPARATOR . ABSPATH . 'wp-content/plugins/trustauth/');
require_once 'libtrustauth.php';
restore_include_path();

/**
 * Inserts the public key for the given user id if the user doesn't have one yet, or updates
 * it to the given public key if the user already has one.
 *
 * @param {int} user_id the id of the user this key belongs to
 * @param {string} public_key the public key to assign this user
 */
function trustauth_insert_or_update_key($user_id, $public_key) {
    if (empty($public_key)) { echo $public_key;die();return; }
    global $wpdb;

    if (trustauth_fetch_public_key($user_id) == null) {
        $wpdb->insert(TRUSTAUTH_TABLE_NAME, array('user_id' => $user_id, 'public_key' => $public_key), array('%s', '%s'));
    } else {
        $wpdb->update(TRUSTAUTH_TABLE_NAME, array('public_key' => $public_key), array('user_id' => $user_id), array('%s'));
    }
}

/**
 * Fetches the public key assigned to the given user id.
 *
 * @param {int} user_id the id of the user to fetch the key for
 * @return {string} the public_key or null if there isn't one for the user
 */
function trustauth_fetch_public_key($user_id) {
    global $wpdb;

    $sql = $wpdb->prepare('SELECT public_key FROM ' . TRUSTAUTH_TABLE_NAME . ' WHERE user_id=%s', $user_id);
    return $wpdb->get_var($sql);
}

/**
 * Adds the TrustAuth fields to the login form.
 */
function trustauth_login() {
    $challenge = TrustAuth::get_challenge();
    setcookie(TRUSTAUTH_COOKIE_NAME, hash('sha256', $challenge . get_option(TRUSTAUTH_SALT_OPTION_NAME)), time() + TRUSTAUTH_COOKIE_EXPIRATION, COOKIEPATH, COOKIE_DOMAIN, false, true);
    echo TrustAuth::authenticate_form(array('challenge' => $challenge));
}

/**
 * Adds the TrustAuth fields to the edit user form.
 */
function trustauth_edit_user() {
    include('edit_user_form.php');
}

/**
 * Authenticates the user's login info with TrustAuth.
 */
function trustauth_authentication($user) {
    if ( ! empty($_POST['pwd'])) { return $user; }
    if ( isset($_POST['log']) && isset($_POST['ta-response']) && isset($_POST['ta-challenge']) && !empty($_POST['ta-challenge']) && isset($_COOKIE[TRUSTAUTH_COOKIE_NAME]) ) {
        $dbuser = get_user_by('login', $_POST['log']);
        if ($dbuser !== null) {
            remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

            if (hash('sha256', $_POST['ta-challenge'] . get_option(TRUSTAUTH_SALT_OPTION_NAME)) === $_COOKIE[TRUSTAUTH_COOKIE_NAME]) {
                try {
                    if (TrustAuth::verify($_POST['ta-challenge'], $_POST['ta-response'], trustauth_fetch_public_key($dbuser->ID))) {
                        $user = new WP_User($dbuser->ID);
                    } else {
                        $user = new WP_Error('trustauth_login_error', __('There was an error verifying the TrustAuth response. Try refreshing the page and logging in again.'));
                    }
                } catch (TAException $e) {
                    $user = new WP_Error('trustauth_exception', __($e->get_user_message()));
                }
            } else {
                $user = new WP_Error('trustauth_hash_error', __('Could not validate the TrustAuth challenge. Try refreshing the page and logging in again.'));
            }
        }
    }
    return $user;
}

/**
 * Checks for a key to add for the user.
 */
function trustauth_after_login($user_login) {
    $user = get_user_by('login', $user_login);
    $public_key = trustauth_fetch_public_key($user->ID);
    if ( isset($user_login) && isset($_POST['ta-key']) && $public_key == null) {
        trustauth_insert_or_update_key($user->ID, $_POST['ta-key']);
    }
}

/**
 * Updates the public_key for the user when edited.
 */
function trustauth_profile_update($user_id) {
    global $wpdb;

    if ( isset($_POST['ta-key']) ) {
        trustauth_insert_or_update_key($user_id, $_POST['ta-key']);
    }
}

/**
 * Creates the tables needed for TrustAuth.
 */
function trustauth_create_tables() {
    global $wpdb;

    $sql = "CREATE TABLE " . TRUSTAUTH_TABLE_NAME . " (
      user_id bigint(20) unsigned NOT NULL,
      public_key text NOT NULL,
      PRIMARY KEY  (user_id)
    );";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    update_option(TRUSTAUTH_DB_VERSION_OPTION_NAME, '1.0.0');
}

/**
 * Deletes the tables needed for TrustAuth.
 */
function trustauth_delete_tables() {
    global $wpdb;

    $sql = "DROP TABLE IF EXISTS " . TRUSTAUTH_TABLE_NAME . ";";
    $wpdb->query($sql);
    delete_option(TRUSTAUTH_DB_VERSION_OPTION_NAME);
}

/**
 * Activates the TrustAuth plugin.
 */
function trustauth_activation() {
    update_option(TRUSTAUTH_SALT_OPTION_NAME, TrustAuth::get_random_value());
    trustauth_create_tables();
}

/**
 * Deactivates the TrustAuth plugin.
 */
function trustauth_deactivation() {
    delete_option(TRUSTAUTH_SALT_OPTION_NAME);
}

/**
 * Uninstalls the TrustAuth plugin.
 */
function trustauth_uninstall() {
    delete_option(TRUSTAUTH_SALT_OPTION_NAME);
    trustauth_delete_tables();
}


// Register all of the hooks
add_action('login_form','trustauth_login');
add_action('show_user_profile', 'trustauth_edit_user');
add_action('profile_update', 'trustauth_profile_update');
add_action('authenticate','trustauth_authentication');
add_action('wp_login', 'trustauth_after_login');

register_activation_hook('trustauth/trustauth.php', 'trustauth_activation');
register_deactivation_hook('trustauth/trustauth.php', 'trustauth_deactivation');
register_uninstall_hook('trustauth/trustauth.php', 'trustauth_uninstall');
?>
